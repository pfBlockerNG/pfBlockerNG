"""``wait_unbound_ready`` must survive slow restart-class reloads AND fail loudly.

Issue #845: a restart-class reload (unbound restart + DNSBL structure rebuild before
the control socket answers) legitimately exceeds the old 60s budget (30 attempts x 2s)
under CI load — the identical rerun passed. Additionally, on exhaustion the old code
raised a bare ``RuntimeError`` with zero diagnostics, making "unbound never started"
indistinguishable from "started but slow". This module pins BOTH the widened budget
and the timeout-diagnostics contract off-VM (no VM I/O; ``tests.smoke.helpers`` is
import-safe — precedent: ``test_smoke_unblock_egress.py``).
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field

import pytest

from tests.smoke import helpers


@dataclass
class _FakeResult:
    """Stand-in for ``subprocess.CompletedProcess[str]`` (the shape ``SmokeVM.ssh`` returns)."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class _FakeVM:
    """Fake ``vm.ssh(*remote, timeout=...)`` — records calls, replays scripted results."""

    results: list[_FakeResult]
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        self.calls.append(remote)
        index = min(len(self.calls) - 1, len(self.results) - 1)
        return self.results[index]


def test_default_budget_polls_at_least_120_seconds_worth_of_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a fake vm whose status check never returns rc=0
    When wait_unbound_ready runs with the DEFAULT attempts/delay
    Then (a) attempts x delay is >= 120s — the widened CI budget (issue #845), not
    the old 60s (30 x 2) that flaked under a slow restart-class reload — and (b) the
    loop actually polls that many times (excluding the post-loop diagnostics call)
    before giving up, proving the widened budget is real, not just a signature claim.
    """
    monkeypatch.setattr(helpers.time, "sleep", lambda _seconds: None)
    sig = inspect.signature(helpers.wait_unbound_ready)
    default_attempts = sig.parameters["attempts"].default
    default_delay = sig.parameters["delay"].default
    assert default_attempts * default_delay >= 120.0

    vm = _FakeVM(results=[_FakeResult(returncode=1, stdout="down", stderr="")])

    with pytest.raises(RuntimeError):
        helpers.wait_unbound_ready(vm)  # type: ignore[arg-type]

    status_polls = [c for c in vm.calls if "unbound-control" in c[0]]
    assert len(status_polls) == default_attempts


def test_timeout_error_reports_last_poll_and_process_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given unbound-control status always fails with distinctive output
    When wait_unbound_ready exhausts its attempts
    Then the raised RuntimeError names the LAST poll's rc/stdout/stderr AND the
    unbound process-list diagnostics — never a bare message (CLAUDE.md: print
    expected vs. actual on every failing poll) — so a reader can tell "never
    started" from "started but slow".
    """
    monkeypatch.setattr(helpers.time, "sleep", lambda _seconds: None)

    status_result = _FakeResult(returncode=1, stdout="STATUS-SENTINEL-OUT", stderr="STATUS-SENTINEL-ERR")
    procs_result = _FakeResult(returncode=0, stdout="PROC-LIST-SENTINEL unbound", stderr="")
    vm = _FakeVM(results=[status_result])

    def ssh(*remote: str, timeout: float = 60.0) -> _FakeResult:
        vm.calls.append(remote)
        if "unbound-control" in remote[0]:
            return status_result
        return procs_result

    monkeypatch.setattr(vm, "ssh", ssh)

    with pytest.raises(RuntimeError) as excinfo:
        helpers.wait_unbound_ready(vm, attempts=2, delay=0)  # type: ignore[arg-type]

    message = str(excinfo.value)
    assert "STATUS-SENTINEL-OUT" in message
    assert "STATUS-SENTINEL-ERR" in message
    assert "rc=1" in message
    assert "PROC-LIST-SENTINEL" in message


def test_timeout_diagnostics_survive_a_failing_process_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given unbound-control status always fails AND the process-list probe itself
    raises (an unresponsive box times out the diagnostics ssh call too)
    When wait_unbound_ready exhausts its attempts
    Then the detailed RuntimeError still fires with the last poll's rc/stdout/stderr
    and names the probe failure — the best-effort probe never replaces the
    expected-vs-actual diagnostics with an opaque unrelated exception (PR #846 review).
    """
    monkeypatch.setattr(helpers.time, "sleep", lambda _seconds: None)

    status_result = _FakeResult(returncode=1, stdout="STATUS-SENTINEL-OUT", stderr="STATUS-SENTINEL-ERR")
    vm = _FakeVM(results=[status_result])

    def ssh(*remote: str, timeout: float = 60.0) -> _FakeResult:
        vm.calls.append(remote)
        if "unbound-control" in remote[0]:
            return status_result
        raise TimeoutError("PROBE-TIMEOUT-SENTINEL")

    monkeypatch.setattr(vm, "ssh", ssh)

    with pytest.raises(RuntimeError) as excinfo:
        helpers.wait_unbound_ready(vm, attempts=2, delay=0)  # type: ignore[arg-type]

    message = str(excinfo.value)
    assert "STATUS-SENTINEL-OUT" in message
    assert "rc=1" in message
    assert "PROBE-TIMEOUT-SENTINEL" in message


def test_returns_without_raising_once_status_reports_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given unbound-control status returns rc=0 on the FIRST poll
    When wait_unbound_ready runs
    Then it returns immediately (no raise, no diagnostics probe, exactly one ssh call).
    """
    monkeypatch.setattr(helpers.time, "sleep", lambda _seconds: None)
    vm = _FakeVM(results=[_FakeResult(returncode=0, stdout="ok", stderr="")])

    helpers.wait_unbound_ready(vm, delay=0)  # type: ignore[arg-type]

    assert len(vm.calls) == 1
