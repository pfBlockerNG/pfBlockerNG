"""``wait_unbound_ready`` must survive slow restart-class reloads AND fail loudly.

Issue #845: a restart-class reload (unbound restart + DNSBL structure rebuild before
the control socket answers) legitimately exceeds the old 60s budget (30 attempts x 2s)
under CI load — the identical rerun passed. Additionally, on exhaustion the old code
raised a bare ``RuntimeError`` with zero diagnostics, making "unbound never started"
indistinguishable from "started but slow". This module pins BOTH the widened budget
and the timeout-diagnostics contract off-VM (no VM I/O; ``tests.smoke.helpers`` is
import-safe — precedent: ``test_smoke_unblock_egress.py``).

The budget is a real deadline (testing.md "Synchronize"): a status probe that hangs spends it too, so the
wait can no longer run for ``attempts x (probe timeout + delay)``. Every case runs on a virtual clock that
the fake ``sleep`` and the fake probes advance, so no case costs real time and none asserts a wall-clock
floor or ceiling.
"""

from __future__ import annotations

import inspect
import subprocess
from dataclasses import dataclass, field

import pytest

from tests.smoke import helpers


class _Clock:
    """Virtual monotonic time: ``sleep`` and a probe that spends its timeout advance it."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _virtual_time(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    clock = _Clock()
    monkeypatch.setattr(helpers.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(helpers.time, "sleep", clock.sleep)
    return clock


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


def test_default_deadline_is_at_least_120_seconds_and_a_failing_status_ends_on_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a fake vm whose status check never returns rc=0
    When wait_unbound_ready runs with the DEFAULT timeout/delay
    Then (a) the deadline is >= 120s — the widened CI budget (issue #845), not the old 60s that flaked
    under a slow restart-class reload — and (b) the wait polls on until that deadline and not a probe
    longer, proving the widened budget is real, not just a signature claim; the error says
    stuck/environment.
    """
    clock = _virtual_time(monkeypatch)
    sig = inspect.signature(helpers.wait_unbound_ready)
    default_timeout = sig.parameters["timeout"].default
    default_delay = sig.parameters["delay"].default
    assert default_timeout >= 120.0

    vm = _FakeVM(results=[_FakeResult(returncode=1, stdout="down", stderr="")])

    with pytest.raises(RuntimeError, match=r"^stuck/environment: Unbound did not become ready"):
        helpers.wait_unbound_ready(vm)  # type: ignore[arg-type]

    status_polls = [c for c in vm.calls if "unbound-control" in c[0]]
    assert len(status_polls) == int(default_timeout / default_delay)
    assert clock.now == default_timeout


def test_status_probes_that_hang_spend_the_deadline_and_cannot_stretch_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given every `unbound-control status` hangs until its own ssh timeout
    When wait_unbound_ready runs with a 100 s deadline
    Then no probe is given more than the time left, so the wait ends at the deadline (the old loop gave each
    of its 60 attempts the full 15 s on top of its 2 s delay), and the error carries the hung probe.
    """
    clock = _virtual_time(monkeypatch)
    probe_timeouts: list[float] = []

    class HungVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
            if "unbound-control" not in remote[0]:
                return _FakeResult(returncode=0, stdout="PROC-LIST-SENTINEL unbound")
            probe_timeouts.append(timeout)
            clock.now += timeout
            raise subprocess.TimeoutExpired(remote, timeout)

    with pytest.raises(RuntimeError, match=r"^stuck/environment: .*TimeoutExpired") as excinfo:
        helpers.wait_unbound_ready(HungVM(), timeout=100.0, delay=2.0)  # type: ignore[arg-type]

    assert max(probe_timeouts) == 15.0
    assert clock.now == 100.0
    assert "PROC-LIST-SENTINEL" in str(excinfo.value)


def test_timeout_error_reports_last_poll_and_process_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given unbound-control status always fails with distinctive output
    When wait_unbound_ready exhausts its deadline
    Then the raised RuntimeError names the LAST poll's rc/stdout/stderr AND the
    unbound process-list diagnostics — never a bare message (CLAUDE.md: print
    expected vs. actual on every failing poll) — so a reader can tell "never
    started" from "started but slow".
    """
    _virtual_time(monkeypatch)

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
        helpers.wait_unbound_ready(vm, timeout=4.0, delay=2.0)  # type: ignore[arg-type]

    message = str(excinfo.value)
    assert message.startswith("stuck/environment:")
    assert "STATUS-SENTINEL-OUT" in message
    assert "STATUS-SENTINEL-ERR" in message
    assert "rc=1" in message
    assert "PROC-LIST-SENTINEL" in message


def test_timeout_diagnostics_survive_a_failing_process_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given unbound-control status always fails AND the process-list probe itself
    raises (an unresponsive box times out the diagnostics ssh call too)
    When wait_unbound_ready exhausts its deadline
    Then the detailed RuntimeError still fires with the last poll's rc/stdout/stderr
    and names the probe failure — the best-effort probe never replaces the
    expected-vs-actual diagnostics with an opaque unrelated exception (PR #846 review).
    """
    _virtual_time(monkeypatch)

    status_result = _FakeResult(returncode=1, stdout="STATUS-SENTINEL-OUT", stderr="STATUS-SENTINEL-ERR")
    vm = _FakeVM(results=[status_result])

    def ssh(*remote: str, timeout: float = 60.0) -> _FakeResult:
        vm.calls.append(remote)
        if "unbound-control" in remote[0]:
            return status_result
        raise TimeoutError("PROBE-TIMEOUT-SENTINEL")

    monkeypatch.setattr(vm, "ssh", ssh)

    with pytest.raises(RuntimeError) as excinfo:
        helpers.wait_unbound_ready(vm, timeout=4.0, delay=2.0)  # type: ignore[arg-type]

    message = str(excinfo.value)
    assert "STATUS-SENTINEL-OUT" in message
    assert "rc=1" in message
    assert "PROBE-TIMEOUT-SENTINEL" in message


def test_returns_without_raising_once_status_reports_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given unbound-control status returns rc=0 on the FIRST poll
    When wait_unbound_ready runs
    Then it returns immediately (no raise, no diagnostics probe, exactly one ssh call, no sleep).
    """
    clock = _virtual_time(monkeypatch)
    vm = _FakeVM(results=[_FakeResult(returncode=0, stdout="ok", stderr="")])

    helpers.wait_unbound_ready(vm, delay=0)  # type: ignore[arg-type]

    assert len(vm.calls) == 1
    assert clock.now == 0.0


def test_a_hung_probe_does_not_end_the_wait_when_a_later_one_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given the first status probe hangs and the second reports ready
    When wait_unbound_ready runs
    Then it returns on the second probe: a hung ssh is one failed poll, not the verdict.
    """
    clock = _virtual_time(monkeypatch)
    polls: list[float] = []

    class SlowThenReadyVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
            polls.append(timeout)
            if len(polls) == 1:
                clock.now += timeout
                raise subprocess.TimeoutExpired(remote, timeout)
            return _FakeResult(returncode=0, stdout="ok")

    helpers.wait_unbound_ready(SlowThenReadyVM(), delay=2.0)  # type: ignore[arg-type]

    assert polls == [15.0, 15.0]
    assert clock.now == 17.0
