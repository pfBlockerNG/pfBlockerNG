"""``guest_file_contains`` must never read a failed grep as "absent".

Issue #909: grep rc 2 (e.g. an unreadable file) was folded into ``False``, so a
negative assertion (``assert not guest_file_contains(...)``) could pass vacuously
on a file that was never actually read. A missing file stays a legitimate
``False`` — the helper's on-guest existence pre-check maps it to rc 1 before
grep runs. Pinned off-VM with the ``_FakeVM`` pattern (precedent:
``test_smoke_unbound_ready.py``).
"""

from __future__ import annotations

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
    """Fake ``vm.ssh(*remote, timeout=...)`` — records calls, replays one scripted result."""

    result: _FakeResult
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        self.calls.append(remote)
        return self.result


def test_match_returns_true() -> None:
    """rc 0 (grep matched) is True."""
    vm = _FakeVM(result=_FakeResult(returncode=0))
    assert helpers.guest_file_contains(vm, "/var/log/x.log", "needle") is True  # type: ignore[arg-type]


def test_absent_returns_false() -> None:
    """rc 1 is False — no match, or the file does not exist (the on-guest
    existence pre-check maps a missing file to rc 1 before grep runs)."""
    vm = _FakeVM(result=_FakeResult(returncode=1))
    assert helpers.guest_file_contains(vm, "/var/log/x.log", "needle") is False  # type: ignore[arg-type]


def test_grep_read_error_raises_not_absent() -> None:
    """rc 2 (grep read fault, e.g. an unreadable file) raises — it must NOT read
    as "does not contain": pre-#909 this returned False, letting a negative
    assertion pass without the log ever being read."""
    vm = _FakeVM(result=_FakeResult(returncode=2, stderr="grep: /var/log/x.log: Permission denied"))
    with pytest.raises(RuntimeError, match=r"rc=2.*Permission denied"):
        helpers.guest_file_contains(vm, "/var/log/x.log", "needle")  # type: ignore[arg-type]


def test_ssh_transport_failure_still_raises() -> None:
    """rc 255 (ssh transport fault) raises, as it always did."""
    vm = _FakeVM(result=_FakeResult(returncode=255, stderr="ssh: connect refused"))
    with pytest.raises(RuntimeError, match=r"rc=255"):
        helpers.guest_file_contains(vm, "/var/log/x.log", "needle")  # type: ignore[arg-type]


def test_probe_prechecks_existence_before_grep() -> None:
    """The single guest command must gate grep behind an existence check, so a
    missing file surfaces as rc 1 (absent) rather than grep's own rc 2."""
    vm = _FakeVM(result=_FakeResult(returncode=1))
    helpers.guest_file_contains(vm, "/var/log/x.log", "needle")  # type: ignore[arg-type]
    (probe,) = vm.calls[0]
    assert "[ -e /var/log/x.log ] || exit 1" in probe
    assert "grep -F -q" in probe
