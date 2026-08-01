"""Issue #738 finding F4 — ``reboot_vm`` must PROVE the guest actually rebooted.

``tests/smoke/helpers.reboot_vm`` now polls the observable ``kern.boottime`` token after issuing
the reboot, tolerating SSH failures while the guest is down. A generous timeout is a salvage cap
that raises loudly if the token never changes; once it does, the full readiness gate receives its
own independent budget.

This module pins that PURE comparison seam off-VM (no VM I/O, no network) — it lives under
``tests/`` (NOT ``tests/smoke/``) so it runs in the default suite. Importing
``tests.smoke.helpers`` itself needs no VM (its own module docstring guarantees import-safety;
mirrors the precedent in ``tests/test_smoke_diag_redaction.py``).
"""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import helpers
from tests.smoke.helpers import _assert_boottime_advanced

_BEFORE = "{ sec = 1751500000, usec = 123456 }"
_AFTER = "{ sec = 1751500090, usec = 654321 }"


def test_assert_boottime_advanced_passes_when_value_changed() -> None:
    """Given a kern.boottime reading that DIFFERS before vs. after the reboot
    When _assert_boottime_advanced runs
    Then it does not raise — this is the real-reboot case.
    """
    _assert_boottime_advanced(_BEFORE, _AFTER)  # must not raise


def test_assert_boottime_advanced_raises_when_value_unchanged() -> None:
    """LOAD-BEARING: an unchanged kern.boottime means the readiness gate answered on the
    PRE-reboot instance (the guest never actually went down and back up).

    Given the same kern.boottime reading before AND after
    When _assert_boottime_advanced runs
    Then it raises AssertionError naming BOTH the before and after value, so a maintainer never
         has to guess which side is stale.
    """
    with pytest.raises(AssertionError) as exc_info:
        _assert_boottime_advanced(_BEFORE, _BEFORE)
    message = str(exc_info.value)
    assert _BEFORE in message, f"expected the unchanged value {_BEFORE!r} in the message, got: {message!r}"
    assert "never rebooted" in message


def test_assert_boottime_advanced_raises_when_before_is_empty() -> None:
    """Given an EMPTY pre-reboot reading (the sysctl read itself failed)
    When _assert_boottime_advanced runs
    Then it raises AssertionError naming the BEFORE side as the empty one — never silently
         treats a failed read as "changed".
    """
    with pytest.raises(AssertionError) as exc_info:
        _assert_boottime_advanced("", _AFTER)
    message = str(exc_info.value)
    assert "BEFORE" in message, f"expected the message to name the empty BEFORE side, got: {message!r}"


def test_assert_boottime_advanced_raises_when_after_is_empty() -> None:
    """Given an EMPTY post-reboot reading (the sysctl read itself failed)
    When _assert_boottime_advanced runs
    Then it raises AssertionError naming the AFTER side as the empty one.
    """
    with pytest.raises(AssertionError) as exc_info:
        _assert_boottime_advanced(_BEFORE, "")
    message = str(exc_info.value)
    assert "AFTER" in message, f"expected the message to name the empty AFTER side, got: {message!r}"


def test_assert_boottime_advanced_strips_whitespace_before_comparing() -> None:
    """Given the same value but with SSH-transport-typical trailing newline/whitespace noise on
         one side
    When _assert_boottime_advanced runs
    Then it still detects the values as unchanged (whitespace alone must not read as "advanced").
    """
    with pytest.raises(AssertionError):
        _assert_boottime_advanced(_BEFORE, f"{_BEFORE}\n")


def test_reboot_vm_waits_for_changed_boottime_before_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeVM:
        ssh_key_path = "/tmp/id_ed25519"
        host = "127.0.0.1"
        ssh_port = 2222
        vm_pid = None
        web_port = 8080

        def __init__(self) -> None:
            self.boottime_reads = 0
            self.calls: list[str] = []

        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            command = " ".join(remote)
            self.calls.append(command)
            if command == helpers._BOOTTIME_SYSCTL:
                self.boottime_reads += 1
                value = _BEFORE if self.boottime_reads <= 3 else _AFTER
                return subprocess.CompletedProcess(remote, 0, value, "")
            if command == "/sbin/reboot":
                return subprocess.CompletedProcess(remote, 0, "", "")
            raise AssertionError(f"unexpected ssh command: {command}")

    fake_vm = FakeVM()
    vm = cast(helpers.SmokeVM, fake_vm)
    ready_calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        ready_calls.append(argv)
        assert fake_vm.boottime_reads == 4, "changed boottime must be observed before readiness"
        return subprocess.CompletedProcess(argv, 0, "ready", "")

    monkeypatch.setattr(helpers.subprocess, "run", fake_run)
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(helpers, "wait_boot_complete", lambda vm: None)
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda vm: None)

    helpers.reboot_vm(vm, timeout=5)

    assert ready_calls
    assert fake_vm.boottime_reads == 4
