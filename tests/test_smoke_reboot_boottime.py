"""Issue #738 finding F4 — ``reboot_vm`` must PROVE the guest actually rebooted.

``tests/smoke/helpers.reboot_vm`` now polls the observable ``kern.boottime`` token after issuing
the reboot, tolerating SSH failures while the guest is down. A generous timeout is a salvage cap
that raises loudly if the token never changes; once it does, the full readiness gate receives its
own independent budget.

This module pins that reboot event flow off-VM with a fake VM (no network) — it lives under
``tests/`` (NOT ``tests/smoke/``) so it runs in the default suite. Importing
``tests.smoke.helpers`` itself needs no VM (its own module docstring guarantees import-safety;
mirrors the precedent in ``tests/test_smoke_diag_redaction.py``).
"""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import helpers

_BEFORE = "{ sec = 1751500000, usec = 123456 }"
_AFTER = "{ sec = 1751500090, usec = 654321 }"


@pytest.mark.parametrize("require_pkg_metadata", [None, False, True])
def test_reboot_vm_waits_for_changed_boottime_before_readiness(
    monkeypatch: pytest.MonkeyPatch,
    require_pkg_metadata: bool | None,
) -> None:
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
                if self.boottime_reads == 1:
                    return subprocess.CompletedProcess(remote, 0, _BEFORE, "")
                if self.boottime_reads == 2:
                    return subprocess.CompletedProcess(remote, 1, _AFTER, "sysctl failed")
                value = _BEFORE if self.boottime_reads == 3 else _AFTER
                return subprocess.CompletedProcess(remote, 0, value, "")
            if command == "/sbin/reboot":
                return subprocess.CompletedProcess(remote, 0, "", "")
            if command == f"/bin/test -f {helpers.PFB_CRON_DISABLE_PATH}":
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
    boot_waits: list[tuple[helpers.SmokeVM, bool]] = []

    def fake_wait_boot_complete(
        candidate: helpers.SmokeVM,
        *,
        require_pkg_metadata: bool = True,
    ) -> None:
        boot_waits.append((candidate, require_pkg_metadata))

    monkeypatch.setattr(helpers, "wait_boot_complete", fake_wait_boot_complete)
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda vm: None)
    cron_guards: list[object] = []
    monkeypatch.setattr(helpers, "_write_cron_disable_flag", lambda vm: cron_guards.append(vm))

    if require_pkg_metadata is None:
        helpers.reboot_vm(vm, timeout=5)
    else:
        helpers.reboot_vm(vm, timeout=5, require_pkg_metadata=require_pkg_metadata)

    assert ready_calls
    assert "/sbin/reboot" in fake_vm.calls
    assert fake_vm.boottime_reads == 4
    # Default False since issue #2624.
    assert boot_waits == [(vm, False if require_pkg_metadata is None else require_pkg_metadata)]
    assert cron_guards == [vm]
