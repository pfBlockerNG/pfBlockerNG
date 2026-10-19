"""Issue #738 finding F4 — ``reboot_vm`` must PROVE the guest actually rebooted.

``tests/smoke/helpers.reboot_vm`` observes three events, in order, after issuing the reboot: the guest going
offline (its boot identity becomes unreadable at the transport), a changed ``kern.boottime`` token, and full
readiness. SSH failures while the guest is down are expected. A generous timeout is a salvage cap that raises
loudly, labelled ``stuck/environment``, and says WHICH event was missing: the guest never went down, it went
down and did not come back with a new boot, or it came back and was not ready. Once the new boot is seen, the
full readiness gate receives its own independent budget.

This module pins that reboot event flow off-VM with a fake VM (no network) — it lives under
``tests/`` (NOT ``tests/smoke/``) so it runs in the default suite. Importing
``tests.smoke.helpers`` itself needs no VM (its own module docstring guarantees import-safety;
mirrors the precedent in ``tests/test_smoke_diag_redaction.py``). The salvage caps run on a virtual clock that the
fake ``sleep`` advances, so no case costs real time.
"""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import helpers

_BEFORE = "{ sec = 1751500000, usec = 123456 }"
_AFTER = "{ sec = 1751500090, usec = 654321 }"
_SSH_FAILED = 255  # ssh's own exit status when the connection fails: the guest is not answering

_Read = tuple[int, str, str] | Exception


class _FakeVM:
    ssh_key_path = "/tmp/id_ed25519"
    host = "127.0.0.1"
    ssh_port = 2222
    vm_pid = None
    web_port = 8080

    def __init__(self, reads: list[_Read], *, reboot_hangs: bool = False) -> None:
        """``reads`` is every ``kern.boottime`` read in order, the pre-reboot one first; the last repeats."""
        self.reads = reads
        self.reboot_hangs = reboot_hangs
        self.boottime_reads = 0
        self.calls: list[str] = []

    def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        command = " ".join(remote)
        self.calls.append(command)
        if command == helpers._BOOTTIME_SYSCTL:
            step = self.reads[min(self.boottime_reads, len(self.reads) - 1)]
            self.boottime_reads += 1
            if isinstance(step, Exception):
                raise step
            return subprocess.CompletedProcess(remote, step[0], step[1], step[2])
        if command == "/sbin/reboot":
            if self.reboot_hangs:
                raise subprocess.TimeoutExpired(remote, timeout)
            return subprocess.CompletedProcess(remote, 0, "", "")
        if command == f"/bin/test -f {helpers.PFB_CRON_DISABLE_PATH}":
            return subprocess.CompletedProcess(remote, 0, "", "")
        raise AssertionError(f"unexpected ssh command: {command}")


def _patch_reboot_collaborators(
    monkeypatch: pytest.MonkeyPatch, fake_vm: _FakeVM, *, ready_exit: int = 0
) -> tuple[list[int], list[tuple[helpers.SmokeVM, bool]], list[object]]:
    """Virtual time, a fake wait_ready.sh exiting ``ready_exit``, and recorders for the later gates.

    The first recorder holds, for each wait_ready.sh run, how many boottime reads had happened by then.
    """
    now = [0.0]
    monkeypatch.setattr(helpers.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(helpers.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))
    ready_calls: list[int] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        ready_calls.append(fake_vm.boottime_reads)
        return subprocess.CompletedProcess(argv, ready_exit, "", "wait_ready: not up" if ready_exit else "ready")

    monkeypatch.setattr(helpers.subprocess, "run", fake_run)
    boot_waits: list[tuple[helpers.SmokeVM, bool]] = []

    def fake_wait_boot_complete(candidate: helpers.SmokeVM, *, require_pkg_metadata: bool = True) -> None:
        boot_waits.append((candidate, require_pkg_metadata))

    monkeypatch.setattr(helpers, "wait_boot_complete", fake_wait_boot_complete)
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda _vm: None)
    cron_guards: list[object] = []
    monkeypatch.setattr(helpers, "_write_cron_disable_flag", lambda vm: cron_guards.append(vm))
    return ready_calls, boot_waits, cron_guards


@pytest.mark.parametrize("require_pkg_metadata", [None, False, True])
def test_reboot_vm_waits_for_offline_then_changed_boottime_before_readiness(
    monkeypatch: pytest.MonkeyPatch,
    require_pkg_metadata: bool | None,
) -> None:
    """Given the guest answers with its old boot, drops off, answers old again, then shows a new boot
    When reboot_vm runs
    Then readiness starts only after the new boot, and only the readiness gate sees require_pkg_metadata.
    """
    fake_vm = _FakeVM(
        [
            (0, _BEFORE, ""),  # the pre-reboot read
            (_SSH_FAILED, "", "ssh: connect to host 127.0.0.1 port 2222: Connection refused"),  # offline
            (0, _BEFORE, ""),  # a stale answer: not a new boot
            (0, _AFTER, ""),  # the new boot
        ]
    )
    vm = cast(helpers.SmokeVM, fake_vm)
    ready_calls, boot_waits, cron_guards = _patch_reboot_collaborators(monkeypatch, fake_vm)

    if require_pkg_metadata is None:
        helpers.reboot_vm(vm, timeout=5)
    else:
        helpers.reboot_vm(vm, timeout=5, require_pkg_metadata=require_pkg_metadata)

    assert ready_calls == [4], "offline, then the changed boottime, must be observed before readiness starts"
    assert "/sbin/reboot" in fake_vm.calls
    assert fake_vm.boottime_reads == 4
    # Default False since issue #2624.
    assert boot_waits == [(vm, False if require_pkg_metadata is None else require_pkg_metadata)]
    assert cron_guards == [vm]


def test_a_new_boottime_is_not_accepted_before_the_guest_was_seen_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given a guest that never fails a read and shows a different boottime at once
    When reboot_vm runs
    Then it does not take that for a reboot: it ends at the salvage cap, naming the missing offline phase,
    and wait_ready.sh never starts.
    """
    fake_vm = _FakeVM([(0, _BEFORE, ""), (0, _AFTER, "")])
    ready_calls, boot_waits, _ = _patch_reboot_collaborators(monkeypatch, fake_vm)

    with pytest.raises(RuntimeError, match=r"^stuck/environment: reboot_vm: .*never observed offline") as excinfo:
        helpers.reboot_vm(cast(helpers.SmokeVM, fake_vm), timeout=10)

    assert _AFTER in str(excinfo.value)
    assert not ready_calls and not boot_waits


def test_a_guest_that_never_goes_down_is_told_apart_from_one_that_does_not_come_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given the old boot keeps answering after the reboot command
    When reboot_vm runs to its salvage cap
    Then the error says the guest never went offline, carries the last read, and no readiness gate ran.
    """
    fake_vm = _FakeVM([(0, _BEFORE, "")])
    ready_calls, boot_waits, _ = _patch_reboot_collaborators(monkeypatch, fake_vm)

    with pytest.raises(RuntimeError, match=r"^stuck/environment: reboot_vm: the guest never went offline") as excinfo:
        helpers.reboot_vm(cast(helpers.SmokeVM, fake_vm), timeout=10)

    assert _BEFORE in str(excinfo.value)
    assert not ready_calls and not boot_waits


@pytest.mark.parametrize(
    "offline",
    [
        (_SSH_FAILED, "", "ssh: connect to host: Connection refused"),
        subprocess.TimeoutExpired("ssh", 15.0),
        OSError("ssh not runnable"),
    ],
    ids=["ssh-exit-255", "hung-connection", "oserror"],
)
def test_a_guest_that_went_offline_and_never_returns_says_so(monkeypatch: pytest.MonkeyPatch, offline: _Read) -> None:
    """Given the guest drops off (an ssh failure, a hung connection or an OS error) and stays down
    When reboot_vm runs to its salvage cap
    Then the error says it went offline but did not come back with a new boottime.
    """
    fake_vm = _FakeVM([(0, _BEFORE, ""), offline])
    ready_calls, _, _ = _patch_reboot_collaborators(monkeypatch, fake_vm)

    with pytest.raises(RuntimeError, match=r"^stuck/environment: reboot_vm: the guest went offline but did not come"):
        helpers.reboot_vm(cast(helpers.SmokeVM, fake_vm), timeout=10)

    assert not ready_calls


def test_a_failing_command_on_a_live_guest_is_not_the_guest_going_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given the guest answers, but the sysctl itself fails (exit 1, not ssh's 255) and then reads a new boot
    When reboot_vm runs
    Then the failed command is not an offline phase, so the new boot is refused as unobserved-offline.
    """
    fake_vm = _FakeVM([(0, _BEFORE, ""), (1, "", "sysctl: unknown oid"), (0, _AFTER, "")])
    _patch_reboot_collaborators(monkeypatch, fake_vm)

    with pytest.raises(RuntimeError, match=r"never observed offline"):
        helpers.reboot_vm(cast(helpers.SmokeVM, fake_vm), timeout=10)


def test_a_guest_that_is_back_but_not_ready_is_told_apart_from_one_that_never_went_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given the guest goes offline and shows a new boot, but wait_ready.sh exits 1
    When reboot_vm runs
    Then the error is stuck/environment and says the guest is back with the new boot but not ready.
    """
    fake_vm = _FakeVM([(0, _BEFORE, ""), (_SSH_FAILED, "", "refused"), (0, _AFTER, "")])
    ready_calls, boot_waits, _ = _patch_reboot_collaborators(monkeypatch, fake_vm, ready_exit=1)

    with pytest.raises(
        RuntimeError, match=r"^stuck/environment: reboot_vm: the guest is back with a new boot"
    ) as excinfo:
        helpers.reboot_vm(cast(helpers.SmokeVM, fake_vm), timeout=10)

    message = str(excinfo.value)
    assert _BEFORE in message and _AFTER in message and "not ready" in message
    assert ready_calls and not boot_waits


def test_a_reboot_command_whose_ssh_session_hangs_is_not_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given /sbin/reboot's own ssh session hangs until its timeout (the guest is going down under it)
    When the guest then shows offline and a new boot
    Then reboot_vm carries on to readiness.
    """
    fake_vm = _FakeVM([(0, _BEFORE, ""), (_SSH_FAILED, "", "refused"), (0, _AFTER, "")], reboot_hangs=True)
    ready_calls, boot_waits, _ = _patch_reboot_collaborators(monkeypatch, fake_vm)

    helpers.reboot_vm(cast(helpers.SmokeVM, fake_vm), timeout=10)

    assert ready_calls == [3] and boot_waits
