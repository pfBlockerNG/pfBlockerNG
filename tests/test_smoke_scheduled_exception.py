"""Hermetic #3977 scheduled opt-in safety contract; no guest or host commands run.

Chosen native service form: ``service cron onestatus/onestop/onestart``.
Supported status results are rc=0 / ``cron is running as pid <pid>.`` and
rc=1 / ``cron is not running.``; rc=1 alone is NOT proof of a stopped cron.
This models that contract, not proof that any particular image supports it.
"""

from __future__ import annotations

import shlex
import subprocess
from typing import Any

import pytest

from tests.smoke import conftest as smoke_conftest

SENTINEL = "/var/db/pfblockerng/.pfb_cron_disable"
STATUS = "service cron onestatus"
STOP = "service cron onestop"
START = "service cron onestart"
REMOVE = f"/bin/rm -f {SENTINEL}"
RESTORE = f"/usr/bin/touch {SENTINEL}"
EXISTS = f"test -f {SENTINEL}"


class _Guest:
    """Stateful subprocess boundary: native exit codes, stdout and stderr."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, running: bool = True) -> None:
        self.vm = smoke_conftest.SmokeVM(
            ssh_key_path="/inert/disposable-key",
            host="127.0.0.1",
            ssh_port=22222,
            vm_pid=424242,
            log_path="/inert/disposable-vm.log",
        )
        self.running = running
        self.sentinel = True
        self.calls: list[str] = []
        self.status_failure: tuple[int, str, str] | None = None
        self.stop_failure = False
        self.stop_ineffective = False
        self.restore_failure = False
        self.remove_failure = False
        self.verify_failure = False
        self.start_failure = False
        self.start_ineffective = False
        self.transport_failure: str | None = None
        monkeypatch.setenv("SMOKE_SCHEDULED_EXCEPTION", "allow")
        monkeypatch.setattr(smoke_conftest.subprocess, "run", self.run)

    def run(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        prefix = [
            "ssh",
            "-i",
            "/inert/disposable-key",
            "-p",
            "22222",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "LogLevel=ERROR",
            "root@127.0.0.1",
            "/bin/sh",
            "-c",
        ]
        assert argv[:-1] == prefix, f"expected isolated SSH transport {prefix!r}, got {argv!r}"
        decoded = shlex.split(argv[-1])
        assert len(decoded) == 1, f"expected one quoted POSIX command, got {argv!r}"
        command = decoded[0]
        assert argv[-1] == shlex.quote(command), f"command is not shell-quoted: {argv!r}"
        assert kwargs.get("capture_output") is True, f"missing captured diagnostics: {kwargs!r}"
        assert kwargs.get("text") is True, f"expected text stdout/stderr: {kwargs!r}"
        assert isinstance(kwargs.get("timeout"), (int, float)) and kwargs["timeout"] > 0, (
            f"guest command needs a bounded timeout: {kwargs!r}"
        )
        self.calls.append(command)
        if self.transport_failure == command:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], stderr="SSH command timed out")
        rc, stdout, stderr = 0, "", ""
        if command == STATUS:
            if self.status_failure is not None:
                rc, stdout, stderr = self.status_failure
            elif self.running:
                stdout = "cron is running as pid 31415.\n"
            else:
                rc, stdout = 1, "cron is not running.\n"
        elif command == STOP:
            assert self.sentinel, "cron stop occurred after sentinel removal"
            if self.stop_failure:
                rc, stderr = 1, "cron could not be stopped: operation failed\n"
            elif not self.stop_ineffective:
                self.running = False
        elif command == REMOVE:
            assert not self.running, "sentinel removed while native guest cron was still running"
            assert self.calls[-2:] == [STATUS, REMOVE], f"missing stopped-state verification: {self.calls!r}"
            if self.remove_failure:
                rc, stderr = 1, "rm: Permission denied\n"
            else:
                self.sentinel = False
        elif command == RESTORE:
            if self.restore_failure:
                rc, stderr = 1, "touch: Permission denied\n"
            else:
                self.sentinel = True
        elif command == EXISTS:
            rc = 0 if self.sentinel and not self.verify_failure else 1
        elif command == START:
            assert self.sentinel, "cron restarted before the sentinel was restored"
            assert self.calls[-3:] == [RESTORE, EXISTS, START], (
                f"cron restarted without verified sentinel restoration: {self.calls!r}"
            )
            if self.start_failure:
                rc, stderr = 1, "cron could not be started\n"
            elif not self.start_ineffective:
                self.running = True
        else:
            pytest.fail(f"unexpected remote command {command!r}; recorded calls: {self.calls!r}")
        result = subprocess.CompletedProcess(argv, rc, stdout, stderr)
        if kwargs.get("check"):
            result.check_returncode()
        return result

    def assert_calls(self, expected: list[str]) -> None:
        assert self.calls == expected, f"expected remote order {expected!r}, got {self.calls!r}"


@pytest.fixture
def guest(monkeypatch: pytest.MonkeyPatch) -> _Guest:
    return _Guest(monkeypatch)


@pytest.mark.parametrize("optin", [None, "", "ALLOW", "true", "allow ", "allow; true"])
def test_optin_denies_before_any_transport(guest: _Guest, monkeypatch: pytest.MonkeyPatch, optin: str | None) -> None:
    if optin is None:
        monkeypatch.delenv("SMOKE_SCHEDULED_EXCEPTION", raising=False)
    else:
        monkeypatch.setenv("SMOKE_SCHEDULED_EXCEPTION", optin)
    with pytest.raises(RuntimeError, match="SMOKE_SCHEDULED_EXCEPTION.*allow"):
        with guest.vm.scheduled_feedphase():
            pytest.fail(f"scheduled body admitted invalid opt-in {optin!r}")
    guest.assert_calls([])
    assert guest.sentinel, "denied opt-in removed the sentinel"


@pytest.mark.parametrize("field", ["vm_pid", "log_path"])
def test_missing_disposable_identity_denies_before_any_transport(guest: _Guest, field: str) -> None:
    setattr(guest.vm, field, None)
    with pytest.raises(RuntimeError, match="(?i)disposable|vm_pid|log_path|boot"):
        with guest.vm.scheduled_feedphase():
            pytest.fail(f"scheduled body admitted missing {field}")
    guest.assert_calls([])
    assert guest.sentinel, "missing disposable identity removed the sentinel"


@pytest.mark.parametrize(
    "remote",
    [
        (REMOVE,),
        ("/bin/rm", "-f", SENTINEL),
        (f"unlink {SENTINEL}",),
        (f"/bin/rm -f {SENTINEL} /tmp/other",),
        (f"{REMOVE}; true",),
    ],
)
def test_default_ssh_guard_is_not_an_optin_bypass(guest: _Guest, remote: tuple[str, ...]) -> None:
    with pytest.raises(RuntimeError, match="scheduled ticks must stay disabled"):
        guest.vm.ssh(*remote)
    guest.assert_calls([])
    assert guest.sentinel, f"ordinary ssh removed sentinel via {remote!r}"


@pytest.mark.parametrize(
    "failure",
    [
        (1, "", "Usage: service <service> <command>\n"),
        (64, "", "onestatus is not supported\n"),
        (255, "", "ssh: Connection refused\n"),
        (0, "unrecognized service status\n", ""),
    ],
)
def test_unsupported_or_unreadable_preflight_never_removes_sentinel(
    guest: _Guest, failure: tuple[int, str, str]
) -> None:
    guest.status_failure = failure
    with pytest.raises(RuntimeError, match="(?i)cron.*(status|preflight)|onestatus"):
        with guest.vm.scheduled_feedphase():
            pytest.fail(f"scheduled body admitted unsupported status {failure!r}")
    guest.assert_calls([STATUS])
    assert guest.sentinel, f"preflight {failure!r} removed sentinel"
    assert guest.running, f"preflight {failure!r} changed cron state"


def test_stop_failure_never_removes_sentinel(guest: _Guest) -> None:
    guest.stop_failure = True
    with pytest.raises(RuntimeError, match="(?i)cron.*stop|onestop"):
        with guest.vm.scheduled_feedphase():
            pytest.fail("scheduled body admitted failed cron stop")
    assert guest.calls[:2] == [STATUS, STOP], f"stop preflight order: {guest.calls!r}"
    assert REMOVE not in guest.calls, f"failed stop removed sentinel: {guest.calls!r}"
    assert guest.sentinel, "failed stop left sentinel absent"
    assert guest.running, "failed stop changed originally-running cron"


def test_successful_stop_must_also_verify_stopped_status(guest: _Guest) -> None:
    guest.stop_ineffective = True
    with pytest.raises(RuntimeError, match="(?i)cron.*(stop|running)|onestatus"):
        with guest.vm.scheduled_feedphase():
            pytest.fail("scheduled body admitted cron still running after onestop")
    assert guest.calls[:3] == [STATUS, STOP, STATUS], f"missing stopped-state probe: {guest.calls!r}"
    assert REMOVE not in guest.calls, f"ineffective stop removed sentinel: {guest.calls!r}"
    assert guest.sentinel, "ineffective stop left sentinel absent"


@pytest.mark.parametrize("body_error", [AssertionError("body assertion failed"), ValueError("body failed")])
def test_body_exception_restores_sentinel_before_originally_running_cron(guest: _Guest, body_error: Exception) -> None:
    with pytest.raises(type(body_error), match=str(body_error)) as caught:
        with guest.vm.scheduled_feedphase():
            assert not guest.sentinel, "scheduled body never received the exact sentinel exception"
            assert not guest.running, "guest cron was not stopped during scheduled body"
            raise body_error
    assert caught.value is body_error, "cleanup replaced the original body failure"
    guest.assert_calls([STATUS, STOP, STATUS, REMOVE, RESTORE, EXISTS, START, STATUS])
    assert guest.sentinel, "exception cleanup left sentinel absent"
    assert guest.running, "exception cleanup failed to restore originally-running cron"


def test_initially_stopped_cron_stays_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    guest = _Guest(monkeypatch, running=False)
    with guest.vm.scheduled_feedphase():
        assert not guest.sentinel, "scheduled context did not remove sentinel"
        assert not guest.running, "scheduled context started originally-stopped cron"
    # No stop/start is necessary for an already-stopped service; recheck before removal.
    assert guest.calls in (
        [STATUS, REMOVE, RESTORE, EXISTS, STATUS],
        [STATUS, STATUS, REMOVE, RESTORE, EXISTS, STATUS],
        [STATUS, STOP, STATUS, REMOVE, RESTORE, EXISTS, STATUS],
    ), f"expected stopped cron preserved and verified, got {guest.calls!r}"
    assert guest.sentinel, "cleanup left sentinel absent"
    assert not guest.running, "cleanup started originally-stopped cron"


def test_success_admits_only_internal_exact_removal_and_restores_in_order(guest: _Guest) -> None:
    with guest.vm.scheduled_feedphase():
        guest.assert_calls([STATUS, STOP, STATUS, REMOVE])
        assert not guest.sentinel, "context failed to admit exact sentinel removal"
        assert not guest.running, "context yielded while native cron was running"
        for command in (REMOVE, f"unlink {SENTINEL}", f"{REMOVE} /tmp/other", f"{REMOVE}; true"):
            with pytest.raises(RuntimeError, match="scheduled ticks must stay disabled"):
                guest.vm.ssh(command)
        guest.assert_calls([STATUS, STOP, STATUS, REMOVE])
    guest.assert_calls([STATUS, STOP, STATUS, REMOVE, RESTORE, EXISTS, START, STATUS])
    assert guest.sentinel, "successful context left sentinel absent"
    assert guest.running, "successful context failed to restore original cron state"


def test_failed_sentinel_restore_must_not_restart_cron(guest: _Guest) -> None:
    guest.restore_failure = True
    with pytest.raises(RuntimeError, match="(?i)sentinel|cron_disable|touch|restor"):
        with guest.vm.scheduled_feedphase():
            assert not guest.sentinel, "context failed to remove sentinel before restoration failure"
    assert guest.calls[:5] == [STATUS, STOP, STATUS, REMOVE, RESTORE], (
        f"unexpected restoration sequence: {guest.calls!r}"
    )
    assert START not in guest.calls, f"unsafe cron restart after restoration failure: {guest.calls!r}"
    assert not guest.running, "restoration failure restarted cron without sentinel"


def test_failed_removal_does_not_yield_and_restores_original_state(guest: _Guest) -> None:
    guest.remove_failure = True
    with pytest.raises(RuntimeError, match="sentinel removal failed"):
        with guest.vm.scheduled_feedphase():
            pytest.fail("failed removal admitted the scheduled body")
    guest.assert_calls([STATUS, STOP, STATUS, REMOVE, RESTORE, EXISTS, START, STATUS])
    assert guest.sentinel and guest.running, "failed removal did not restore the original safe state"


def test_failed_sentinel_verification_does_not_restart_cron(guest: _Guest) -> None:
    guest.verify_failure = True
    with pytest.raises(RuntimeError, match="restoration not verified"):
        with guest.vm.scheduled_feedphase():
            assert not guest.sentinel, "scheduled body did not receive its isolated exception"
    guest.assert_calls([STATUS, STOP, STATUS, REMOVE, RESTORE, EXISTS])
    assert not guest.running, "unverified sentinel restoration restarted cron"


def test_failed_cron_start_is_not_reported_as_restored(guest: _Guest) -> None:
    guest.start_failure = True
    with pytest.raises(RuntimeError, match="cron restoration failed"):
        with guest.vm.scheduled_feedphase():
            assert not guest.running, "cron was running during the scheduled body"
    guest.assert_calls([STATUS, STOP, STATUS, REMOVE, RESTORE, EXISTS, START])
    assert guest.sentinel and not guest.running, "cron start failure lost the verified sentinel"


def test_successful_cron_start_must_verify_original_running_state(guest: _Guest) -> None:
    guest.start_ineffective = True
    with pytest.raises(RuntimeError, match="cron restoration state differs"):
        with guest.vm.scheduled_feedphase():
            assert not guest.running, "cron was running during the scheduled body"
    guest.assert_calls([STATUS, STOP, STATUS, REMOVE, RESTORE, EXISTS, START, STATUS])
    assert guest.sentinel and not guest.running, "ineffective cron start lost the sentinel"


@pytest.mark.parametrize("command", [STATUS, STOP, REMOVE, RESTORE, EXISTS, START])
def test_transport_failure_never_leaves_cron_running_without_sentinel(guest: _Guest, command: str) -> None:
    guest.transport_failure = command
    with pytest.raises(subprocess.TimeoutExpired):
        with guest.vm.scheduled_feedphase():
            assert command not in (STATUS, STOP, REMOVE), f"transport failure at {command!r} admitted the body"
    assert guest.sentinel or not guest.running, f"unsafe state after transport failure: {guest.calls!r}"
    if command in (STATUS, STOP):
        assert REMOVE not in guest.calls, f"preflight transport failure removed sentinel: {guest.calls!r}"
    elif command == REMOVE:
        guest.assert_calls([STATUS, STOP, STATUS, REMOVE, RESTORE, EXISTS, START, STATUS])
        assert guest.sentinel and guest.running, "removal transport failure did not restore the original state"
    else:
        assert not guest.running, f"cleanup transport failure restarted cron: {guest.calls!r}"
