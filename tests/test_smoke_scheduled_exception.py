"""Frozen #3977 cron-running safety contract; fake only the subprocess boundary."""

from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any

import pytest

from tests.smoke import conftest as smoke_conftest

SENTINEL = "/var/db/pfblockerng/.pfb_cron_disable"
STATUS = "service cron onestatus"
REMOVE = f"/bin/rm -f {SENTINEL}"
RESTORE = f"/usr/bin/touch {SENTINEL}"
EXISTS = f"test -f {SENTINEL}"
CRONTAB = "/usr/bin/crontab -l"
CONFIG = "/usr/local/bin/php -r " + shlex.quote(
    "require_once('/etc/inc/config.inc');"
    "echo json_encode(array_column(config_get_path('cron/item', array()), 'command'));"
)


class _Guest:
    """Use the same config/crontab probes as the #3996 maintenance safety contract."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.vm = smoke_conftest.SmokeVM(
            ssh_key_path="/inert/disposable-key",
            host="127.0.0.1",
            ssh_port=22222,
            vm_pid=424242,
            log_path="/inert/disposable-vm.log",
        )
        self.running = True
        self.pid = 31415
        self.sentinel = True
        self.config: list[str] = []
        self.crontab = "*/5 * * * * /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics\n"
        self.calls: list[str] = []
        self.fail: str | None = None
        self.status_failure: tuple[int, str, str] | None = None
        self.transport_failure: str | None = None
        self.ineffective_restore = False
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
        assert argv[:-1] == prefix, f"expected isolated SSH transport, got {argv!r}"
        decoded = shlex.split(argv[-1])
        assert len(decoded) == 1
        command = decoded[0]
        assert argv[-1] == shlex.quote(command)
        assert kwargs.get("capture_output") is True and kwargs.get("text") is True
        assert isinstance(kwargs.get("timeout"), (int, float)) and 0 < kwargs["timeout"] <= 60
        self.calls.append(command)
        if command == self.transport_failure:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], stderr="SSH command timed out")
        rc, stdout, stderr = 0, "", ""
        if command == self.fail:
            rc, stderr = 1, "injected boundary failure"
        elif command == STATUS:
            if self.status_failure is not None:
                rc, stdout, stderr = self.status_failure
            else:
                rc = 0 if self.running else 1
                stdout = f"cron is running as pid {self.pid}.\n" if self.running else "cron is not running.\n"
        elif command == CRONTAB:
            stdout = self.crontab
        elif command == CONFIG:
            stdout = json.dumps(self.config)
        elif command == EXISTS:
            rc = 0 if self.sentinel else 1
        elif command == REMOVE:
            assert self.sentinel and self.running, "sentinel removal requires unchanged, running system cron"
            assert STATUS in self.calls and CRONTAB in self.calls and CONFIG in self.calls
            self.sentinel = False
        elif command == RESTORE:
            if not self.ineffective_restore:
                self.sentinel = True
        else:
            pytest.fail(f"Unapproved command (no cron control, signals or job deletion allowed): {command!r}")
        result = subprocess.CompletedProcess(argv, rc, stdout, stderr)
        if kwargs.get("check"):
            result.check_returncode()
        return result


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
    assert guest.calls == [] and guest.sentinel


@pytest.mark.parametrize("field,value", [("vm_pid", None), ("log_path", None), ("host", "192.0.2.1")])
def test_nonowned_guest_denies_before_any_transport(guest: _Guest, field: str, value: object) -> None:
    setattr(guest.vm, field, value)
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            pytest.fail(f"scheduled body admitted nonowned identity {field}={value!r}")
    assert guest.calls == [] and guest.sentinel


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
    assert guest.calls == [] and guest.sentinel


@pytest.mark.parametrize("verb", ["cron-tick", "tick", "cron"])
@pytest.mark.parametrize("source", ["config", "crontab"])
def test_competing_dispatch_job_refused_without_deletion(guest: _Guest, verb: str, source: str) -> None:
    command = f"/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php {verb} >> /var/log/pfb.log 2>&1"
    if source == "config":
        guest.config = [command]
    else:
        guest.crontab += f"*/15 * * * * {command}\n"
    before = (guest.config[:], guest.crontab)
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            pytest.fail("competing cron dispatch admitted")
    assert REMOVE not in guest.calls and guest.sentinel and guest.running
    assert (guest.config, guest.crontab) == before


def test_success_admits_only_internal_exact_removal_with_cron_running(guest: _Guest) -> None:
    guest.config = [
        f"/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php {verb}"
        for verb in ("metrics", "clearip", "cleardnsbl")
    ]
    before = (guest.config[:], guest.crontab, guest.pid)
    with guest.vm.scheduled_feedphase():
        assert not guest.sentinel and guest.running
        assert guest.calls.count(REMOVE) == 1
        before_denied = guest.calls[:]
        for command in (REMOVE, f"unlink {SENTINEL}", f"{REMOVE} /tmp/other", f"{REMOVE}; true"):
            with pytest.raises(RuntimeError, match="scheduled ticks must stay disabled"):
                guest.vm.ssh(command)
        assert guest.calls == before_denied
    assert guest.sentinel and guest.running
    assert (guest.config, guest.crontab, guest.pid) == before
    assert guest.calls.count(CRONTAB) >= 2 and guest.calls.count(CONFIG) >= 2
    assert guest.calls.count(STATUS) >= 2
    assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]


def test_stopped_cron_refused_not_started(guest: _Guest) -> None:
    guest.running = False
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            pytest.fail("stopped cron admitted")
    assert guest.sentinel and not guest.running and REMOVE not in guest.calls


def test_initial_sentinel_required(guest: _Guest) -> None:
    guest.sentinel = False
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            pytest.fail("missing initial sentinel admitted")
    assert REMOVE not in guest.calls and guest.running


@pytest.mark.parametrize(
    "failure",
    [
        (1, "", "Usage: service <service> <command>\n"),
        (64, "", "onestatus is not supported\n"),
        (255, "", "ssh: Connection refused\n"),
        (0, "unrecognized service status\n", ""),
    ],
)
def test_unsupported_status_never_removes_sentinel(guest: _Guest, failure: tuple[int, str, str]) -> None:
    guest.status_failure = failure
    with pytest.raises(RuntimeError, match="(?i)cron.*(status|preflight)|onestatus"):
        with guest.vm.scheduled_feedphase():
            pytest.fail("unsupported cron status admitted")
    assert guest.calls == [STATUS] and guest.sentinel and guest.running


@pytest.mark.parametrize("command", [STATUS, CRONTAB, CONFIG, EXISTS])
def test_unreadable_preflight_never_removes_sentinel(guest: _Guest, command: str) -> None:
    guest.fail = command
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            pytest.fail("unreadable preflight admitted")
    assert REMOVE not in guest.calls and guest.sentinel and guest.running


def test_failed_removal_does_not_yield_and_restores_sentinel(guest: _Guest) -> None:
    guest.fail = REMOVE
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            pytest.fail("failed removal admitted scheduled body")
    assert RESTORE in guest.calls and guest.sentinel and guest.running
    assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]


@pytest.mark.parametrize("body_error", [AssertionError("body failed"), ValueError("body failed")])
def test_body_failure_restores_and_verifies_before_outer_config_cleanup(guest: _Guest, body_error: Exception) -> None:
    with pytest.raises(type(body_error), match="body failed") as caught:
        try:
            with guest.vm.scheduled_feedphase():
                assert not guest.sentinel and guest.running
                raise body_error
        finally:
            assert guest.sentinel, "outer configuration cleanup would run without sentinel"
            assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]
    assert caught.value is body_error and guest.running


@pytest.mark.parametrize("ineffective", [False, True])
def test_failed_sentinel_restore_is_never_reported_safe(guest: _Guest, ineffective: bool) -> None:
    guest.ineffective_restore = ineffective
    guest.fail = None if ineffective else RESTORE
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            pass
    assert not guest.sentinel and guest.running


def test_failed_restore_verification_is_never_reported_safe(guest: _Guest) -> None:
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            guest.fail = EXISTS
    assert RESTORE in guest.calls and guest.sentinel and guest.running


@pytest.mark.parametrize("command", [REMOVE, RESTORE])
def test_transport_failure_reports_and_attempts_restore(guest: _Guest, command: str) -> None:
    guest.transport_failure = command
    with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
        with guest.vm.scheduled_feedphase():
            pass
    assert RESTORE in guest.calls and guest.running
    if command == REMOVE:
        assert guest.sentinel
        assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]


@pytest.mark.parametrize("command", [STATUS, CRONTAB, CONFIG, EXISTS])
def test_preflight_transport_failure_never_removes_sentinel(guest: _Guest, command: str) -> None:
    guest.transport_failure = command
    with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
        with guest.vm.scheduled_feedphase():
            pytest.fail("preflight transport failure yielded")
    assert REMOVE not in guest.calls and guest.sentinel and guest.running


@pytest.mark.parametrize("source", ["config", "crontab"])
def test_competing_job_appearing_in_body_fails_after_restoration(guest: _Guest, source: str) -> None:
    command = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick"
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            if source == "config":
                guest.config.append(command)
            else:
                guest.crontab += f"*/15 * * * * {command}\n"
    assert guest.sentinel and guest.running
    assert command in (guest.config if source == "config" else guest.crontab)


def test_changed_cron_identity_fails_without_service_control(guest: _Guest) -> None:
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_feedphase():
            guest.pid += 1
    assert guest.sentinel and guest.running
