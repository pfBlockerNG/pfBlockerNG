"""Frozen #3996 safety contract; exercise SmokeVM, fake only subprocess transport."""

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
ABSENT = f"test ! -f {SENTINEL}"
CRONTAB = "/usr/bin/crontab -l"
GENERATED_CRONTAB = "/bin/cat /etc/crontab"
# The config probe emits only JSON (not the pfSsh.php startup banner).
CONFIG = "/usr/local/bin/php -r " + shlex.quote(
    "require_once('/etc/inc/config.inc');"
    "echo json_encode(array_column(config_get_path('cron/item', array()), 'command'));"
)


class Guest:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.vm = smoke_conftest.SmokeVM(ssh_key_path="/inert/key", vm_pid=424242, log_path="/inert/vm.log")
        self.sentinel = True
        self.running = True
        self.pid = 31415
        self.config: list[str] = []
        self.crontab = "*/5 * * * * /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics\n"
        self.generated_crontab = "*/5 * * * * root /usr/libexec/atrun\n"
        self.calls: list[str] = []
        self.fail: str | None = None
        self.transport_failure: str | None = None
        self.ineffective_restore = False
        self.ineffective_remove = False
        monkeypatch.setenv("SMOKE_SCHEDULED_EXCEPTION", "allow")
        monkeypatch.setattr(smoke_conftest.subprocess, "run", self.run)

    def run(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert argv[:-1] == self.vm.ssh_argv("unused")[:-1]
        command = shlex.split(argv[-1])[0]
        assert argv[-1] == shlex.quote(command)
        assert kwargs.get("capture_output") is True and kwargs.get("text") is True
        assert 0 < kwargs["timeout"] <= 60
        self.calls.append(command)
        if command == self.transport_failure:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        rc, out, err = 0, "", ""
        if command == self.fail:
            rc, err = 1, "injected boundary failure"
        elif command == STATUS:
            rc = 0 if self.running else 1
            out = f"cron is running as pid {self.pid}.\n" if self.running else "cron is not running.\n"
        elif command == CRONTAB:
            out = self.crontab
        elif command == GENERATED_CRONTAB:
            out = self.generated_crontab
        elif command == CONFIG:
            out = json.dumps(self.config)
        elif command == EXISTS:
            rc = 0 if self.sentinel else 1
        elif command == ABSENT:
            rc = 0 if not self.sentinel else 1
        elif command == REMOVE:
            assert self.sentinel and self.running
            assert STATUS in self.calls and CRONTAB in self.calls and CONFIG in self.calls
            assert not self.config or all("metrics" in row or "clear" in row for row in self.config)
            if not self.ineffective_remove:
                self.sentinel = False
        elif command == RESTORE:
            if not self.ineffective_restore:
                self.sentinel = True
        else:
            pytest.fail(f"Unapproved command (no cron control, signals or job deletion allowed): {command!r}")
        result = subprocess.CompletedProcess(argv, rc, out, err)
        if kwargs.get("check"):
            result.check_returncode()
        return result


@pytest.fixture
def guest(monkeypatch: pytest.MonkeyPatch) -> Guest:
    return Guest(monkeypatch)


@pytest.mark.parametrize("optin", [None, "", "ALLOW", "true", "allow ", "allow; true"])
def test_missing_literal_optin_never_transports(
    guest: Guest, monkeypatch: pytest.MonkeyPatch, optin: str | None
) -> None:
    if optin is None:
        monkeypatch.delenv("SMOKE_SCHEDULED_EXCEPTION", raising=False)
    else:
        monkeypatch.setenv("SMOKE_SCHEDULED_EXCEPTION", optin)
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("unauthorized context yielded")
    assert guest.calls == [] and guest.sentinel


@pytest.mark.parametrize("field,value", [("vm_pid", None), ("log_path", None), ("host", "192.0.2.1")])
def test_nonowned_guest_never_transports(guest: Guest, field: str, value: object) -> None:
    setattr(guest.vm, field, value)
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("nonowned guest yielded")
    assert guest.calls == [] and guest.sentinel


@pytest.mark.parametrize("remote", [(REMOVE,), ("rm", "-f", SENTINEL), (f"unlink {SENTINEL}",)])
def test_ordinary_ssh_guard_stays_closed_with_optin(guest: Guest, remote: tuple[str, ...]) -> None:
    with pytest.raises(RuntimeError, match="scheduled ticks must stay disabled"):
        guest.vm.ssh(*remote)
    assert guest.calls == [] and guest.sentinel


@pytest.mark.parametrize("verb", ["cron-tick", "tick", "cron"])
@pytest.mark.parametrize("source", ["config", "crontab", "generated"])
def test_competing_dispatch_job_refused_without_deletion(guest: Guest, verb: str, source: str) -> None:
    command = f"/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php {verb} >> /var/log/pfb.log 2>&1"
    if source == "config":
        guest.config = [command]
    elif source == "crontab":
        guest.crontab += f"*/15 * * * * {command}\n"
    else:
        guest.config = []
        guest.crontab = ""
        guest.generated_crontab += f"*/15 * * * * root {command}\n"
    before = (guest.config[:], guest.crontab, guest.generated_crontab)
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("competing cron dispatch admitted")
    assert REMOVE not in guest.calls and guest.sentinel and guest.running
    assert (guest.config, guest.crontab, guest.generated_crontab) == before


def test_metrics_and_counter_siblings_allow_real_context(guest: Guest) -> None:
    guest.config = [
        f"/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php {verb}"
        for verb in ("metrics", "clearip", "cleardnsbl")
    ]
    before = (guest.config[:], guest.crontab, guest.pid)
    with guest.vm.scheduled_maintenance():
        assert not guest.sentinel and guest.running
        assert guest.calls.count(REMOVE) == 1
        assert ABSENT in guest.calls, "context must verify sentinel absence before yielding"
    assert guest.sentinel and guest.running
    assert (guest.config, guest.crontab, guest.pid) == before
    assert guest.calls.count(CRONTAB) >= 2 and guest.calls.count(CONFIG) >= 2
    assert guest.calls.count(GENERATED_CRONTAB) >= 2
    assert guest.calls.count(STATUS) >= 2
    assert guest.calls.index(RESTORE) < len(guest.calls) - 1
    assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]


def test_stopped_cron_refused_not_started(guest: Guest) -> None:
    guest.running = False
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("stopped cron admitted")
    assert guest.sentinel and not guest.running and REMOVE not in guest.calls


def test_sentinel_initially_required(guest: Guest) -> None:
    guest.sentinel = False
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("missing initial sentinel admitted")
    assert REMOVE not in guest.calls


@pytest.mark.parametrize("command", [STATUS, CRONTAB, GENERATED_CRONTAB, CONFIG, EXISTS])
def test_unreadable_preflight_refused(guest: Guest, command: str) -> None:
    guest.fail = command
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("unreadable preflight admitted")
    assert guest.sentinel and REMOVE not in guest.calls and guest.running


def test_remove_failure_restores_without_yield(guest: Guest) -> None:
    guest.fail = REMOVE
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("failed removal yielded")
    assert RESTORE in guest.calls and guest.sentinel and guest.running


@pytest.mark.parametrize("error", [AssertionError("body failed"), ValueError("body failed")])
def test_body_failure_restores_before_outer_config_cleanup(guest: Guest, error: Exception) -> None:
    with pytest.raises(type(error), match="body failed") as caught:
        try:
            with guest.vm.scheduled_maintenance():
                assert not guest.sentinel
                raise error
        finally:
            assert guest.sentinel, "configuration cleanup would run without sentinel"
            assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]
    assert caught.value is error and guest.running


@pytest.mark.parametrize("ineffective", [False, True])
def test_failed_restore_is_never_reported_safe(guest: Guest, ineffective: bool) -> None:
    guest.ineffective_restore = ineffective
    guest.fail = None if ineffective else RESTORE
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pass
    assert not guest.sentinel and guest.running


@pytest.mark.parametrize("command", [REMOVE, RESTORE])
def test_transport_failure_reported_and_restore_attempted(guest: Guest, command: str) -> None:
    guest.transport_failure = command
    with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
        with guest.vm.scheduled_maintenance():
            pass
    assert RESTORE in guest.calls and guest.running
    if command == REMOVE:
        assert guest.sentinel


def test_competing_job_appearing_in_body_fails_after_restoration(guest: Guest) -> None:
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            guest.crontab += "*/15 * * * * php /usr/local/www/pfblockerng/pfblockerng.php cron-tick\n"
    assert guest.sentinel and guest.running
    assert "cron-tick" in guest.crontab, "fixture must not delete a competing job"


def test_changed_cron_identity_fails_without_service_control(guest: Guest) -> None:
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            guest.pid += 1
    assert guest.sentinel and guest.running


def test_restore_verification_failure_is_not_reported_safe(guest: Guest) -> None:
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            guest.fail = EXISTS
    assert RESTORE in guest.calls and guest.sentinel and guest.running


@pytest.mark.parametrize("command", [STATUS, CRONTAB, GENERATED_CRONTAB, CONFIG, EXISTS])
def test_preflight_transport_failure_never_removes_sentinel(guest: Guest, command: str) -> None:
    guest.transport_failure = command
    with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
        with guest.vm.scheduled_maintenance():
            pytest.fail("transport failure yielded")
    assert REMOVE not in guest.calls and guest.sentinel and guest.running


def test_successful_but_ineffective_removal_never_yields_and_restores(guest: Guest) -> None:
    guest.ineffective_remove = True
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("rm returned success but retained sentinel; body must not run")
    assert ABSENT in guest.calls, "successful rm must be independently verified"
    assert guest.sentinel and guest.running
    assert RESTORE in guest.calls
    assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]


def test_absence_verification_failure_restores_without_yield(guest: Guest) -> None:
    guest.fail = ABSENT
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            pytest.fail("unverified sentinel absence yielded")
    assert REMOVE in guest.calls and RESTORE in guest.calls
    assert guest.sentinel and guest.running
    assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]


def test_benign_effective_crontab_is_read_and_never_mutated(guest: Guest) -> None:
    guest.generated_crontab = (
        "SHELL=/bin/sh\n"
        "*/5 * * * * root /usr/libexec/atrun\n"
        "*/5 * * * * root /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics\n"
        "0 0 * * * root /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php clearip\n"
        "0 0 * * * root /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cleardnsbl\n"
        "# */15 * * * * root php /usr/local/www/pfblockerng/pfblockerng.php cron-tick\n"
    )
    before = guest.generated_crontab
    with guest.vm.scheduled_maintenance():
        assert GENERATED_CRONTAB in guest.calls, "effective system crontab was not inspected"
        assert ABSENT in guest.calls
        assert not guest.sentinel and guest.running
    assert guest.generated_crontab == before and guest.sentinel and guest.running
    assert guest.calls.count(GENERATED_CRONTAB) >= 2


def test_effective_dispatch_appearing_in_body_is_refused_after_restoration(guest: Guest) -> None:
    with pytest.raises(RuntimeError):
        with guest.vm.scheduled_maintenance():
            guest.generated_crontab += "*/15 * * * * root php /usr/local/www/pfblockerng/pfblockerng.php cron-tick\n"
    assert guest.sentinel and guest.running
    assert "cron-tick" in guest.generated_crontab, "context must refuse, not delete the effective job"
    assert RESTORE in guest.calls
    assert EXISTS in guest.calls[guest.calls.index(RESTORE) + 1 :]
    restored_at = guest.calls.index(RESTORE)
    verified_at = guest.calls.index(EXISTS, restored_at + 1)
    assert GENERATED_CRONTAB in guest.calls[verified_at + 1 :], (
        "effective jobs must be rechecked after verified restore"
    )
