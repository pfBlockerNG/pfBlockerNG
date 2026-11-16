"""Hermetic FreeBSD root-crontab result classification for scheduled maintenance."""

from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any

import pytest

from tests.smoke import helpers as h
from tests.smoke.test_core_scheduled_maintenance import _assert_no_dispatch
from tests.test_smoke_scheduled_maintenance import CRONTAB, EXISTS, GENERATED_CRONTAB, REMOVE, Guest

NO_ROOT_CRONTAB = "crontab: no crontab for root\n"


class CrontabResultGuest(Guest):
    def __init__(self, monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, stderr: str) -> None:
        super().__init__(monkeypatch)
        self.crontab_result = (returncode, stdout, stderr)

    def run(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = shlex.split(argv[-1])[0]
        if command == h.PFSSH_BIN:
            assert argv[:-1] == self.vm.ssh_argv("unused")[:-1]
            self.calls.append(command)
            return subprocess.CompletedProcess(
                argv, 0, h._CFG_VAL_OPEN + json.dumps(self.config) + h._CFG_VAL_CLOSE, ""
            )
        result = super().run(argv, **kwargs)
        if argv[-1] == shlex.quote(CRONTAB):
            code, out, err = self.crontab_result
            return subprocess.CompletedProcess(argv, code, out, err)
        return result


def test_exact_absent_root_crontab_is_an_empty_readonly_source(monkeypatch: pytest.MonkeyPatch) -> None:
    guest = CrontabResultGuest(monkeypatch, 1, "", NO_ROOT_CRONTAB)
    guest.crontab = ""
    before = (guest.config[:], guest.crontab, guest.generated_crontab)

    _assert_no_dispatch(guest.vm, "root-has-no-crontab")

    assert guest.config == before[0]
    assert guest.crontab == before[1]
    assert guest.generated_crontab == before[2]
    assert CRONTAB in guest.calls and GENERATED_CRONTAB in guest.calls
    assert h.PFSSH_BIN in guest.calls and EXISTS in guest.calls
    assert REMOVE not in guest.calls and guest.sentinel and guest.running


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    [
        (1, "", "crontab: /var/cron/tabs/root: Permission denied\n"),
        (1, "unexpected output\n", NO_ROOT_CRONTAB),
        (1, "", "crontab: no crontab for another-user\n"),
        (2, "", NO_ROOT_CRONTAB),
    ],
)
def test_other_root_crontab_failures_remain_fatal(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, stderr: str
) -> None:
    guest = CrontabResultGuest(monkeypatch, returncode, stdout, stderr)
    with pytest.raises(AssertionError, match="root crontab"):
        _assert_no_dispatch(guest.vm, "invalid-root-crontab-result")
    assert CRONTAB in guest.calls
    assert REMOVE not in guest.calls and guest.sentinel and guest.running


def test_effective_etc_crontab_read_failure_remains_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    guest = CrontabResultGuest(monkeypatch, 0, "", "")
    guest.fail = GENERATED_CRONTAB
    with pytest.raises(AssertionError, match="effective crontab"):
        _assert_no_dispatch(guest.vm, "unreadable-effective-crontab")
    assert CRONTAB in guest.calls and GENERATED_CRONTAB in guest.calls
    assert REMOVE not in guest.calls and guest.sentinel and guest.running


@pytest.mark.parametrize("source", ["config", "generated"])
def test_configured_or_effective_dispatch_remains_fatal(monkeypatch: pytest.MonkeyPatch, source: str) -> None:
    guest = CrontabResultGuest(monkeypatch, 0, "", "")
    dispatch = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick\n"
    if source == "config":
        guest.config = [dispatch]
    else:
        guest.generated_crontab += f"*/15 * * * * root {dispatch}"
    with pytest.raises(AssertionError, match="competing"):
        _assert_no_dispatch(guest.vm, f"competing-{source}-dispatch")
    assert REMOVE not in guest.calls and guest.sentinel and guest.running
