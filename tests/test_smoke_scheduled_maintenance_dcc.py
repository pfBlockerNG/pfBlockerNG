"""Hermetic contract for #3996's supported DCC maintenance-window setup."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.smoke import helpers as h
from tests.smoke import test_core_scheduled_maintenance as acceptance

NOW = 1_800_000_000
DCC = "extra:dcc"
BLACKLIST = "extra:bl"
HOUR = f"{h.CFG_GLOBAL}/pfb_schedule_hour"
MINUTE = f"{h.CFG_GLOBAL}/pfb_schedule_minute"
BLACKLIST_ENABLE = "installedpackages/pfblockerngblacklist/blacklist_enable"


def schedule_reply(extras: dict[str, Any], successful: Any) -> dict[str, Any]:
    return {
        "status": 200,
        "body": {
            "scheduled": False,
            "feeds": None,
            "extras": extras,
            "lastSuccessfulCheck": successful,
        },
        "error": None,
    }


def dcc_entry(*, last_run: int, next_due: int) -> dict[str, int]:
    return {"lastRun": last_run, "nextDue": next_due}


class DccSetup:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
        successful: Any = None,
        update_result: str = "success",
    ) -> None:
        self.config: dict[str, str] = {}
        self.installs: list[dict[str, str]] = []
        self.config_reads: list[tuple[int, str]] = []
        self.core_calls: list[tuple[str, dict[str, Any]]] = []
        self.phases: list[str] = []
        self.settings_notices = 0
        self.start_reply = {"status": 200, "body": [], "error": None}
        self.update_result = update_result
        completed = after or schedule_reply(
            {DCC: dcc_entry(last_run=NOW + 5, next_due=NOW + 80_000)},
            {DCC: NOW + 5} if successful is None else successful,
        )
        self.schedules = [
            before or schedule_reply({DCC: dcc_entry(last_run=0, next_due=NOW)}, []),
            completed,
            completed,
        ]
        self.vm = self

        def ssh(*argv: str, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            if argv == ("date", "-v+23H", "-v0M", "+%H"):
                return subprocess.CompletedProcess(argv, 0, "10\n", "")
            if argv == ("date", "+%s"):
                return subprocess.CompletedProcess(argv, 0, f"{NOW}\n", "")
            if argv == ("ps ax -o command",):
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "root 1 pfb_core --maintenance-cmd /usr/local/pkg/pfblockerng/pfb_core_maintenance.sh\n",
                    "",
                )
            if argv == ("test", "-f", acceptance.SENTINEL):
                return subprocess.CompletedProcess(argv, 0, "", "")
            pytest.fail(f"unapproved fake guest command: {argv!r}")

        self.ssh = ssh

        def config_set(_vm: Any, path: str, value: str) -> None:
            self.config[path] = value

        def config_get(_vm: Any, path: str) -> str:
            self.config_reads.append((len(self.installs), path))
            return self.config.get(path, "")

        def force_install(_vm: Any, _pkg: Path) -> None:
            self.installs.append(self.config.copy())

        def core_call(_vm: Any, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            self.core_calls.append((method, dict(params or {})))
            if method == "GetSchedule":
                return self.schedules.pop(0)
            if method == "StartUpdate":
                return self.start_reply
            pytest.fail(f"unexpected public Core method: {method}")

        monkeypatch.setenv("SMOKE_PKG", "/tmp/current.pkg")
        monkeypatch.setenv("SMOKE_SCHEDULED_EXCEPTION", "allow")
        for name in (
            "deploy",
            "ensure_dnsbl_vip",
            "use_stub_for_safesearch",
            "inject",
            "set_package_enabled",
            "reload",
            "set_pfb_keep",
            "wait_unbound_ready",
            "unblock_egress",
            "collect_host_diagnostics",
        ):
            monkeypatch.setattr(h, name, lambda *_args, **_kwargs: None)
        monkeypatch.setattr(h, "unique_domain", lambda label: f"{label}.example")
        monkeypatch.setattr(h, "write_local_feed", lambda *_args, **_kwargs: "file:///local/feed")
        monkeypatch.setattr(h, "config_set", config_set)
        monkeypatch.setattr(h, "config_get", config_get)
        monkeypatch.setattr(
            h,
            "tell_core_the_settings_changed",
            lambda _vm: setattr(self, "settings_notices", self.settings_notices + 1),
        )
        monkeypatch.setattr(h, "core_call", core_call)
        monkeypatch.setattr(h, "core_update_view", lambda _vm: {"update": None})
        monkeypatch.setattr(
            h,
            "await_core_update_end",
            lambda *_args, **_kwargs: {
                "running": False,
                "update": {"trigger": "retry", "result": self.update_result},
            },
        )
        monkeypatch.setattr(h, "dns_probe", lambda *_args, **_kwargs: "198.51.100.9")
        monkeypatch.setattr(h, "is_vip", lambda _answer: True)
        monkeypatch.setattr(acceptance, "_assert_no_dispatch", lambda _vm, phase: self.phases.append(phase))
        monkeypatch.setattr(acceptance, "_force_install", force_install)
        monkeypatch.setattr(acceptance, "await_core_up", lambda _vm: None)

    def run(self) -> tuple[Any, Any]:
        fixture = getattr(acceptance.maintenance_vm, "__wrapped__")
        generator = fixture(self.vm, object(), Path("/tmp/previous.pkg"))
        return generator, next(generator)


def test_dcc_setup_uses_supported_schedule_and_public_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch)
    generator, yielded = setup.run()
    try:
        assert yielded is setup.vm
        assert setup.config[HOUR] == "10" and setup.config[MINUTE] == "0"
        assert setup.config[f"{h.CFG_GLOBAL}/pfb_scheduled_feed_updates"] == ""
        assert setup.config[BLACKLIST_ENABLE] == "Disable"
        assert [snapshot[HOUR] for snapshot in setup.installs] == ["10", "10"]
        assert [snapshot[MINUTE] for snapshot in setup.installs] == ["0", "0"]
        assert [(n, key) for n, key in setup.config_reads if key in (HOUR, MINUTE)] == [
            (1, HOUR),
            (1, MINUTE),
            (2, HOUR),
            (2, MINUTE),
        ]
        assert setup.settings_notices >= 1
        assert [call for call in setup.core_calls if call[0] == "StartUpdate"] == [
            ("StartUpdate", {"trigger": "retry"})
        ]
    finally:
        generator.close()


@pytest.mark.parametrize(
    ("case", "after", "update_result", "message"),
    [
        (
            "still-due",
            schedule_reply({DCC: dcc_entry(last_run=NOW + 5, next_due=NOW)}, {DCC: NOW + 5}),
            "success",
            "DCC nextDue is not outside",
        ),
        (
            "failed-retry",
            schedule_reply({DCC: dcc_entry(last_run=0, next_due=NOW)}, []),
            "failed",
            "retry Update failed",
        ),
        (
            "other-extra",
            schedule_reply(
                {
                    DCC: dcc_entry(last_run=NOW + 5, next_due=NOW + 80_000),
                    BLACKLIST: dcc_entry(last_run=0, next_due=NOW),
                },
                {DCC: NOW + 5},
            ),
            "success",
            "enabled extras are not DCC-only",
        ),
        (
            "too-soon",
            schedule_reply({DCC: dcc_entry(last_run=NOW + 5, next_due=NOW + 2160)}, {DCC: NOW + 5}),
            "success",
            "DCC nextDue is not outside",
        ),
    ],
)
def test_dcc_setup_rejects_unsafe_public_state(
    monkeypatch: pytest.MonkeyPatch, case: str, after: dict[str, Any], update_result: str, message: str
) -> None:
    setup = DccSetup(monkeypatch, after=after, update_result=update_result)
    with pytest.raises(AssertionError, match=message):
        setup.run()
    assert any(method == "StartUpdate" for method, _params in setup.core_calls), case


def test_due_other_extra_blocks_public_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    before = schedule_reply(
        {
            DCC: dcc_entry(last_run=0, next_due=NOW),
            BLACKLIST: dcc_entry(last_run=0, next_due=NOW),
        },
        [],
    )
    setup = DccSetup(monkeypatch, before=before)
    with pytest.raises(AssertionError, match="enabled extras are not DCC-only"):
        setup.run()
    assert not any(method == "StartUpdate" for method, _params in setup.core_calls)


def test_naturally_completed_dcc_needs_no_private_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch)
    finished = schedule_reply(
        {DCC: dcc_entry(last_run=NOW - 10, next_due=NOW + 80_000)},
        {DCC: NOW - 10},
    )
    setup.schedules = [finished, finished]
    generator, yielded = setup.run()
    try:
        assert yielded is setup.vm
        assert not any(method == "StartUpdate" for method, _params in setup.core_calls)
    finally:
        generator.close()
