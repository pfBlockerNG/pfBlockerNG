"""Execute fixture PHP against a local stand-in for the external guest config API."""

from __future__ import annotations

import copy
import json
import re
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, cast
from zoneinfo import ZoneInfo

import pytest

from tests.smoke import helpers as h


class Guest:
    def __init__(self) -> None:
        self.config: dict[str, Any] = {
            "system": {"timezone": "America/New_York"},
            "installedpackages": {
                "pfblockernglistsv4": {
                    "config": [
                        {"aliasname": "Other", "cron": "EveryDay", "row": [{"header": "keep", "url": "keep"}]},
                        {
                            "aliasname": "Target",
                            "cron": "Never",
                            "schedule_hour": "09",
                            "custom": "keep",
                            "row": [{"header": "target", "url": "keep"}],
                        },
                    ]
                },
                "pfblockerngipsettings": {
                    "config": [
                        {
                            "maxmind_key": "SECRET_KEY",
                            "maxmind_account": "SECRET_ACCOUNT",
                            "asn_token": "SECRET_TOKEN",
                            "database_cc": "",
                        }
                    ]
                },
                "pfblockerngdnsblsettings": {"config": [{"top1m_enable": "on"}]},
            },
        }
        self.events: list[list[str]] = []
        self.fail: Callable[[str], bool] | None = None

    def php(self, vm: h.SmokeVM, snippet: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if self.fail and self.fail(snippet):
            raise RuntimeError("SECRET_KEY SECRET_ACCOUNT SECRET_TOKEN")
        snippet = re.sub(r"require_once\([^;]+;", "", snippet)
        bootstrap = r"""
function config_get_path($path, $default = null) {
    global $config; $v = $config;
    foreach (explode('/', $path) as $k) {
        if (!is_array($v) || !array_key_exists($k, $v)) return $default;
        $v = $v[$k];
    }
    return $v;
}
function config_set_path($path, $value) {
    global $config; $v =& $config;
    foreach (explode('/', $path) as $k) { $v =& $v[$k]; }
    $v = $value;
}
function config_del_path($path) {
    global $config; $parts = explode('/', $path); $key = array_pop($parts); $v =& $config;
    foreach ($parts as $k) { if (!isset($v[$k])) return; $v =& $v[$k]; }
    unset($v[$key]);
}
function write_config($message) {}
function pfb_global() {}
function pfb_core_settings_changed($unused, $force) { global $events; $events[] = ['notice']; return null; }
enum PfbToggle { case On; case Off; }
class PfbConfig {
    static function writeSystem($key, $value) {
        global $events; $events[] = [$key, $value->name];
        $paths = [
            'ip/database_cc' => 'installedpackages/pfblockerngipsettings/config/0/database_cc',
            'dnsbl/top1m_enable' => 'installedpackages/pfblockerngdnsblsettings/config/0/top1m_enable'
        ];
        config_set_path($paths[$key], $value === PfbToggle::On ? 'on' : '');
    }
}
"""
        program = (
            "$config = json_decode("
            + h._php_str(json.dumps(self.config))
            + ", true); $events = [];\n"
            + bootstrap
            + "\n"
            + snippet
            + '\necho "\\nSTATE:" . json_encode([$config, $events]);'
        )
        result = subprocess.run(["php"], input="<?php\n" + program, text=True, capture_output=True, check=False)
        assert result.returncode == 0, result.stderr
        output, state = result.stdout.rsplit("\nSTATE:", 1)
        self.config, events = json.loads(state)
        self.events.extend(events)
        return subprocess.CompletedProcess([], 0, output, "")


@pytest.fixture
def guest(monkeypatch: pytest.MonkeyPatch) -> Guest:
    guest = Guest()
    monkeypatch.setattr(h, "php_eval", guest.php)
    return guest


def test_weekly_due_settings_restore_exact_raw_presence_and_leave_other_groups(guest: Guest) -> None:
    before = copy.deepcopy(guest.config)
    day = h.guest_previous_date(cast(h.SmokeVM, guest))
    assert day == (datetime.now(ZoneInfo("America/New_York")).date() - timedelta(days=1)).isoformat()
    with h.due_feed_group(cast(h.SmokeVM, guest), "ipv4", "Target", day=day):
        package = guest.config["installedpackages"]
        target = package["pfblockernglistsv4"]["config"][1]
        assert target == {
            "aliasname": "Target",
            "cron": "Weekly",
            "schedule_override": "on",
            "schedule_weekday": str(datetime.fromisoformat(day).isoweekday()),
            "schedule_hour": "0",
            "schedule_minute": "0",
            "custom": "keep",
            "row": [{"header": "target", "url": "keep"}],
        }
        assert package["pfblockerng"]["config"][0]["pfb_scheduled_feed_updates"] == "on"
        assert (
            package["pfblockernglistsv4"]["config"][0] == before["installedpackages"]["pfblockernglistsv4"]["config"][0]
        )
        assert package["pfblockerngipsettings"]["config"][0] == {
            "maxmind_key": "",
            "maxmind_account": "",
            "asn_token": "",
            "database_cc": "on",
        }
        assert package["pfblockerngdnsblsettings"]["config"][0]["top1m_enable"] == ""
    # Parent sections created by ordinary config writes may remain; leaf presence must not.
    guest.config["installedpackages"].pop("pfblockerng")
    assert guest.config == before
    assert guest.events == [["ip/database_cc", "On"], ["dnsbl/top1m_enable", "Off"], ["notice"], ["notice"]]


def test_fixed_day_four_slots_advance_and_dst_day_roundtrips(guest: Guest) -> None:
    slots = []
    for slot in range(4):
        with h.due_feed_group(cast(h.SmokeVM, guest), "ipv4", "Target", slot=slot, day="2026-03-08"):
            target = guest.config["installedpackages"]["pfblockernglistsv4"]["config"][1]
            slots.append((target["schedule_weekday"], target["schedule_hour"], target["schedule_minute"]))
    assert slots == [("7", "0", "0"), ("7", "0", "15"), ("7", "0", "30"), ("7", "0", "45")]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"family": "v4"},
        {"family": "bogus"},
        {"slot": -1},
        {"slot": 4},
        {"slot": True},
        {"day": "2026-02-30"},
        {"day": "2026-3-08"},
        {"day": "2999-01-01"},
        {"day": ""},
    ],
)
def test_invalid_input_never_mutates_config(guest: Guest, kwargs: dict[str, Any]) -> None:
    before = copy.deepcopy(guest.config)
    args = {"family": "ipv4", "group": "Target", **kwargs}
    with pytest.raises(ValueError):
        with h.due_feed_group(cast(h.SmokeVM, guest), **args):
            pytest.fail("invalid fixture entered")
    assert guest.config == before
    assert guest.events == []


def test_nonexistent_calendar_day_in_guest_timezone_is_rejected(guest: Guest) -> None:
    guest.config["system"]["timezone"] = "Pacific/Apia"
    with pytest.raises(ValueError):
        with h.due_feed_group(cast(h.SmokeVM, guest), "ipv4", "Target", day="2011-12-30"):
            pytest.fail("skipped calendar day entered")
    assert guest.events == []


@pytest.mark.parametrize("duplicate", [False, True])
def test_missing_or_duplicate_alias_rejected_before_mutation(guest: Guest, duplicate: bool) -> None:
    groups = guest.config["installedpackages"]["pfblockernglistsv4"]["config"]
    groups[0]["aliasname"] = "Target" if duplicate else "Other"
    before = copy.deepcopy(guest.config)
    with pytest.raises(ValueError):
        with h.due_feed_group(cast(h.SmokeVM, guest), "ipv4", "Target" if duplicate else "Missing"):
            pytest.fail("ambiguous fixture entered")
    assert guest.config == before
    assert not guest.events


def test_body_exception_restores_and_propagates(guest: Guest) -> None:
    before = copy.deepcopy(guest.config)
    with pytest.raises(LookupError, match="body"):
        with h.due_feed_group(cast(h.SmokeVM, guest), "ipv4", "Target"):
            raise LookupError("body")
    guest.config["installedpackages"].pop("pfblockerng")
    assert guest.config == before
    assert guest.events[-1] == ["notice"]


def test_setup_failure_restores_every_field_and_sanitizes_errors(guest: Guest) -> None:
    before = copy.deepcopy(guest.config)
    guest.fail = lambda snippet: "PfbToggle::Off" in snippet
    with pytest.raises(RuntimeError) as error:
        with h.due_feed_group(cast(h.SmokeVM, guest), "ipv4", "Target"):
            pytest.fail("failed setup entered")
    assert "SECRET" not in str(error.value)
    guest.config["installedpackages"].pop("pfblockerng")
    assert guest.config == before
    assert guest.events[-1] == ["notice"]


def test_restore_failure_attempts_remaining_fields_and_notice(guest: Guest, monkeypatch: pytest.MonkeyPatch) -> None:
    original = h.config_restore_state
    attempted = []

    def restore(vm: h.SmokeVM, path: str, state: tuple[bool, str], **kwargs: Any) -> None:
        attempted.append(path)
        if path.endswith("/cron"):
            raise RuntimeError("SECRET_KEY")
        original(vm, path, state, **kwargs)

    monkeypatch.setattr(h, "config_restore_state", restore)
    with pytest.raises(RuntimeError) as error:
        with h.due_feed_group(cast(h.SmokeVM, guest), "ipv4", "Target"):
            pass
    assert "SECRET" not in str(error.value)
    assert len(attempted) == 11
    assert guest.events[-1] == ["notice"]
    assert guest.config["installedpackages"]["pfblockerngipsettings"]["config"][0]["maxmind_key"] == "SECRET_KEY"
