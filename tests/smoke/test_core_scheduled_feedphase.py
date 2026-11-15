"""#3977: owner-authorized, disposable-only native quarter-hour scheduler acceptance."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_core_update import (
    DB,
    _add_ip_custom_lists,
    _assert_dnsbl_prerequisites,
    _assert_feed_disposition,
    _configure_every_feed_type,
    _prepare_mock_feeds,
    _snapshot,
    await_idle,
)
from .test_core_update import core_vm as core_vm
from .test_smoke_feeds import _blacklist_tar_gz

pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        os.environ.get("SMOKE_SCHEDULED_EXCEPTION") != "allow",
        reason="dispatch-only: requires explicit isolated SMOKE_SCHEDULED_EXCEPTION=allow",
    ),
]

SCHEDULED_WATCHDOG = 1800.0


def _configure_custom_only(vm: SmokeVM) -> tuple[dict[str, str], str]:
    """Empty URL rows leave only the three parent groups' custom lists eligible."""
    aliases = {family: f"nco{uuid.uuid4().hex[:12]}" for family in ("dnsbl", "ipv4", "ipv6")}
    domain = h.unique_domain("nativecustom")
    _prepare_mock_feeds(vm, dnsbl=True)
    h.inject_dnsbl_lists(
        vm,
        [
            (
                h.DnsblCase(aliasname=aliases["dnsbl"], header=aliases["dnsbl"], feed_url="", custom_domains=[domain]),
                "Deny",
            )
        ],
    )
    h.inject_ip_lists(
        vm,
        [
            h.IpCase(aliasname=aliases[family], header=aliases[family], feed_url="", family=version)
            for family, version in (("ipv4", "v4"), ("ipv6", "v6"))
        ],
    )
    _add_ip_custom_lists(
        vm,
        {
            h.CFG_IP_V4_LISTS: (aliases["ipv4"], "198.51.100.177\n"),
            h.CFG_IP_V6_LISTS: (aliases["ipv6"], "2001:db8::177\n"),
        },
    )
    disabled = h.php_eval(
        vm,
        "config_set_path('installedpackages/pfblockerngblacklist', array());"
        "write_config('pfBlockerNG smoke: custom-only without Blacklist'); echo 'OK';",
    )
    assert disabled.returncode == 0 and "OK" in disabled.stdout, disabled
    _assert_dnsbl_prerequisites(vm)
    return aliases, domain


def _capture_scheduled_update(vm: SmokeVM, before: Any) -> tuple[dict[str, Any], str]:
    """The exclusively owned scheduler window excludes other admissions through the final drain."""
    deadline = time.monotonic() + SCHEDULED_WATCHDOG
    after: str | None = None
    admitted: dict[str, Any] | None = None
    terminal: dict[str, Any] | None = None
    chunks: list[str] = []
    while True:
        current = h.core_update_view(vm, after, timeout=60.0)
        update = current["update"]
        if admitted is None and update == before:
            assert not current["running"], f"unexpected pre-existing running Update: {current}"
            if time.monotonic() > deadline:
                pytest.fail(f"STUCK/ENVIRONMENT: native scheduled Update did not start: {current}")
            time.sleep(1)
            continue
        assert update is not None and update["trigger"] == "scheduled", current
        if admitted is None:
            admitted = update
        assert all(update.get(k) == admitted.get(k) for k in ("trigger", "scope", "force", "startedAt")), (
            f"Update replaced in exclusive scheduled window: {admitted} -> {current}"
        )
        if terminal is not None:
            assert not current["running"] and update == terminal, (
                f"Update replaced during terminal log drain: {terminal} -> {current}"
            )
        assert isinstance(current["next"], str), f"opaque log cursor required: {current}"
        chunks.append(current["log"])
        after = current["next"]
        if not current["running"]:
            terminal = update
            if not current["log"]:
                return update, "".join(chunks)
        if time.monotonic() > deadline:
            pytest.fail(f"STUCK/ENVIRONMENT: native scheduled Update did not finish draining: {current}")
        if not current["log"]:
            time.sleep(1)


@pytest.mark.parametrize("feed_selection", ("all-kinds", "custom-only"))
@pytest.mark.timeout(2400)
def test_scheduled_update_runs_core_feedphase_for_every_feed_kind(
    core_vm: SmokeVM, mock_feeds: Any, feed_selection: str
) -> None:
    """The real scheduler consumes all feed kinds, or only three custom-only parent groups."""
    vm = core_vm
    sentinel = h.PFB_CRON_DISABLE_PATH
    assert vm.ssh("test", "-f", sentinel).returncode == 0, "setup must retain the scheduler sentinel"
    original_cron = vm.ssh("service cron onestatus")
    snapshot = "/tmp/smoke-scheduled-config.xml"
    saved = vm.ssh("cp", "/conf/config.xml", snapshot)
    assert saved.returncode == 0, f"cannot snapshot scheduled-test config: {saved}"
    try:
        await_idle(vm)
        if feed_selection == "all-kinds":
            regular, own_less = _configure_every_feed_type(vm, mock_feeds, "native")
            archive_name = "native_blacklists.tar.gz"
            archive_url = mock_feeds.register(
                archive_name, _blacklist_tar_gz("blacklists", "test-cat", "blacklist.example.com")
            )
            provider = h._php_kv_array(
                {"xml": "ut1", "title": "Corenative", "feed": archive_url, "selected": "test-cat", "size": "0"}
            )
            refreshed_category = h.php_eval(
                vm,
                "config_set_path('installedpackages/pfblockerngblacklist', array("
                "'blacklist_enable'=>'on','blacklist_selected'=>'ut1','blacklist_freq'=>'EveryDay',"
                f"'item'=>array({provider})));"
                "write_config('pfBlockerNG smoke: scheduled UT1 archive'); echo 'OK';",
            )
            assert refreshed_category.returncode == 0 and "OK" in refreshed_category.stdout, refreshed_category
            own_less = tuple("blacklist:ut1:test-cat" if fid.startswith("blacklist:") else fid for fid in own_less)
        else:
            aliases, domain = _configure_custom_only(vm)
            regular = {}
            own_less = tuple(f"custom:{family}:{alias}" for family, alias in aliases.items())
        with mock_feeds._lock:
            requests_before = {name: list(statuses) for name, statuses in mock_feeds._responses.items()}
        # The all-kinds category must be refreshed by its real archive Extra before FeedPhase parses it.
        configured = h.php_eval(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
            "$slot = (new DateTimeImmutable('@' . (intdiv(time(), 900) * 900 + 900)))"
            "->setTimezone(new DateTimeZone(date_default_timezone_get()));"
            "PfbConfig::writeSystem('gen/pfb_schedule_weekday', $slot->format('N'));"
            "PfbConfig::writeSystem('gen/pfb_schedule_hour', $slot->format('G'));"
            "PfbConfig::writeSystem('gen/pfb_schedule_minute', (string)(int)$slot->format('i'));"
            "PfbConfig::writeSystem('gen/pfb_quiet_hours', '');"
            f"config_set_path({h._php_str(h.CFG_IP_SETTINGS + '/maxmind_account')}, '');"
            f"config_set_path({h._php_str(h.CFG_IP_SETTINGS + '/maxmind_key')}, '');"
            f"config_set_path({h._php_str(h.CFG_IP_SETTINGS + '/asn_token')}, '');"
            "PfbConfig::writeSystem('ip/database_cc', PfbToggle::On);"
            "PfbConfig::writeSystem('dnsbl/top1m_enable', PfbToggle::Off);"
            "config_set_path('installedpackages/pfblockerngblacklist/blacklist_freq', "
            f"'{'EveryDay' if feed_selection == 'all-kinds' else 'Never'}');"
            + "".join(
                f"$groups = config_get_path({h._php_str(root)}, array());"
                "foreach ($groups as &$group) { $group['cron'] = 'EveryDay'; $group['schedule_override'] = ''; }"
                "unset($group);"
                f"config_set_path({h._php_str(root)}, $groups);"
                for root in (h.CFG_IP_V4_LISTS, h.CFG_IP_V6_LISTS, h.CFG_DNSBL_LISTS)
            )
            + "write_config('pfBlockerNG smoke: isolated native scheduled feeds'); echo 'OK';",
        )
        assert configured.returncode == 0 and "OK" in configured.stdout, f"schedule setup failed: {configured}"
        controls = h.php_eval(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc'); pfb_global();"
            "echo (empty($pfb['maxmind_account']) && empty($pfb['maxmind_key']) && empty($pfb['asn_token'])"
            " && $pfb['dnsbl_top1m'] === PfbToggle::Off && $pfb['cc']) ? 'NO_EXTERNAL_EXTRAS' : 'UNSAFE';",
        )
        assert controls.returncode == 0 and "NO_EXTERNAL_EXTRAS" in controls.stdout, (
            f"DCC must have no enabled external sources: {controls}"
        )
        h.config_set(vm, f"{h.CFG_GLOBAL}/pfb_scheduled_feed_updates", "on")
        h.tell_core_the_settings_changed(vm)
        settings = h.core_call(
            vm, "GetSettings", {"projectionIds": ["schedule", "feeds/ipv4", "feeds/ipv6", "feeds/dnsbl"]}
        )
        assert settings["status"] == 200, f"cannot inspect controlled settings: {settings}"
        projections = {p["resourceId"]: p["value"] for p in settings["body"]["projections"]}
        schedule = projections["settings/schedule"]
        expected_frequency = "EveryDay" if feed_selection == "all-kinds" else "Never"
        assert schedule["scheduledUpdates"] and schedule["categoryFrequency"] == expected_frequency, settings
        for family in ("ipv4", "ipv6", "dnsbl"):
            groups = projections[f"settings/feeds/{family}"]["groups"]
            assert len(groups) == 1, f"unrelated {family} groups enabled: {groups}"
            feeds = groups[0]["feeds"]
            if feed_selection == "all-kinds":
                expected = mock_feeds.feed_url(regular[next(fid for fid in regular if fid.startswith(family + ":"))])
                assert len(feeds) == 1 and feeds[0]["url"] == expected, f"uncontrolled {family} source: {feeds}"
            else:
                assert groups[0]["name"] == aliases[family] and groups[0]["customList"].strip(), groups
                assert all(feed["url"] == "" for feed in feeds), f"regular {family} URL configured: {feeds}"
        view = h.core_call(vm, "GetSchedule")
        assert view["status"] == 200 and view["body"]["feeds"] is not None, view
        assert ("extra:bl" in view["body"]["extras"]) == (feed_selection == "all-kinds"), (
            f"Blacklist archive Extra must match the selected fixture: {view}"
        )
        print(f"scheduled_feedphase: controlled registered schedule={view['body']}", flush=True)
        before = h.core_update_view(vm)["update"]
        assert vm.ssh("test", "-f", sentinel).returncode == 0, "setup removed the scheduler sentinel"
        with vm.scheduled_feedphase():
            update, log = _capture_scheduled_update(vm, before)
            assert update["trigger"] == "scheduled", f"expected real scheduler trigger, got {update}"
            assert update["result"] == "success", f"scheduled Update failed: {update}"
            print(f"scheduled_feedphase: actual completed Update={update}", flush=True)
            print(f"scheduled_feedphase: captured Core log:\n{log}", flush=True)
            for feed_id in (*regular, *own_less):
                _assert_feed_disposition(log, feed_id, "changed")
            for feed_id, mock in regular.items():
                assert 200 in mock_feeds.statuses(mock), f"{feed_id}: scheduled run never fetched local source"
            if feed_selection == "all-kinds":
                assert 200 in mock_feeds.statuses(archive_name), "scheduled Extra never fetched the UT1 archive"
            if feed_selection == "custom-only":
                assert not re.search(r"(?<![A-Za-z0-9_:-])(?:dnsbl|ipv4|ipv6):[A-Za-z0-9_]+", log), log
                with mock_feeds._lock:
                    requests_after = {name: list(statuses) for name, statuses in mock_feeds._responses.items()}
                assert requests_after == requests_before, f"custom-only run made feed requests: {requests_after}"
                for family, suffix, expected in (
                    ("ipv4", "v4", b"198.51.100.177\n"),
                    ("ipv6", "v6", b"2001:db8::177\n"),
                ):
                    stem = f"{aliases[family]}_custom_{suffix}"
                    for path, (actual, _) in _snapshot(
                        vm,
                        [
                            f"{DB}/original/{stem}.orig",
                            f"{DB}/original/{stem}.parsed.ip",
                            f"{DB}/deny/{stem}.txt",
                        ],
                    ).items():
                        assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"
                stem = f"{aliases['dnsbl']}_custom"
                original = _snapshot(vm, [f"{DB}/dnsblorig/{stem}.orig"])
                assert next(iter(original.values()))[0] == domain.encode(), original
                for path, (actual, _) in _snapshot(
                    vm,
                    [
                        f"{DB}/dnsblorig/{stem}.parsed.ndjson",
                        f"{DB}/dnsbl/{stem}.txt",
                    ],
                ).items():
                    assert [json.loads(line) for line in actual.splitlines()] == [["d", domain]], (
                        f"{path}: wrong custom domain payload: {actual!r}"
                    )
                checked = h.core_call(vm, "GetSchedule")
                assert checked["status"] == 200, checked
                successful = checked["body"]["lastSuccessfulCheck"]
                for feed_id in own_less:
                    assert update["startedAt"] <= successful.get(feed_id, 0) <= update["finishedAt"], (
                        f"{feed_id}: scheduled successful check missing: {checked}"
                    )
                return
            for stem, expected_bytes in {
                "cunativev4_v4": b"198.51.100.44\n",
                "cunativev6_v6": b"2001:db8::44\n",
                "cunativev4_custom_v4": b"198.51.100.77\n",
                "cunativev6_custom_v6": b"2001:db8::77\n",
                "DNSBLIP_v4": b"203.0.113.9\n",
                "DNSBLIP_v6": b"2001:db8::9\n",
            }.items():
                for path, (actual, _) in _snapshot(
                    vm, [f"{DB}/original/{stem}.parsed.ip", f"{DB}/deny/{stem}.txt"]
                ).items():
                    assert actual == expected_bytes, f"{path}: expected {expected_bytes!r}, got {actual!r}"
            for stem, domain in (
                ("cunativednsbl", "ads.example.com"),
                ("cunativednsbl_custom", "custom.example.com"),
                ("Corenative_test_cat", "blacklist.example.com"),
            ):
                for path, (actual, _) in _snapshot(
                    vm, [f"{DB}/dnsblorig/{stem}.parsed.ndjson", f"{DB}/dnsbl/{stem}.txt"]
                ).items():
                    payloads = [json.loads(line)[1] for line in actual.splitlines()]
                    assert domain in payloads, f"{path}: expected {domain!r}, got {payloads!r}"
    finally:
        assert vm.ssh("test", "-f", sentinel).returncode == 0, "refusing config restoration without sentinel"
        restored_cron = vm.ssh("service cron onestatus")
        expected_status = (
            r"cron is running as pid [1-9][0-9]*\." if original_cron.returncode == 0 else r"cron is not running\."
        )
        assert (
            restored_cron.returncode == original_cron.returncode
            and not restored_cron.stderr.strip()
            and re.fullmatch(expected_status, restored_cron.stdout.strip())
        ), f"refusing config restoration: cron differs from original: {original_cron} -> {restored_cron}"
        print("scheduled_feedphase: sentinel/cron verified before config restoration and diagnostics", flush=True)
        h.restore_pfb_config_baseline(vm, snapshot_path=snapshot)
        h.tell_core_the_settings_changed(vm)
        assert vm.ssh("rm", "-f", snapshot).returncode == 0, "cannot remove config snapshot"
