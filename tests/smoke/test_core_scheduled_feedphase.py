"""#3977: owner-authorized, disposable-only native quarter-hour scheduler acceptance."""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_core_update import DB, _assert_feed_disposition, _configure_every_feed_type, _snapshot, await_idle
from .test_core_update import core_vm as core_vm

pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        os.environ.get("SMOKE_SCHEDULED_EXCEPTION") != "allow",
        reason="dispatch-only: requires explicit isolated SMOKE_SCHEDULED_EXCEPTION=allow",
    ),
]

SCHEDULED_WATCHDOG = 1800.0


@pytest.mark.timeout(2400)
def test_scheduled_update_runs_core_feedphase_for_every_feed_kind(core_vm: SmokeVM, mock_feeds: Any) -> None:
    """Given only controlled feeds, the real scheduler runs and consumes every Core feed kind."""
    vm = core_vm
    sentinel = h.PFB_CRON_DISABLE_PATH
    assert vm.ssh("test", "-f", sentinel).returncode == 0, "setup must retain the scheduler sentinel"
    original_cron = vm.ssh("service cron onestatus")
    snapshot = "/tmp/smoke-scheduled-config.xml"
    saved = vm.ssh("cp", "/conf/config.xml", snapshot)
    assert saved.returncode == 0, f"cannot snapshot scheduled-test config: {saved}"
    try:
        await_idle(vm)
        regular, own_less = _configure_every_feed_type(vm, mock_feeds, "native")
        # Blacklist category parsing stays enabled; Never independently disables its archive Extra.
        configured = h.php_eval(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
            "PfbConfig::writeSystem('gen/pfb_schedule_weekday', '7');"
            "PfbConfig::writeSystem('gen/pfb_schedule_hour', '0');"
            "PfbConfig::writeSystem('gen/pfb_schedule_minute', '0');"
            "PfbConfig::writeSystem('gen/pfb_quiet_hours', '');"
            "PfbConfig::writeSystem('ip/maxmind_account', '');"
            "PfbConfig::writeSystem('ip/maxmind_key', '');"
            "PfbConfig::writeSystem('ip/asn_token', '');"
            "PfbConfig::writeSystem('ip/database_cc', 'on');"
            "PfbConfig::writeSystem('dnsbl/top1m_enable', '');"
            "config_set_path('installedpackages/pfblockerngblacklist/blacklist_freq', 'Never');"
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
        assert schedule["scheduledUpdates"] and schedule["categoryFrequency"] == "Never", settings
        for family in ("ipv4", "ipv6", "dnsbl"):
            groups = projections[f"settings/feeds/{family}"]["groups"]
            assert len(groups) == 1, f"unrelated {family} groups enabled: {groups}"
            feeds = groups[0]["feeds"]
            expected = mock_feeds.feed_url(regular[next(fid for fid in regular if fid.startswith(family + ":"))])
            assert len(feeds) == 1 and feeds[0]["url"] == expected, f"uncontrolled {family} source: {feeds}"
        view = h.core_call(vm, "GetSchedule")
        assert view["status"] == 200 and view["body"]["feeds"] is not None, view
        assert "extra:bl" not in view["body"]["extras"], f"blacklist archive Extra must be disabled: {view}"
        print(f"scheduled_feedphase: controlled registered schedule={view['body']}", flush=True)
        before = h.core_update_view(vm)["update"]
        assert vm.ssh("test", "-f", sentinel).returncode == 0, "setup removed the scheduler sentinel"
        with vm.scheduled_feedphase():
            deadline = time.monotonic() + SCHEDULED_WATCHDOG
            while True:
                current = h.core_update_view(vm)
                update = current["update"]
                if update != before and update is not None and not current["running"]:
                    break
                if time.monotonic() > deadline:
                    pytest.fail(f"STUCK/ENVIRONMENT: native scheduled Update did not complete: {current}")
                time.sleep(1)
            assert update["trigger"] == "scheduled", f"expected real scheduler trigger, got {update}"
            assert update["result"] == "success", f"scheduled Update failed: {update}"
            log = h.core_update_log(vm)
            print(f"scheduled_feedphase: actual completed Update={update}", flush=True)
            for feed_id in (*regular, *own_less):
                _assert_feed_disposition(log, feed_id, "changed")
            for feed_id, mock in regular.items():
                assert 200 in mock_feeds.statuses(mock), f"{feed_id}: scheduled run never fetched local source"
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
