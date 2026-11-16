"""#3996 real quarter-hour acceptance; no scheduler clock/state injection.

Only the exact explicitly opted-in case may enter scheduled_maintenance.
SafeSearch CSV effects and real 900-second duty ledgers are the live oracles.
Other duty branches remain covered by the real PHP suite, not claimed here.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer
from .test_smoke_core_api import await_core_up
from .test_smoke_tick import (
    _drain_pending_apply,
    _read_ledger,
    _remove_ss_row,
    _reset_ss_extdns,
    _seed_ss_refresh_positive_control,
)

SENTINEL = "/var/db/pfblockerng/.pfb_cron_disable"
PHP = "/usr/local/bin/php"
CLI = "/usr/local/www/pfblockerng/pfblockerng.php"
DISPATCH = re.compile(r"pfblockerng\.php\s+(?:cron-tick|tick|cron)(?:\s|$)")
DUTIES = ("ss_refresh", "apply_reconcile")
MARKER = "SafeSearch CNAME fallback IPs refreshed"
SCHEDULE_HOUR = f"{h.CFG_GLOBAL}/pfb_schedule_hour"
SCHEDULE_MINUTE = f"{h.CFG_GLOBAL}/pfb_schedule_minute"
DCC_ID = "extra:dcc"
WINDOW_BOUND_SECONDS = 2160


def _schedule_view(vm: SmokeVM, phase: str) -> tuple[dict[str, int], dict[str, int], dict[str, Any]]:
    reply = h.core_call(vm, "GetSchedule", {})
    assert reply["status"] == 200, f"{phase}: GetSchedule failed: {reply}"
    body = reply["body"]
    assert isinstance(body, dict), f"{phase}: malformed GetSchedule body: {reply}"
    assert body.get("scheduled") is False and body.get("feeds") is None, f"{phase}: feeds remain eligible: {reply}"
    extras = body.get("extras")
    assert isinstance(extras, dict) and set(extras) == {DCC_ID}, f"{phase}: enabled extras are not DCC-only: {reply}"
    dcc = extras[DCC_ID]
    assert isinstance(dcc, dict) and type(dcc.get("lastRun")) is int and type(dcc.get("nextDue")) is int, (
        f"{phase}: malformed DCC schedule entry: {reply}"
    )
    checks = body.get("lastSuccessfulCheck")
    if type(checks) is list:
        assert checks == [], f"{phase}: malformed empty lastSuccessfulCheck: {reply}"
        checks = {}
    assert isinstance(checks, dict) and all(
        isinstance(item, str) and type(stamp) is int and stamp > 0 for item, stamp in checks.items()
    ), f"{phase}: malformed lastSuccessfulCheck: {reply}"
    return dcc, checks, reply


def _complete_due_dcc(vm: SmokeVM) -> int:
    dcc, checks, reply = _schedule_view(vm, "before-DCC-setup")
    previous = checks.get(DCC_ID)
    now = _epoch(vm, "before-DCC-setup")
    if previous is not None and dcc["lastRun"] > 0 and dcc["nextDue"] > now:
        assert dcc["nextDue"] > now + WINDOW_BOUND_SECONDS, (
            f"DCC nextDue is not outside the full bounded window: {reply}"
        )
        return previous

    before = h.core_update_view(vm)["update"]
    started = h.core_call(vm, "StartUpdate", {"trigger": "retry"})
    assert started["status"] == 200 and not started["body"], f"public StartUpdate retry was not admitted: {started}"
    ended = h.await_core_update_end(vm, before=before)
    after_dcc, after_checks, after = _schedule_view(vm, "after-DCC-retry")
    update = ended.get("update")
    assert (
        ended.get("running") is False
        and isinstance(update, dict)
        and (update.get("trigger") == "retry" and update.get("result") == "success")
    ), f"retry Update failed: start={started!r}, end={ended!r}, schedule={after!r}"
    successful = after_checks.get(DCC_ID)
    assert successful is not None and (previous is None or successful > previous) and after_dcc["lastRun"] > 0, (
        f"retry did not complete DCC successfully: prior={previous!r}, schedule={after!r}"
    )
    return successful


def _assert_dcc_window_safe(vm: SmokeVM, successful: int) -> None:
    dcc, checks, reply = _schedule_view(vm, "immediately-before-yield")
    now = _epoch(vm, "immediately-before-yield")
    assert checks.get(DCC_ID, 0) >= successful and dcc["lastRun"] > 0, (
        f"DCC has no retained terminal success: expected at least {successful}, schedule={reply!r}"
    )
    assert dcc["nextDue"] > now + WINDOW_BOUND_SECONDS, (
        f"DCC nextDue is not outside the full bounded window: now={now}, schedule={reply!r}"
    )


def _schedule_hour_far_from_window(vm: SmokeVM) -> str:
    result = vm.ssh("date", "-v+23H", "-v0M", "+%H")
    assert result.returncode == 0 and result.stdout.strip().isdigit(), (
        f"could not derive a future local daily schedule slot: {result}"
    )
    hour = result.stdout.strip()
    assert 0 <= int(hour) <= 23, f"invalid guest local hour {hour!r}"
    return hour


def _epoch(vm: SmokeVM, phase: str) -> int:
    result = vm.ssh("date", "+%s")
    assert result.returncode == 0 and result.stdout.strip().isdigit(), result
    now = int(result.stdout.strip())
    print(f"PFB_MAINTENANCE_TIME phase={phase} guest_epoch={now}", flush=True)
    return now


def _assert_no_dispatch(vm: SmokeVM, phase: str) -> None:
    result = vm.ssh("/usr/bin/crontab", "-l")
    if result.returncode == 0:
        root_crontab = result.stdout
    elif result.returncode == 1 and result.stdout == "" and result.stderr == "crontab: no crontab for root\n":
        # FreeBSD crontab(1) uses this exact ENOENT result when root has no per-user tab.
        root_crontab = ""
    else:
        raise AssertionError(f"{phase}: unreadable root crontab: {result}")

    effective = vm.ssh("/bin/cat", "/etc/crontab")
    assert effective.returncode == 0, f"{phase}: unreadable effective crontab: {effective}"
    commands = h._php_read_scalar(
        vm,
        "",
        "json_encode(array_column(config_get_path('cron/item', array()), 'command'))",
    )
    parsed = json.loads(commands)
    assert isinstance(parsed, list) and all(isinstance(command, str) for command in parsed), commands
    active_lines = [
        line
        for source in (root_crontab, effective.stdout)
        for line in source.splitlines()
        if not line.lstrip().startswith("#")
    ]
    assert not any(DISPATCH.search(command) for command in [*parsed, *active_lines]), (
        f"{phase}: competing config/effective dispatch job: {commands}"
    )
    assert vm.ssh("test", "-f", SENTINEL).returncode == 0, f"{phase}: sentinel missing"


def _force_install(vm: SmokeVM, pkg: Path) -> None:
    """Same forced pkg replacement as ha_versions, without its unrelated HA markers."""
    assert vm.ssh("test", "-f", SENTINEL).returncode == 0
    remote = f"/tmp/pfb-maintenance-{pkg.name}"
    with pkg.open("rb") as stream:
        copied = subprocess.run(
            vm.ssh_argv(f"cat > {shlex.quote(remote)}"),
            stdin=stream,
            capture_output=True,
            timeout=300,
            check=False,
        )
    assert copied.returncode == 0, copied.stderr
    try:
        abi = os.environ.get("SMOKE_ABI", "")
        add = f"pkg -o ABI={shlex.quote(abi)} add" if abi else "pkg add"
        result = vm.ssh(f"env ASSUME_ALWAYS_YES=yes {add} -f {shlex.quote(remote)}", timeout=600)
        assert result.returncode == 0, result.stdout + result.stderr
        assert not re.search(r"(?:POST-INSTALL|PRE-DEINSTALL) script failed", result.stdout + result.stderr)
        assert vm.ssh("test", "-f", SENTINEL).returncode == 0, "install removed sentinel"
        h.wait_unbound_ready(vm)
    finally:
        removed = vm.ssh("rm", "-f", remote)
        assert removed.returncode == 0, removed.stderr


@pytest.fixture(scope="module")
def maintenance_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer, prev_pkg: Path) -> Iterator[SmokeVM]:
    del stub_dns  # starts the real hermetic DNS boundary before install
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built package")
    if os.environ.get("SMOKE_SCHEDULED_EXCEPTION") != "allow":
        pytest.fail("scheduled maintenance requires explicit --scheduled-exception allow")
    vm = smoke_vm
    h.deploy(vm)
    _assert_no_dispatch(vm, "branch-install")
    h.ensure_dnsbl_vip(vm)
    h.use_stub_for_safesearch(vm, False)
    blocked = h.unique_domain("maintenanceblocked")
    feed = h.write_local_feed(vm, "smoke_maintenance.txt", blocked + "\n")
    h.inject(vm, h.DnsblCase(aliasname="smokemaint", header="smokemaint", feed_url=feed, mode=h.DnsblMode.VIP))
    h.set_package_enabled(vm, True)
    # Supported settings isolate feeds/blacklist and keep DCC's next daily slot outside this test.
    h.config_set(vm, f"{h.CFG_GLOBAL}/pfb_scheduled_feed_updates", "")
    h.config_set(vm, "installedpackages/pfblockerngblacklist/blacklist_enable", "Disable")
    hour = _schedule_hour_far_from_window(vm)
    h.config_set(vm, SCHEDULE_HOUR, hour)
    h.config_set(vm, SCHEDULE_MINUTE, "0")
    h.reload(vm, "update")
    _assert_no_dispatch(vm, "enabled-apply")
    h.set_pfb_keep(vm, True)
    _force_install(vm, prev_pkg)
    assert h.config_get(vm, SCHEDULE_HOUR) == hour, "previous forced install changed the daily schedule hour"
    assert h.config_get(vm, SCHEDULE_MINUTE) == "0", "previous forced install changed the daily schedule minute"
    _force_install(vm, Path(os.environ["SMOKE_PKG"]))
    assert h.config_get(vm, SCHEDULE_HOUR) == hour, "current forced install changed the daily schedule hour"
    assert h.config_get(vm, SCHEDULE_MINUTE) == "0", "current forced install changed the daily schedule minute"
    _assert_no_dispatch(vm, "enabled-upgrade")
    h.reload(vm, "update")
    h.tell_core_the_settings_changed(vm)
    _assert_no_dispatch(vm, "repeated-enabled-apply")
    await_core_up(vm)
    process = vm.ssh("ps ax -o command")
    assert process.returncode == 0, process.stderr
    assert any(
        "pfb_core" in line and "--maintenance-cmd /usr/local/pkg/pfblockerng/pfb_core_maintenance.sh" in line
        for line in process.stdout.splitlines()
    ), f"installed Core is not wired to real maintenance: {process.stdout}"
    dcc_success = _complete_due_dcc(vm)
    h.wait_unbound_ready(vm)
    # First answer is authoritative: never retry toward the expected DNS value.
    answer = h.dns_probe(vm, blocked, "A", attempts=1)
    assert h.is_vip(answer), f"DNSBL gate failed before cadence acceptance: {answer}"
    _assert_dcc_window_safe(vm, dcc_success)
    try:
        yield vm
    finally:
        assert vm.ssh("test", "-f", SENTINEL).returncode == 0, "unsafe cleanup: sentinel absent"
        h.unblock_egress()
        h.collect_host_diagnostics(vm)


def _row(vm: SmokeVM, source: str) -> str:
    result = vm.ssh("cat", h.UNBOUND_PY_SS_FILE)
    assert result.returncode == 0, result.stderr
    rows = [row for row in result.stdout.splitlines() if row.startswith(source + ",")]
    assert len(rows) == 1, f"expected exact seeded CSV source {source}: {rows}"
    return rows[0]


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(2100)
def test_core_scheduled_maintenance_preserves_tick_duties(maintenance_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
    vm = maintenance_vm
    h.block_egress()
    target = h.unique_domain("maintenancetarget")
    stub_dns.set_records(target, a=(h.SS_TARGET_A,))
    answer = h.dns_probe(vm, target, "A", attempts=1)
    assert h.resolves_to(answer, h.SS_TARGET_A), f"first target DNS answer failed: {answer}"
    _drain_pending_apply(vm)
    # Only the Outpost's PHP duty ledger is reset, as in test_smoke_tick.
    # Core's scheduler state and clock are never written.
    cleared = vm.ssh("rm", "-f", "/var/db/pfblockerng/pfb_due_ledger.json")
    assert cleared.returncode == 0, cleared.stderr
    source = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
    try:
        # Direct tick is a manual control ONLY, never scheduled proof.
        direct = vm.ssh(PHP, CLI, "tick", timeout=180)
        assert direct.returncode == 0, direct.stdout + direct.stderr
        assert h.SS_TARGET_A in _row(vm, source), "manual tick was incorrectly sentinel-gated"
        _remove_ss_row(vm, source)
        source = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
        before = _read_ledger(vm)
        assert all(job in before for job in DUTIES), before
        assert h.SS_BAKED_A in _row(vm, source)
        marker_before = h.count_log_marker(vm, h.PFB_LOG, MARKER)
        last_update = h.core_update_view(vm)["update"]
        # Observe an actual production timer boundary with the sentinel STILL PRESENT.
        guarded_start = _epoch(vm, "sentinel-present-start")
        guarded_end = (guarded_start // 900 + 1) * 900 + 30
        deadline = time.monotonic() + 960
        while _epoch(vm, "sentinel-present-poll") < guarded_end:
            assert time.monotonic() < deadline, "guest clock did not cross guarded quarter-hour"
            time.sleep(5)
        assert _read_ledger(vm) == before, "sentinel-present maintenance changed duty ledger"
        assert h.SS_BAKED_A in _row(vm, source), "sentinel-present maintenance performed SafeSearch duty"
        assert h.count_log_marker(vm, h.PFB_LOG, MARKER) == marker_before
        assert h.core_update_view(vm)["update"] == last_update, "guarded maintenance created an Update"
        _assert_no_dispatch(vm, "before-scheduled-window")
        with vm.scheduled_maintenance():
            started = _epoch(vm, "scheduled-window-start")
            deadline = time.monotonic() + 990
            while True:
                after = _read_ledger(vm)
                if all(after.get(job, {}).get("last_run", 0) > before[job]["last_run"] for job in DUTIES):
                    break
                assert time.monotonic() < deadline, f"real Core quarter-hour did not advance duties: {after}"
                time.sleep(5)
            ended = _epoch(vm, "scheduled-window-end")
            assert ended // 900 > started // 900, "effect appeared before an actual production boundary"
            assert h.SS_TARGET_A in _row(vm, source), "ledger advanced without real SafeSearch CSV effect"
            assert h.count_log_marker(vm, h.PFB_LOG, MARKER) > marker_before
            for job in DUTIES:
                assert started <= after[job]["last_run"] <= ended, (job, after[job], started, ended)
                assert after[job]["next_due"] > after[job]["last_run"]
                assert after[job]["next_due"] % 900 == 0, (job, after[job])
            assert h.core_update_view(vm)["update"] == last_update, "maintenance minted a public Update"
        _assert_no_dispatch(vm, "after-scheduled-window")
    finally:
        # Context finally MUST have restored+verified sentinel before any config cleanup.
        assert vm.ssh("test", "-f", SENTINEL).returncode == 0, "refusing unsafe configuration cleanup"
        _remove_ss_row(vm, source)
        _reset_ss_extdns(vm)
        stub_dns.clear_cname()
