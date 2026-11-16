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
    # Ordinary supported settings: no feed or Extra may explain the duty effects.
    h.config_set(vm, f"{h.CFG_GLOBAL}/pfb_scheduled_feed_updates", "")
    h.config_set(vm, "installedpackages/pfblockerngblacklist/blacklist_enable", "Disable")
    h.reload(vm, "update")
    _assert_no_dispatch(vm, "enabled-apply")
    h.set_pfb_keep(vm, True)
    _force_install(vm, prev_pkg)
    _force_install(vm, Path(os.environ["SMOKE_PKG"]))
    _assert_no_dispatch(vm, "enabled-upgrade")
    h.reload(vm, "update")
    _assert_no_dispatch(vm, "repeated-enabled-apply")
    await_core_up(vm)
    process = vm.ssh("ps ax -o command")
    assert process.returncode == 0, process.stderr
    assert any(
        "pfb_core" in line and "--maintenance-cmd /usr/local/pkg/pfblockerng/pfb_core_maintenance.sh" in line
        for line in process.stdout.splitlines()
    ), f"installed Core is not wired to real maintenance: {process.stdout}"
    schedule = h.core_call(vm, "GetSchedule")
    assert schedule["status"] == 200, schedule
    assert schedule["body"]["scheduled"] is False, schedule
    assert schedule["body"]["feeds"] is None and schedule["body"]["extras"] == {}, schedule
    h.wait_unbound_ready(vm)
    # First answer is authoritative: never retry toward the expected DNS value.
    answer = h.dns_probe(vm, blocked, "A", attempts=1)
    assert h.is_vip(answer), f"DNSBL gate failed before cadence acceptance: {answer}"
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
