"""ADR-43 Phase 4 — Due-ledger trigger-tick smoke tests.

These tests exercise the tick verb and the due-ledger on a LIVE pfSense CE VM
(ADR-04 harness). They are authored in Phase 4 but DISPATCHED in Phase 7 as
part of the full smoke fan-out.

Dispatch (when ready):
    gh workflow run smoke.yml -f pytest_marker="tick"

Tests:
    test_tick_dispatches_due_feed     — tick fires a due feed (ledger past)
    test_tick_skips_non_due_feed      — tick skips a feed whose next_due is future
    test_tick_wiped_ledger_jittered   — wiped ledger gives due-now but jittered next_due
    test_tick_reboot_persists_ledger  — clean reboot keeps the schedule (ledger restored)
"""

import json
import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

# Module mark: 'tick' on every test. 'smoke' is applied PER-TEST (not module-wide)
# so the reboot test — which reboots the shared session VM — carries 'reboot' but
# NOT 'smoke', keeping it out of the -m smoke run (see the 'reboot' marker rationale
# in pyproject.toml; mirrors test_smoke_boot_reload.py).
pytestmark = [pytest.mark.tick]


# ---------------------------------------------------------------------------
# Module-scoped deployed_vm: install the branch .pkg once for all tick tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for the tick module."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LEDGER_PATH = "/var/db/pfblockerng/pfb_due_ledger.json"
_PHP = "/usr/local/bin/php"
_PFB_PHP = "/usr/local/www/pfblockerng/pfblockerng.php"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_ledger(vm) -> dict:
    """Return the parsed ledger as a dict (empty on absent/corrupt)."""
    raw = vm.ssh(f"cat {LEDGER_PATH} 2>/dev/null || echo '{{}}'").stdout
    try:
        return json.loads(raw.strip()) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def _write_ledger_entry(vm, job_key: str, last_run: int, next_due: int, jitter: int = 0) -> None:
    """Merge one entry into the on-box ledger via a small Python snippet."""
    # Build the JSON snippet inline (no shell escaping needed beyond basic quoting).
    entry_json = json.dumps({"last_run": last_run, "next_due": next_due, "jitter": jitter})
    script = (
        "import json, os; "
        f"p='{LEDGER_PATH}'; "
        "d=json.load(open(p)) if os.path.exists(p) else {}; "
        f"d['{job_key}']={entry_json}; "
        "open(p,'w').write(json.dumps(d))"
    )
    vm.ssh(f"/usr/local/bin/python3 -c {json.dumps(script)}")


def _run_tick(vm) -> str:
    """Fire one tick synchronously and return its combined stdout+stderr."""
    return vm.ssh(f"{_PHP} {_PFB_PHP} tick 2>&1").stdout


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.tick
def test_tick_dispatches_due_feed(deployed_vm: SmokeVM):
    """Tick fires a due feed sync when the cron ledger entry is past.

    Scenario:
        Background: pfBlockerNG installed with at least one enabled feed.
            Given the 'cron' ledger entry has next_due in the past.
            When pfblockerng.php tick runs.
            Then the log contains 'Tick: dispatching feed cron.'
            And  the 'cron' ledger entry's next_due is updated to the future.
    """
    vm = deployed_vm

    now_ts = int(vm.ssh("date +%s").stdout.strip())

    # Given: force cron past.
    _write_ledger_entry(vm, "cron", now_ts - 90000, now_ts - 1)

    before = _read_ledger(vm)
    assert before.get("cron", {}).get("next_due", 0) < now_ts, (
        f"before: cron next_due should be in the past; ledger={before}"
    )

    # When: tick fires. Its "Tick: dispatching feed cron." line goes to SYSLOG via logger()
    # (NOT stdout), and the cron pass is backgrounded to the log file — so the tick's stdout
    # is empty. Observe the dispatch through the ledger (mark_ran updates next_due), not stdout.
    _run_tick(vm)

    # Then: mark_ran persisted the updated next_due — proves the tick dispatched the cron.
    assert h.wait_until(
        lambda: _read_ledger(vm).get("cron", {}).get("next_due", 0) > now_ts,
        timeout=30,
        interval=2,
    ), f"after: cron next_due should be in the future;\n  ledger={_read_ledger(vm)}, now_ts={now_ts}"


@pytest.mark.smoke
@pytest.mark.tick
def test_tick_skips_non_due_feed(deployed_vm: SmokeVM):
    """Tick does NOT fire a feed sync when cron next_due is in the future.

    Scenario:
        Background: pfBlockerNG installed.
            Given the 'cron' ledger entry has next_due = now + 1 hour.
            When pfblockerng.php tick runs.
            Then the log does NOT contain 'Tick: dispatching feed cron.'
    """
    vm = deployed_vm

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    future = now_ts + 3600

    _write_ledger_entry(vm, "cron", now_ts - 86400, future)

    # The tick logs to syslog, not stdout, so observe via the ledger: a non-due cron is
    # NOT dispatched, so mark_ran does not run and next_due stays at the future value.
    _run_tick(vm)

    assert _read_ledger(vm).get("cron", {}).get("next_due", 0) == future, (
        f"expected NO dispatch (cron not yet due) — next_due should stay {future}; ledger={_read_ledger(vm)}"
    )


@pytest.mark.smoke
@pytest.mark.tick
def test_tick_wiped_ledger_jittered(deployed_vm: SmokeVM):
    """After the ledger is wiped, the tick runs jobs but schedules them jittered.

    Scenario:
        Background: pfBlockerNG installed.
            Given the ledger file is deleted (RAM-disk reboot simulation).
            When pfblockerng.php tick runs.
            Then all jobs run (due-now after absent ledger).
            And  the 'dcc' next_due has non-zero jitter (not exactly last_run+86400).
    """
    vm = deployed_vm

    # Wipe the ledger.
    vm.ssh(f"rm -f {LEDGER_PATH}")

    # Tick — all jobs are due (absent ledger ⇒ due-now).
    _run_tick(vm)

    # Poll until mark_ran has persisted the dcc entry.
    assert h.wait_until(lambda: "dcc" in _read_ledger(vm), timeout=30, interval=2), (
        f"dcc ledger entry missing after wiped-ledger tick; ledger={_read_ledger(vm)}"
    )
    ledger = _read_ledger(vm)

    # dcc should have run and have a non-zero jitter.
    assert "dcc" in ledger, f"dcc ledger entry missing after wiped-ledger tick; ledger={ledger}"
    now_ts = int(vm.ssh("date +%s").stdout.strip())
    no_jitter_next_due = ledger["dcc"]["last_run"] + 86400
    actual_next = ledger["dcc"]["next_due"]
    assert actual_next != no_jitter_next_due, (
        f"dcc next_due should differ from last_run+86400 (jitter expected);\n"
        f"  next_due={actual_next} last_run={ledger['dcc']['last_run']} "
        f"no-jitter={no_jitter_next_due}"
    )
    assert actual_next > now_ts, f"dcc next_due should be in the future; got {actual_next} now={now_ts}"


@pytest.mark.reboot
@pytest.mark.tick
def test_tick_reboot_persists_ledger(deployed_vm: SmokeVM):
    """A clean reboot keeps the due-ledger (restored via #468 earlyshellcmd).

    Scenario:
        Background: pfBlockerNG installed with MFS /var (use_mfs_tmpvar).
            Given the ledger has a future cron next_due.
            When the VM reboots cleanly.
            Then the ledger is restored.
            And  the cron next_due is still in the future (no spurious dispatch).
    """
    vm = deployed_vm

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    future = now_ts + 7200  # 2 hours out

    _write_ledger_entry(vm, "cron", now_ts, future)

    # Reboot.
    h.reboot_vm(vm)

    # After reboot: verify ledger was restored.
    after = _read_ledger(vm)
    assert "cron" in after, f"cron ledger entry missing after reboot; ledger={after}"
    assert after["cron"]["next_due"] == future, (
        f"cron next_due changed across reboot;\n  before={future} after={after['cron']['next_due']}"
    )


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(220)  # the cron pass is backgrounded + serialised behind sibling ticks'
#                            crons; its CRON PROCESS marker can land past the 30s body cap.
def test_tick_feed_cron_routes_through_sync_cron(deployed_vm: SmokeVM):
    """The tick's due feed-cron dispatches the ``cron`` verb (-> pfblockerng_sync_cron),
    NOT a bare ``pfb_trigger scope=both`` (issue #570).

    Only ``pfblockerng_sync_cron()`` applies each feed's per-list Update Frequency
    (``$list['cron']``: EveryDay/Weekly/NNhour) and runs the scheduled log trim + reset
    (``pfb_log_mgmt``/``pfb_log_reset``).  A bare ``pfb_trigger`` does neither — it would
    poll every feed on every tick (provider-ban risk) and never rotate the report logs
    (ADR-30 dead on-box).  The discriminator is the `` CRON  PROCESS  START`` marker that
    ONLY ``pfblockerng_sync_cron()`` logs; if the tick regresses to dispatching
    ``pfb_trigger`` directly the marker count never increases.

    Scenario:
        Background: pfBlockerNG installed.
            Given the 'cron' ledger entry is due (next_due in the past).
            And   a count of the ' CRON  PROCESS  START' marker taken BEFORE the tick.
            When  pfblockerng.php tick runs (it backgrounds the cron pass).
            Then  the tick logs 'Tick: dispatching feed cron.'
            And   the ' CRON  PROCESS  START' marker count increases — proving the pass
                  ran through pfblockerng_sync_cron, not a bare pfb_trigger.
    """
    vm = deployed_vm
    marker = "CRON  PROCESS  START"

    now_ts = int(vm.ssh("date +%s").stdout.strip())

    # Drain any in-flight backgrounded cron from a prior tick test first: a sync pass holds
    # a lock, so a second cron launched while one is running exits early WITHOUT its own
    # CRON PROCESS pass — which would leave our marker count flat even though the tick
    # dispatched correctly. Wait until no `pfblockerng.php cron` process remains.
    assert h.wait_until(
        lambda: (
            vm.ssh("pgrep -f 'pfblockerng[.]php cron' >/dev/null && echo BUSY || echo CLEAR").stdout.strip() == "CLEAR"
        ),
        timeout=90,
        interval=3,
    ), "a prior backgrounded cron never finished; cannot isolate this tick's sync_cron pass"

    # Given: cron due, and the sync_cron marker count BEFORE this tick.
    _write_ledger_entry(vm, "cron", now_ts - 90000, now_ts - 1)
    before = h.count_log_marker(vm, h.PFB_LOG, marker)

    # When: the tick fires (backgrounds the cron pass via the `cron` verb). The tick's
    # "Tick: dispatching feed cron." line goes to syslog, not stdout, so do not assert on
    # tick stdout — the CRON PROCESS marker below is the actual discriminator.
    _run_tick(vm)

    # Then: the backgrounded pass ran through pfblockerng_sync_cron (marker count rose).
    assert h.wait_until(
        lambda: h.count_log_marker(vm, h.PFB_LOG, marker) > before,
        timeout=90,
        interval=3,
    ), (
        "tick must route the feed cron through pfblockerng_sync_cron — the "
        f"' {marker}' marker count did not increase (before={before}, "
        f"after={h.count_log_marker(vm, h.PFB_LOG, marker)}).  A bare pfb_trigger would "
        "skip per-list Update Frequency and the scheduled log reset (issue #570 / ADR-30)."
    )
