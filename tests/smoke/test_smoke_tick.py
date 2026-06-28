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


@pytest.fixture(autouse=True)
def _reset_ledger(deployed_vm: SmokeVM) -> None:
    """Per-test isolation for the due-ledger.

    The module baseline reset (``_pfb_module_baseline``) is module-scoped and does NOT touch
    ``pfb_due_ledger.json``, so without this each test would inherit the previous test's ledger —
    e.g. a dispatch's ``mark_ran`` leaving a future ``next_due``. That coupling is what let
    ``test_tick_skips_non_due_feed`` pass only because an earlier test had run. Wipe the ledger
    before every test so each one establishes its own state from a known-empty baseline.
    """
    # SmokeVM.ssh() is check=False, so verify the wipe took — a silently-failed rm would leave
    # the prior test's ledger in place and defeat the isolation this fixture exists to provide.
    result = deployed_vm.ssh("rm", "-f", LEDGER_PATH)
    if result.returncode != 0:
        raise AssertionError(
            f"_reset_ledger failed to wipe {LEDGER_PATH}: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LEDGER_PATH = "/var/db/pfblockerng/pfb_due_ledger.json"
_LEDGER_DIR = "/var/db/pfblockerng"
_PHP = "/usr/local/bin/php"
_PFB_PHP = "/usr/local/www/pfblockerng/pfblockerng.php"
_PFB_EXTRA = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"


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
    """Merge one entry into the on-box ledger via the package's own PHP ledger writer.

    pfSense ships no ``python3`` (python3.11 only, no symlink), and the product already owns the
    ledger format, so ``pfb_due_ledger_write_entry()`` (PHP) is the right tool — not a here-doc
    Python snippet, which silently no-op'd at rc=127 and left these writes ineffective.
    """
    snippet = (
        f"require_once('{_PFB_EXTRA}');"
        f"pfb_due_ledger_write_entry('{job_key}', array("
        f"'last_run' => {int(last_run)}, 'next_due' => {int(next_due)}, 'jitter' => {int(jitter)}"
        f"), '{_LEDGER_DIR}');"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_write_ledger_entry failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _run_tick(vm) -> str:
    """Fire one tick synchronously and return its combined stdout+stderr."""
    return vm.ssh(f"{_PHP} {_PFB_PHP} tick 2>&1").stdout


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(150)  # the cron pass is backgrounded; its CRON PROCESS marker lands async
def test_tick_dispatches_due_feed(deployed_vm: SmokeVM):
    """Tick fires a due feed sync, dispatched THROUGH pfblockerng_sync_cron (issue #570).

    Two observables (the tick logs to syslog, not stdout, so we never assert on tick stdout):
      1. mark_ran updates the 'cron' ledger next_due (the tick dispatched a cron job), and
      2. a ' CRON  PROCESS  START' marker appears in pfblockerng.log — that marker is logged
         ONLY by pfblockerng_sync_cron, so it proves the tick dispatches the `cron` verb
         (-> per-list Update Frequency + scheduled log reset) and NOT a bare
         `pfb_trigger scope=both` (which logs no CRON PROCESS pass). This is the FIRST tick
         test, so it runs on a clean box (no prior backgrounded cron holding the sync lock).

    Scenario:
        Background: pfBlockerNG installed with at least one enabled feed.
            Given the 'cron' ledger entry has next_due in the past.
            When pfblockerng.php tick runs.
            Then the 'cron' ledger entry's next_due is updated to the future,
            And  a ' CRON  PROCESS  START' marker appears (dispatched via pfblockerng_sync_cron).
    """
    vm = deployed_vm
    marker = "CRON  PROCESS  START"

    now_ts = int(vm.ssh("date +%s").stdout.strip())

    # Given: force cron past; snapshot the sync_cron marker count before the tick.
    _write_ledger_entry(vm, "cron", now_ts - 90000, now_ts - 1)
    cron_marker_before = h.count_log_marker(vm, h.PFB_LOG, marker)

    before = _read_ledger(vm)
    assert before.get("cron", {}).get("next_due", 0) < now_ts, (
        f"before: cron next_due should be in the past; ledger={before}"
    )

    # When: tick fires (backgrounds the `cron` verb).
    _run_tick(vm)

    # Then (1): mark_ran persisted the updated next_due — proves the tick dispatched the cron.
    assert h.wait_until(
        lambda: _read_ledger(vm).get("cron", {}).get("next_due", 0) > now_ts,
        timeout=30,
        interval=2,
    ), f"after: cron next_due should be in the future;\n  ledger={_read_ledger(vm)}, now_ts={now_ts}"

    # Then (2): the backgrounded pass ran through pfblockerng_sync_cron (marker count rose) —
    # a bare pfb_trigger would never log CRON PROCESS, so this is the routing discriminator.
    assert h.wait_until(
        lambda: h.count_log_marker(vm, h.PFB_LOG, marker) > cron_marker_before,
        timeout=90,
        interval=3,
    ), (
        "tick must route the feed cron through pfblockerng_sync_cron — the "
        f"' {marker}' marker count did not increase (before={cron_marker_before}, "
        f"after={h.count_log_marker(vm, h.PFB_LOG, marker)}).  A bare pfb_trigger would "
        "skip per-list Update Frequency and the scheduled log reset (issue #570 / ADR-30)."
    )


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(150)  # drain + bounded no-dispatch poll can exceed the 30s body cap
def test_tick_skips_non_due_feed(deployed_vm: SmokeVM):
    """Tick does NOT dispatch a feed sync when the cron ledger entry is not yet due.

    The tick logs to syslog (not stdout), so observe the NON-dispatch via the
    ' CRON  PROCESS  START' marker (logged only by pfblockerng_sync_cron): a non-due cron
    must produce NO new marker. Drain any in-flight cron from a prior tick test first so the
    marker baseline is stable. This is marker-based (not ledger-value-based) so it is immune
    to a prior test's mark_ran overwriting the cron entry — both values stay 'future' anyway.
    (Positive-control hardening — proving the tick itself ran — is tracked in #582.)

    Scenario:
        Background: pfBlockerNG installed.
            Given the 'cron' ledger entry has next_due = now + 1 hour.
            When pfblockerng.php tick runs.
            Then NO new ' CRON  PROCESS  START' marker appears (the cron was skipped).
    """
    vm = deployed_vm
    marker = "CRON  PROCESS  START"

    # Drain any in-flight backgrounded cron from a prior tick test so the marker baseline
    # is stable (a still-running prior cron would log a marker unrelated to this tick).
    assert h.wait_until(
        lambda: (
            vm.ssh("pgrep -f 'pfblockerng[.]php cron' >/dev/null && echo BUSY || echo CLEAR").stdout.strip() == "CLEAR"
        ),
        timeout=90,
        interval=3,
    ), "a prior backgrounded cron never finished; cannot isolate this tick"

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    _write_ledger_entry(vm, "cron", now_ts - 86400, now_ts + 3600)
    before = h.count_log_marker(vm, h.PFB_LOG, marker)

    # When: tick fires — cron is not due.
    _run_tick(vm)

    # Then: no new CRON PROCESS pass appeared (cron skipped). The bounded poll gives any
    # erroneous late dispatch a window to show; wait_until returns False (good) when the
    # count never rises.
    assert not h.wait_until(
        lambda: h.count_log_marker(vm, h.PFB_LOG, marker) > before,
        timeout=20,
        interval=4,
    ), f"tick dispatched a cron for a NON-due feed — ' {marker}' marker count rose from {before}"


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
