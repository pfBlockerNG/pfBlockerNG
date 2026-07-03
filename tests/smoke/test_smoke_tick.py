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
    test_tick_reboot_persists_ledger  — clean reboot with MFS /var keeps the schedule
                                        (ledger restored via the #468 earlyshellcmd)
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
_PFB_INC = "/usr/local/pkg/pfblockerng/pfblockerng.inc"

# A throwaway marker dropped in /var right before the reboot in test_tick_reboot_persists_ledger.
# Distinct from test_smoke_boot_reload.VAR_WIPE_SENTINEL — a different fixture, a different reboot.
# Its disappearance after the reboot is direct, implementation-agnostic proof that /var actually
# came up as a memory filesystem (MFS wipes /var on every boot); if it survived, use_mfs_tmpvar
# never engaged and the whole scenario would be a false positive.
_VAR_WIPE_SENTINEL = "/var/PFB_SMOKE_TICK_WIPE_SENTINEL"


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


@pytest.fixture
def mfs_var(deployed_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Arrange test_tick_reboot_persists_ledger's documented Background: MFS /var.

    ``set_ramdisk`` only flips the ``use_mfs_tmpvar`` config flag; the reload that follows
    runs ``pfb_aliastables('conf')`` (pfblockerng.inc:13273, on every package sync), which
    registers the aliastables-restore earlyshellcmd because the flag is now on. /var only
    comes up as a memory filesystem after the REBOOT that follows — that is the state the
    reboot-persists scenario needs, so this fixture reboots to actually engage it (not just
    set the flag).

    Function-scoped so no other test inherits MFS /var: issue #762 is exactly that leak —
    a sibling module's ramdisk leg turns the flag off WITHOUT rebooting, so the previously
    engaged MFS /var kept running underneath this test, which never arranged its own
    Background and inherited whatever state came before it. Teardown reboots back to a
    disk-backed /var so it never leaks forward either.
    """
    vm = deployed_vm
    h.set_ramdisk(vm, True)
    h.reload(vm, "update")
    h.reboot_vm(vm)
    try:
        yield vm
    finally:
        # Best-effort, mirrors test_smoke_boot_reload's deployed_vm teardown: never mask
        # the test result on cleanup failure. The reboot here is REQUIRED (not optional) —
        # without it the running /var stays MFS and pollutes every module that runs next.
        try:
            h.set_ramdisk(vm, False)
            h.reload(vm, "update")
            h.reboot_vm(vm)
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] mfs_var teardown reboot failed (non-fatal): {exc}")


@pytest.mark.reboot
@pytest.mark.tick
# Unlike the boot_reload siblings (which reboot in a FIXTURE, exempt from the workflow's
# 30s func-only body cap), this test reboots in its BODY too: the 30s settle alone exhausts
# the default cap, so it could never pass a dispatch without its own budget (#738 F4
# validation run). Reboot ~90-150s (settle + readiness gate) + ledger checks + margin. The
# mfs_var fixture reboots twice more (arrange + teardown) — exempt from the func-only cap,
# same as boot_reload's fixture reboots — so the body still contains exactly ONE reboot.
@pytest.mark.timeout(300)
def test_tick_reboot_persists_ledger(mfs_var: SmokeVM):
    """A clean reboot with MFS /var keeps the due-ledger (restored via #468 earlyshellcmd).

    Scenario:
        Background: pfBlockerNG installed with MFS /var engaged (the ``mfs_var`` fixture;
            issue #762 — previously only claimed in this docstring, never arranged, so the
            test silently rode whatever /var state a sibling module happened to leave behind).
            Given the ledger has a future cron next_due, and the aliastables archive has been
            refreshed to include it (the archiver is called directly: ``pfb_aliastables('update')``
            is reached only on the rule-change or alias-content-change paths, and this module
            configures no IP feeds, so a quiescent update pass would never archive the ledger).
        When the VM reboots cleanly.
        Then the /var sentinel is gone (MFS actually engaged this reboot),
        And  the ledger is restored,
        And  the cron next_due is still the value written before the reboot (no spurious dispatch).
    """
    vm = mfs_var

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    future = now_ts + 7200  # 2 hours out

    _write_ledger_entry(vm, "cron", now_ts, future)

    # Refresh the archive directly (see docstring: 'update' mode is change-gated and this
    # module has no IP feeds to trip either gate).
    snippet = f"require_once('{_PFB_INC}');pfb_global();pfb_aliastables('update');echo 'OK';"
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"pfb_aliastables('update') archive refresh failed: "
            f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        )

    # --- Given (before reboot): archive refreshed, ledger holds the just-written entry ---
    assert h.archive_exists(vm, h.ALIASARCHIVE), (
        f"precondition: {h.ALIASARCHIVE}.{{zst,bz2}} must exist after the archive refresh"
    )
    before = _read_ledger(vm)
    assert before.get("cron", {}).get("next_due") == future, (
        f"precondition: cron next_due should be {future} before reboot; ledger={before}"
    )

    # Drop a /var sentinel so the post-reboot check can PROVE /var came up as a memory
    # filesystem this reboot (the sentinel is wiped), not merely re-use a prior MFS mount.
    vm.ssh("/usr/bin/touch", _VAR_WIPE_SENTINEL)
    assert vm.ssh("test", "-e", _VAR_WIPE_SENTINEL).returncode == 0, (
        f"precondition: {_VAR_WIPE_SENTINEL} must exist before reboot"
    )

    # When: reboot.
    h.reboot_vm(vm)

    # Then: the sentinel is gone -- print the /var mount line so a not-engaged MFS is
    # diagnosable rather than a bare boolean (the test-coverage mandate's expected-vs-actual rule).
    var_mount = next(
        (ln for ln in vm.ssh("/sbin/mount").stdout.splitlines() if " on /var " in ln),
        "",
    )
    assert vm.ssh("test", "-e", _VAR_WIPE_SENTINEL).returncode != 0, (
        f"/var sentinel survived the reboot -- MFS did not engage; /var mount line: {var_mount!r}"
    )

    after = _read_ledger(vm)
    assert "cron" in after, f"cron ledger entry missing after reboot; ledger={after}"
    assert after["cron"]["next_due"] == future, (
        f"cron next_due changed across reboot; expected={future} actual={after['cron']['next_due']}; ledger={after}"
    )
