"""ADR-43 Phase 5 — Apply-on-change + quiet-hours window smoke tests.

These tests exercise the quiet-hours window and the pending-apply deferral on a
LIVE pfSense CE VM (ADR-04 harness). They are AUTHORED in Phase 5 but DISPATCHED
in Phase 7 as part of the full smoke fan-out.

Dispatch (when ready):
    gh workflow run smoke.yml -f pytest_marker="apply_on_change"

Tests:
    test_apply_no_window_dispatches_immediately — no window → tick fires the feed without deferral
    test_apply_inside_window_dispatches         — inside window → tick fires the feed
    test_apply_outside_window_defers            — outside window → pending recorded, no dispatch
    test_apply_pending_cleared_by_window_open   — pending → tick fires when window opens
"""

import json
import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

# Module mark: 'apply_on_change' on every test; 'smoke' per-test.
pytestmark = [pytest.mark.apply_on_change]


# ---------------------------------------------------------------------------
# Module-scoped deployed_vm: install the branch .pkg once for all tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for the apply_on_change module."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    # issue #2506: the due ledger is a derived cache post-ADR-43 — without a configured
    # feed group the runtime model has nothing to schedule, so pfb_schedule_cache_refresh
    # legitimately PRUNES the 'cron' row, and every "entry must exist" assertion in this
    # module goes vacuous. Configure one real feed group, then immediately consume its
    # reservation so the module's own quiet-hours/pending-apply scenarios (which arrange
    # their own due-ness via _seed_pending_apply) never race a surprise scheduled feed pass.
    feed_url = h.write_local_feed(smoke_vm, "smoke_apply_ip.txt", "192.0.2.20/32\n192.0.2.21/32\n")
    h.inject(smoke_vm, h.IpCase(aliasname="smokeapply", feed_url=feed_url, header="smokeapply", family="v4"))
    h.pin_cron_due(smoke_vm)
    _complete_feed_reservation(smoke_vm)
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
# The ledger lives at $pfb['dbdir']/pfb_due_ledger.json (dbdir = /var/db/pfblockerng).
_LEDGER_DIR = "/var/db/pfblockerng"
_PFB_EXTRA = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"
# issue #2506: the model id pin_cron_due()/pfb_schedule_runtime_config() derive for the
# module's IpCase feed group ("ipv4:<header>_v4").
_FEED_GROUP_ID = "ipv4:smokeapply_v4"
# Logged by sync_package_pfblockerng (pfblockerng_apply.inc) when the package master switch is
# on and the pass is not save-only. The scheduled cron pass tail-calls the same function, so
# the marker is NOT manual-apply-exclusive in general — it discriminates here only because the
# fixture keeps this module's one feed group never-due, so no scheduled pass can contribute.
_UPDATE_MARKER = "UPDATE PROCESS START"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _complete_feed_reservation(vm: SmokeVM) -> None:
    """Consume the durable pending reservation :func:`h.pin_cron_due` made for the module's feed group.

    Same rationale as the tick module's sibling helper (#2506): completes the reservation right
    after pin_cron_due so this module's scenarios never race a surprise scheduled feed pass —
    module-local duplication is the house pattern here (this module already duplicates
    _read_ledger/_write_ledger_entry rather than importing the tick module's copies).
    """
    # State dir derived the way pin_cron_due derives it (pfb_global guarded + the production
    # `?? '/usr/local/etc'` fallback), and record_outcome's bool — its only failure signal —
    # is echoed rather than discarded.
    snippet = (
        f"require_once('{_PFB_EXTRA}');"
        "if (function_exists('pfb_global')) { pfb_global(); }"
        "$state_dir = $pfb['schedule_state_dir'] ?? '/usr/local/etc';"
        f"echo pfb_schedule_state_record_outcome('{_FEED_GROUP_ID}', "
        "PfbScheduleTerminalResult::Success, $state_dir) ? 'OK' : 'FAIL';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_complete_feed_reservation failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _read_ledger(vm: SmokeVM) -> dict:
    """Return the parsed ledger from the box (empty on absent/corrupt)."""
    raw = vm.ssh(f"cat {LEDGER_PATH} 2>/dev/null || echo '{{}}'").stdout
    try:
        return json.loads(raw.strip()) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def _write_ledger_entry(vm: SmokeVM, job_key: str, last_run: int, next_due: int, jitter: int = 0) -> None:
    """Write a single ledger entry via the package's own PHP ledger writer.

    pfSense ships no ``python3``, and the product already owns the ledger format, so
    ``pfb_due_ledger_write_entry()`` (PHP) is the right tool — not a here-doc Python snippet.
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


def _set_quiet_hours(vm: SmokeVM, window: str) -> None:
    """Set pfb_quiet_hours in config.xml via pfSsh.php.

    pfSsh.php is a no-session CLI caller, so this uses the config gateway's
    system-context entry point (``PfbConfig::writeSystem``) rather than the
    page-authorized ``PfbConfig::write()`` a UI save would use (issue #2071).
    """
    snippet = (
        f"require_once('{_PFB_EXTRA}');"
        f"PfbConfig::writeSystem('gen/pfb_quiet_hours', {json.dumps(window)});"
        "write_config('ADR-43 smoke: set quiet-hours');"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_quiet_hours({window!r}) failed: rc={result.returncode} {result.stderr!r}")


def _clear_quiet_hours(vm: SmokeVM) -> None:
    """Clear pfb_quiet_hours (reset to default '')."""
    _set_quiet_hours(vm, "")


def _seed_pending_apply(vm: SmokeVM) -> None:
    """Seed the legacy manual-apply marker consumed by the Apply Window."""
    _write_ledger_entry(vm, "cron", last_run=0, next_due=0)
    result = h.php_eval(
        vm,
        f"require_once('{_PFB_EXTRA}');pfb_due_ledger_set_pending('cron', '{_LEDGER_DIR}');echo 'OK';",
    )
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_pending_apply failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _run_tick(vm: SmokeVM, *, timeout: float = 180.0) -> str:
    """Fire one tick synchronously and return combined stdout+stderr.

    Drains any in-flight pfBlockerNG pass first: the tick defers its feed cron while
    another feed pass holds the cross-process lock ("Tick: feed cron deferred (another
    feed pass is running)"), which would silently turn this module's dispatch
    assertions into false negatives (issue #1202).

    issue #2506: post-ADR-43 the tick can dispatch a scheduled feed pass or a manual apply
    INLINE (synchronously) rather than merely backgrounding it, so a tick that enters the
    dispatch lock can run well past SmokeVM.ssh's 60s default -- widen the budget here.
    """
    h.wait_no_active_pfb_task(vm)
    return vm.ssh(f"{_PHP} {_PFB_PHP} tick 2>&1", timeout=timeout).stdout


def _cron_ledger(vm: SmokeVM) -> dict | None:
    """Return the 'cron' entry from the ledger, or None if absent."""
    return _read_ledger(vm).get("cron")


def _is_pending(vm: SmokeVM) -> bool:
    """Return True iff the 'cron' ledger entry has pending_apply set."""
    entry = _cron_ledger(vm)
    return bool(entry and entry.get("pending_apply"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.apply_on_change
def test_apply_no_window_dispatches_immediately(deployed_vm: SmokeVM) -> None:
    """No Apply Window → tick consumes a pending manual apply immediately.

    Scenario:
      Background: pfb_quiet_hours = '' (apply immediately).
        Given pfb_quiet_hours is '' (default).
        And a manual apply is pending.
      When tick fires.
      Then pending_apply is cleared for dispatch.
      And  the UPDATE PROCESS marker count rises (issue #2506: proof the pending apply
          actually dispatched, not merely that the flag vanished).
    """
    vm = deployed_vm

    _clear_quiet_hours(vm)
    _seed_pending_apply(vm)
    assert _is_pending(vm), "before tick: pending_apply must be set"
    before_updates = h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER)

    _run_tick(vm)

    entry = _cron_ledger(vm)
    assert entry is not None, f"after tick: ledger entry for 'cron' must exist; ledger={_read_ledger(vm)}"
    assert not _is_pending(vm), f"after tick (no window): pending_apply must NOT be set; ledger={entry}"
    assert h.wait_until(
        lambda: h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER) > before_updates,
        timeout=60,
        interval=2,
    ), (
        f"after tick (no window): the pending apply must have actually dispatched — "
        f"' {_UPDATE_MARKER}' marker count did not rise "
        f"(before={before_updates}, after={h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER)})"
    )


@pytest.mark.smoke
@pytest.mark.apply_on_change
def test_apply_inside_window_dispatches(deployed_vm: SmokeVM) -> None:
    """Window that covers now → tick consumes the pending manual apply.

    Scenario:
      Background: pfb_quiet_hours set to a window that includes the current time.
        Given pfb_quiet_hours = "00:00-23:59" (covers every minute of the day).
        And a manual apply is pending.
      When tick fires.
      Then pending_apply is cleared for dispatch.
      And  the UPDATE PROCESS marker count rises (issue #2506: proof the pending apply
          actually dispatched, not merely that the flag vanished).
    """
    vm = deployed_vm

    _set_quiet_hours(vm, "00:00-23:59")  # always-open window covers any real clock
    _seed_pending_apply(vm)
    assert _is_pending(vm), "before tick: pending_apply must be set"
    before_updates = h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER)

    _run_tick(vm)

    entry = _cron_ledger(vm)
    assert entry is not None, f"after tick: 'cron' entry must exist; ledger={_read_ledger(vm)}"
    assert not _is_pending(vm), f"after tick (inside window): pending_apply must NOT be set; ledger={entry}"
    assert h.wait_until(
        lambda: h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER) > before_updates,
        timeout=60,
        interval=2,
    ), (
        f"after tick (inside window): the pending apply must have actually dispatched — "
        f"' {_UPDATE_MARKER}' marker count did not rise "
        f"(before={before_updates}, after={h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER)})"
    )

    _clear_quiet_hours(vm)


@pytest.mark.smoke
@pytest.mark.apply_on_change
def test_apply_outside_window_defers(deployed_vm: SmokeVM) -> None:
    """Window that excludes now → tick defers (pending set, job NOT dispatched).

    Scenario:
      Background: pfb_quiet_hours set to a window that EXCLUDES the current time.
        Given pfb_quiet_hours = "00:00-00:01" (1-minute window, almost certainly past).
        And a manual apply is pending.
        And the actual clock is NOT in "00:00-00:01" (asserted).
      When tick fires.
      Then pending_apply IS set (deferred).
      And the previously-absent 'ss_refresh' ledger row APPEARS (positive control: the tick
          genuinely ran its due-jobs pass),
      And the UPDATE PROCESS marker count is UNCHANGED (job did not run — exec() not called).

    Note: This test must be run outside 00:00-00:01 local time. It asserts the
    clock is not in the window before proceeding; if the VM clock is in that
    1-minute window the test is skipped (not failed) to avoid false positives.

    issue #2506: previously asserted ``last_run == 0`` directly, which breaks once the module
    fixture seeds durable schedule state for its feed group — the derived-cache refresh
    recomputes 'cron' last_run from the schedule state's last_successful_check, not from the
    forced-0 seed. The UPDATE PROCESS marker count is the discriminator that survives that:
    it only rises when sync_package_pfblockerng actually runs.
    """
    vm = deployed_vm

    # Skip only if the GUEST clock is actually inside the 1-minute exclusion window — the
    # quiet-hours window is evaluated against the VM's local time, not the host's, so probe
    # the VM (single-clock; a host datetime.now() would race the host/guest skew).
    vm_hm = vm.ssh("date +%H:%M").stdout.strip()
    if vm_hm in ("00:00", "00:01"):
        pytest.skip(f"VM clock {vm_hm} is inside the 1-minute exclusion window; re-run after 00:01")

    _set_quiet_hours(vm, "00:00-00:01")  # 1-min window in the dead of night
    # Wipe the ledger BEFORE seeding so the 'ss_refresh' row is provably absent — that absence
    # arms the positive control below (an absent row is due on the next tick).
    result = vm.ssh("rm", "-f", LEDGER_PATH)
    assert result.returncode == 0, f"precondition: ledger wipe failed rc={result.returncode} {result.stderr!r}"
    _seed_pending_apply(vm)
    assert _is_pending(vm), "before tick: pending_apply must be set"
    assert "ss_refresh" not in _read_ledger(vm), (
        f"precondition: 'ss_refresh' row must be absent so its appearance can prove the tick ran; "
        f"ledger={_read_ledger(vm)}"
    )
    before_updates = h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER)

    _run_tick(vm)

    # Positive control FIRST: on its own, "marker unchanged + pending still set" cannot
    # distinguish "tick correctly deferred" from "tick never ran at all". The tick's own
    # ss_refresh cadence (900s, window-independent — it runs after the dispatch section
    # regardless of quiet-hours) writes its ledger row when the row is absent, so the row's
    # appearance proves the tick genuinely ran. (The deferral branch's own LOG_INFO syslog
    # line is not reliably observable in system.log on the appliance, so it cannot serve as
    # the control here.)
    assert "ss_refresh" in _read_ledger(vm), (
        f"tick did not run its due-jobs pass — the absent 'ss_refresh' row was not written; "
        f"cannot tell 'deferred correctly' from 'the tick itself never ran'; ledger={_read_ledger(vm)}"
    )

    entry = _cron_ledger(vm)
    assert entry is not None, f"after tick: 'cron' entry must exist; ledger={_read_ledger(vm)}"
    assert _is_pending(vm), (
        f"after tick (outside window): pending_apply must be TRUE;\n"
        f"  ledger={entry}\n"
        f"  (if this failed, verify the VM clock is outside 00:00-00:01 local time)"
    )
    # The dispatch discriminator: the deferred job must NOT have actually run.
    after_updates = h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER)
    assert after_updates == before_updates, (
        f"after tick (outside window): the deferred apply must NOT have dispatched — "
        f"' {_UPDATE_MARKER}' marker count changed: before={before_updates}, after={after_updates}"
    )

    _clear_quiet_hours(vm)


@pytest.mark.smoke
@pytest.mark.apply_on_change
def test_apply_pending_cleared_by_window_open(deployed_vm: SmokeVM) -> None:
    """Pending job is applied when window opens (pending cleared, apply dispatched).

    Scenario:
      Background: a job was deferred in a prior tick (pending_apply=TRUE).
        Given the ledger has pending_apply=TRUE for 'cron'.
        And pfb_quiet_hours = '00:00-23:59' (always-open window).
        And the cron job is still due (next_due = 0).
      When tick fires.
      Then pending_apply is NOT set (cleared by the dispatch in the tick).
      And  the UPDATE PROCESS marker count rises (issue #2506: proof the pending apply
          actually dispatched, not merely that the flag vanished).

    Red→green: before Phase 5, is_pending/set_pending didn't exist — a
    "pending" entry written manually would be silently ignored.
    """
    vm = deployed_vm

    # Arrange: force due + mark pending via the product's own setter (simulates a prior
    # deferred tick). pfb_due_ledger_set_pending() adds pending_apply=TRUE to the entry.
    _seed_pending_apply(vm)

    assert _is_pending(vm), f"precondition: pending_apply must be TRUE before tick; ledger={_read_ledger(vm)}"

    _set_quiet_hours(vm, "00:00-23:59")
    before_updates = h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER)

    _run_tick(vm)

    entry = _cron_ledger(vm)
    assert entry is not None, f"after tick: 'cron' entry must exist; ledger={_read_ledger(vm)}"
    assert not _is_pending(vm), (
        f"after tick (pending + window open): pending_apply must be FALSE (cleared by dispatch); ledger={entry}"
    )
    assert h.wait_until(
        lambda: h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER) > before_updates,
        timeout=60,
        interval=2,
    ), (
        f"after tick (pending + window open): the pending apply must have actually dispatched — "
        f"' {_UPDATE_MARKER}' marker count did not rise "
        f"(before={before_updates}, after={h.count_log_marker(vm, h.PFB_LOG, _UPDATE_MARKER)})"
    )

    _clear_quiet_hours(vm)
