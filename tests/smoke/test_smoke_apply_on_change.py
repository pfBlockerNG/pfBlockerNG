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
    """Deploy the branch .pkg once for the apply_on_change module, feed-cron dispatch re-armed.

    ``h.deploy`` disables the tick's feed-cron dispatch for the suite (issue #1179); the
    quiet-hours cases below drive exactly that branch, so this module opts back in with an
    hour count (a leaked 'Disabled' already bit it once — issue #805).
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.set_feed_cron_interval(smoke_vm, "1")
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
# The ledger lives at $pfb['dbdir']/pfb_due_ledger.json (dbdir = /var/db/pfblockerng).
_LEDGER_DIR = "/var/db/pfblockerng"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_ledger(vm) -> dict:
    """Return the parsed ledger from the box (empty on absent/corrupt)."""
    raw = vm.ssh(f"cat {LEDGER_PATH} 2>/dev/null || echo '{{}}'").stdout
    try:
        return json.loads(raw.strip()) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def _write_ledger_entry(vm, job_key: str, last_run: int, next_due: int, jitter: int = 0) -> None:
    """Write a single ledger entry via the package's own PHP ledger writer.

    pfSense ships no ``python3``, and the product already owns the ledger format, so
    ``pfb_due_ledger_write_entry()`` (PHP) is the right tool — not a here-doc Python snippet.
    """
    snippet = (
        f"require_once('{h.PFB_EXTRA_INC}');"
        f"pfb_due_ledger_write_entry('{job_key}', array("
        f"'last_run' => {int(last_run)}, 'next_due' => {int(next_due)}, 'jitter' => {int(jitter)}"
        f"), '{_LEDGER_DIR}');"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_write_ledger_entry failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _set_quiet_hours(vm, window: str) -> None:
    """Set pfb_quiet_hours in config.xml via pfSsh.php."""
    # Use the config gateway rather than direct xml munging.
    snippet = (
        f"require_once('{h.PFB_EXTRA_INC}');"
        f"PfbConfig::write('pfb_quiet_hours', {json.dumps(window)});"
        "write_config('ADR-43 smoke: set quiet-hours');"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_quiet_hours({window!r}) failed: rc={result.returncode} {result.stderr!r}")


def _clear_quiet_hours(vm) -> None:
    """Clear pfb_quiet_hours (reset to default '')."""
    _set_quiet_hours(vm, "")


def _force_cron_due(vm) -> None:
    """Force the cron job due-now by back-dating next_due to epoch 0."""
    _write_ledger_entry(vm, "cron", last_run=0, next_due=0)


def _run_tick(vm) -> str:
    """Fire one tick synchronously and return combined stdout+stderr."""
    return vm.ssh(f"{_PHP} {_PFB_PHP} tick 2>&1").stdout


def _cron_ledger(vm) -> dict | None:
    """Return the 'cron' entry from the ledger, or None if absent."""
    return _read_ledger(vm).get("cron")


def _is_pending(vm) -> bool:
    """Return True iff the 'cron' ledger entry has pending_apply set."""
    entry = _cron_ledger(vm)
    return bool(entry and entry.get("pending_apply"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.apply_on_change
def test_apply_no_window_dispatches_immediately(deployed_vm: SmokeVM):
    """No quiet-hours window → tick dispatches a due job without deferral.

    Scenario:
      Background: pfb_quiet_hours = '' (apply immediately).
        Given pfb_quiet_hours is '' (default).
        And the cron job is due (next_due = 0).
      When tick fires.
      Then the ledger entry has an updated last_run (job ran, not deferred).
      And pending_apply is NOT set.

    Red→green: before Phase 5, the tick had no window check — it would still
    dispatch, but the quiet-hours registry entry didn't exist and neither did
    pfb_quiet_hours_in_window(). This test pins that the default behaviour is
    preserved after Phase 5.
    """
    vm = deployed_vm

    _clear_quiet_hours(vm)
    _force_cron_due(vm)  # seeds last_run = 0 — a fired tick advances it past 0

    # Before: pending not set.
    assert not _is_pending(vm), "before tick: pending_apply must not be set"

    _run_tick(vm)

    # After: last_run updated (dispatched) and not pending.
    entry = _cron_ledger(vm)
    assert entry is not None, f"after tick: ledger entry for 'cron' must exist; ledger={_read_ledger(vm)}"
    # Dispatch evidence is a CHANGE in the guest-stamped ledger, not a host-clock
    # comparison: _force_cron_due seeded last_run=0, so a fired tick advances it
    # past 0. Comparing the guest last_run against the host's time.time() raced the
    # ~1s host/guest clock skew — an off-by-one flake.
    assert entry.get("last_run", 0) > 0, (
        f"after tick: expected last_run to advance past the forced 0 (job dispatched), "
        f"got last_run={entry.get('last_run')}; ledger={entry}"
    )
    assert not _is_pending(vm), f"after tick (no window): pending_apply must NOT be set; ledger={entry}"


@pytest.mark.smoke
@pytest.mark.apply_on_change
def test_apply_inside_window_dispatches(deployed_vm: SmokeVM):
    """Window that covers now → tick dispatches, pending NOT set.

    Scenario:
      Background: pfb_quiet_hours set to a window that includes the current time.
        Given pfb_quiet_hours = "00:00-23:59" (covers every minute of the day).
        And the cron job is due (next_due = 0).
      When tick fires.
      Then last_run is updated (job ran).
      And pending_apply is NOT set (was inside window).
    """
    vm = deployed_vm

    _set_quiet_hours(vm, "00:00-23:59")  # always-open window covers any real clock
    _force_cron_due(vm)  # seeds last_run = 0 — a fired tick advances it past 0

    assert not _is_pending(vm), "before tick: pending_apply must not be set"

    _run_tick(vm)

    entry = _cron_ledger(vm)
    assert entry is not None, f"after tick: 'cron' entry must exist; ledger={_read_ledger(vm)}"
    # Advanced past the forced-due 0 ⇒ dispatched (single-clock change check; see
    # test_apply_no_window_dispatches_immediately for why not host time.time()).
    assert entry.get("last_run", 0) > 0, (
        f"after tick (inside window): expected last_run to advance past the forced 0, "
        f"got {entry.get('last_run')}; ledger={entry}"
    )
    assert not _is_pending(vm), f"after tick (inside window): pending_apply must NOT be set; ledger={entry}"

    _clear_quiet_hours(vm)


@pytest.mark.smoke
@pytest.mark.apply_on_change
def test_apply_outside_window_defers(deployed_vm: SmokeVM):
    """Window that excludes now → tick defers (pending set, job NOT dispatched).

    Scenario:
      Background: pfb_quiet_hours set to a window that EXCLUDES the current time.
        Given pfb_quiet_hours = "00:00-00:01" (1-minute window, almost certainly past).
        And the cron job is due (next_due = 0).
        And the actual clock is NOT in "00:00-00:01" (asserted).
      When tick fires.
      Then pending_apply IS set (deferred).
      And last_run is NOT updated (job did not run — exec() not called).

    Note: This test must be run outside 00:00-00:01 local time. It asserts the
    clock is not in the window before proceeding; if the VM clock is in that
    1-minute window the test is skipped (not failed) to avoid false positives.
    """
    vm = deployed_vm

    # Skip only if the GUEST clock is actually inside the 1-minute exclusion window — the
    # quiet-hours window is evaluated against the VM's local time, not the host's, so probe
    # the VM (single-clock; a host datetime.now() would race the host/guest skew).
    vm_hm = vm.ssh("date +%H:%M").stdout.strip()
    if vm_hm in ("00:00", "00:01"):
        pytest.skip(f"VM clock {vm_hm} is inside the 1-minute exclusion window; re-run after 00:01")

    _set_quiet_hours(vm, "00:00-00:01")  # 1-min window in the dead of night
    _force_cron_due(vm)  # writes last_run=0; a DEFERRED tick must leave it there

    assert not _is_pending(vm), "before tick: pending_apply must not be set"

    _run_tick(vm)

    entry = _cron_ledger(vm)
    assert entry is not None, f"after tick: 'cron' entry must exist; ledger={_read_ledger(vm)}"
    assert _is_pending(vm), (
        f"after tick (outside window): pending_apply must be TRUE;\n"
        f"  ledger={entry}\n"
        f"  (if this failed, verify the VM clock is outside 00:00-00:01 local time)"
    )
    # last_run must NOT have advanced past the forced 0 (job deferred, did not execute).
    assert entry.get("last_run", 0) == 0, (
        f"after tick (outside window): last_run must stay at the forced 0 (deferred, not dispatched), "
        f"got {entry.get('last_run')}; ledger={entry}"
    )

    _clear_quiet_hours(vm)


@pytest.mark.smoke
@pytest.mark.apply_on_change
def test_apply_pending_cleared_by_window_open(deployed_vm: SmokeVM):
    """Pending job is applied when window opens (pending cleared, last_run updated).

    Scenario:
      Background: a job was deferred in a prior tick (pending_apply=TRUE).
        Given the ledger has pending_apply=TRUE for 'cron'.
        And pfb_quiet_hours = '00:00-23:59' (always-open window).
        And the cron job is still due (next_due = 0).
      When tick fires.
      Then last_run is updated (job ran this tick).
      And pending_apply is NOT set (cleared by mark_ran in the tick).

    Red→green: before Phase 5, is_pending/set_pending didn't exist — a
    "pending" entry written manually would be silently ignored.
    """
    vm = deployed_vm

    # Arrange: force due + mark pending via the product's own setter (simulates a prior
    # deferred tick). pfb_due_ledger_set_pending() adds pending_apply=TRUE to the entry.
    _force_cron_due(vm)
    pend = h.php_eval(
        vm,
        f"require_once('{h.PFB_EXTRA_INC}');pfb_due_ledger_set_pending('cron', '{_LEDGER_DIR}');echo 'OK';",
    )
    assert pend.returncode == 0 and "OK" in pend.stdout, (
        f"set_pending failed: rc={pend.returncode} {pend.stderr!r} {pend.stdout!r}"
    )

    assert _is_pending(vm), f"precondition: pending_apply must be TRUE before tick; ledger={_read_ledger(vm)}"

    _set_quiet_hours(vm, "00:00-23:59")

    _run_tick(vm)

    entry = _cron_ledger(vm)
    assert entry is not None, f"after tick: 'cron' entry must exist; ledger={_read_ledger(vm)}"
    # Advanced past the forced-due 0 ⇒ dispatched (single-clock change check).
    assert entry.get("last_run", 0) > 0, (
        f"after tick (pending + window open): expected last_run to advance past the forced 0, "
        f"got {entry.get('last_run')}; ledger={entry}"
    )
    assert not _is_pending(vm), (
        f"after tick (pending + window open): pending_apply must be FALSE (cleared by dispatch); ledger={entry}"
    )

    _clear_quiet_hours(vm)
