"""ADR-60 — live-VM smoke: age-based log retention (``log_max_days_<type>``).

Proves the §2.2/§2.3 contract on a real pfSense CE VM:

  1. Host-side CSV log (``ip_blocklog``): lines older than the configured
     ``log_max_days_<type>`` cutoff are dropped, newer ones kept, inode preserved.
  2. Chrooted python-side CSV log (``dnslog``): same age-cutoff trim, PLUS inode and
     ``unbound`` ownership preserved (the chroot + ``chown unbound`` path Phase 6
     could only unit-test with a stubbed filesystem).
  3. Control: ``log_max_days_<type>='0'`` (the default) is a total no-op for the age
     logic — the log stays byte-identical, proving line-count-only behaviour is
     unchanged for every operator who never opts in (§2.3 item 2).

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``);
without them all cases skip cleanly. No live DNS or feed server is required: this
feature is purely log-file + config I/O, not DNSBL — mirrors the retired ADR-30
``test_log_rotate.py``'s own rationale for skipping DNSBL setup.

Driven via the ``tick`` verb (``pfblockerng_tick()`` -> ``pfb_log_mgmt()``, the only
path that runs log maintenance, and only on an IDLE tick — see
``pfb_update_pass_running()`` in ``pfblockerng.inc``). The ``deployed_vm`` fixture
primes every scheduled item as completed so its next occurrence is in the future.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

# --------------------------------------------------------------------------- #
# Paths (mirroring pfblockerng.inc $pfb[] definitions, verified via grep)
# --------------------------------------------------------------------------- #

PFB_LOGDIR = "/var/log/pfblockerng"
PFB_DBDIR = "/var/db/pfblockerng"

_PFB_EXTRA_INC = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"

# Host-side (non-chrooted) PHP-written CSV log; timestamp at CSV field 0.
LOG_IP_BLOCKLOG = f"{PFB_LOGDIR}/ip_block.log"

# Python-written CSV log — chrooted to /var/unbound on pfSense; timestamp at CSV
# field 1. pfb_log_mgmt() resolves it as /var/unbound/var/log/pfblockerng/dnsbl.log
# when the chroot dir exists, otherwise falls back to the host path (inc:2907).
LOG_DNSLOG_HOST = f"{PFB_LOGDIR}/dnsbl.log"
LOG_DNSLOG_CHROOT = f"/var/unbound{PFB_LOGDIR}/dnsbl.log"

CFG_GENERAL = "installedpackages/pfblockerng/config/0"

# The age cutoff exercised by every case here.
_CUTOFF_DAYS = 7

# --------------------------------------------------------------------------- #
# Module-scoped fixture: deploy once, then run all age-retention cases
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for this module and set up idle-tick state.

    Mirrors the retired ADR-30 ``test_log_rotate.py``'s own ``deployed_vm``: age-based
    log retention runs from ``pfblockerng_tick()`` and needs neither DNSBL nor feed
    infrastructure, only ``enable_cb=on`` (so the tick body executes) and every tick in
    this module being idle-only, so ``pfb_log_mgmt()`` runs on every ``tick`` call below.

    The helper marks every configured schedule identity completed at the current instant,
    publishes the matching runtime cache, and writes a future-dated cron entry.
    The next tick is therefore maintenance-only without relying on retired cron knobs.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    _set_enable_cb(smoke_vm)
    _prime_idle_schedule(smoke_vm)
    smoke_vm.ssh("/bin/mkdir", "-p", PFB_LOGDIR, timeout=30)
    smoke_vm.ssh("/bin/mkdir", "-p", PFB_DBDIR, timeout=30)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


@pytest.fixture(autouse=True)
def _reset_log_max_days(deployed_vm: SmokeVM) -> None:
    """Per-test isolation: log_max_days_<type> starts at '0' (off) for every case.

    Without this, a sibling test's leftover config could leak into the next one — the
    module VM is shared (CLAUDE.md "self-encapsulated — never order-dependent").
    """
    _set_log_max_days(deployed_vm, {"ip_blocklog": "0", "dnslog": "0"})


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #


def _set_enable_cb(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Set enable_cb=on so pfBlockerNG's cron body executes."""
    snippet = (
        f"$g = config_get_path({h._php_str(CFG_GENERAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(CFG_GENERAL)}, $g);\n"
        "write_config('pfBlockerNG smoke: enable_cb on');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_enable_cb failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _prime_idle_schedule(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Publish completed schedule state and a matching future runtime cache."""
    snippet = (
        f"require_once('{_PFB_EXTRA_INC}');"
        # issue #2492: guard, do not require pfblockerng.inc — see the measured
        # comparison at helpers.py pin_cron_due. Nothing here needs $pfb beyond
        # schedule_state_dir, which uses the same production fallback below.
        # Latent (#2495): pfb_schedule_runtime_config() reaches pfb_filter()/
        # PFB_FILTER_CSV (pfblockerng.inc-only) once blacklist_selected is populated.
        "if (function_exists('pfb_global')) { pfb_global(); }"
        "$now = time();"
        "$state_dir = $pfb['schedule_state_dir'] ?? '/usr/local/etc';"
        "$model = pfb_schedule_runtime_config();"
        "$state = array('schema' => 1, 'items' => array());"
        "foreach (($model['entries'] ?? array()) as $id => $entry) {"
        "  if (!empty($entry['enabled'])) {"
        "    $state['items'][$id] = array("
        "      'last_successful_check' => $now,"
        "      'last_completed_occurrence' => $now,"
        "      'completion_outcome' => 'success'"
        "    );"
        "  }"
        "}"
        "$ok = $model !== NULL && pfb_schedule_state_write($state, $state_dir)"
        f" && pfb_schedule_cache_refresh($model, $state, $now, "
        f"new DateTimeZone(date_default_timezone_get()), {h._php_str(PFB_DBDIR)});"
        "$ok = $ok && pfb_due_ledger_write_entry('cron', "
        "array('last_run' => $now, 'next_due' => $now + 86400, 'jitter' => 0), "
        f"{h._php_str(PFB_DBDIR)});"
        "if (!$ok) { exit(1); }"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_prime_idle_schedule failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _set_log_max_days(vm: SmokeVM, values: dict[str, str], *, timeout: float = 60.0) -> None:
    """Set one or more log_max_days_<type> config values (numeric string, '0' = off).

    ``values`` maps log type (e.g. ``'ip_blocklog'``) to the day-count string. Mirrors the
    retired ADR-30 ``_set_log_rotate_schedule()``'s config-set shape, adapted for ADR-60's
    numeric key — written directly into the General settings config section so
    PfbConfig::read picks it up on the next cron tick.
    """
    sets = ""
    for log_type, value in values.items():
        key = f"log_max_days_{log_type}"
        sets += f"$g[{h._php_str(key)}] = {h._php_str(str(value))};\n"
    snippet = (
        f"$g = config_get_path({h._php_str(CFG_GENERAL)}, array());\n"
        f"{sets}"
        f"config_set_path({h._php_str(CFG_GENERAL)}, $g);\n"
        "write_config('pfBlockerNG smoke: set log_max_days');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_log_max_days failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _seed_log(vm: SmokeVM, log_path: str, content: str, *, timeout: float = 30.0) -> None:
    """Write ``content`` into ``log_path`` via ``tee`` (replaces the file)."""
    result = subprocess.run(
        vm.ssh_argv("tee", log_path),
        input=content,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"_seed_log({log_path}) failed: rc={result.returncode} {result.stderr!r}")


def _read_file(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> str:
    """Return the contents of a guest file, or '' if absent."""
    result = vm.ssh("cat", path, timeout=timeout)
    return result.stdout if result.returncode == 0 else ""


def _get_inode(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> str:
    """Return the inode number of ``path`` on the guest (via ls -i), or ''."""
    result = vm.ssh("ls", "-i", path, timeout=timeout)
    if result.returncode != 0:
        return ""
    # ``ls -i`` output: ``<inode> <path>``
    parts = result.stdout.strip().split()
    return parts[0] if parts else ""


def _get_file_owner(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> str:
    """Return the owner (user) of ``path`` via ``stat -f '%Su'`` (FreeBSD stat)."""
    result = vm.ssh("stat", "-f", "%Su", path, timeout=timeout)
    return result.stdout.strip() if result.returncode == 0 else ""


def _rm_log(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> None:
    """Remove a log file (cleanup / between-case isolation)."""
    vm.ssh("/bin/rm", "-f", path, timeout=timeout)


_PASS_RUNNING_OPEN = "<<<PFBPASSRUNNING>>>"
_PASS_RUNNING_CLOSE = "<<<PFBPASSRUNNINGEND>>>"


def _update_pass_running(vm: SmokeVM, *, timeout: float = 30.0) -> bool:
    """True iff the real, on-box ``pfb_update_pass_running()`` sees a live update pass.

    Driven via ``pfSsh.php`` (h.php_eval — the established helper for running pkg PHP
    on-box; CLAUDE.md forbids a bare ``php -r``), not an injected ``ps`` snapshot: this
    probes the SAME live process table ``pfblockerng_tick()``'s log-maintenance gate
    scans (issue #1769).
    """
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        f"echo {h._php_str(_PASS_RUNNING_OPEN)} . (pfb_update_pass_running() ? '1' : '0') "
        f". {h._php_str(_PASS_RUNNING_CLOSE)};"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    out = result.stdout
    start, end = out.find(_PASS_RUNNING_OPEN), out.find(_PASS_RUNNING_CLOSE)
    if result.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(f"_update_pass_running probe failed: rc={result.returncode} {result.stderr!r} {out!r}")
    return out[start + len(_PASS_RUNNING_OPEN) : end] == "1"


def _wait_update_pass_idle(vm: SmokeVM, *, timeout: float = 60.0, poll_interval: float = 2.0) -> None:
    """Poll until ``pfb_update_pass_running()`` reports FALSE on-box, or fail loudly.

    issue #1769: ``pfblockerng_tick()``'s log-maintenance gate silently skips
    ``pfb_log_mgmt()`` whenever ANY process matches ``pfb_update_pass_running()``'s
    ps-scan (confirmed live: a stray matching process left a seeded log untrimmed with
    zero trace). A maintenance-sensitive tick that races that gate unsynchronized reads
    as a false trim failure. This cap is SALVAGE only (testing.md: a timeout never does
    assertion work) — it bounds how long we wait for the real "idle" event and fails with
    a distinguishable message when the box never reaches it; it never substitutes for
    the event itself.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _update_pass_running(vm):
            return
        time.sleep(poll_interval)
    if not _update_pass_running(vm):
        return
    raise RuntimeError(
        "salvage cap expired / stuck or environment: _wait_update_pass_idle awaited "
        f"pfb_update_pass_running() == False within {timeout}s; observed running=True "
        "(an update pass or stray matching process held the tick log-maintenance gate "
        "closed; issue #1769)"
    )


def _tick(vm: SmokeVM) -> None:
    """Run the maintenance-sensitive ``tick`` verb, synchronized on the real idle state.

    issue #1769: EVERY call to ``h.reload(vm, "tick")`` in this module is
    maintenance-sensitive (the assertions that follow depend on ``pfb_log_mgmt()``
    actually running), so every one of them needs the same ``_wait_update_pass_idle()``
    synchronization -- not just the first. Centralised here so a future case can't
    reintroduce the same race by calling ``h.reload(vm, "tick")`` directly.
    """
    _wait_update_pass_idle(vm)
    h.reload(vm, "tick")


def _resolve_dnslog_path(vm: SmokeVM) -> str:
    """Return the effective dnslog path: chrooted if /var/unbound's log dir exists.

    Mirrors pfb_log_mgmt()'s own chroot-path resolution (inc:2907) and the retired
    ADR-30 test's identical resolution logic.
    """
    chroot_dir = vm.ssh("test", "-d", "/var/unbound/var/log/pfblockerng", timeout=10)
    if chroot_dir.returncode == 0:
        return LOG_DNSLOG_CHROOT
    mk = vm.ssh("/bin/mkdir", "-p", "/var/unbound/var/log/pfblockerng", timeout=30)
    return LOG_DNSLOG_CHROOT if mk.returncode == 0 else LOG_DNSLOG_HOST


def _ts(days_ago: float) -> str:
    """A Y-m-d H:i:s timestamp ``days_ago`` days before now (guest clock assumed synced
    with the test runner — same assumption the retired ADR-30 test made for its daily-key
    computation)."""
    return (dt.datetime.now() - dt.timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


def _ip_blocklog_line(ts: str, ip: str) -> str:
    """One realistic ip_blocklog CSV row: ADR-60 field0 timestamp, then pfb_daemon_filterlog()'s
    real column shape (inc:12734/:12750/:12758) with inert filler (RFC 5737 TEST-NET-1 IP,
    synthetic labels) — semantic correctness of the filler fields isn't required, only that
    field 0 is a real timestamp the age-cutoff parser must actually parse."""
    return (
        f"{ts},1,em0,WAN,block,4,tcp,{ip},192.0.2.254,12345,443,"
        f"in,US,pfB_TestList,{ip},pfB_TestList,Unknown,Unknown,Unknown,+\n"
    )


def _dnslog_line(ts: str, q_name: str, q_ip: str) -> str:
    """One realistic dnslog CSV row: ADR-60 field1 timestamp, matching pfb_unbound.py's
    python-mode DNSBL-block writer shape (pfb_unbound.py:2617-2632) verbatim."""
    return f"DNSBL-python,{ts},{q_name},{q_ip},Python,DNSBL,pfB_TestList,NXDOMAIN,pfB_TestList,+,A\n"


# --------------------------------------------------------------------------- #
# Case 1: host-side CSV log (ip_blocklog) — age cutoff trims only expired lines
# --------------------------------------------------------------------------- #

# issue #1769: the deferred-maintenance marker pfblockerng_tick() emits via
# pfb_syslog_emit() (B3/B4: the openlog('pfblockerng') path is the only one that
# reaches this file) when the pfb_update_pass_running() half of its gate closes
# -- deliberately NOT $pfb['log'], which would grow the very file whose trim is
# being deferred.
_DEFERRED_LOG = "/var/log/pfblockerng_syslog.log"
_DEFERRED_MARKER = "log maintenance deferred (an update pass is running)"


def test_age_cutoff_trims_expired_lines_host_path_ip_blocklog(deployed_vm: SmokeVM) -> None:
    """Scenario 1 — host-path age cutoff: expired lines dropped, current lines kept, inode stable.

    Given:
      - ``ip_blocklog`` seeded with 2 lines older than a 7-day cutoff and 2 lines newer.
      - ``log_max_days_ip_blocklog`` = 7.
      - Inode captured before the cron runs.

    When: the (idle) tick runs (``pfblockerng.php tick`` -> ``pfblockerng_tick()`` ->
          ``pfb_log_mgmt()``'s age-cutoff pass).

    Then:
      - The 2 expired lines are GONE; the 2 current lines remain, in order.
      - Inode is UNCHANGED (in-place truncation preserved it, per §2.3 item 1).
    """
    vm = deployed_vm
    expired = _ip_blocklog_line(_ts(10), "192.0.2.1") + _ip_blocklog_line(_ts(8), "192.0.2.2")
    kept = _ip_blocklog_line(_ts(3), "192.0.2.3") + _ip_blocklog_line(_ts(1), "192.0.2.4")
    seed = expired + kept

    try:
        # --- Given ---
        _set_log_max_days(vm, {"ip_blocklog": str(_CUTOFF_DAYS)})
        _seed_log(vm, LOG_IP_BLOCKLOG, seed)

        # --- Before ---
        content_before = _read_file(vm, LOG_IP_BLOCKLOG)
        assert content_before == seed, f"BEFORE: seed did not land verbatim, got {content_before!r}"
        inode_before = _get_inode(vm, LOG_IP_BLOCKLOG)
        assert inode_before, "BEFORE: could not read ip_blocklog inode — file may not exist"

        # --- When ---
        # issue #1769: capture the deferred-maintenance marker count BEFORE this
        # maintenance-sensitive tick (_tick() synchronizes on the real idle state
        # first) so a failure can tell a NEW deferral (this tick's own gate closed)
        # apart from a stale line an earlier tick left behind -- a raw substring/tail
        # read can't make that distinction (see the failure branch below).
        deferred_before = h.count_log_marker(vm, _DEFERRED_LOG, _DEFERRED_MARKER)
        _tick(vm)

        # --- Then ---
        content_after = _read_file(vm, LOG_IP_BLOCKLOG)
        if content_after != kept:
            # issue #1769: self-diagnosing failure -- if the log-maintenance gate was
            # closed by a running update pass, the product now says so; a NEW-since-
            # baseline count (not a raw substring on a truncated tail, which
            # false-positives on a stale line and false-negatives once enough log has
            # accumulated since) tells whether THIS tick's own gate closed.
            deferred_after = h.count_log_marker(vm, _DEFERRED_LOG, _DEFERRED_MARKER)
            deferred_seen = deferred_after > deferred_before
        else:
            deferred_seen = False
        assert content_after == kept, (
            f"AFTER: ip_blocklog should hold exactly the 2 non-expired lines.\n"
            f"  expected: {kept!r}\n  got: {content_after!r}\n"
            f"  NEW '{_DEFERRED_MARKER}' line in {_DEFERRED_LOG} since this tick: {deferred_seen} "
            "(TRUE would mean an update pass held the gate closed despite the idle wait -- issue #1769)"
        )
        inode_after = _get_inode(vm, LOG_IP_BLOCKLOG)
        assert inode_after == inode_before, (
            f"AFTER: ip_blocklog inode changed — file was recreated instead of truncated in place "
            f"(before={inode_before!r}, after={inode_after!r})"
        )
    finally:
        _rm_log(vm, LOG_IP_BLOCKLOG)


# --------------------------------------------------------------------------- #
# Case 2: chrooted python-side CSV log (dnslog) — age cutoff + unbound ownership
# --------------------------------------------------------------------------- #


def test_age_cutoff_trims_expired_lines_chrooted_dnslog_preserves_ownership(
    deployed_vm: SmokeVM,
) -> None:
    """Scenario 2 — chrooted dnslog age cutoff: same trim, PLUS inode + unbound ownership held.

    pfBlockerNG's dnslog (dnsbl.log) is written by the Unbound Python module, which runs
    chrooted at /var/unbound. pfb_log_mgmt() resolves the chrooted path when it exists and
    re-chowns to unbound after every trim (inc:2907/:2936-2937).

    Given:
      - dnslog seeded with 2 expired + 2 current lines at the effective (chroot-aware) path.
      - File owned by unbound (mirrors production state).
      - ``log_max_days_dnslog`` = 7.
      - Inode + owner captured before the cron runs.

    When: the (idle) tick runs.

    Then:
      - The 2 expired lines are GONE; the 2 current lines remain, in order.
      - Inode is UNCHANGED.
      - File is still owned by ``unbound``.
    """
    vm = deployed_vm
    dnslog_path = _resolve_dnslog_path(vm)

    q_old1, q_old2 = h.unique_domain("pfb60-expired"), h.unique_domain("pfb60-expired")
    q_new1, q_new2 = h.unique_domain("pfb60-kept"), h.unique_domain("pfb60-kept")
    ts_old1, ts_old2 = _ts(10), _ts(8)
    ts_new1, ts_new2 = _ts(3), _ts(1)

    expired = _dnslog_line(ts_old1, q_old1, "192.0.2.10") + _dnslog_line(ts_old2, q_old2, "192.0.2.11")
    kept = _dnslog_line(ts_new1, q_new1, "192.0.2.12") + _dnslog_line(ts_new2, q_new2, "192.0.2.13")
    seed = expired + kept

    try:
        # --- Given ---
        _set_log_max_days(vm, {"dnslog": str(_CUTOFF_DAYS)})
        _seed_log(vm, dnslog_path, seed)
        vm.ssh("/usr/sbin/chown", "unbound:unbound", dnslog_path, timeout=30)

        # --- Before ---
        content_before = _read_file(vm, dnslog_path)
        assert content_before == seed, f"BEFORE: seed did not land verbatim, got {content_before!r}"
        inode_before = _get_inode(vm, dnslog_path)
        assert inode_before, f"BEFORE: could not read dnslog inode at {dnslog_path}"
        owner_before = _get_file_owner(vm, dnslog_path)
        assert owner_before == "unbound", f"BEFORE: dnslog owner should be 'unbound', got {owner_before!r}"

        # --- When ---
        _tick(vm)

        # --- Then ---
        content_after = _read_file(vm, dnslog_path)
        assert content_after == kept, (
            f"AFTER: dnslog should hold exactly the 2 non-expired lines.\n"
            f"  expected: {kept!r}\n  got: {content_after!r}"
        )
        inode_after = _get_inode(vm, dnslog_path)
        assert inode_after == inode_before, (
            f"AFTER: dnslog inode changed — file was recreated instead of truncated in place "
            f"(before={inode_before!r}, after={inode_after!r})"
        )
        owner_after = _get_file_owner(vm, dnslog_path)
        assert owner_after == "unbound", f"AFTER: dnslog owner should still be 'unbound', got {owner_after!r}"
    finally:
        _rm_log(vm, dnslog_path)


# --------------------------------------------------------------------------- #
# Case 3: control — log_max_days_<type>='0' (default) is a no-op for the age logic
# --------------------------------------------------------------------------- #


def test_log_max_days_zero_leaves_only_line_count_trim(deployed_vm: SmokeVM) -> None:
    """Scenario 3 — control: log_max_days_ip_blocklog='0' (default) never engages the age logic.

    Pairs with Scenario 1 (a set cutoff) to prove the OFF default is a true no-op, not just
    a large/inert cutoff (§2.3 item 2: "Default log_max_days_<type> = '0' ⇒ zero behaviour
    change to the existing line-count trim").

    Given:
      - ``ip_blocklog`` seeded with lines far older than any plausible cutoff (400/200 days).
      - ``log_max_days_ip_blocklog`` left at '0' (the autouse fixture's reset value).

    When: the (idle) tick runs.

    Then:
      - The file is BYTE-IDENTICAL before and after (well under the default 20000-line cap,
        so line-count trim is also a no-op) — proves the age-cutoff pass never engages when
        the config key is off, even for lines that would fail any age check.
      - Inode is UNCHANGED.
    """
    vm = deployed_vm
    seed = _ip_blocklog_line(_ts(400), "192.0.2.20") + _ip_blocklog_line(_ts(200), "192.0.2.21")

    try:
        # --- Given (log_max_days_ip_blocklog already '0' via the autouse fixture) ---
        _seed_log(vm, LOG_IP_BLOCKLOG, seed)

        # --- Before ---
        content_before = _read_file(vm, LOG_IP_BLOCKLOG)
        assert content_before == seed, f"BEFORE: seed did not land verbatim, got {content_before!r}"
        inode_before = _get_inode(vm, LOG_IP_BLOCKLOG)
        assert inode_before, "BEFORE: could not read ip_blocklog inode — file may not exist"

        # --- When ---
        _tick(vm)

        # --- Then ---
        content_after = _read_file(vm, LOG_IP_BLOCKLOG)
        assert content_after == content_before, (
            f"AFTER: log_max_days_ip_blocklog='0' should leave the log byte-identical (no age "
            f"trim engaged even for 400/200-day-old lines), but it changed: "
            f"before={content_before!r}, after={content_after!r}"
        )
        inode_after = _get_inode(vm, LOG_IP_BLOCKLOG)
        assert inode_after == inode_before, (
            f"AFTER: inode changed even though log_max_days='0' should have left the file untouched "
            f"(before={inode_before!r}, after={inode_after!r})"
        )
    finally:
        _rm_log(vm, LOG_IP_BLOCKLOG)
