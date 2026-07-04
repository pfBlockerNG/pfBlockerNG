"""ADR-30 — live-VM smoke: per-log scheduled reset (calendar-boundary truncation).

Proves the §2.2 contract on a real pfSense CE VM:

  1. Per-log boundary reset: a log with a stale marker entry is emptied on the
     next cron tick; inode preserved; a log left "off" is untouched; the marker
     entry now holds today's period.
  2. Same-period idempotency: a second cron tick in the same period is a no-op.
  3. Chrooted python log: dnslog (unbound-chrooted) is emptied, inode preserved,
     still owned by ``unbound``.
  4. All-off no-op: with every schedule "off", no log is emptied even with stale
     markers.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``);
without them all cases skip cleanly.  No live DNS or feed server is required:
this feature is purely log-file + marker-file I/O, not DNSBL.

Since PR #790 (issue #573 phase 2) ``pfb_log_mgmt()``/``pfb_log_reset()`` moved from the
tail of ``pfblockerng_sync_cron()`` into ``pfblockerng_tick()``, and now run only on an
IDLE tick (no update pass dispatched this tick or still running from an earlier one — see
``pfb_update_pass_running()`` in ``pfblockerng.inc``). This suite drives the ``tick`` verb
(not ``cron``); the ``deployed_vm`` fixture makes every tick idle-only (Disabled feed cron +
not-due dcc/bl) so the tick under test exercises exactly the ADR-30 reset/trim.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

# --------------------------------------------------------------------------- #
# Paths (mirroring pfblockerng.inc $pfb[] definitions)
# --------------------------------------------------------------------------- #

PFB_LOGDIR = "/var/log/pfblockerng"
PFB_DBDIR = "/var/db/pfblockerng"

# require_once target for the due-ledger API (pfSsh.php does not auto-load pfBlockerNG
# includes — mirrors test_smoke_tick._PFB_EXTRA).
_PFB_EXTRA_INC = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"

# Host-side (non-chrooted) log files
LOG_IP_BLOCKLOG = f"{PFB_LOGDIR}/ip_block.log"
LOG_IP_PERMITLOG = f"{PFB_LOGDIR}/ip_permit.log"

# DNS/python log — chrooted to /var/unbound on pfSense
# pfb_log_reset resolves it as /var/unbound/var/log/pfblockerng/dnsbl.log
# when the chroot dir exists, otherwise falls back to the host path.
LOG_DNSLOG_HOST = f"{PFB_LOGDIR}/dnsbl.log"
LOG_DNSLOG_CHROOT = f"/var/unbound{PFB_LOGDIR}/dnsbl.log"

# Marker file written by pfb_log_reset
LOG_ROTATE_MARKER = f"{PFB_DBDIR}/log_rotate.last"

# Config path for per-log schedule (under the General settings section)
CFG_GENERAL = "installedpackages/pfblockerng/config/0"

# --------------------------------------------------------------------------- #
# Module-scoped fixture: deploy once, then run all rotation cases
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for this module and set up the base state.

    Log rotation does not require DNSBL to be active — it runs from ``pfblockerng_tick()``
    (PR #790 re-homed ``pfb_log_mgmt()``/``pfb_log_reset()`` there from the tail of
    ``pfblockerng_sync_cron()``), driven here via ``helpers.reload(vm, 'tick')``. The tick
    only runs log maintenance on an IDLE tick — no update pass dispatched this tick or still
    running from an earlier one (``pfb_update_pass_running()`` in ``pfblockerng.inc``) — so
    this fixture makes every tick in this module idle-only: ``pfb_interval='Disabled'``
    (the feed cron never dispatches) plus ``dcc``/``bl`` seeded not-due. That exercises
    exactly the ADR-30 reset/trim LOGIC under test, and also live-validates the issue #573
    fix itself (log maintenance surviving a Disabled Update Frequency). We still need
    pfBlockerNG installed and ``enable_cb=on`` so the tick's function bodies execute. The
    DNSBL VIP and feed infrastructure are NOT needed for these cases.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    # Enable pfBlockerNG so the tick body runs (enable_cb=on required by
    # inc:793; the IP/DNSBL subsystems can stay disabled for this test).
    _set_enable_cb(smoke_vm)
    # Make every tick in this module idle-only (see docstring above): Disabled feed cron +
    # not-due dcc/bl, so pfb_update_pass_running()'s "nothing dispatched" gate stays open and
    # pfb_log_mgmt()/pfb_log_reset() run on every 'tick' call below.
    _set_pfb_interval_disabled(smoke_vm)
    _seed_future_ledger_entry(smoke_vm, "dcc")
    _seed_future_ledger_entry(smoke_vm, "bl")
    # Ensure the log dir exists on the guest (normally created by a first full
    # reload; create it explicitly so seed writes don't fail before that).
    smoke_vm.ssh("/bin/mkdir", "-p", PFB_LOGDIR, timeout=30)
    smoke_vm.ssh("/bin/mkdir", "-p", PFB_DBDIR, timeout=30)
    yield smoke_vm


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


def _set_pfb_interval_disabled(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Set pfb_interval='Disabled' so the tick's feed-cron branch never dispatches.

    Part of making every tick in this module idle-only (see the ``deployed_vm`` fixture
    docstring) — this is also the exact setting issue #573 fixed (log maintenance used to
    silently stop with a Disabled Update Frequency), so this module doubles as its live
    validation.
    """
    snippet = (
        f"$g = config_get_path({h._php_str(CFG_GENERAL)}, array());\n"
        "$g['pfb_interval'] = 'Disabled';\n"
        f"config_set_path({h._php_str(CFG_GENERAL)}, $g);\n"
        "write_config('pfBlockerNG smoke: pfb_interval Disabled');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_set_pfb_interval_disabled failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _seed_future_ledger_entry(vm: SmokeVM, job_key: str, *, timeout: float = 60.0) -> None:
    """Seed a due-ledger entry for ``job_key`` whose next_due is far in the future.

    Drives the box via PHP (CLAUDE.md hard constraint: no appliance python) —
    ``pfb_due_ledger_write_entry()`` is the package's own ledger writer (mirrors
    ``test_smoke_tick._write_ledger_entry``). Keeps 'dcc'/'bl' from dispatching on the
    'tick' verb so every tick in this module is maintenance-only.
    """
    snippet = (
        f"require_once('{_PFB_EXTRA_INC}');"
        f"pfb_due_ledger_write_entry('{job_key}', array("
        "'last_run' => time(), 'next_due' => time() + 86400, 'jitter' => 0"
        f"), {h._php_str(PFB_DBDIR)});"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_seed_future_ledger_entry({job_key!r}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _set_log_rotate_schedule(
    vm: SmokeVM,
    schedules: dict[str, str],
    *,
    timeout: float = 60.0,
) -> None:
    """Set one or more log_rotate_<type> schedules in config (off|daily|weekly|monthly).

    ``schedules`` maps log type (e.g. ``'ip_blocklog'``) to value
    (``'daily'`` / ``'weekly'`` / ``'monthly'`` / ``'off'``).
    Written directly into the General settings config section so PfbConfig::read
    picks them up on the next cron tick.
    """
    sets = ""
    for log_type, value in schedules.items():
        key = f"log_rotate_{log_type}"
        sets += f"$g[{h._php_str(key)}] = {h._php_str(value)};\n"
    snippet = (
        f"$g = config_get_path({h._php_str(CFG_GENERAL)}, array());\n"
        f"{sets}"
        f"config_set_path({h._php_str(CFG_GENERAL)}, $g);\n"
        "write_config('pfBlockerNG smoke: set log_rotate schedules');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_set_log_rotate_schedule failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _set_log_reset_keep(
    vm: SmokeVM,
    keep_counts: dict[str, int],
    *,
    timeout: float = 60.0,
) -> None:
    """Set one or more log_reset_keep_<type> retention counts in config.

    ``keep_counts`` maps log type (e.g. ``'ip_blocklog'``) to the number of
    lines to retain on a scheduled reset (0 = clear fully, K > 0 = keep last K).
    Written directly into the General settings config section so PfbConfig::read
    picks them up on the next cron tick, mirroring ``_set_log_rotate_schedule``.
    """
    sets = ""
    for log_type, count in keep_counts.items():
        key = f"log_reset_keep_{log_type}"
        sets += f"$g[{h._php_str(key)}] = {h._php_str(str(count))};\n"
    snippet = (
        f"$g = config_get_path({h._php_str(CFG_GENERAL)}, array());\n"
        f"{sets}"
        f"config_set_path({h._php_str(CFG_GENERAL)}, $g);\n"
        "write_config('pfBlockerNG smoke: set log_reset_keep counts');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_log_reset_keep failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _seed_log(vm: SmokeVM, log_path: str, content: str, *, timeout: float = 30.0) -> None:
    """Write ``content`` into ``log_path`` via ``tee`` (replaces the file)."""
    result = h.subprocess.run(
        vm.ssh_argv("tee", log_path),
        input=content,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"_seed_log({log_path}) failed: rc={result.returncode} {result.stderr!r}")


def _write_marker(vm: SmokeVM, entries: dict[str, str], *, timeout: float = 30.0) -> None:
    """Write the log_rotate.last marker file with the given type->period-key entries."""
    lines = "".join(f"{t}={k}\n" for t, k in sorted(entries.items()))
    result = h.subprocess.run(
        vm.ssh_argv("tee", LOG_ROTATE_MARKER),
        input=lines,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"_write_marker failed: rc={result.returncode} {result.stderr!r}")


def _read_marker(vm: SmokeVM, *, timeout: float = 30.0) -> dict[str, str]:
    """Read and parse the log_rotate.last marker file into a dict."""
    result = vm.ssh("cat", LOG_ROTATE_MARKER, timeout=timeout)
    if result.returncode != 0:
        return {}
    entries: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        t, _, k = line.partition("=")
        entries[t.strip()] = k
    return entries


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


def _rm_marker(vm: SmokeVM, *, timeout: float = 30.0) -> None:
    """Remove the log_rotate.last marker file so the next cron sees 'never reset'."""
    vm.ssh("/bin/rm", "-f", LOG_ROTATE_MARKER, timeout=timeout)


def _rm_log(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> None:
    """Remove a log file (teardown / between-case cleanup)."""
    vm.ssh("/bin/rm", "-f", path, timeout=timeout)


def _stale_daily_key() -> str:
    """Return a 'daily' period key for yesterday (always stale for a daily schedule)."""
    import datetime

    yesterday = datetime.date.today() - datetime.timedelta(days=1)
    return yesterday.strftime("%Y-%m-%d")


def _current_daily_key() -> str:
    """Return a 'daily' period key for today (current period)."""
    import datetime

    return datetime.date.today().strftime("%Y-%m-%d")


# Inert seed content for log files.
# Uses only RFC 5737 IPs (192.0.2.x TEST-NET-1) and benign labels — never
# HSTS-preload names, RFC 6761 TLDs, or real IP ranges.
_SEED_IP_BLOCKLOG = (
    "2026-01-15 01:00:00 pfblockerng 192.0.2.1 BLOCK pfB_TestList\n"
    "2026-01-15 01:01:00 pfblockerng 192.0.2.2 BLOCK pfB_TestList\n"
)
_SEED_IP_PERMITLOG = "2026-01-15 02:00:00 pfblockerng 192.0.2.3 PERMIT pfB_PermitList\n"
_SEED_DNSLOG = (
    "2026-01-15 03:00:00 DNSBL pfb-smoke-inert-label-1 192.0.2.10 1\n"
    "2026-01-15 03:01:00 DNSBL pfb-smoke-inert-label-2 192.0.2.11 1\n"
)

# 6-line seeds for retention-buffer tests (N=6, K=3: keep the last 3 lines).
# Lines are numbered so the tail assertion can be exact and unambiguous.
_SEED_IP_BLOCKLOG_6 = (
    "2026-01-15 01:00:00 pfblockerng 192.0.2.1 BLOCK pfB_TestList line-1\n"
    "2026-01-15 01:01:00 pfblockerng 192.0.2.2 BLOCK pfB_TestList line-2\n"
    "2026-01-15 01:02:00 pfblockerng 192.0.2.3 BLOCK pfB_TestList line-3\n"
    "2026-01-15 01:03:00 pfblockerng 192.0.2.4 BLOCK pfB_TestList line-4\n"
    "2026-01-15 01:04:00 pfblockerng 192.0.2.5 BLOCK pfB_TestList line-5\n"
    "2026-01-15 01:05:00 pfblockerng 192.0.2.6 BLOCK pfB_TestList line-6\n"
)
# Expected tail after keep K=3: the last 3 lines of _SEED_IP_BLOCKLOG_6.
_SEED_IP_BLOCKLOG_6_TAIL3 = (
    "2026-01-15 01:03:00 pfblockerng 192.0.2.4 BLOCK pfB_TestList line-4\n"
    "2026-01-15 01:04:00 pfblockerng 192.0.2.5 BLOCK pfB_TestList line-5\n"
    "2026-01-15 01:05:00 pfblockerng 192.0.2.6 BLOCK pfB_TestList line-6\n"
)

_SEED_DNSLOG_6 = (
    "2026-01-15 03:00:00 DNSBL pfb-smoke-inert-label-1 192.0.2.10 1\n"
    "2026-01-15 03:01:00 DNSBL pfb-smoke-inert-label-2 192.0.2.11 1\n"
    "2026-01-15 03:02:00 DNSBL pfb-smoke-inert-label-3 192.0.2.12 1\n"
    "2026-01-15 03:03:00 DNSBL pfb-smoke-inert-label-4 192.0.2.13 1\n"
    "2026-01-15 03:04:00 DNSBL pfb-smoke-inert-label-5 192.0.2.14 1\n"
    "2026-01-15 03:05:00 DNSBL pfb-smoke-inert-label-6 192.0.2.15 1\n"
)
# Expected tail after keep K=3: the last 3 lines of _SEED_DNSLOG_6.
_SEED_DNSLOG_6_TAIL3 = (
    "2026-01-15 03:03:00 DNSBL pfb-smoke-inert-label-4 192.0.2.13 1\n"
    "2026-01-15 03:04:00 DNSBL pfb-smoke-inert-label-5 192.0.2.14 1\n"
    "2026-01-15 03:05:00 DNSBL pfb-smoke-inert-label-6 192.0.2.15 1\n"
)


# --------------------------------------------------------------------------- #
# Case 1: per-log boundary reset + inode preserved + per-log independence
# --------------------------------------------------------------------------- #


def test_boundary_reset_inode_preserved_and_per_log_independence(
    deployed_vm: SmokeVM,
) -> None:
    """Scenario 1 — boundary reset: stale marker triggers reset; off log untouched.

    Given:
      - ``ip_blocklog`` schedule = daily, marker entry = yesterday (stale).
      - ``ip_permitlog`` schedule = off, marker absent.
      - Both logs seeded with inert content.
      - Inode of ``ip_blocklog`` captured before the cron runs.

    When: the tick entry runs (``pfblockerng.php tick`` -> ``pfblockerng_tick()``), idle (see the
          ``deployed_vm`` fixture -- Disabled feed cron + not-due dcc/bl).

    Then:
      - ``ip_blocklog`` is EMPTY (reset occurred).
      - ``ip_blocklog`` inode is UNCHANGED (in-place truncation preserved it).
      - ``ip_permitlog`` is UNTOUCHED (its content is unchanged).
      - The marker entry for ``ip_blocklog`` now holds today's period key.
      - No marker entry for ``ip_permitlog`` (schedule was off; no write).
    """
    vm = deployed_vm

    # --- Given ---
    _set_log_rotate_schedule(vm, {"ip_blocklog": "daily", "ip_permitlog": "off"})
    _seed_log(vm, LOG_IP_BLOCKLOG, _SEED_IP_BLOCKLOG)
    _seed_log(vm, LOG_IP_PERMITLOG, _SEED_IP_PERMITLOG)
    _write_marker(vm, {"ip_blocklog": _stale_daily_key()})

    # Capture before-state: content non-empty and inode stable.
    content_before_block = _read_file(vm, LOG_IP_BLOCKLOG)
    assert content_before_block.strip(), "BEFORE: ip_blocklog should be non-empty after seed — test setup failed"
    inode_before = _get_inode(vm, LOG_IP_BLOCKLOG)
    assert inode_before, "BEFORE: could not read ip_blocklog inode — file may not exist"

    content_before_permit = _read_file(vm, LOG_IP_PERMITLOG)
    assert content_before_permit.strip(), "BEFORE: ip_permitlog should be non-empty after seed — test setup failed"

    marker_before = _read_marker(vm)
    assert marker_before.get("ip_blocklog") == _stale_daily_key(), (
        f"BEFORE: marker ip_blocklog should be yesterday's key {_stale_daily_key()!r}, "
        f"got {marker_before.get('ip_blocklog')!r}"
    )
    assert "ip_permitlog" not in marker_before, "BEFORE: marker should have no ip_permitlog entry (schedule is off)"

    # --- When ---
    # Trigger the (idle) tick; pfb_log_reset() now runs inside pfblockerng_tick().
    h.reload(vm, "tick")

    # --- Then ---
    content_after_block = _read_file(vm, LOG_IP_BLOCKLOG)
    assert not content_after_block.strip(), (
        f"AFTER: ip_blocklog should be EMPTY after boundary reset, got {content_after_block!r}"
    )

    inode_after = _get_inode(vm, LOG_IP_BLOCKLOG)
    assert inode_after == inode_before, (
        f"AFTER: ip_blocklog inode changed — file was recreated instead of truncated "
        f"in place (before={inode_before!r}, after={inode_after!r})"
    )

    content_after_permit = _read_file(vm, LOG_IP_PERMITLOG)
    assert content_after_permit == content_before_permit, (
        f"AFTER: ip_permitlog should be UNTOUCHED (schedule=off), "
        f"but content changed from {content_before_permit!r} to {content_after_permit!r}"
    )

    marker_after = _read_marker(vm)
    expected_key = _current_daily_key()
    assert marker_after.get("ip_blocklog") == expected_key, (
        f"AFTER: marker ip_blocklog should be today's key {expected_key!r}, got {marker_after.get('ip_blocklog')!r}"
    )
    assert "ip_permitlog" not in marker_after, "AFTER: marker should still have no ip_permitlog entry (schedule is off)"

    # --- Cleanup ---
    _set_log_rotate_schedule(vm, {"ip_blocklog": "off", "ip_permitlog": "off"})
    _rm_marker(vm)
    _rm_log(vm, LOG_IP_BLOCKLOG)
    _rm_log(vm, LOG_IP_PERMITLOG)


# --------------------------------------------------------------------------- #
# Case 2: same-period idempotency (no second reset in the same period)
# --------------------------------------------------------------------------- #


def test_same_period_is_idempotent(deployed_vm: SmokeVM) -> None:
    """Scenario 2 — idempotency: a second cron tick in the same period is a no-op.

    Given:
      - ``ip_blocklog`` schedule = daily, marker entry = today's key (current period).
      - Log seeded AFTER the marker write (simulating content that arrived after a reset).

    When: the (idle) tick entry runs.

    Then:
      - ``ip_blocklog`` is NOT emptied (still contains the seed content).
      - The marker entry still holds today's period key.
    """
    vm = deployed_vm

    # --- Given ---
    _set_log_rotate_schedule(vm, {"ip_blocklog": "daily"})
    # Marker already at today's key — the period has NOT rolled over.
    _write_marker(vm, {"ip_blocklog": _current_daily_key()})
    _seed_log(vm, LOG_IP_BLOCKLOG, _SEED_IP_BLOCKLOG)

    content_before = _read_file(vm, LOG_IP_BLOCKLOG)
    assert content_before.strip(), "BEFORE: ip_blocklog should be non-empty after seed"

    marker_before = _read_marker(vm)
    assert marker_before.get("ip_blocklog") == _current_daily_key(), (
        f"BEFORE: marker should be today's key {_current_daily_key()!r}"
    )

    # --- When ---
    h.reload(vm, "tick")

    # --- Then ---
    content_after = _read_file(vm, LOG_IP_BLOCKLOG)
    assert content_after.strip(), (
        "AFTER: ip_blocklog should NOT be emptied (same period, idempotent no-op), "
        "got empty content — second reset occurred unexpectedly"
    )
    # Content should be unchanged (the tick only called pfb_log_mgmt line-cap, not reset).
    # The line-cap default (20000 lines) won't trim our 2-line file.
    assert content_after == content_before, (
        f"AFTER: ip_blocklog content changed unexpectedly — expected no-op: "
        f"before={content_before!r}, after={content_after!r}"
    )

    marker_after = _read_marker(vm)
    assert marker_after.get("ip_blocklog") == _current_daily_key(), (
        f"AFTER: marker ip_blocklog should still be today's key {_current_daily_key()!r}, "
        f"got {marker_after.get('ip_blocklog')!r}"
    )

    # --- Cleanup ---
    _set_log_rotate_schedule(vm, {"ip_blocklog": "off"})
    _rm_marker(vm)
    _rm_log(vm, LOG_IP_BLOCKLOG)


# --------------------------------------------------------------------------- #
# Case 3: chrooted python log (dnslog) — emptied, inode preserved, owned by unbound
# --------------------------------------------------------------------------- #


def test_chrooted_python_log_reset_preserves_inode_and_ownership(
    deployed_vm: SmokeVM,
) -> None:
    """Scenario 3 — chrooted python log: dnslog reset preserves inode + unbound ownership.

    pfBlockerNG's dnslog (dnsbl.log) is written by the Unbound Python module,
    which runs chrooted at /var/unbound.  pfb_log_reset uses the same chroot-path
    resolution as pfb_log_mgmt: when /var/unbound/var/log/pfblockerng exists, the
    effective path is /var/unbound/var/log/pfblockerng/dnsbl.log; otherwise it
    falls back to the host path.  Either way pfb_log_reset re-chowns the file to
    unbound after truncation.

    Given:
      - dnslog schedule = daily, marker entry = yesterday (stale).
      - dnslog seeded with inert content at whatever path pfb_log_reset will use.
      - File owned by unbound (to mirror the production state).
      - Inode captured before the cron runs.

    When: the (idle) tick entry runs.

    Then:
      - dnslog is EMPTY.
      - dnslog inode UNCHANGED.
      - dnslog is still owned by unbound.
      - The marker entry for dnslog holds today's period key.
    """
    vm = deployed_vm

    # Determine the effective log path: use the chroot path if the chroot dir exists,
    # otherwise the host path (mirrors pfb_log_reset logic).
    chroot_dir_result = vm.ssh("test", "-d", "/var/unbound/var/log/pfblockerng", timeout=10)
    if chroot_dir_result.returncode == 0:
        dnslog_path = LOG_DNSLOG_CHROOT
    else:
        # Create the chroot log dir so pfb_log_reset uses the chrooted path on a
        # post-deploy VM (a full pfBlockerNG reload creates it; we seed it here).
        mk = vm.ssh("/bin/mkdir", "-p", "/var/unbound/var/log/pfblockerng", timeout=30)
        if mk.returncode == 0:
            dnslog_path = LOG_DNSLOG_CHROOT
        else:
            dnslog_path = LOG_DNSLOG_HOST

    # --- Given ---
    _set_log_rotate_schedule(vm, {"dnslog": "daily"})
    _seed_log(vm, dnslog_path, _SEED_DNSLOG)
    # Set owner to unbound (mirrors production state after pfb_log_mgmt)
    vm.ssh("/usr/sbin/chown", "unbound:unbound", dnslog_path, timeout=30)

    _write_marker(vm, {"dnslog": _stale_daily_key()})

    content_before = _read_file(vm, dnslog_path)
    assert content_before.strip(), "BEFORE: dnslog should be non-empty after seed"

    inode_before = _get_inode(vm, dnslog_path)
    assert inode_before, f"BEFORE: could not read dnslog inode at {dnslog_path}"

    owner_before = _get_file_owner(vm, dnslog_path)
    assert owner_before == "unbound", f"BEFORE: dnslog owner should be 'unbound', got {owner_before!r}"

    marker_before = _read_marker(vm)
    assert marker_before.get("dnslog") == _stale_daily_key(), (
        f"BEFORE: marker dnslog should be yesterday's key {_stale_daily_key()!r}"
    )

    # --- When ---
    h.reload(vm, "tick")

    # --- Then ---
    content_after = _read_file(vm, dnslog_path)
    assert not content_after.strip(), f"AFTER: dnslog should be EMPTY after reset, got {content_after!r}"

    inode_after = _get_inode(vm, dnslog_path)
    assert inode_after == inode_before, (
        f"AFTER: dnslog inode changed — file was recreated instead of truncated "
        f"in place (before={inode_before!r}, after={inode_after!r})"
    )

    owner_after = _get_file_owner(vm, dnslog_path)
    assert owner_after == "unbound", f"AFTER: dnslog owner should still be 'unbound' after reset, got {owner_after!r}"

    marker_after = _read_marker(vm)
    expected_key = _current_daily_key()
    assert marker_after.get("dnslog") == expected_key, (
        f"AFTER: marker dnslog should be today's key {expected_key!r}, got {marker_after.get('dnslog')!r}"
    )

    # --- Cleanup ---
    _set_log_rotate_schedule(vm, {"dnslog": "off"})
    _rm_marker(vm)
    _rm_log(vm, dnslog_path)


# --------------------------------------------------------------------------- #
# Case 4: all schedules off — no log emptied even with stale markers
# --------------------------------------------------------------------------- #


def test_all_off_no_log_emptied(deployed_vm: SmokeVM) -> None:
    """Scenario 4 — all-off: stale markers with every schedule 'off' ⇒ no reset.

    Given:
      - ALL log_rotate_<type> schedules set to 'off'.
      - ip_blocklog and ip_permitlog seeded with inert content.
      - Marker entries for both set to yesterday (would trigger a reset if enabled).

    When: the (idle) tick entry runs.

    Then:
      - ip_blocklog is UNTOUCHED (content identical to before).
      - ip_permitlog is UNTOUCHED (content identical to before).
      - Marker file is UNCHANGED (no reset happened, nothing updated).
    """
    vm = deployed_vm

    # --- Given: all log_rotate schedules off ---
    all_log_types = [
        "log",
        "errlog",
        "extraslog",
        "ip_blocklog",
        "ip_permitlog",
        "ip_matchlog",
        "dnslog",
        "dnsbl_parse_err",
        "dnsreplylog",
        "unilog",
    ]
    _set_log_rotate_schedule(vm, {t: "off" for t in all_log_types})

    _seed_log(vm, LOG_IP_BLOCKLOG, _SEED_IP_BLOCKLOG)
    _seed_log(vm, LOG_IP_PERMITLOG, _SEED_IP_PERMITLOG)

    # Stale markers for both — would cause resets if the schedules were enabled.
    stale_key = _stale_daily_key()
    _write_marker(vm, {"ip_blocklog": stale_key, "ip_permitlog": stale_key})

    content_before_block = _read_file(vm, LOG_IP_BLOCKLOG)
    assert content_before_block.strip(), "BEFORE: ip_blocklog should be non-empty"

    content_before_permit = _read_file(vm, LOG_IP_PERMITLOG)
    assert content_before_permit.strip(), "BEFORE: ip_permitlog should be non-empty"

    marker_before = _read_marker(vm)
    assert marker_before.get("ip_blocklog") == stale_key, f"BEFORE: marker ip_blocklog should be {stale_key!r}"
    assert marker_before.get("ip_permitlog") == stale_key, f"BEFORE: marker ip_permitlog should be {stale_key!r}"

    # --- When ---
    h.reload(vm, "tick")

    # --- Then ---
    content_after_block = _read_file(vm, LOG_IP_BLOCKLOG)
    assert content_after_block == content_before_block, (
        f"AFTER: ip_blocklog should be UNTOUCHED (all schedules off), "
        f"but content changed: before={content_before_block!r}, after={content_after_block!r}"
    )

    content_after_permit = _read_file(vm, LOG_IP_PERMITLOG)
    assert content_after_permit == content_before_permit, (
        f"AFTER: ip_permitlog should be UNTOUCHED (all schedules off), "
        f"but content changed: before={content_before_permit!r}, after={content_after_permit!r}"
    )

    # Marker must be UNCHANGED — pfb_log_reset only writes when $changed is TRUE.
    marker_after = _read_marker(vm)
    assert marker_after.get("ip_blocklog") == stale_key, (
        f"AFTER: marker ip_blocklog should still be stale {stale_key!r} (no reset), "
        f"got {marker_after.get('ip_blocklog')!r}"
    )
    assert marker_after.get("ip_permitlog") == stale_key, (
        f"AFTER: marker ip_permitlog should still be stale {stale_key!r} (no reset), "
        f"got {marker_after.get('ip_permitlog')!r}"
    )

    # --- Cleanup ---
    _rm_marker(vm)
    _rm_log(vm, LOG_IP_BLOCKLOG)
    _rm_log(vm, LOG_IP_PERMITLOG)


# --------------------------------------------------------------------------- #
# Case 5: retention buffer (K > 0) — plain log keeps the last K lines
# --------------------------------------------------------------------------- #


def test_retention_buffer_plain_log_keeps_last_k_lines(deployed_vm: SmokeVM) -> None:
    """Scenario 5 — retention buffer (plain log): keep last K=3 lines on scheduled reset.

    Pairs with Scenario 1 (K=0, full clear) to prove log_reset_keep_<type> is a
    real branch on a real VM: when K > 0, pfb_log_reset() tails the last K lines
    into the same inode instead of blanking it.

    Given:
      - ``ip_blocklog`` schedule = daily, log_reset_keep_ip_blocklog = 3.
      - Log seeded with 6 distinct inert lines (N=6 > K=3).
      - Marker entry for ip_blocklog = yesterday (stale, boundary triggers reset).
      - Inode captured before the cron runs.
      - Content asserted non-empty (N lines) BEFORE cron.

    When: the tick entry runs (``pfblockerng.php tick`` → ``pfblockerng_tick()``), idle.

    Then:
      - ``ip_blocklog`` holds EXACTLY the last 3 seeded lines (lines 4–6), in order.
      - The inode is UNCHANGED (the keep is done in-place via tail→temp→cat).
      - The marker entry for ip_blocklog now holds today's daily key.
    """
    vm = deployed_vm

    try:
        # --- Given ---
        _set_log_rotate_schedule(vm, {"ip_blocklog": "daily"})
        _set_log_reset_keep(vm, {"ip_blocklog": 3})
        _seed_log(vm, LOG_IP_BLOCKLOG, _SEED_IP_BLOCKLOG_6)
        _write_marker(vm, {"ip_blocklog": _stale_daily_key()})

        content_before = _read_file(vm, LOG_IP_BLOCKLOG)
        assert content_before.strip(), "BEFORE: ip_blocklog should be non-empty after 6-line seed — test setup failed"
        assert content_before.count("\n") >= 6, (  # noqa: PLR2004
            f"BEFORE: ip_blocklog should have 6 lines, got: {content_before!r}"
        )

        inode_before = _get_inode(vm, LOG_IP_BLOCKLOG)
        assert inode_before, "BEFORE: could not read ip_blocklog inode — file may not exist"

        marker_before = _read_marker(vm)
        assert marker_before.get("ip_blocklog") == _stale_daily_key(), (
            f"BEFORE: marker ip_blocklog should be yesterday's key {_stale_daily_key()!r}, "
            f"got {marker_before.get('ip_blocklog')!r}"
        )

        # --- When ---
        h.reload(vm, "tick")

        # --- Then ---
        content_after = _read_file(vm, LOG_IP_BLOCKLOG)
        assert content_after == _SEED_IP_BLOCKLOG_6_TAIL3, (
            f"AFTER: ip_blocklog should hold exactly the last 3 seeded lines.\n"
            f"  expected: {_SEED_IP_BLOCKLOG_6_TAIL3!r}\n"
            f"  got:      {content_after!r}"
        )

        inode_after = _get_inode(vm, LOG_IP_BLOCKLOG)
        assert inode_after == inode_before, (
            f"AFTER: ip_blocklog inode changed — file was recreated instead of kept in-place "
            f"(before={inode_before!r}, after={inode_after!r})"
        )

        marker_after = _read_marker(vm)
        expected_key = _current_daily_key()
        assert marker_after.get("ip_blocklog") == expected_key, (
            f"AFTER: marker ip_blocklog should be today's key {expected_key!r}, got {marker_after.get('ip_blocklog')!r}"
        )
    finally:
        # --- Cleanup (always runs, even on assertion failure — shared module VM) ---
        _set_log_rotate_schedule(vm, {"ip_blocklog": "off"})
        _set_log_reset_keep(vm, {"ip_blocklog": 0})
        _rm_marker(vm)
        _rm_log(vm, LOG_IP_BLOCKLOG)


# --------------------------------------------------------------------------- #
# Case 6: retention buffer (K > 0) — chrooted dns log keeps last K lines + unbound ownership
# --------------------------------------------------------------------------- #


def test_retention_buffer_chrooted_dns_log_keeps_last_k_lines_and_ownership(
    deployed_vm: SmokeVM,
) -> None:
    """Scenario 6 — retention buffer (chrooted dns log): keep last K=3 lines + unbound ownership.

    Pairs with Scenario 3 (K=0, full clear for dnslog) to prove the chroot path +
    ``chown unbound`` in pfb_log_reset() also fires for the K > 0 branch.  The
    chroot-path resolution mirrors test_chrooted_python_log_reset_preserves_inode_and_ownership:
    use /var/unbound/var/log/pfblockerng/dnsbl.log when the chroot dir exists.

    Given:
      - dnslog schedule = daily, log_reset_keep_dnslog = 3.
      - dnslog seeded with 6 distinct inert lines (N=6 > K=3) at the effective path.
      - File owned by unbound (mirrors production state after pfb_log_mgmt).
      - Marker entry for dnslog = yesterday (stale).
      - Inode captured before the cron runs.
      - Content asserted non-empty (N lines) and owner = unbound BEFORE cron.

    When: the (idle) tick entry runs.

    Then:
      - dnslog holds EXACTLY the last 3 seeded lines (lines 4–6), in order.
      - dnslog inode is UNCHANGED (in-place keep preserved it).
      - dnslog is still owned by ``unbound`` (pfb_log_reset re-chowns after the keep).
      - The marker entry for dnslog holds today's daily key.
    """
    vm = deployed_vm

    # Determine the effective log path (mirrors Scenario 3 resolution).
    chroot_dir_result = vm.ssh("test", "-d", "/var/unbound/var/log/pfblockerng", timeout=10)
    if chroot_dir_result.returncode == 0:
        dnslog_path = LOG_DNSLOG_CHROOT
    else:
        mk = vm.ssh("/bin/mkdir", "-p", "/var/unbound/var/log/pfblockerng", timeout=30)
        if mk.returncode == 0:
            dnslog_path = LOG_DNSLOG_CHROOT
        else:
            dnslog_path = LOG_DNSLOG_HOST

    try:
        # --- Given ---
        _set_log_rotate_schedule(vm, {"dnslog": "daily"})
        _set_log_reset_keep(vm, {"dnslog": 3})
        _seed_log(vm, dnslog_path, _SEED_DNSLOG_6)
        vm.ssh("/usr/sbin/chown", "unbound:unbound", dnslog_path, timeout=30)
        _write_marker(vm, {"dnslog": _stale_daily_key()})

        content_before = _read_file(vm, dnslog_path)
        assert content_before.strip(), "BEFORE: dnslog should be non-empty after 6-line seed — test setup failed"
        assert content_before.count("\n") >= 6, (  # noqa: PLR2004
            f"BEFORE: dnslog should have 6 lines, got: {content_before!r}"
        )

        inode_before = _get_inode(vm, dnslog_path)
        assert inode_before, f"BEFORE: could not read dnslog inode at {dnslog_path}"

        owner_before = _get_file_owner(vm, dnslog_path)
        assert owner_before == "unbound", f"BEFORE: dnslog owner should be 'unbound', got {owner_before!r}"

        marker_before = _read_marker(vm)
        assert marker_before.get("dnslog") == _stale_daily_key(), (
            f"BEFORE: marker dnslog should be yesterday's key {_stale_daily_key()!r}, "
            f"got {marker_before.get('dnslog')!r}"
        )

        # --- When ---
        h.reload(vm, "tick")

        # --- Then ---
        content_after = _read_file(vm, dnslog_path)
        assert content_after == _SEED_DNSLOG_6_TAIL3, (
            f"AFTER: dnslog should hold exactly the last 3 seeded lines.\n"
            f"  expected: {_SEED_DNSLOG_6_TAIL3!r}\n"
            f"  got:      {content_after!r}"
        )

        inode_after = _get_inode(vm, dnslog_path)
        assert inode_after == inode_before, (
            f"AFTER: dnslog inode changed — file was recreated instead of kept in-place "
            f"(before={inode_before!r}, after={inode_after!r})"
        )

        owner_after = _get_file_owner(vm, dnslog_path)
        assert owner_after == "unbound", (
            f"AFTER: dnslog owner should still be 'unbound' after retention keep, got {owner_after!r}"
        )

        marker_after = _read_marker(vm)
        expected_key = _current_daily_key()
        assert marker_after.get("dnslog") == expected_key, (
            f"AFTER: marker dnslog should be today's key {expected_key!r}, got {marker_after.get('dnslog')!r}"
        )
    finally:
        # --- Cleanup (always runs, even on assertion failure — shared module VM) ---
        _set_log_rotate_schedule(vm, {"dnslog": "off"})
        _set_log_reset_keep(vm, {"dnslog": 0})
        _rm_marker(vm)
        _rm_log(vm, dnslog_path)
