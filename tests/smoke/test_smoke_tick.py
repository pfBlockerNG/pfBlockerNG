"""ADR-43 Phase 4 — Due-ledger trigger-tick smoke tests.

These tests exercise the tick verb and the due-ledger on a LIVE pfSense CE VM
(ADR-04 harness). They are authored in Phase 4 but DISPATCHED in Phase 7 as
part of the full smoke fan-out.

Dispatch (when ready):
    gh workflow run smoke.yml -f pytest_marker="tick"

Tests:
    test_tick_cron_entry_installed         — the installed cron entry is the cron-tick verb (#1204)
    test_cron_tick_respects_disable_flag   — cron-tick honours .pfb_cron_disable (#1204)
    test_tick_verb_ignores_disable_flag    — the direct tick verb is never gated (#1204)
    test_tick_asks_core_to_retry_a_failed_feed — a failed feed: the tick asks Core for a retry Update (#3941)
    test_tick_starts_no_update_when_nothing_asks — nothing pending or failed: no Update started (#3941)
    test_tick_wiped_ledger_rebuilds_only_its_own_rows — a wiped ledger regrows the tick's own rows only (#3941)
    test_tick_reboot_persists_ledger       — clean reboot with MFS /var keeps the ledger
                                              (ledger restored via the #468 earlyshellcmd)

The tick no longer plans or runs scheduled feeds: Core does (issue #3941, tests/smoke/test_core_update.py). What stays
the tick's is what only the Outpost can tell: a pending apply and a failed feed ask Core for an `apply` or `retry`
Update, and SafeSearch, apply reconciliation and log maintenance run in the tick itself.
"""

import json
import os
import subprocess
from collections.abc import Iterator
from typing import Literal

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer
from .test_smoke_core_api import await_core_up

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
    # One real feed group: a failed feed of it is what the retry test arranges. Core answers the tick's calls.
    feed_url = h.write_local_feed(smoke_vm, "smoke_tick_ip.txt", "192.0.2.10/32\n192.0.2.11/32\n")
    h.inject(smoke_vm, h.IpCase(aliasname="smoketick", feed_url=feed_url, header="smoketick", family="v4"))
    await_core_up(smoke_vm)
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
_REBOOT_LEDGER_PROBE = "reboot_persistence_probe"

# What a failed check of the module's IpCase feed leaves: its header + family suffix, in its action's (Deny) folder.
_FAIL_MARKER = "/var/db/pfblockerng/deny/smoketick_v4.fail"
# A per-feed header line only the feed pass (pfblockerng_sync_cron) logs.
_FEED_PASS_MARKER = "CRON  PROCESS  START"
# Outer bound on an Update Core runs: salvage only, never an assertion about duration.
_UPDATE_WATCHDOG = 300.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pending_apply(vm: SmokeVM) -> bool:
    """Whether the Outpost holds a change that waits for an apply (what makes a tick ask Core for an `apply` Update)."""
    pre = "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\npfb_global();"
    return h._php_read_scalar(vm, pre, "pfb_core_update_pending_apply() ? '1' : '0'") == "1"


def _drain_pending_apply(vm: SmokeVM) -> None:
    """Leave no apply pending, so the tick's next ask (an `apply` wins over a `retry`) is the one a test arranges."""
    for _ in range(3):
        if not _pending_apply(vm):
            return
        before = h.core_update_view(vm)["update"]
        _run_tick(vm)
        h.await_core_update_end(vm, before=before, watchdog=_UPDATE_WATCHDOG)
    assert not _pending_apply(vm), (
        "precondition: an apply stays pending after three ticks, so every tick asks Core for it"
    )


def _read_ledger(vm: SmokeVM) -> dict:
    """Return the parsed ledger as a dict (empty on absent/corrupt)."""
    raw = vm.ssh(f"cat {LEDGER_PATH} 2>/dev/null || echo '{{}}'").stdout
    try:
        return json.loads(raw.strip()) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def _write_ledger_entry(vm: SmokeVM, job_key: str, last_run: int, next_due: int, jitter: int = 0) -> None:
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


def _run_tick(
    vm: SmokeVM, verb: Literal["tick", "cron-tick"] = "tick", *, timeout: float = 180.0
) -> subprocess.CompletedProcess[str]:
    """Drain active pfBlockerNG tasks, then fire one tick verb.

    issue #2506: post-ADR-43 the tick can dispatch a scheduled feed pass or a manual apply
    INLINE (synchronously) rather than merely backgrounding it, so a tick that enters the
    dispatch lock can run well past SmokeVM.ssh's 60s default -- widen the budget here.
    """
    h.wait_no_active_pfb_task(vm)
    return vm.ssh(_PHP, _PFB_PHP, verb, timeout=timeout)


_SS_EXTDNS_STUB = "192.168.89.2"  # WAN SLIRP host alias -> the stub_dns fixture
_SS_EXTDNS_DEFAULT = "8.8.8.8"  # pfb_global()'s documented absent-default


def _seed_ss_refresh_positive_control(vm: SmokeVM, target: str, stale_v4: str) -> str:
    """Point ss_refresh's resolver at the stub DNS and seed a CNAME row baked STALE.

    pfblockerng_ss_refresh() re-resolves each SafeSearch CNAME row's target and rewrites
    the CSV IFF the freshly resolved address differs from the row's baked one
    (pfb_ss_refresh_lines). Pointing 'pfbextdns' — pfb_ss_resolve_target's resolver,
    default 8.8.8.8 — at the hermetic stub instead, and baking the row with an address the
    stub will not repeat, makes THIS tick's ss_refresh deterministically detect a change.

    Returns the seeded row's source domain so the caller can remove the row again
    (`_remove_ss_row`) — a leftover row would make every later tick in this module
    re-resolve a dead uuid target against the restored default resolver.
    """
    domain = h.unique_domain("tickssrefreshsrc")
    row = f"{domain},cname,{target},{stale_v4},\n"
    snippet = (
        "$g = config_get_path('installedpackages/pfblockerngglobal', array());"
        f"$g['pfbextdns'] = {h._php_str(_SS_EXTDNS_STUB)};"
        "config_set_path('installedpackages/pfblockerngglobal', $g);"
        "write_config('pfBlockerNG smoke: point ss_refresh at the stub DNS');"
        f"file_put_contents({h._php_str(h.UNBOUND_PY_SS_FILE)}, {h._php_str(row)}, FILE_APPEND | LOCK_EX);"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_seed_ss_refresh_positive_control failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )
    return domain


def _remove_ss_row(vm: SmokeVM, domain: str) -> None:
    """Strip the seeded SafeSearch CSV row again (issue #582 cleanup).

    Matched by the row's unique source domain — ss_refresh may have rewritten the
    baked IP by the time this runs, but the domain field is stable.
    """
    snippet = (
        f"$f = {h._php_str(h.UNBOUND_PY_SS_FILE)};"
        "if (file_exists($f)) {"
        "  $lines = file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);"
        f"  $keep = array_filter($lines, fn($l) => strpos($l, {h._php_str(domain)}) === FALSE);"
        '  file_put_contents($f, implode("\\n", $keep) . (empty($keep) ? \'\' : "\\n"), LOCK_EX);'
        "}"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_remove_ss_row failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _reset_ss_extdns(vm: SmokeVM) -> None:
    """Restore the 'pfbextdns' general setting to its documented default (issue #582 cleanup)."""
    snippet = (
        "$g = config_get_path('installedpackages/pfblockerngglobal', array());"
        f"$g['pfbextdns'] = {h._php_str(_SS_EXTDNS_DEFAULT)};"
        "config_set_path('installedpackages/pfblockerngglobal', $g);"
        "write_config('pfBlockerNG smoke: restore pfbextdns default');"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_reset_ss_extdns failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


# issue #1204: needles distinguishing the two possible installed cron commands.
# 'pfblockerng.php tick' does NOT substring-match '...cron-tick' (a hyphen sits where
# the legacy needle expects a space) -- mirrors pfblockerng_configure_tick_cron's own
# trailing-space needle rationale (pfblockerng.inc).
_CRON_TICK_NEEDLE = "pfblockerng.php cron-tick"
_LEGACY_TICK_NEEDLE = "pfblockerng.php tick"
_ENABLE_CB_CFG = "installedpackages/pfblockerng/config/0/enable_cb"


# pfSsh.php prints a startup banner on stdout, so a snippet that READS a value must
# delimit it (helpers.php_eval's contract; same idiom as helpers.config_get).
_CRON_JSON_OPEN = "<<<PFBCRON>>>"
_CRON_JSON_CLOSE = "<<<ENDPFBCRON>>>"


def _read_pfb_tick_cron_items(vm: SmokeVM) -> list[str]:
    """Return the 'command' string of every config.xml cron/item naming the
    tick-family verb (the current cron-tick, or the legacy bare tick)."""
    snippet = (
        "$out = array();\n"
        "foreach (config_get_path('cron/item', array()) as $i) {\n"
        "    $cmd = $i['command'] ?? '';\n"
        f"    if (strpos($cmd, {h._php_str(_CRON_TICK_NEEDLE)}) !== FALSE"
        f" || strpos($cmd, {h._php_str(_LEGACY_TICK_NEEDLE)}) !== FALSE) {{ $out[] = $cmd; }}\n"
        "}\n"
        f"echo {h._php_str(_CRON_JSON_OPEN)} . json_encode($out) . {h._php_str(_CRON_JSON_CLOSE)};"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0:
        raise RuntimeError(f"_read_pfb_tick_cron_items failed: rc={result.returncode} {result.stderr!r}")
    out = result.stdout
    start = out.find(_CRON_JSON_OPEN)
    end = out.find(_CRON_JSON_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"_read_pfb_tick_cron_items: no delimited value in pfSsh.php output: {out!r}")
    return json.loads(out[start + len(_CRON_JSON_OPEN) : end])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(180)  # two foreground sync passes (master switch off, then on)
def test_tick_cron_entry_installed(deployed_vm: SmokeVM) -> None:
    """The installed scheduled-tick cron entry is the #1204 cron-tick verb.

    Guards pfblockerng_configure_tick_cron's trailing-space teardown needle
    ('pfblockerng.php cron ', not the bare 'pfblockerng.php cron'): the bare needle
    substring-matches the just-installed 'cron-tick' command too, so
    install_cron_job() would delete it on every sync pass, leaving NO tick cron
    installed at all.

    Scenario:
        Background: pfBlockerNG's master switch driven OFF then synced (before-state).
            Given no tick-family cron/item entry exists,
            When the master switch is turned ON and a sync pass runs,
            Then EXACTLY ONE tick-family cron/item entry exists, its command is the
                cron-tick verb, and no legacy 'pfblockerng.php tick >>' entry survives.
    """
    vm = deployed_vm
    # deployed_vm is module-scoped: restore the master switch to whatever this module
    # was left in, never to a hardcoded state (the later tests here need it enabled).
    original_enabled = h.config_get(vm, _ENABLE_CB_CFG)
    try:
        h.set_package_enabled(vm, False)
        h.reload(vm, "update")
        before = _read_pfb_tick_cron_items(vm)
        assert before == [], (
            f"before: no tick-family cron/item entry should exist while pfBlockerNG is disabled; found {before}"
        )

        h.set_package_enabled(vm, True)
        h.reload(vm, "update")
        after = _read_pfb_tick_cron_items(vm)
        assert len(after) == 1, f"after: expected exactly one tick-family cron/item entry, found {len(after)}: {after}"
        assert _CRON_TICK_NEEDLE in after[0], f"the installed entry must be the cron-tick verb; got {after[0]!r}"
        assert "pfblockerng.php tick >>" not in after[0], (
            f"the legacy 'pfblockerng.php tick' entry must not survive; got {after[0]!r}"
        )
    finally:
        h.config_set(vm, _ENABLE_CB_CFG, original_enabled)
        h.reload(vm, "update")


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(120)
def test_cron_tick_respects_disable_flag(deployed_vm: SmokeVM) -> None:
    """The cron-tick verb honours the harness's .pfb_cron_disable sentinel.

    Scenario:
        Background: the 'ss_refresh' ledger entry is due (next_due in the past): a tick that ran
            would dispatch it and move the entry.
            Given the harness flag PRESENT (deploy()'s default state),
            When 'pfblockerng.php cron-tick' runs,
            Then it prints the disabled banner and the ledger 'ss_refresh' entry is
                UNCHANGED (no dispatch).
        Direct tick execution is proved separately without ever disarming the suite.
    """
    vm = deployed_vm
    flag = h.PFB_CRON_DISABLE_PATH
    assert vm.ssh("test", "-f", flag).returncode == 0, f"precondition: deploy() must have written {flag}"

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    _write_ledger_entry(vm, "ss_refresh", now_ts - 90000, now_ts - 1)
    before = _read_ledger(vm)
    result = _run_tick(vm, "cron-tick")
    assert result.returncode == 0, f"cron-tick rc={result.returncode} stderr={result.stderr!r}"
    assert f"[ Disabled by {flag} ]" in result.stdout, f"cron-tick must print disabled banner; got {result.stdout!r}"
    after = _read_ledger(vm)
    assert after.get("ss_refresh") == before.get("ss_refresh"), (
        f"cron-tick must not dispatch: before={before.get('ss_refresh')} after={after.get('ss_refresh')}"
    )


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(90)
def test_tick_verb_ignores_disable_flag(deployed_vm: SmokeVM) -> None:
    """The direct 'tick' verb is NEVER gated by .pfb_cron_disable -- only 'cron-tick' is.

    Scenario:
        Background: the harness flag is PRESENT (its normal, always-on state during
            the suite) and the built-in 'ss_refresh' ledger entry is due.
            When 'pfblockerng.php tick' runs directly,
            Then it dispatches the due job (ledger 'ss_refresh' next_due advances) and
                prints no '[ Disabled by ... ]' banner.
    """
    vm = deployed_vm
    flag = h.PFB_CRON_DISABLE_PATH
    assert vm.ssh("test", "-f", flag).returncode == 0, f"precondition: {flag} must be present for this test"

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    _write_ledger_entry(vm, "ss_refresh", now_ts - 90000, now_ts - 1)

    result = _run_tick(vm)
    assert result.returncode == 0, f"tick rc={result.returncode} stderr={result.stderr!r}"
    assert "[ Disabled by" not in result.stdout, (
        f"the direct 'tick' verb must never print the cron-tick disabled banner; got {result.stdout!r}"
    )
    assert h.wait_until(
        lambda: _read_ledger(vm).get("ss_refresh", {}).get("next_due", 0) > now_ts,
        timeout=30,
        interval=2,
    ), f"the direct 'tick' verb must dispatch a due job regardless of the flag; ledger={_read_ledger(vm)}"


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(900)  # salvage cap: drain + tick (180s ssh budget) + the retry Update Core runs
def test_tick_asks_core_to_retry_a_failed_feed(deployed_vm: SmokeVM) -> None:
    """A failed feed makes the tick ask Core for a `retry` Update, which runs the feed pass (issue #3941).

    The `.fail` marker is something only the Outpost sees, so the tick (not Core's quarter-hour plan) asks. Two
    observables: Core's last Update is a `retry` newer than the one before the tick, and its log holds the
    ' CRON  PROCESS  START' line that only pfblockerng_sync_cron writes (a bare apply logs none).

    Scenario:
        Background: scheduled feed updates are ON and the module's smoketick feed group is enabled.
            Given no apply is pending (an `apply` ask comes first) and the feed's `.fail` marker exists.
            When pfblockerng.php tick runs.
            Then Core's last Update is a `retry` that ended,
            And  its log holds the feed pass's start line.
    """
    vm = deployed_vm
    _drain_pending_apply(vm)
    with h.scheduled_updates_on(vm):
        try:
            assert vm.ssh("mkdir", "-p", _FAIL_MARKER.rsplit("/", 1)[0]).returncode == 0
            assert vm.ssh("touch", _FAIL_MARKER).returncode == 0
            before = h.core_update_view(vm)["update"]
            # The baseline is taken once the box is quiet: a task still ending would add the marker after it.
            h.wait_no_active_pfb_task(vm)
            marker_before = h.count_log_marker(vm, h.PFB_LOG, _FEED_PASS_MARKER)

            _run_tick(vm)

            view = h.await_core_update_end(vm, before=before, watchdog=_UPDATE_WATCHDOG)
            assert view["update"]["trigger"] == "retry", (
                f"the tick must ask Core for a retry; Core ran {view['update']}"
            )
            assert _FEED_PASS_MARKER in h.core_update_log(vm), (
                f"the retry Update's log has no ' {_FEED_PASS_MARKER}' line: the feed pass did not run;\n"
                f"{h.core_update_log(vm)[-1500:]}"
            )
            assert h.count_log_marker(vm, h.PFB_LOG, _FEED_PASS_MARKER) > marker_before, (
                f"' {_FEED_PASS_MARKER}' did not reach {h.PFB_LOG} (before={marker_before})"
            )
        finally:
            vm.ssh("rm", "-f", _FAIL_MARKER)


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(900)  # salvage cap: drain + tick (180s ssh budget) + control seeding
def test_tick_starts_no_update_when_nothing_asks(deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
    """With no apply pending and no failed feed a tick asks Core for nothing, yet genuinely ran (issue #582 control).

    "No Update started" cannot tell a tick that skipped correctly from a tick that never ran. The positive
    control: an absent ss_refresh ledger entry is due on this first tick, so a SafeSearch CNAME row seeded with a
    STALE baked IP and a resolver (the 'pfbextdns' setting) pointed at the hermetic stub DNS makes THIS tick's
    ss_refresh deterministically detect a change and log its own marker.

    Scenario:
        Background: scheduled feed updates are ON (so a retry WOULD be asked for a failed feed).
            Given no apply is pending, no `.fail` marker exists, and a stale SafeSearch row is seeded.
            When pfblockerng.php tick runs.
            Then the ss_refresh marker DOES appear (the tick ran),
            And  no ' CRON  PROCESS  START' line is added (no feed pass),
            And  Core's last Update is the one it was before the tick, or a quarter-hour `scheduled` one:
                 never an `apply` or a `retry`.
    """
    vm = deployed_vm
    ss_marker = "SafeSearch CNAME fallback IPs refreshed"
    _drain_pending_apply(vm)
    vm.ssh("rm", "-f", _FAIL_MARKER)
    h.wait_no_active_pfb_task(vm)

    # Positive control: a resolvable CNAME target the stub answers, baked stale in the CSV.
    target = h.unique_domain("tickssrefresh")
    stub_dns.set_records(target, a=(h.SS_TARGET_A,))
    src_domain = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
    ss_before = h.count_log_marker(vm, h.PFB_LOG, ss_marker)
    feed_pass_before = h.count_log_marker(vm, h.PFB_LOG, _FEED_PASS_MARKER)

    try:
        with h.scheduled_updates_on(vm):
            before = h.core_update_view(vm)["update"]

            _run_tick(vm)

            ss_after = h.count_log_marker(vm, h.PFB_LOG, ss_marker)
            assert ss_after > ss_before, (
                f"tick did not run ss_refresh (before={ss_before}, after={ss_after}) — cannot tell "
                "'nothing asked' from 'the tick itself never ran'"
            )
            feed_pass_after = h.count_log_marker(vm, h.PFB_LOG, _FEED_PASS_MARKER)
            assert feed_pass_after == feed_pass_before, (
                f"a feed pass ran although nothing asked for one: ' {_FEED_PASS_MARKER}' "
                f"before={feed_pass_before}, after={feed_pass_after}"
            )
            after = h.core_update_view(vm)["update"]
            assert after == before or after["trigger"] == "scheduled", (
                f"the tick asked Core for an Update with nothing pending or failed: before={before} after={after}"
            )
    finally:
        _remove_ss_row(vm, src_domain)
        _reset_ss_extdns(vm)


@pytest.mark.smoke
@pytest.mark.tick
def test_tick_wiped_ledger_rebuilds_only_its_own_rows(deployed_vm: SmokeVM) -> None:
    """After the ledger is wiped, the tick regrows the rows it owns and none of the retired schedule ones (issue #3941).

    Core owns the schedule now, so the ledger holds only the Outpost's own: 'ss_refresh' and 'apply_reconcile'
    (each its own 900 s cadence) and, while an apply waits, the 'cron' pending flag. The PHP scheduler's derived
    cache ('_meta', one 'extra:*' row per Extra) is gone: a tick that wrote it again is the regression.

    Scenario:
        Background: pfBlockerNG installed with the module's smoketick feed group configured.
            Given the ledger file is deleted (RAM-disk reboot simulation).
            When pfblockerng.php tick runs.
            Then 'ss_refresh' and 'apply_reconcile' rows are present with a future next_due,
            And  no '_meta' stamp and no 'extra:dcc' / 'extra:bl' row exists.
    """
    vm = deployed_vm
    now_ts = int(vm.ssh("date +%s").stdout.strip())

    # Wipe the ledger — verify it took, else a stale document would satisfy the assertions below.
    wipe = vm.ssh("rm", "-f", LEDGER_PATH)
    assert wipe.returncode == 0, f"precondition: ledger wipe failed rc={wipe.returncode} {wipe.stderr!r}"
    assert _read_ledger(vm) == {}, f"precondition: ledger must be empty before the tick; ledger={_read_ledger(vm)}"

    _run_tick(vm)

    assert h.wait_until(
        lambda: {"ss_refresh", "apply_reconcile"} <= _read_ledger(vm).keys(),
        timeout=30,
        interval=2,
    ), f"'ss_refresh'/'apply_reconcile' rows missing after wiped-ledger tick; ledger={_read_ledger(vm)}"
    ledger = _read_ledger(vm)
    for job in ("ss_refresh", "apply_reconcile"):
        assert ledger[job]["next_due"] > now_ts, f"{job} next_due must be in the future; ledger={ledger}"
    retired = sorted(k for k in ledger if k == "_meta" or k.startswith("extra:"))
    assert retired == [], f"the tick wrote the PHP scheduler's derived cache again: {retired}; ledger={ledger}"


@pytest.fixture
def mfs_var(deployed_vm: SmokeVM, request: pytest.FixtureRequest) -> Iterator[SmokeVM]:
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
    try:
        h.reload(vm, "update")
        h.reboot_vm(vm)
    except Exception:
        # Arrange failed AFTER the flag write: best-effort revert so the persisted
        # use_mfs_tmpvar never outlives the failed arrange (the #762 leak class, relocated
        # to the failure path). No reboot — the box is already failing; don't compound it.
        try:
            h.set_ramdisk(vm, False)
        except Exception as exc:  # noqa: BLE001 -- cleanup on an already-failing path
            print(f"[smoke] mfs_var arrange-failure revert failed (non-fatal): {exc}")
        raise
    try:
        yield vm
    finally:
        # Failure-time capture FIRST (issue #774): the revert reboot below wipes the MFS
        # /var this test ran on, and the autouse _dump_vm_on_failure finalizes only AFTER
        # this fixture (reverse setup order — pinned by test_fixture_teardown_contract.py),
        # i.e. post-reboot, when that state is already gone. Dump here, pre-reboot, and
        # flag the node so the autouse dump doesn't print a second, post-reboot snapshot.
        rep = getattr(request.node, "_rep_call", None)
        if rep is not None and rep.failed:
            # Own try: dump_diagnostics is best-effort by contract, but a future probe
            # that raises here would skip the ramdisk revert AND the reboot below — a
            # worse leak than the one #774 fixes. Guard like the sibling steps.
            try:
                print("\n[smoke] mfs_var: failure-time diagnostics BEFORE the teardown reboot (issue #774)")
                h.dump_diagnostics(vm)
                request.node._pfb_failure_dumped = True  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 -- pre-revert diagnostics, never mask the test result
                print(f"[smoke] mfs_var pre-reboot diagnostics failed (non-fatal): {exc}")
        # Best-effort, mirrors test_smoke_boot_reload's deployed_vm teardown: never mask
        # the test result on cleanup failure.
        try:
            h.set_ramdisk(vm, False)
            h.reload(vm, "update")
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] mfs_var ramdisk-off teardown failed (non-fatal): {exc}")
        # Own try (matches the #765 sibling teardowns): a flaky reload must not skip the
        # reboot — the one step that actually clears the running MFS /var once the flag is
        # off. Without it /var stays MFS and pollutes every module that runs next.
        try:
            h.reboot_vm(vm)
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] mfs_var teardown reboot failed (non-fatal): {exc}")


@pytest.mark.reboot
@pytest.mark.tick
# Unlike the boot_reload siblings (which reboot in a FIXTURE, exempt from the workflow's
# 30s func-only body cap), this test reboots in its BODY too. The reboot helper first consumes
# the observable boottime-change event, then runs readiness with its own full budget; the
# mfs_var fixture reboots twice more (arrange + teardown) — exempt from the func-only cap,
# same as boot_reload's fixture reboots — so the body still contains exactly ONE reboot.
@pytest.mark.timeout(300)
def test_tick_reboot_persists_ledger(mfs_var: SmokeVM) -> None:
    """MFS /var restores the ledger file, and a later tick keeps its unrelated rows while it regrows its own.

    Scenario:
        Background: pfBlockerNG installed with MFS /var engaged (the ``mfs_var`` fixture).
            Given the ledger contains a unique persistence probe, and the aliastables archive has
            been refreshed to include it.
        When the VM reboots cleanly.
        Then the /var sentinel is gone (MFS actually engaged this reboot),
        And  the persistence probe is restored from the archive.
        When a real post-reboot tick runs.
        Then the persistence probe remains byte-identical and the tick's own 'ss_refresh' row appears
        (the tick ran against the restored ledger), with no retired schedule row beside them.
    """
    vm = mfs_var

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    persistence_probe = {"last_run": now_ts, "next_due": now_ts + (10 * 366 * 86400), "jitter": 0}

    _write_ledger_entry(vm, _REBOOT_LEDGER_PROBE, **persistence_probe)

    # Wipe any stale archive a sibling module left behind, so archive_exists() below can
    # only be true if this refresh wrote it.
    vm.ssh("rm", "-f", f"{h.ALIASARCHIVE}.zst", f"{h.ALIASARCHIVE}.bz2")
    assert not h.archive_exists(vm, h.ALIASARCHIVE), (
        f"precondition: stale {h.ALIASARCHIVE}.{{zst,bz2}} survived the wipe"
    )

    snippet = f"require_once('{_PFB_INC}');pfb_global();pfb_aliastables('update');echo 'OK';"
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"pfb_aliastables('update') archive refresh failed: "
            f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        )

    assert h.archive_exists(vm, h.ALIASARCHIVE), (
        f"precondition: {h.ALIASARCHIVE}.{{zst,bz2}} must exist after the archive refresh"
    )
    before = _read_ledger(vm)
    assert before.get(_REBOOT_LEDGER_PROBE) == persistence_probe, (
        f"precondition: persistence probe was not written; ledger={before}"
    )

    vm.ssh("/usr/bin/touch", _VAR_WIPE_SENTINEL)
    assert vm.ssh("test", "-e", _VAR_WIPE_SENTINEL).returncode == 0, (
        f"precondition: {_VAR_WIPE_SENTINEL} must exist before reboot"
    )

    h.reboot_vm(vm)

    var_mount = next(
        (ln for ln in vm.ssh("/sbin/mount").stdout.splitlines() if " on /var " in ln),
        "",
    )
    assert vm.ssh("test", "-e", _VAR_WIPE_SENTINEL).returncode != 0, (
        f"/var sentinel survived the reboot -- MFS did not engage; /var mount line: {var_mount!r}"
    )

    restored = _read_ledger(vm)
    assert restored.get(_REBOOT_LEDGER_PROBE) == persistence_probe, (
        f"ledger persistence probe missing after reboot; expected={persistence_probe} ledger={restored}"
    )

    tick_result = _run_tick(vm)
    assert tick_result.returncode == 0, (
        f"post-reboot tick failed: rc={tick_result.returncode} stderr={tick_result.stderr!r}"
    )

    after = _read_ledger(vm)
    assert after.get(_REBOOT_LEDGER_PROBE) == persistence_probe, (
        f"persistence probe changed by the post-reboot tick; expected={persistence_probe} ledger={after}"
    )
    assert "ss_refresh" in after, f"the post-reboot tick did not write its own 'ss_refresh' row; ledger={after}"
    retired = sorted(k for k in after if k == "_meta" or k.startswith("extra:"))
    assert retired == [], f"the post-reboot tick wrote the PHP scheduler's derived cache: {retired}; ledger={after}"
