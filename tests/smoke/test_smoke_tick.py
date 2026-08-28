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
    test_tick_dispatches_due_feed          — tick dispatches a durably-pending feed group (ADR-43)
    test_tick_skips_non_due_feed           — tick does not dispatch once the reservation is consumed
    test_tick_wiped_ledger_regenerates     — a wiped ledger is regenerated as a derived cache (#2506);
                                              post-ADR-43 extras are calendar-anchored, not jittered
    test_tick_reboot_persists_ledger       — clean reboot with MFS /var keeps the schedule
                                              (ledger restored via the #468 earlyshellcmd)
"""

import json
import os
import subprocess
from collections.abc import Iterator
from typing import Literal

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
    # issue #2506: the due ledger is a derived cache post-ADR-43 — every tick that enters
    # the scheduler dispatch lock recomputes the 'cron' row from the runtime model (config)
    # + schedule state, and with NO feed group configured the refresh legitimately PRUNES
    # 'cron' rather than write it. Configure one real feed group so the model has something
    # to schedule, then immediately consume its reservation so tests that tick without
    # arranging due-ness (the disable-flag tests, the ss_refresh positive control) never
    # trigger a surprise feed pass.
    feed_url = h.write_local_feed(smoke_vm, "smoke_tick_ip.txt", "192.0.2.10/32\n192.0.2.11/32\n")
    h.inject(smoke_vm, h.IpCase(aliasname="smoketick", feed_url=feed_url, header="smoketick", family="v4"))
    h.pin_cron_due(smoke_vm)
    _complete_feed_reservation(smoke_vm)
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

# issue #2506: the model id pin_cron_due()/pfb_schedule_runtime_config() derive for the
# module's IpCase feed group ("ipv4:<header>_v4" — helpers._ip_inject_snippet's config
# feeds pfb_schedule_runtime_config()'s id derivation).
_FEED_GROUP_ID = "ipv4:smoketick_v4"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _complete_feed_reservation(vm: SmokeVM) -> None:
    """Consume the durable pending reservation :func:`h.pin_cron_due` made for the module's feed group.

    ``pfb_schedule_state_record_outcome(..., Success, ...)`` is the product's own terminal-outcome
    writer (pfblockerng_extra.inc): it sets ``last_completed_occurrence`` to the reserved occurrence
    and ``last_successful_check`` to now, so the group is not due again until its next calendar
    occurrence. Used right after ``pin_cron_due`` to arrange a "just completed, not due" baseline
    without a surprise feed pass on every tick that does not itself arrange due-ness (#2506).
    """
    # The state dir mirrors pin_cron_due's own derivation (helpers.py): pfb_global() guarded —
    # extra.inc alone is loadable without it — and the same `?? '/usr/local/etc'` fallback every
    # production consumer uses, never a Python-side hardcoded path. record_outcome's bool is the
    # only failure signal (it logs-and-returns FALSE rather than throwing), so echo it.
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
        Background: the 'cron' ledger entry is due (next_due in the past).
            Given the harness flag PRESENT (deploy()'s default state),
            When 'pfblockerng.php cron-tick' runs,
            Then it prints the disabled banner and the ledger 'cron' entry is
                UNCHANGED (no dispatch).
        Direct tick execution is proved separately without ever disarming the suite.
    """
    vm = deployed_vm
    flag = h.PFB_CRON_DISABLE_PATH
    assert vm.ssh("test", "-f", flag).returncode == 0, f"precondition: deploy() must have written {flag}"

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    _write_ledger_entry(vm, "cron", now_ts - 90000, now_ts - 1)
    before = _read_ledger(vm)
    result = _run_tick(vm, "cron-tick")
    assert result.returncode == 0, f"cron-tick rc={result.returncode} stderr={result.stderr!r}"
    assert f"[ Disabled by {flag} ]" in result.stdout, f"cron-tick must print disabled banner; got {result.stdout!r}"
    after = _read_ledger(vm)
    assert after.get("cron") == before.get("cron"), (
        f"cron-tick must not dispatch: before={before.get('cron')} after={after.get('cron')}"
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
@pytest.mark.timeout(360)  # salvage cap: inline tick (180s ssh budget) + marker/ledger waits + arrange steps
def test_tick_dispatches_due_feed(deployed_vm: SmokeVM) -> None:
    """Tick fires a durably-pending feed group, dispatched THROUGH pfblockerng_sync_cron (issue #570).

    Post-ADR-43 (#2506) the due-ness signal is the durable schedule-state reservation
    :func:`h.pin_cron_due` makes, not a hand-seeded ledger row — the ledger's 'cron' row is a
    derived cache the tick rebuilds from the runtime model + schedule state on every pass that
    enters the dispatch lock, so seeding it directly no longer represents production behaviour.

    Two observables, asserted in this order (the tick logs to syslog, not stdout, so we never
    assert on tick stdout):
      1. a ' CRON  PROCESS  START' marker appears in pfblockerng.log — that marker is logged
         ONLY by pfblockerng_sync_cron, so it proves the tick dispatches the `cron` verb
         (-> per-list Update Frequency + scheduled log reset) and NOT a bare
         `pfb_trigger scope=both` (which logs no CRON PROCESS pass). The module-local runner
         drains active pfBlockerNG tasks before dispatch, establishing a quiescent appliance.
      2. the ledger's 'cron' row ends up with next_due in the future — corroboration that the
         derived cache was rebuilt after the pass, NOT dispatch proof on its own (a still-due
         refresh also writes next_due = now; the marker in (1) carries the dispatch claim).

    Scenario:
        Background: pfBlockerNG installed with the module's smoketick feed group configured
            and scheduling enabled (the deployed_vm fixture's pin_cron_due + reservation-complete
            arrangement).
            Given h.pin_cron_due(vm) reserves a fresh pending occurrence for the feed group.
            When pfblockerng.php tick runs.
            Then a ' CRON  PROCESS  START' marker appears (dispatched via pfblockerng_sync_cron),
            And  the 'cron' ledger entry's next_due ends up in the future (the derived cache was
                rebuilt for the group's next planned occurrence).
    """
    vm = deployed_vm
    marker = "CRON  PROCESS  START"

    # Given: a fresh durable reservation for the feed group (post-ADR-43 due-ness).
    h.pin_cron_due(vm)
    h.wait_no_active_pfb_task(vm)
    cron_marker_before = h.count_log_marker(vm, h.PFB_LOG, marker)
    now_ts = int(vm.ssh("date +%s").stdout.strip())

    # When: tick fires (dispatches the `cron` verb inline).
    _run_tick(vm)

    # Then (1): the dispatched pass ran through pfblockerng_sync_cron (marker count rose) —
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

    # Then (2): corroboration — the final refresh rebuilt the derived cache with the group's
    # next planned occurrence (dispatch itself is proven by the marker above, not this).
    assert h.wait_until(
        lambda: _read_ledger(vm).get("cron", {}).get("next_due", 0) > now_ts,
        timeout=60,
        interval=2,
    ), f"after: cron next_due should be in the future;\n  ledger={_read_ledger(vm)}, now_ts={now_ts}"


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(360)  # salvage cap: inline tick (180s ssh budget) + control seeding + ledger wait
def test_tick_skips_non_due_feed(deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
    """Tick does NOT dispatch a feed sync once the group's reservation is consumed —
    yet the tick itself genuinely ran (issue #582 positive control).

    Post-ADR-43 (#2506) the due-ledger 'cron' row is a derived cache, not a synchronous
    dispatch-decision record: even a non-due tick can legitimately REWRITE it (the refresh
    still runs whenever the cache is absent/invalid), so "entry exactly unchanged" is no
    longer a valid oracle. The dispatch discriminator instead is the CRON PROCESS marker
    count, which only pfblockerng_sync_cron logs.

    On its own, "no CRON PROCESS marker" cannot distinguish "tick correctly skipped the
    non-due group" from "tick never ran at all" — both look identical. The positive control:
    an absent ss_refresh ledger entry is due on this first tick (pfblockerng_tick calls it
    when due), so a SafeSearch CNAME row seeded with a STALE baked IP and a resolver (the
    'pfbextdns' setting) pointed at the hermetic stub DNS makes THIS tick's ss_refresh
    deterministically detect a change and log its own marker — proving the tick executed.

    Scenario:
        Background: pfBlockerNG installed with the module's smoketick feed group configured.
            Given h.pin_cron_due(vm) reserves a fresh occurrence and _complete_feed_reservation(vm)
                immediately consumes it — the group is "just completed", not due again until its
                next calendar occurrence (arranged fresh here, not inherited from module setup or
                a sibling test's ordering).
            And  a SafeSearch CNAME row is seeded with a baked IP the stub will not repeat.
            When pfblockerng.php tick runs.
            Then the ss_refresh marker DOES appear (the tick genuinely ran),
            And  no ' CRON  PROCESS  START' marker appears (the feed group was not dispatched),
            And  the 'cron' ledger entry still exists with next_due in the future (the derived
                cache was rebuilt, not a stale row left over from a dispatch).
    """
    vm = deployed_vm
    ss_marker = "SafeSearch CNAME fallback IPs refreshed"
    cron_marker = "CRON  PROCESS  START"

    # The default feed schedule anchors EveryDay at 00:00 local (pfblockerng.inc defaults), so
    # a midnight crossing between the reservation-complete below and the tick's plan would make
    # the group genuinely due again — a real dispatch and a false failure for this oracle.
    # Mirror test_apply_outside_window_defers' clock-guard idiom: probe the GUEST clock, skip
    # in the tiny window rather than fail.
    vm_hm = vm.ssh("date +%H:%M").stdout.strip()
    if vm_hm in ("23:58", "23:59", "00:00", "00:01"):
        pytest.skip(f"VM clock {vm_hm} is within the midnight schedule-anchor window; re-run after 00:01")

    # Given: the feed group's reservation is freshly made, then immediately consumed — not
    # due again until its next calendar occurrence (self-contained; never order-dependent on
    # a sibling test having already completed it).
    h.pin_cron_due(vm)
    _complete_feed_reservation(vm)

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    h.wait_no_active_pfb_task(vm)

    # Positive control: a resolvable CNAME target the stub answers, baked stale in the CSV.
    target = h.unique_domain("tickssrefresh")
    stub_dns.set_records(target, a=(h.SS_TARGET_A,))
    src_domain = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
    ss_before = h.count_log_marker(vm, h.PFB_LOG, ss_marker)
    cron_marker_before = h.count_log_marker(vm, h.PFB_LOG, cron_marker)

    try:
        # When: tick fires — the feed group is not due (reservation already consumed), and the
        # absent ss_refresh entry is due.
        _run_tick(vm)

        # Then: the ss_refresh marker DID appear — the tick genuinely ran; this is what
        # distinguishes "skipped correctly" from "never ran" below.
        ss_after = h.count_log_marker(vm, h.PFB_LOG, ss_marker)
        assert ss_after > ss_before, (
            f"tick did not run ss_refresh (before={ss_before}, after={ss_after}) — cannot tell "
            "'feed group correctly skipped' from 'the tick itself never ran'"
        )

        # Then: no feed pass was dispatched for the non-due group — the routing discriminator
        # (a derived-cache rewrite of the ledger row, by itself, cannot prove this: #2506).
        cron_marker_after = h.count_log_marker(vm, h.PFB_LOG, cron_marker)
        assert cron_marker_after == cron_marker_before, (
            "tick dispatched a cron for a NON-due feed group — "
            f"' {cron_marker}' marker count changed: before={cron_marker_before}, after={cron_marker_after}"
        )

        # Then: the derived cache still holds a 'cron' row with next_due in the future — the
        # refresh rebuilt it from the runtime model + schedule state rather than dispatching.
        assert h.wait_until(
            lambda: _read_ledger(vm).get("cron", {}).get("next_due", 0) > now_ts,
            timeout=30,
            interval=2,
        ), f"after: cron next_due should be in the future;\n  ledger={_read_ledger(vm)}, now_ts={now_ts}"
    finally:
        _remove_ss_row(vm, src_domain)
        _reset_ss_extdns(vm)


@pytest.mark.smoke
@pytest.mark.tick
def test_tick_wiped_ledger_regenerates(deployed_vm: SmokeVM) -> None:
    """After the ledger is wiped, the tick regenerates it as a derived cache (#2506).

    Post-ADR-43 the wiped-ledger contract is REGENERATION of the derived cache — an absent
    ledger makes cache_ready FALSE, so the tick's dispatch lock always engages and rebuilds
    the document from the runtime model + schedule state — not per-entry random jitter: the
    Extras (dcc/bl) are calendar-anchored (issue #1944 / ADR-43) and their jitter is fixed at 0.

    Scenario:
        Background: pfBlockerNG installed with the module's smoketick feed group configured.
            Given the ledger file is deleted (RAM-disk reboot simulation).
            When pfblockerng.php tick runs.
            Then the regenerated document carries '_meta' (schema 1) and an 'extra:dcc' row
                with next_due in the future,
            And  the 'ss_refresh' row is present (its own independent 900s cadence also fired),
            And  the 'cron' row is present with an integer next_due (the feed group's derived
                schedule, calendar-anchored — not a jittered offset).
    """
    vm = deployed_vm
    now_ts = int(vm.ssh("date +%s").stdout.strip())

    # Wipe the ledger — verify it took, else a stale document would satisfy the assertions below.
    wipe = vm.ssh("rm", "-f", LEDGER_PATH)
    assert wipe.returncode == 0, f"precondition: ledger wipe failed rc={wipe.returncode} {wipe.stderr!r}"
    assert _read_ledger(vm) == {}, f"precondition: ledger must be empty before the tick; ledger={_read_ledger(vm)}"

    # Tick — the absent ledger makes cache_ready FALSE, so the dispatch lock engages and
    # regenerates the document regardless of what is/isn't due.
    _run_tick(vm)

    # Poll until the refresh has published the regenerated document.
    assert h.wait_until(
        lambda: "_meta" in _read_ledger(vm) and "extra:dcc" in _read_ledger(vm),
        timeout=30,
        interval=2,
    ), f"'_meta'/'extra:dcc' missing after wiped-ledger tick; ledger={_read_ledger(vm)}"
    ledger = _read_ledger(vm)

    assert ledger["_meta"]["schema"] == 1, f"_meta.schema should be 1; ledger={ledger}"

    dcc_next_due = ledger["extra:dcc"]["next_due"]
    assert dcc_next_due > now_ts, (
        f"extra:dcc next_due should be in the future; got {dcc_next_due} now={now_ts}; ledger={ledger}"
    )

    assert "ss_refresh" in ledger, f"ss_refresh row missing after wiped-ledger tick; ledger={ledger}"

    assert "cron" in ledger, f"cron row missing after wiped-ledger tick; ledger={ledger}"
    # Pin the calendar-anchored contract: post-ADR-43 the cron row carries NO random jitter
    # (the pre-ADR-43 per-entry draw this test used to assert non-zero), and its next_due is
    # the plan's occurrence — `now` if still due, the future occurrence otherwise — so it can
    # never precede the pre-tick clock. (A bare isinstance-int check is unfailable: json.loads
    # always yields int here.)
    assert ledger["cron"]["jitter"] == 0, (
        f"cron jitter should be 0 (calendar-anchored, ADR-43); got {ledger['cron']['jitter']!r}; ledger={ledger}"
    )
    assert ledger["cron"]["next_due"] >= now_ts, (
        f"cron next_due should not precede the pre-tick clock; got {ledger['cron']['next_due']} "
        f"now={now_ts}; ledger={ledger}"
    )


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
    """A clean reboot with MFS /var keeps the due-ledger (restored via #468 earlyshellcmd).

    Scenario:
        Background: pfBlockerNG installed with MFS /var engaged (the ``mfs_var`` fixture;
            issue #762 — previously only claimed in this docstring, never arranged, so the
            test silently rode whatever /var state a sibling module happened to leave behind).
            Given the ledger has a future cron next_due, and the aliastables archive has been
            refreshed to include it (the archiver is called directly: ``pfb_aliastables('update')``
            is reached only on the rule-change or alias-content-change paths, and this module's
            one static smoketick feed (#2506) never changes between passes, so a quiescent
            update pass would never archive the ledger).
        When the VM reboots cleanly.
        Then the /var sentinel is gone (MFS actually engaged this reboot),
        And  the ledger is restored,
        And  the cron next_due is still the value written before the reboot (no spurious dispatch).
    """
    vm = mfs_var

    now_ts = int(vm.ssh("date +%s").stdout.strip())
    future = now_ts + 7200  # 2 hours out

    _write_ledger_entry(vm, "cron", now_ts, future)

    # Wipe any stale archive a sibling module left behind (boot_reload's ramdisk legs write
    # the same unscoped file), so archive_exists() below can only be true if THIS refresh
    # wrote it — the archiver's exec() discards its output, so a silently-failed refresh
    # would otherwise pass the precondition against the leftover.
    vm.ssh("rm", "-f", f"{h.ALIASARCHIVE}.zst", f"{h.ALIASARCHIVE}.bz2")
    assert not h.archive_exists(vm, h.ALIASARCHIVE), (
        f"precondition: stale {h.ALIASARCHIVE}.{{zst,bz2}} survived the wipe"
    )

    # Refresh the archive directly (see docstring: 'update' mode is change-gated and the
    # module's static smoketick feed trips neither gate on a quiescent pass).
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
