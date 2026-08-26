"""
Live-VM oracle: the IP auto-rule reconciler (ADR-41), 4-way pass_order assembly.

Verifies that pfb_build_autorule_list() applied by sync_package_pfblockerng()
(a) never drops, duplicates, or content-mutates a user-authored firewall rule
across an Enable/Force-Update cycle, and (b) orders pfBlockerNG's own rules
around the user's per the pass_order ORDER table — in particular that a pfB
**Permit** list (pass) precedes a user **Block** for order_1..order_4.

THE PRECEDENCE TRAP (why this file exists)
------------------------------------------
The binary-anchor design (PR #561) put the whole block of user rules — including
user Block rules — ahead of the pfB block for order_1/order_2, so a pfB Permit
list could not override a user Block. The Deny-only kill-gate never saw it
(the pfB-pass bucket was empty). The sweep below uses a config with BOTH a pfB
Permit and a pfB Deny list AND a user pass AND a user block on the same
interface, and asserts the data-plane verdict per pass_order — this is the
falsifying case the Phase-2 gate omitted (RESULTS/05).

ADR-41 Phase 4 (#812): live wiring. Every fixture below is materialized on-box
(LAN-interface lists via ``_inject_lan_lists`` / a scoped user Block rule via
``_inject_user_block_rule``), ``pass_order`` is set explicitly per test via
``config_set_path`` (never left to the fixture's implicit state — the isolation
guarantee is that EVERY test/fixture that cares sets its own value, since
``h.reset()``/``h.reset_pfb_baseline()`` do not touch the IP-settings
``pass_order`` key), and the parametrized trap sweep adds the ADR-41 §7
data-plane probe on top of the pre-existing config-order assertions. All index
assertions are computed WITHIN the LAN-interface projection (``_lan_rules``):
the ORDER table applies per pf group, and the flat filter/rule array
interleaves other interfaces' baked rules (MGT blocks, an empty-descr row on
the smoke image). T1-T4 are single-VM (``pfb_enabled_deny_only``); the trap
sweep + the order_4 reorder test additionally need the two-VM ``client_vm``
(civm) fixture to drive real traffic through pf — requesting it auto-applies
the ``two_vm`` marker (conftest's ``_needs_two_vm``; never hand-applied).

CIVM-BRICKING TRAP (heeded, not just avoided): a LAN-interface pfB rule was
once found to drop the baked "Default allow LAN to any" rule on a second
reload, cutting civm off entirely (see test_syslog_export.py's Test-2 comment
block). ADR-41's immutable-user reconciliation is precisely the fix for that
drop — T1 pins it — but the injected user Block rule below is still scoped to
a SINGLE RFC 5737 destination (never 'any'), so regardless of where pass_order
places it, civm's own DNS/ICMP/control traffic is never a match.

Off-appliance contract (incl. the Permit-vs-Block trap, all five orders) is
pinned in tests/php/AutoruleListOracleTest.php.

Run manually once deployed (box at 10.0.0.23, NO_TWO_VM=1 for the single-VM
tests only — T5/T6 need civm):

    python -m pytest tests/smoke/test_smoke_autorule_immutable.py \
        --override-ini="addopts=" -v
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import PFSENSE_LAN_IP, SmokeVM

pytestmark = pytest.mark.smoke

# LAN interface friendly name — the interface that exercises the #532/ADR-41 reconciliation
# (helpers.SMOKE_IP_IFACE defaults to 'wan', so every list injection here uses a dedicated
# LAN-scoped helper instead of helpers.inject()/inject_ip_lists()).
LAN_IFACE = "lan"

# The user LAN pass rule description pfSense bakes into fresh images (mirrors
# test_smoke_lan_rule_preserve.py — same baked-in fixture, same needle).
DEFAULT_ALLOW_LAN_DESCR = "Default allow LAN to any"


# ---------------------------------------------------------------------------
# Helpers — read the filter-rule list from config.xml on-box
# ---------------------------------------------------------------------------


def _get_filter_rules(vm: SmokeVM) -> list[dict]:
    """Return config.xml /filter/rule as a Python list of dicts.

    Uses the proven harness pattern: h.php_eval() runs the snippet via pfSsh.php (config already
    loaded), and the <<RULES>>..<<END>> delimiters fence the JSON off from pfSsh's banner.
    """
    snippet = "echo '<<RULES>>' . json_encode(config_get_path('filter/rule', array())) . '<<END>>';"
    res = h.php_eval(vm, snippet)
    if "<<RULES>>" not in res.stdout or "<<END>>" not in res.stdout:
        raise RuntimeError(f"_get_filter_rules: unexpected output: {res.stdout!r} {res.stderr!r}")
    return json.loads(res.stdout.split("<<RULES>>", 1)[1].split("<<END>>", 1)[0])


def _descr_list(rules: list[dict]) -> list[str]:
    """Extract the 'descr' field from each rule (for readable assertions)."""
    return [r.get("descr", "") for r in rules]


def _user_rules(rules: list[dict]) -> list[dict]:
    """Filter to non-pfB-owned rules (mirrors the helper's keep logic)."""
    PFB_BYPASS_PREFIXES = ("pfB_DNS_Redirect_", "pfB_DoT_Block_")
    out = []
    for r in rules:
        descr = r.get("descr", "")
        if descr.startswith("pfB_") and not any(descr.startswith(p) for p in PFB_BYPASS_PREFIXES):
            continue
        out.append(r)
    return out


def _lan_rules(rules: list[dict]) -> list[dict]:
    """Project to the LAN interface pf group (non-floating rules with interface == LAN_IFACE).

    The ORDER table applies PER pf GROUP — pfb_build_autorule_list() reorders each interface's
    rules and the floating group INDEPENDENTLY (the off-appliance oracle asserts per-interface
    projections for the same reason). The flat filter/rule array interleaves OTHER interfaces'
    rules — the smoke image bakes MGT-interface block rules ('Deny all from MGT', 'Deny MG1 to
    LAN/WAN' — descr mentions LAN but the interface is MGT) and one rule with an EMPTY descr —
    so an index comparison is only meaningful within one interface's projection. This bit the
    first live run: "first non-pfB block anywhere" matched a baked MGT block at flat index 0
    while the LAN ordering was actually correct.
    """
    return [r for r in rules if r.get("interface") == LAN_IFACE and r.get("floating", "") != "yes"]


def _default_allow_lan_idx(lan_rules: list[dict]) -> int | None:
    """Index of the baked 'Default allow LAN to any' pass rule within the LAN projection.

    Needle-matched case-insensitively (the live descr is 'Default Allow LAN to any rule' —
    capital A + ' rule' suffix); the needle excludes the IPv6 sibling. Matching THE specific
    baked rule — never "first pass with a truthy descr" — because the image also bakes rules
    with an empty descr and anti-lockout pass rows.
    """
    needle = DEFAULT_ALLOW_LAN_DESCR.lower()
    return next(
        (i for i, r in enumerate(lan_rules) if needle in r.get("descr", "").lower() and r.get("type") == "pass"),
        None,
    )


def _has_default_allow_lan(rules: list[dict]) -> bool:
    """True iff the baked-in LAN 'Default allow LAN to any' pass rule is present."""
    needle = DEFAULT_ALLOW_LAN_DESCR.lower()
    return any(needle in r.get("descr", "").lower() and r.get("type") == "pass" for r in rules)


def _assert_default_allow_lan_present(rules: list[dict], *, when: str) -> None:
    """Verify the baked-in user pass rule survives — never assumed (issue #532/ADR-41)."""
    assert _has_default_allow_lan(rules), (
        f"{when}: {DEFAULT_ALLOW_LAN_DESCR!r} must be present in config.xml filter/rule (the "
        f"ADR-41 immutable-user guarantee) — actual descrs:\n  {_descr_list(rules)}"
    )


# ---------------------------------------------------------------------------
# Helpers — LAN-scoped config injection (pass_order, IP lists, a user rule)
# ---------------------------------------------------------------------------


def _set_pass_order(vm: SmokeVM, pass_order: str | None, *, timeout: float = 60.0) -> None:
    """Set (or clear) the IP-settings pass_order field — the reconciler's ``$pfb['order']`` input.

    ``None`` removes the key (defaults to order_0 per #532); an explicit ``'order_N'`` value
    exercises the configured-order branch. Mirrors ``_inject_lan_ip_rule``'s pass_order handling
    in test_smoke_lan_rule_preserve.py. Neither ``h.reset()`` nor ``h.reset_pfb_baseline()``
    restores this key by itself (reset() never touches IP settings at all;
    reset_pfb_baseline() deletes the whole IP-settings SECTION between MODULES, not between
    tests within this one) — every test in this file that cares about pass_order sets it
    explicitly, which is the isolation guarantee, not an assumption about run order.
    """
    line = (
        f"$ip['pass_order'] = {h._php_str(pass_order)};\n" if pass_order is not None else "unset($ip['pass_order']);\n"
    )
    snippet = (
        f"$ip = config_get_path({h._php_str(h.CFG_IP_SETTINGS)}, array());\n"
        f"{line}"
        f"config_set_path({h._php_str(h.CFG_IP_SETTINGS)}, $ip);\n"
        "write_config('pfBlockerNG smoke: autorule-immutable pass_order');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_pass_order({pass_order!r}) failed: rc={result.returncode} {result.stderr!r}")


def _inject_lan_lists(vm: SmokeVM, specs: list[h.IpCase], *, timeout: float = 90.0) -> None:
    """Write one or more IPv4 list groups to CFG_IP_V4_LISTS with inbound/outbound = LAN.

    Reuses helpers.IpCase + the private helpers._ip_list_php literal builder (same pattern
    helpers.inject_ip_lists uses to group MULTIPLE list rows in one write, so a second
    single-list write cannot replace the first) but forces LAN — the interface that exercises
    the #532/ADR-41 reconciliation — rather than helpers.SMOKE_IP_IFACE's 'wan' default.
    """
    groups = ", ".join(h._ip_list_php(spec) for spec in specs)
    ipset = {"inbound_interface": LAN_IFACE, "outbound_interface": LAN_IFACE}
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"$ip = config_get_path({h._php_str(h.CFG_IP_SETTINGS)}, array());\n"
        f"$ip = array_merge($ip, {h._php_kv_array(ipset)});\n"
        f"config_set_path({h._php_str(h.CFG_IP_SETTINGS)}, $ip);\n"
        f"config_set_path({h._php_str(h.CFG_IP_V4_LISTS)}, array({groups}));\n"
        "write_config('pfBlockerNG smoke: autorule-immutable LAN lists');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_inject_lan_lists failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _inject_user_block_rule(vm: SmokeVM, *, descr: str, dest_ip: str, timeout: float = 60.0) -> None:
    """Prepend (idempotently replace) a narrowly-scoped user Block rule on LAN.

    PREPENDED — ahead of the baked-in "Default allow LAN to any" — the standard admin layout
    (block above allow), and what makes the order_0 data-plane probe DECISIVE: order_0 keeps
    the user bucket UNSPLIT in original config order, so an APPENDED Block would sit behind
    the broad default allow and PERMIT_VICTIM would be reachable via that allow regardless of
    whether pfB's Permit actually beats the Block. With the Block first, only pfB's Permit
    (emitted ahead of the whole user bucket) can pass the SYN — and the probe would also have
    caught the historical binary-anchor bug shape (the whole user bucket, Block first, placed
    ahead of pfB's rules).

    Deliberately scoped to a SINGLE RFC 5737 destination (never 'any'): a LAN-interface pfB
    rule was once found to drop the permissive "Default allow LAN to any" rule on reload and
    brick every subsequent civm probe (see test_syslog_export.py's civm-bricking trap comment).
    ADR-41's immutable-user reconciliation fixes that drop (T1 pins it), but a BROAD user Block
    here would still legitimately intercept civm's own DNS/ICMP traffic depending on pass_order
    — scoping the destination to one victim keeps every other civm probe unaffected regardless
    of where this rule lands in the reconciled sequence.
    """
    snippet = (
        "$rules = config_get_path('filter/rule', array());\n"
        f"$rules = array_values(array_filter($rules, fn($r) => ($r['descr'] ?? '') !== {h._php_str(descr)}));\n"
        "array_unshift($rules, array(\n"
        f"  'descr' => {h._php_str(descr)},\n"
        "  'type' => 'block',\n"
        f"  'interface' => {h._php_str(LAN_IFACE)},\n"
        "  'ipprotocol' => 'inet',\n"
        "  'source' => array('any' => ''),\n"
        f"  'destination' => array('address' => {h._php_str(dest_ip)}),\n"
        "));\n"
        "config_set_path('filter/rule', $rules);\n"
        "write_config('pfBlockerNG smoke: autorule-immutable user block rule');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_inject_user_block_rule({descr!r}) failed: rc={result.returncode} {result.stderr!r}")


def _remove_filter_rule(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> None:
    """Remove any filter/rule row with this descr — idempotent (no-op if already gone).

    A manually-injected user rule (no pfB marker) is NEVER auto-removed by the immutable-user
    reconciler, so the injector must clean it up itself in a finally, or it leaks into every
    later smoke module (issue #582 — see test_dot_doq_block.py's _remove_user_filter).
    """
    snippet = (
        "$rules = config_get_path('filter/rule', array());\n"
        "$kept = array_values(array_filter($rules, function ($r) {\n"
        f"  return ($r['descr'] ?? '') !== {h._php_str(descr)};\n"
        "}));\n"
        "config_set_path('filter/rule', $kept);\n"
        "write_config('pfBlockerNG smoke: remove autorule-immutable user block rule');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_remove_filter_rule({descr!r}) failed: rc={result.returncode} {result.stderr!r}")


# ---------------------------------------------------------------------------
# Helpers — the ADR-41 §7 data-plane probe (civm-driven, killstates instrument style)
# ---------------------------------------------------------------------------


def _civm_connect(cl: SmokeVM, ip: str, *, timeout: float = 20.0) -> int:
    """civm attempts a TCP connection to ``ip`` through pfSense; return curl's rc.

    Pins a host route for ``ip`` via pfSense (civm has two equal-metric default routes;
    without the pin the SYN may egress the mgmt NIC instead of the LAN data NIC) — identical
    technique to test_smoke_killstates.py's ``_civm_connect``.
    """
    r = cl.ssh(
        "/bin/sh",
        "-c",
        f"dev=$(ip -4 -o addr show | awk '/192\\.168\\.1\\./{{print $2; exit}}'); "
        f'ip route replace {ip}/32 via {PFSENSE_LAN_IP} dev "$dev" 2>/dev/null || true; '
        f"curl -s -o /dev/null --connect-timeout 3 --max-time 4 http://{ip}/ >/dev/null 2>&1; echo rc=$?",
        timeout=timeout,
    )
    marker = "rc="
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith(marker)), "rc=-1")
    return int(line[len(marker) :] or -1)


def _victim_states(vm: SmokeVM, ip: str, *, timeout: float = 30.0) -> str:
    """The pf state-table lines referencing exactly ``ip`` (boundary-anchored, empty if none).

    Boundary-anchored for the same reason as test_smoke_killstates.py's ``_victim_states``: a
    bare substring grep for e.g. 203.0.113.5 would ALSO match 203.0.113.50/.60.
    """
    pat = ip.replace(".", "\\.")
    cmd = f"pfctl -ss 2>/dev/null | grep -E '(^|[^0-9]){pat}([^0-9]|$)' || true"
    return vm.ssh("/bin/sh", "-c", cmd, timeout=timeout).stdout.strip()


def _rule_block_packets(vm: SmokeVM, alias_table: str, *, timeout: float = 30.0) -> int:
    """Packets the rule referencing ``alias_table`` has matched (its pf counter); -1 if unreadable.

    Mirrors test_smoke_killstates.py's ``_rule_block_packets`` — proves a rule actively DROPPED
    traffic (the counter incremented), not merely that no state happened to form.
    """
    out = vm.ssh(
        "/bin/sh",
        "-c",
        f"pfctl -sr -vv 2>/dev/null | grep -A1 '{alias_table}' "
        "| grep -oE 'Packets: [0-9]+' | head -1 | grep -oE '[0-9]+'",
        timeout=timeout,
    ).stdout.strip()
    return int(out or -1)


def _probe_reachable(vm: SmokeVM, cl: SmokeVM, ip: str, *, attempts: int = 6) -> bool:
    """civm attempts a connection to ``ip`` through pfSense; True iff a pf state formed (SYN passed).

    Kills any stale state for ``ip`` FIRST — in BOTH directions: this fixture is shared across
    a 5-order parametrized sweep, and pf matches an EXISTING state before rules (the classic
    gotcha test_smoke_killstates.py exercises) — a leftover PASS-shaped state from an earlier
    pass_order case would falsely read as "reachable" for THIS case too. ``pfctl -k <host>``
    with a SINGLE -k kills by SOURCE host only; the two-arg form ``-k 0.0.0.0/0 -k <host>``
    kills src-any -> dst <host>. The victim is always our probes' DESTINATION, so the
    source-only kill misses the stale states entirely — the take-2 live run failed exactly
    there: order_1/order_2 legitimately created PASS states to DENY_VICTIM (SYN_SENT,
    tcp.first ~120s), which survived into order_3/order_4 and false-read as "reachable".
    Bounded retry with a fixed inter-attempt settle: the SYN's round-trip is real network I/O
    we cannot signal on (issue #456's documented poll-is-last-resort carve-out), never an
    unbounded wait.
    """
    kill = f"pfctl -k {ip} >/dev/null 2>&1; pfctl -k 0.0.0.0/0 -k {ip} >/dev/null 2>&1 || true"
    vm.ssh("/bin/sh", "-c", kill, timeout=15)
    for _ in range(attempts):
        _civm_connect(cl, ip)
        time.sleep(1.0)
        if ip in _victim_states(vm, ip):
            return True
        time.sleep(1.0)
    return False


def _probe_diag(vm: SmokeVM, ip: str) -> str:
    """Expected-vs-actual diagnostics for a data-plane reachability probe failure.

    Layers the same way test_smoke_killstates.py's ``_state_diag`` does: alias membership,
    the matched rule lines, and the live pf state — so a failure localises instead of printing
    a bare boolean.
    """

    def _try(cmd: str) -> str:
        try:
            return vm.ssh("/bin/sh", "-c", cmd, timeout=20).stdout.strip()
        except Exception:
            return "(error)"

    state = _victim_states(vm, ip)
    permit_tbl = _try(f"pfctl -t {PERMIT_ALIAS_TABLE} -T show 2>/dev/null | tr -d ' ' || true")
    deny_tbl = _try(f"pfctl -t {DENY_ALIAS_TABLE} -T show 2>/dev/null | tr -d ' ' || true")
    rules = _try(
        f"pfctl -sr 2>/dev/null | grep -iE '{PERMIT_HEADER}|{DENY_HEADER}|Default Allow LAN|{USER_BLOCK_DESCR}' "
        "|| echo '(no matching rule lines)'"
    )
    return (
        f"\n  pf states for {ip}: {state or '(none)'}\n"
        f"  permit alias {PERMIT_ALIAS_TABLE}: {permit_tbl!r}\n"
        f"  deny alias {DENY_ALIAS_TABLE}: {deny_tbl!r}\n"
        f"  matching pf rules (pfctl -sr):\n{rules}"
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the ADR-41 autorule-immutability module."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    yield smoke_vm


# Fixture: ensure pfBlockerNG is enabled with a minimal Deny_* IP list
DENY_ONLY_HEADER = "pfbautoruledenyonly"
DENY_ONLY_FEED_FILE = "pfb_autorule_denyonly_ip.txt"
DENY_ONLY_DUMMY_IP = "203.0.113.40"  # RFC 5737 TEST-NET-3, inert — only rule PRESENCE matters here


@pytest.fixture()
def pfb_enabled_deny_only(deployed_vm: SmokeVM) -> SmokeVM:
    """
    Given:
        pfBlockerNG enabled, one Deny_* v4 IP list active (RFC-5737 addresses),
        LAN default-pass rule present (pfSense default).

    Function-scoped (fresh per test): each test sets its OWN pass_order and runs its OWN
    reload, so re-materializing the list config here (a plain overwrite) costs nothing and
    guarantees no test depends on a sibling's leftover pass_order or reload cycle.
    """
    vm = deployed_vm
    feed = h.write_local_feed(vm, DENY_ONLY_FEED_FILE, f"{DENY_ONLY_DUMMY_IP}/32\n")
    _inject_lan_lists(
        vm,
        [
            h.IpCase(
                aliasname=DENY_ONLY_HEADER, feed_url=feed, action="Deny_Outbound", family="v4", header=DENY_ONLY_HEADER
            )
        ],
    )
    return vm


# ---------------------------------------------------------------------------
# T1. User-rule fidelity: LAN pass rule survives a Force-Update
# ---------------------------------------------------------------------------


@pytest.mark.timeout(90)  # two Force-Update reloads in the test body > the 30s smoke cap.
def test_user_rules_preserved_after_force_update(pfb_enabled_deny_only: SmokeVM) -> None:
    """
    Scenario: pfBlockerNG Force-Update on an install with a default-pass LAN rule.

    Given:
        pfBlockerNG active; config.xml has a user 'Default allow LAN to any' pass rule;
        pass_order pinned to 'order_0' (this test's own baseline — self-encapsulated).

    When:
        pfblockerng.php update  (Force-Update = full reconcile), twice.

    Then:
        - Every non-pfB-owned rule that existed BEFORE the second update still exists AFTER.
        - No user rule is duplicated (multiset check).
        - User rules appear in the same relative order (order check).

    Evidence requirement (test-coverage mandate):
        Assert BEFORE state first, then trigger update, then assert AFTER —
        never just the final state.
    """
    vm = pfb_enabled_deny_only
    _set_pass_order(vm, "order_0")

    # --- Given: establish the baseline via one reload, THEN capture "before". ---
    h.force_ip_refetch(vm, f"{DENY_ONLY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)

    before = _user_rules(_get_filter_rules(vm))
    assert len(before) >= 1, (
        f"Pre-condition: at least one user rule expected before update.\n"
        f"Actual rules: {_descr_list(_get_filter_rules(vm))}"
    )

    # --- When ---
    h.force_ip_refetch(vm, f"{DENY_ONLY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)

    # --- Then ---
    after = _user_rules(_get_filter_rules(vm))

    assert [r.get("descr") for r in before] == [r.get("descr") for r in after], (
        "User-rule fidelity failure: non-pfB rules changed across the update.\n"
        f"\nExpected (before):\n  {_descr_list(before)}"
        f"\nActual (after):\n  {_descr_list(after)}"
    )


# ---------------------------------------------------------------------------
# T2. Idempotence: second Force-Update produces identical rule list
# ---------------------------------------------------------------------------


@pytest.mark.timeout(90)  # two Force-Update reloads in the test body > the 30s smoke cap.
def test_force_update_is_idempotent(pfb_enabled_deny_only: SmokeVM) -> None:
    """
    Scenario: two successive Force-Updates produce the same filter-rule list.

    Given:
        pfBlockerNG active after an initial update; pass_order pinned to 'order_0'.

    When:
        pfblockerng.php update  (first pass)
        pfblockerng.php update  (second pass, on own output)

    Then:
        filter/rule array after pass 2 == filter/rule array after pass 1.

    Covers the idempotence invariant (pfb_build_autorule_list() applied to its own
    output is a no-op), proven off-appliance in Phase 3 PHPUnit and validated
    live here.
    """
    vm = pfb_enabled_deny_only
    _set_pass_order(vm, "order_0")

    # --- first update ---
    h.force_ip_refetch(vm, f"{DENY_ONLY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)
    after_first = _get_filter_rules(vm)

    # --- second update ---
    h.force_ip_refetch(vm, f"{DENY_ONLY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)
    after_second = _get_filter_rules(vm)

    assert _descr_list(after_first) == _descr_list(after_second), (
        "Idempotence failure: second update mutated the rule list.\n"
        f"\nAfter first update:\n  {_descr_list(after_first)}"
        f"\nAfter second update:\n  {_descr_list(after_second)}"
    )


# ---------------------------------------------------------------------------
# T3. pfB-block position: order_0 — pfB rules appear BEFORE user pass (pfB wins)
# ---------------------------------------------------------------------------


@pytest.mark.timeout(60)  # a pass_order change forces a filter/rule rewrite, not just content > 30s cap.
def test_order0_pfb_block_before_user_pass(pfb_enabled_deny_only: SmokeVM) -> None:
    """
    Scenario: pass_order=order_0 (default); pfB block must precede the user pass rule
    in config.xml (which maps to pf first-match order on the LAN interface).

    Given:
        pass_order='order_0' (set explicitly — this test's own precondition), one pfB
        Deny_* block rule, one user pass rule on LAN.

    When:
        Force-Update applied.

    Then:
        In the post-update filter/rule list, at least one pfB block rule appears
        at a lower index than the user pass rule on the same interface.
    """
    vm = pfb_enabled_deny_only
    _set_pass_order(vm, "order_0")
    h.force_ip_refetch(vm, f"{DENY_ONLY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)
    rules = _get_filter_rules(vm)
    # Indices are computed WITHIN the LAN projection — the ORDER table is per pf group, and the
    # flat array interleaves other interfaces' baked rules (see _lan_rules).
    lan = _lan_rules(rules)
    both = f"LAN-projection descrs:\n  {_descr_list(lan)}\nFull filter/rule descrs:\n  {_descr_list(rules)}"

    pfb_block_idx = next(
        (
            i
            for i, r in enumerate(lan)
            if r.get("descr", "").startswith("pfB_") and r.get("type") in ("block", "reject")
        ),
        None,
    )
    user_pass_idx = _default_allow_lan_idx(lan)

    assert pfb_block_idx is not None, f"No pfB block rule found in the LAN projection.\n{both}"
    assert user_pass_idx is not None, f"No LAN default-allow pass rule found in the LAN projection.\n{both}"
    assert pfb_block_idx < user_pass_idx, (
        f"order_0: pfB block must appear BEFORE the user pass (pfB wins) within the LAN group.\n"
        f"pfB block at LAN index {pfb_block_idx}, user pass at LAN index {user_pass_idx}.\n{both}"
    )


# ---------------------------------------------------------------------------
# T4. pfB-block position: order_1 — user pass appears BEFORE pfB block (user wins)
# ---------------------------------------------------------------------------


@pytest.mark.timeout(60)  # a pass_order change forces a filter/rule rewrite, not just content > 30s cap.
def test_order1_user_pass_before_pfb_block(pfb_enabled_deny_only: SmokeVM) -> None:
    """
    Scenario: pass_order=order_1; the user's pass rule must precede the pfB block.

    Given:
        pass_order='order_1' (set explicitly — this test's own precondition), same fixture as T3.

    When:
        Force-Update applied.

    Then:
        The user pass rule appears at a lower index than the first pfB block rule
        on the same interface.
    """
    vm = pfb_enabled_deny_only
    _set_pass_order(vm, "order_1")
    h.force_ip_refetch(vm, f"{DENY_ONLY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)
    rules = _get_filter_rules(vm)
    # Indices within the LAN projection — per pf group, see _lan_rules.
    lan = _lan_rules(rules)
    both = f"LAN-projection descrs:\n  {_descr_list(lan)}\nFull filter/rule descrs:\n  {_descr_list(rules)}"

    user_pass_idx = _default_allow_lan_idx(lan)
    pfb_block_idx = next(
        (
            i
            for i, r in enumerate(lan)
            if r.get("descr", "").startswith("pfB_") and r.get("type") in ("block", "reject")
        ),
        None,
    )

    assert user_pass_idx is not None, f"No LAN default-allow pass rule found in the LAN projection.\n{both}"
    assert pfb_block_idx is not None, f"No pfB block rule found in the LAN projection.\n{both}"
    assert user_pass_idx < pfb_block_idx, (
        f"order_1: user pass must appear BEFORE pfB block (user wins) within the LAN group.\n"
        f"User pass at LAN index {user_pass_idx}, pfB block at LAN index {pfb_block_idx}.\n{both}"
    )


# ---------------------------------------------------------------------------
# Fixture + sweep: THE PRECEDENCE TRAP — pfB Permit + pfB Deny + user pass + block
# ---------------------------------------------------------------------------

PERMIT_HEADER = "pfbautorulepermit"
DENY_HEADER = "pfbautoruledeny"
PERMIT_FEED_FILE = "pfb_autorule_permit_ip.txt"
DENY_FEED_FILE = "pfb_autorule_deny_ip.txt"
# PERMIT_VICTIM sits on the Permit_* alias AND is the user Block rule's dst — the genuine
# conflict the trap is about (an admin allowlist vs a user's own block on the SAME host).
# DENY_VICTIM sits only on the Deny_* alias, untouched by the user Block.
PERMIT_VICTIM = "203.0.113.50"
DENY_VICTIM = "203.0.113.60"
PERMIT_ALIAS_TABLE = f"pfB_{PERMIT_HEADER}_v4"
DENY_ALIAS_TABLE = f"pfB_{DENY_HEADER}_v4"
USER_BLOCK_DESCR = "pfbsmoke-autorule-user-block"

# order -> (does pfB Permit precede the user Block?  does the user Pass precede the pfB Deny?)
# Per the ORDER table, the pfB Permit (pass) precedes the user Block in EVERY order_1..order_4
# (and order_0); order_1/order_2 additionally place the user Pass ahead of the pfB Deny.
_TRAP_ORDERS = ["order_0", "order_1", "order_2", "order_3", "order_4"]

# Orders where pfB's whole pass/block bucket precedes ALL user rules on the LAN interface
# group (order_0/order_3: pfB p/m, pfB b/r, user p/m, user b/r; order_4: pfB p/m, pfB b/r,
# user b/r, user p/m) -> pfB's narrower Deny rule is the first match for DENY_VICTIM, so it is
# genuinely BLOCKED. For order_0 this holds regardless of the user Block's PREPENDED position
# (see _inject_user_block_rule): the unsplit user bucket — Block first or last — sits entirely
# BEHIND pfB's buckets, and DENY_VICTIM is not the user Block's dst anyway. order_1 (user p/m,
# pfB p/m, pfB b/r, user b/r) and order_2 (pfB p/m, user p/m, pfB b/r, user b/r) both place the
# broad "Default allow LAN to any" user-pass rule (destination=any — a pf first-match SUPERSET
# of pfB's alias-scoped Deny) ahead of pfB's block bucket, so that broad allow wins for EVERY
# destination including DENY_VICTIM (REACHABLE) — the documented "user rules take precedence"
# semantics of order_1/order_2, not a probe limitation. See the ORDER table in
# RESULTS/05_Results.txt and pfb_build_autorule_list()'s $apply() sequencing (pfblockerng.inc).
_DENY_BLOCKED_ORDERS = frozenset({"order_0", "order_3", "order_4"})


@pytest.fixture()
def pfb_enabled_permit_and_deny(deployed_vm: SmokeVM) -> Iterator[SmokeVM]:
    """
    Given:
        pfBlockerNG enabled with BOTH a Permit_* and a Deny_* v4 IP list active on LAN
        (RFC-5737 addresses), plus the baked-in user PASS rule and an injected user BLOCK
        rule (scoped to PERMIT_VICTIM only) on LAN.

    This is the config the binary-anchor design got wrong and the Deny-only gate missed:
    the pfB Permit (pass) must precede the user Block for order_1..order_4.

    Function-scoped: fresh per (parametrized) test, so no case's pass_order or reload state
    can leak into a sibling's. The injected user Block rule is removed in the finally (issue
    #582 — a non-pfB rule is never auto-swept, so the injector must clean up its own mess).
    """
    vm = deployed_vm
    permit_feed = h.write_local_feed(vm, PERMIT_FEED_FILE, f"{PERMIT_VICTIM}/32\n")
    deny_feed = h.write_local_feed(vm, DENY_FEED_FILE, f"{DENY_VICTIM}/32\n")
    _inject_lan_lists(
        vm,
        [
            h.IpCase(
                aliasname=PERMIT_HEADER,
                feed_url=permit_feed,
                action="Permit_Outbound",
                family="v4",
                header=PERMIT_HEADER,
            ),
            h.IpCase(
                aliasname=DENY_HEADER, feed_url=deny_feed, action="Deny_Outbound", family="v4", header=DENY_HEADER
            ),
        ],
    )
    _inject_user_block_rule(vm, descr=USER_BLOCK_DESCR, dest_ip=PERMIT_VICTIM)
    try:
        yield vm
    finally:
        _remove_filter_rule(vm, USER_BLOCK_DESCR)


@pytest.mark.timeout(180)  # a reload + two civm-driven data-plane probes (up to ~12s each) > 30s cap.
@pytest.mark.parametrize("pass_order", _TRAP_ORDERS)
def test_pfb_permit_precedes_user_block_every_order(
    pfb_enabled_permit_and_deny: SmokeVM, client_vm: SmokeVM, pass_order: str
) -> None:
    """
    Scenario: with a pfB Permit list AND a user Block on LAN, the pfB Permit (pass) must precede
    the user Block for every pass_order — so the admin's allowlist overrides the user's block.

    THIS IS THE TRAP. The binary-anchor design failed it for order_1/order_2 (it put the whole
    user block of rules, including the user Block, ahead of the pfB Permit).

    Given:
        pass_order=<param>; pfB Permit_* + Deny_* lists; the baked-in user pass rule; a user
        Block scoped to PERMIT_VICTIM (the trap: pfB's allowlist and the user's block target
        the SAME host).

    When:
        Force-Update applied with pass_order set to <param>.

    Then (config-order-proven):
        config.xml index(pfB Permit pass) < index(user Block) on LAN.
    And (data-plane-proven, ADR-41 §7):
        a connection to PERMIT_VICTIM from civm creates a pf state (REACHABLE) despite the
        user Block targeting the same address.
    And (data-plane-proven where feasible, config-order-proven implicitly otherwise):
        DENY_VICTIM is BLOCKED for order_0/order_3/order_4 (pfB's Deny bucket precedes every
        user rule) and REACHABLE for order_1/order_2 (the broad user-pass-any rule precedes
        pfB's Deny there — real pf first-match semantics, not an infeasible probe).
    """
    vm = pfb_enabled_permit_and_deny
    cl = client_vm

    # --- When: pin this case's pass_order and force a full reconcile. ---
    _set_pass_order(vm, pass_order)
    h.force_ip_refetch(vm, f"{PERMIT_HEADER}_v4")
    h.force_ip_refetch(vm, f"{DENY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)

    rules = _get_filter_rules(vm)
    _assert_default_allow_lan_present(rules, when=f"{pass_order}: after reload")
    # Indices are computed WITHIN the LAN projection — the ORDER table is per pf group, and the
    # flat array interleaves other interfaces' baked rules (MGT blocks, an empty-descr row); the
    # first live run failed exactly on that (see _lan_rules).
    lan = _lan_rules(rules)
    both = f"LAN-projection descrs:\n  {_descr_list(lan)}\nFull filter/rule descrs:\n  {_descr_list(rules)}"

    # --- Then (config-order-proven): pfB Permit precedes the user Block on LAN. ---
    pfb_permit_idx = next(
        (i for i, r in enumerate(lan) if r.get("descr", "").startswith("pfB_") and r.get("type") == "pass"),
        None,
    )
    # OUR injected Block by exact descr — never "first non-pfB block": foreign baked blocks exist.
    user_block_idx = next((i for i, r in enumerate(lan) if r.get("descr") == USER_BLOCK_DESCR), None)

    assert pfb_permit_idx is not None, f"No pfB Permit (pass) rule found in the LAN projection.\n{both}"
    assert user_block_idx is not None, (
        f"The injected user Block ({USER_BLOCK_DESCR!r}) not found in the LAN projection.\n{both}"
    )
    assert pfb_permit_idx < user_block_idx, (
        f"{pass_order}: pfB Permit (pass) must precede the user Block within the LAN group — a "
        f"pfB allowlist must override a user block.\npfB Permit at LAN index {pfb_permit_idx}, "
        f"user block at LAN index {user_block_idx}.\n{both}"
    )

    # --- Then (data-plane-proven, ADR-41 §7): the permit-listed victim is reachable despite
    # the user Block on the SAME address — some pass rule always precedes the user Block in
    # the intended layout (config-order-proven above / by construction of the ORDER table), so
    # a live SYN must get through. The user Block is PREPENDED ahead of the default allow (see
    # _inject_user_block_rule), so for order_0 (unsplit user bucket, Block first) and order_4
    # (user b/r before user p/m) pfB's Permit is the ONLY pass rule before the Block — fully
    # decisive. In order_1/2/3 the default allow (user p/m) also precedes the user b/r bucket,
    # so reachability alone cannot attribute the pass to pfB's Permit there — but the probe
    # still catches the historical binary-anchor failure shape (the whole user bucket, Block
    # first, placed ahead of ALL pfB rules for order_1/order_2: the SYN would hit the Block
    # and fail), and the config-order assertion above pins the Permit-before-Block invariant
    # in every order. ---
    assert _probe_reachable(vm, cl, PERMIT_VICTIM), (
        f"{pass_order}: expected the Permit-listed {PERMIT_VICTIM} REACHABLE despite the user "
        f"Block on the same address (the ADR-41 trap) — the connection never created a pf "
        f"state.\n{_probe_diag(vm, PERMIT_VICTIM)}"
    )

    # --- Then (data-plane-proven both branches): the deny-listed victim's reachability
    # follows pf's real first-match semantics on the sequence above, per _DENY_BLOCKED_ORDERS. ---
    expect_deny_blocked = pass_order in _DENY_BLOCKED_ORDERS
    pkts_before = _rule_block_packets(vm, DENY_ALIAS_TABLE)
    deny_reachable = _probe_reachable(vm, cl, DENY_VICTIM)
    if expect_deny_blocked:
        assert not deny_reachable, (
            f"{pass_order}: expected the Deny-listed {DENY_VICTIM} BLOCKED (pfB's Deny bucket "
            f"precedes every user rule in this order) but a pf state formed.\n"
            f"{_probe_diag(vm, DENY_VICTIM)}"
        )
        pkts_after = _rule_block_packets(vm, DENY_ALIAS_TABLE)
        # A -1 read is "counter unreadable", not a packet count — surface it as a distinct
        # read failure instead of letting it masquerade as a precedence failure below.
        assert pkts_before >= 0 and pkts_after >= 0, (
            f"{pass_order}: could not READ the Deny rule's pf packet counter (before="
            f"{pkts_before}, after={pkts_after}; -1 = unreadable) — cannot judge the block "
            f"delta; check the pfctl -sr -vv output format.\n{_probe_diag(vm, DENY_VICTIM)}"
        )
        assert pkts_after > pkts_before, (
            f"{pass_order}: the Deny rule's pf packet counter did not increase (before="
            f"{pkts_before}, after={pkts_after}) — absence of a state is not proof of an "
            f"active block.\n{_probe_diag(vm, DENY_VICTIM)}"
        )
    else:
        assert deny_reachable, (
            f"{pass_order}: expected the Deny-listed {DENY_VICTIM} REACHABLE (the broad "
            f"'Default allow LAN to any' user pass rule precedes pfB's Deny bucket in this "
            f"order — documented user-first semantics) but no pf state formed.\n"
            f"{_probe_diag(vm, DENY_VICTIM)}"
        )


@pytest.mark.timeout(90)  # two Force-Update reloads (order_3 baseline + order_4) > the 30s smoke cap.
def test_order4_reorders_user_block_before_user_pass(pfb_enabled_permit_and_deny: SmokeVM) -> None:
    """
    Scenario: order_4 places the user's own Block before its Pass (intended pass_order semantics:
    order_4 = pfB p/m | pfB b/r | pfSense Block/Reject | pfSense Pass/Match).

    The binary-anchor design wrongly dropped this (it froze user-rule order). Confirm — with a
    genuine before/after — that order_3 emits user pass-before-block and order_4 flips it, so
    the flip is attributable to the pass_order change, not incidental.

    Given: pass_order='order_3' (baseline) — user p/m precedes user b/r BY BUCKET ORDER
           (order_3 = pfB p/m | pfB b/r | user p/m | user b/r), deliberately insertion-
           independent: the fixture PREPENDS the user Block ahead of the default allow (see
           _inject_user_block_rule), so an order_0 baseline (unsplit user bucket in original
           config order) would already read block-before-pass and destroy the contrast.
    When:  pass_order switches to 'order_4'.
    Then:  the user Block now precedes the user Pass.
    """
    vm = pfb_enabled_permit_and_deny

    # --- Given: order_3 baseline (user pass-before-block by bucket order). ---
    _set_pass_order(vm, "order_3")
    h.force_ip_refetch(vm, f"{PERMIT_HEADER}_v4")
    h.force_ip_refetch(vm, f"{DENY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)

    rules = _get_filter_rules(vm)
    _assert_default_allow_lan_present(rules, when="Given (order_3 baseline)")
    # User rules within the LAN projection only — the ORDER table is per pf group, and the flat
    # array interleaves other interfaces' baked user rules (MGT blocks — see _lan_rules).
    user_rules = _user_rules(_lan_rules(rules))
    both = f"LAN user-rule descrs:\n  {_descr_list(user_rules)}\nFull filter/rule descrs:\n  {_descr_list(rules)}"
    base_pass_idx = _default_allow_lan_idx(user_rules)
    base_block_idx = next((i for i, r in enumerate(user_rules) if r.get("descr") == USER_BLOCK_DESCR), None)
    assert base_pass_idx is not None, f"No LAN default-allow pass rule found.\n{both}"
    assert base_block_idx is not None, f"The injected user Block ({USER_BLOCK_DESCR!r}) not found on LAN.\n{both}"
    assert base_pass_idx < base_block_idx, (
        f"Before-state (order_3): user pass must precede user block (the user p/m bucket leads "
        f"the user b/r bucket in order_3), so the order_4 reorder below is attributable to the "
        f"pass_order change, not incidental.\n{both}"
    )

    # --- When: switch to order_4. ---
    _set_pass_order(vm, "order_4")
    h.force_ip_refetch(vm, f"{PERMIT_HEADER}_v4")
    h.force_ip_refetch(vm, f"{DENY_HEADER}_v4")
    h.reload(vm, "update")
    h.apply_filter_sync(vm)

    # --- Then: the user's own Block now precedes its Pass (within the LAN projection). ---
    rules = _get_filter_rules(vm)
    user_rules = _user_rules(_lan_rules(rules))
    both = f"LAN user-rule descrs:\n  {_descr_list(user_rules)}\nFull filter/rule descrs:\n  {_descr_list(rules)}"

    user_block_idx = next((i for i, r in enumerate(user_rules) if r.get("descr") == USER_BLOCK_DESCR), None)
    user_pass_idx = _default_allow_lan_idx(user_rules)

    assert user_block_idx is not None, f"The injected user Block ({USER_BLOCK_DESCR!r}) not found on LAN.\n{both}"
    assert user_pass_idx is not None, f"No LAN default-allow pass rule found.\n{both}"
    assert user_block_idx < user_pass_idx, (
        f"order_4: the user's own Block must precede its Pass (intended pass_order layout).\n"
        f"user block at LAN index {user_block_idx}, user pass at LAN index {user_pass_idx}.\n{both}"
    )
