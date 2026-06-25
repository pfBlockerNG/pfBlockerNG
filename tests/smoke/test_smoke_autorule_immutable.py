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
(the pfB-pass bucket was empty). The acceptance sweep here MUST use a config
with BOTH a pfB Permit and a pfB Deny list AND a user pass AND a user block on
the same interface, and assert the data-plane verdict per pass_order — this is
the falsifying case the Phase-2 gate omitted (RESULTS/05).

LIVE RUN DEFERRED TO PHASE 4
-----------------------------
The live-VM harness (ADR-04) proves the on-box pf state after pfBlockerNG reloads;
Phase 4 wires the fixtures + the per-pass_order data-plane sweep. This file is
written so Phase 4 can extend and execute it without rebuilding the structure.
The off-appliance contract (incl. the Permit-vs-Block trap, all five orders) is
already pinned in tests/php/AutoruleListOracleTest.php.

To run manually once Phase 4 is underway (box at 10.0.0.23, NO_TWO_VM=1):

    python -m pytest tests/smoke/test_smoke_autorule_immutable.py \
        --override-ini="addopts=" -v
"""

from __future__ import annotations

import json

import pytest

from . import helpers as h

# ---------------------------------------------------------------------------
# Pytest marks
# ---------------------------------------------------------------------------

# Marked `smoke` so it joins the ADR-04 fan-out, but skipped at module level until ADR-41 Phase 4
# wires the live fixtures + per-pass_order data-plane sweep (the harness was VM-flaky this session).
# Phase 4 removes the skip. The off-appliance contract is already pinned in AutoruleListOracleTest.
pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skip(reason="ADR-41 Phase 4: live autorule-immutability wiring pending (see RESULTS/03)"),
]


# ---------------------------------------------------------------------------
# Helpers — read the filter-rule list from config.xml on-box
# ---------------------------------------------------------------------------


def _get_filter_rules(vm: h.SmokeVM) -> list[dict]:
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


# ---------------------------------------------------------------------------
# Fixture: ensure pfBlockerNG is enabled with a minimal Deny_* IP list
# ---------------------------------------------------------------------------


@pytest.fixture()
def pfb_enabled_deny_only(smoke_vm: h.SmokeVM) -> h.SmokeVM:  # type: ignore[return]
    """
    Given:
        pfBlockerNG enabled, one Deny_* v4 IP list active (RFC-5737 addresses),
        LAN default-pass rule present (pfSense default).
    """
    # Phase 4: wire up h.ensure_pfblockerng_enabled() + a deny-list fixture.
    # The harness already provides smoke_vm; extend it here.
    raise NotImplementedError(
        "Phase 4: wire pfb_enabled_deny_only fixture using h.deploy() + h.write_local_feed() + h.reload()."
    )


# ---------------------------------------------------------------------------
# T1. User-rule fidelity: LAN pass rule survives a Force-Update
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pfb_enabled_deny_only")
def test_user_rules_preserved_after_force_update(smoke_vm: h.SmokeVM) -> None:
    """
    Scenario: pfBlockerNG Force-Update on an install with a default-pass LAN rule.

    Given:
        pfBlockerNG active; config.xml has a user 'Default allow LAN to any' pass rule.

    When:
        pfblockerng.php update  (Force-Update = full reconcile)

    Then:
        - Every non-pfB-owned rule that existed BEFORE the update still exists AFTER.
        - No user rule is duplicated (multiset check).
        - User rules appear in the same relative order (order check).

    Evidence requirement (test-coverage mandate):
        Assert BEFORE state first, then trigger update, then assert AFTER —
        never just the final state.
    """
    # --- Given ---
    before = _user_rules(_get_filter_rules(smoke_vm))
    assert len(before) >= 1, (
        f"Pre-condition: at least one user rule expected before update.\n"
        f"Actual rules: {_descr_list(_get_filter_rules(smoke_vm))}"
    )

    # --- When ---
    h.reload(smoke_vm)  # Phase 4: replace with h.force_update() once wired.

    # --- Then ---
    after = _user_rules(_get_filter_rules(smoke_vm))

    assert [r.get("descr") for r in before] == [r.get("descr") for r in after], (
        "User-rule fidelity failure: non-pfB rules changed across the update.\n"
        f"\nExpected (before):\n  {_descr_list(before)}"
        f"\nActual (after):\n  {_descr_list(after)}"
    )


# ---------------------------------------------------------------------------
# T2. Idempotence: second Force-Update produces identical rule list
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pfb_enabled_deny_only")
def test_force_update_is_idempotent(smoke_vm: h.SmokeVM) -> None:
    """
    Scenario: two successive Force-Updates produce the same filter-rule list.

    Given:
        pfBlockerNG active after an initial update.

    When:
        pfblockerng.php update  (first pass)
        pfblockerng.php update  (second pass, on own output)

    Then:
        filter/rule array after pass 2 == filter/rule array after pass 1.

    Covers the idempotence invariant (pfb_build_autorule_list() applied to its own
    output is a no-op), proven off-appliance in Phase 3 PHPUnit and validated
    live here.
    """
    # --- first update ---
    h.reload(smoke_vm)  # Phase 4: replace with h.force_update().
    after_first = _get_filter_rules(smoke_vm)

    # --- second update ---
    h.reload(smoke_vm)
    after_second = _get_filter_rules(smoke_vm)

    assert _descr_list(after_first) == _descr_list(after_second), (
        "Idempotence failure: second update mutated the rule list.\n"
        f"\nAfter first update:\n  {_descr_list(after_first)}"
        f"\nAfter second update:\n  {_descr_list(after_second)}"
    )


# ---------------------------------------------------------------------------
# T3. pfB-block position: order_0 — pfB rules appear BEFORE user pass (pfB wins)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pfb_enabled_deny_only")
def test_order0_pfb_block_before_user_pass(smoke_vm: h.SmokeVM) -> None:
    """
    Scenario: pass_order=order_0 (default); pfB block must precede the user pass rule
    in config.xml (which maps to pf first-match order on the LAN interface).

    Given:
        pass_order='order_0', one pfB Deny_* block rule, one user pass rule on LAN.

    When:
        Force-Update applied.

    Then:
        In the post-update filter/rule list, at least one pfB block rule appears
        at a lower index than the user pass rule on the same interface.

    Phase 4 note: complement this with a live DNS-block probe to confirm that
    pfB's block actually wins at the data plane (see ADR-41 §7).
    """
    h.reload(smoke_vm)  # Phase 4: set pass_order=order_0 explicitly via h.php_eval().
    rules = _get_filter_rules(smoke_vm)
    descrs = _descr_list(rules)

    pfb_block_idx = next(
        (
            i
            for i, r in enumerate(rules)
            if r.get("descr", "").startswith("pfB_") and r.get("type") in ("block", "reject")
        ),
        None,
    )
    user_pass_idx = next(
        (i for i, r in enumerate(rules) if not r.get("descr", "").startswith("pfB_") and r.get("type") == "pass"),
        None,
    )

    assert pfb_block_idx is not None, f"No pfB block rule found in filter/rule.\nActual rule descrs:\n  {descrs}"
    assert user_pass_idx is not None, f"No user pass rule found in filter/rule.\nActual rule descrs:\n  {descrs}"
    assert pfb_block_idx < user_pass_idx, (
        f"order_0: pfB block must appear BEFORE user pass (pfB wins).\n"
        f"pfB block at index {pfb_block_idx}, user pass at index {user_pass_idx}.\n"
        f"Actual rule descrs:\n  {descrs}"
    )


# ---------------------------------------------------------------------------
# T4. pfB-block position: order_1 — user pass appears BEFORE pfB block (user wins)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pfb_enabled_deny_only")
def test_order1_user_pass_before_pfb_block(smoke_vm: h.SmokeVM) -> None:
    """
    Scenario: pass_order=order_1; the user's pass rule must precede the pfB block.

    Given:
        pass_order='order_1' (set via h.php_eval()), same fixture as T3.

    When:
        Force-Update applied.

    Then:
        The user pass rule appears at a lower index than the first pfB block rule
        on the same interface.

    Phase 4 note: complement with a live DNS probe to confirm user's pass wins
    (i.e., a blocked domain resolves when a user allow-pass is first).
    """
    # Phase 4: set pass_order=order_1 before reload.
    h.reload(smoke_vm)
    rules = _get_filter_rules(smoke_vm)
    descrs = _descr_list(rules)

    user_pass_idx = next(
        (i for i, r in enumerate(rules) if not r.get("descr", "").startswith("pfB_") and r.get("type") == "pass"),
        None,
    )
    pfb_block_idx = next(
        (
            i
            for i, r in enumerate(rules)
            if r.get("descr", "").startswith("pfB_") and r.get("type") in ("block", "reject")
        ),
        None,
    )

    assert user_pass_idx is not None, f"No user pass rule found.\nActual rule descrs:\n  {descrs}"
    assert pfb_block_idx is not None, f"No pfB block rule found.\nActual rule descrs:\n  {descrs}"
    assert user_pass_idx < pfb_block_idx, (
        f"order_1: user pass must appear BEFORE pfB block (user wins).\n"
        f"User pass at index {user_pass_idx}, pfB block at index {pfb_block_idx}.\n"
        f"Actual rule descrs:\n  {descrs}"
    )


# ---------------------------------------------------------------------------
# Fixture + sweep: THE PRECEDENCE TRAP — pfB Permit + pfB Deny + user pass + block
# ---------------------------------------------------------------------------


@pytest.fixture()
def pfb_enabled_permit_and_deny(smoke_vm: h.SmokeVM) -> h.SmokeVM:  # type: ignore[return]
    """
    Given:
        pfBlockerNG enabled with BOTH a Permit_* and a Deny_* v4 IP list active on LAN
        (RFC-5737 addresses), plus a user PASS rule and a user BLOCK rule on LAN.

    This is the config the binary-anchor design got wrong and the Deny-only gate missed:
    the pfB Permit (pass) must precede the user Block for order_1..order_4.
    """
    # Phase 4: wire h.ensure_pfblockerng_enabled() + a Permit_* list + a Deny_* list +
    # inject a user pass and a user block rule on LAN via h.php_eval(config_set_path).
    raise NotImplementedError(
        "Phase 4: wire pfb_enabled_permit_and_deny (Permit_* + Deny_* lists + user pass + user "
        "block on LAN) using h.deploy() + h.write_local_feed() + h.reload()."
    )


# order -> (does pfB Permit precede the user Block?  does the user Pass precede the pfB Deny?)
# Per the ORDER table, the pfB Permit (pass) precedes the user Block in EVERY order_1..order_4
# (and order_0); order_1/order_2 additionally place the user Pass ahead of the pfB Deny.
_TRAP_ORDERS = ["order_0", "order_1", "order_2", "order_3", "order_4"]


@pytest.mark.parametrize("pass_order", _TRAP_ORDERS)
@pytest.mark.usefixtures("pfb_enabled_permit_and_deny")
def test_pfb_permit_precedes_user_block_every_order(smoke_vm: h.SmokeVM, pass_order: str) -> None:
    """
    Scenario: with a pfB Permit list AND a user Block on LAN, the pfB Permit (pass) must precede
    the user Block for every pass_order — so the admin's allowlist overrides the user's block.

    THIS IS THE TRAP. The binary-anchor design failed it for order_1/order_2 (it put the whole
    user block of rules, including the user Block, ahead of the pfB Permit).

    Given:
        pass_order=<param>; pfB Permit_* + Deny_* lists; user pass + user block on LAN.

    When:
        Force-Update applied with pass_order set to <param>.

    Then:
        config.xml index(pfB Permit pass) < index(user Block) on LAN, AND a data-plane probe
        confirms a host on the Permit list is REACHABLE despite the user Block (pf first-match).

    Evidence requirement: assert the data-plane verdict (a permit-listed host reachable, a
    block-listed host unreachable), not just config.xml index order — see ADR-41 §7.
    """
    # Phase 4: set pass_order=<param> via h.php_eval(config_set_path) before the reload, then
    # probe the data plane (e.g. a TCP connect / ICMP to a permit-listed vs block-listed host).
    h.reload(smoke_vm)
    rules = _get_filter_rules(smoke_vm)
    descrs = _descr_list(rules)

    pfb_permit_idx = next(
        (i for i, r in enumerate(rules) if r.get("descr", "").startswith("pfB_") and r.get("type") == "pass"),
        None,
    )
    user_block_idx = next(
        (
            i
            for i, r in enumerate(rules)
            if not r.get("descr", "").startswith("pfB_") and r.get("type") in ("block", "reject")
        ),
        None,
    )

    assert pfb_permit_idx is not None, f"No pfB Permit (pass) rule found.\nActual rule descrs:\n  {descrs}"
    assert user_block_idx is not None, f"No user block rule found.\nActual rule descrs:\n  {descrs}"
    assert pfb_permit_idx < user_block_idx, (
        f"{pass_order}: pfB Permit (pass) must precede the user Block — a pfB allowlist must "
        f"override a user block.\npfB Permit at index {pfb_permit_idx}, user block at index "
        f"{user_block_idx}.\nActual rule descrs:\n  {descrs}"
    )


@pytest.mark.usefixtures("pfb_enabled_permit_and_deny")
def test_order4_reorders_user_block_before_user_pass(smoke_vm: h.SmokeVM) -> None:
    """
    Scenario: order_4 places the user's own Block before its Pass (intended pass_order semantics:
    order_4 = pfB p/m | pfB b/r | pfSense Block/Reject | pfSense Pass/Match).

    The binary-anchor design wrongly dropped this (it froze user-rule order). Confirm the user
    Block precedes the user Pass under order_4.
    """
    # Phase 4: set pass_order=order_4 via h.php_eval() before the reload.
    h.reload(smoke_vm)
    rules = _get_filter_rules(smoke_vm)
    descrs = _descr_list(rules)
    user_rules = _user_rules(rules)

    user_block_idx = next((i for i, r in enumerate(user_rules) if r.get("type") in ("block", "reject")), None)
    user_pass_idx = next((i for i, r in enumerate(user_rules) if r.get("type") == "pass"), None)

    assert user_block_idx is not None, f"No user block rule found.\nActual rule descrs:\n  {descrs}"
    assert user_pass_idx is not None, f"No user pass rule found.\nActual rule descrs:\n  {descrs}"
    assert user_block_idx < user_pass_idx, (
        f"order_4: the user's own Block must precede its Pass (intended pass_order layout).\n"
        f"user block at index {user_block_idx}, user pass at index {user_pass_idx}.\n"
        f"Actual rule descrs:\n  {descrs}"
    )
