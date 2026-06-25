"""
Live-VM oracle: immutable-user-rule splice (ADR-41 Phase 3).

Verifies that pfb_build_autorule_list() applied by sync_package_pfblockerng()
never drops, duplicates, or reorders user-authored firewall rules across an
Enable/Force-Update cycle.

LIVE RUN DEFERRED TO PHASE 4
-----------------------------
The live-VM harness (ADR-04) proves the on-box pf state after pfBlockerNG reloads;
Phase 4 is the designated phase for the per-pass_order precedence sweep.
This file is written in Phase 3 so Phase 4 can extend and execute it without
rewriting the fixture structure from scratch.

To run manually once Phase 4 is underway (box at 10.0.0.23, NO_TWO_VM=1):

    python -m pytest tests/smoke/test_smoke_autorule_immutable.py \
        --override-ini="addopts=" -v

All tests in this file are marked ``immutable_autorule`` (a Phase-4 gate marker
— not yet wired into CI).
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
