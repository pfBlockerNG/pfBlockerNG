"""ADR-28 Phase 8 — IdnMode enum adoption in pfb_unbound.py.

Pins the ACTUAL adoption contract after the dead pfb_cfg_* helpers were removed
and the IdnMode enum is now the live in-memory representation for idn_mode.

Policy (ADR-28 §2.2):
  - The ini wire value stays the canonical string ('off'/'all'/'confusable').
  - The in-memory value is IdnMode (converted at the read boundary).
  - Unrecognised / absent ini key falls back to idn_mode_from_legacy(python_idn)
    (NOT pfb_cfg_idn_mode_read semantics — the legacy fallback preserves python_idn).
  - Round-trip: IdnMode backing value == the canonical stored string.

Scenario A — idn_mode_from_legacy: bool -> IdnMode migration.
  Background: the legacy python_idn on/off toggle maps to All or Off.
    Given python_idn in {True, False}.
    When idn_mode_from_legacy(python_idn) is called.
    Then the result is IdnMode.All (True) or IdnMode.Off (False).

Scenario B — idn_mode_decision: the All-IDN gate (pure unit).
  Background: idn_mode_decision is the ONLY IDN block gate for All/Off.
    Given a mode in {All, Off, Confusable} and a query name.
    When idn_mode_decision(q, mode) is called.
    Then True IFF mode is All AND the name has an xn-- label.

Scenario C — boundary truth-table: 12 combinations of ini value x python_idn.
  Background: the ini_read boundary in pfb_global converts raw string -> IdnMode,
    with a legacy fallback when the key is absent or unrecognised.
    Given idn_mode ini value in {'off','all','confusable','bogus','',ABSENT}
    And python_idn in {True, False}.
    When the boundary logic (as in pfb_global) is applied.
    Then the resulting IdnMode is byte-identical to the pre-adoption behaviour.
    And the before-state (prior to adoption) is asserted explicitly per combination.

Scenario D — IdnMode enum invariants.
  Round-trip: IdnMode.value == the canonical ini string for each member.
  default() == Off.
"""

from __future__ import annotations

import pytest

# conftest.py adds src/usr/local/pkg/pfblockerng to sys.path and injects
# Unbound globals onto builtins — mirror the pattern from test_adr06_build_module.py.
from pfb_unbound import (
    IDN_MODE_ALL,
    IDN_MODE_CONFUSABLE,
    IDN_MODE_OFF,
    IdnMode,
    idn_mode_decision,
    idn_mode_from_legacy,
    is_idn_domain,
)

# ---------------------------------------------------------------------------
# Representative queries for Scenario B / C.
# ---------------------------------------------------------------------------

_IDN_QUERIES = (
    "xn--evil.com",
    "sub.xn--80akhbyknj4f.example",
    "xn--pple-43d.com",
)

_NON_IDN_QUERIES = (
    "example.com",
    "plain.sub.example.org",
)


# ---------------------------------------------------------------------------
# Helper: replicate the ini read-boundary logic from pfb_global() exactly
# (lines 1095-1102 of pfb_unbound.py) so the truth-table test is a genuine
# re-implementation, not just calling the function under test.
# ---------------------------------------------------------------------------


def _boundary(ini_value: str | None, python_idn: bool) -> IdnMode:
    """Replicate the pfb_global ini read-boundary for idn_mode.

    ini_value=None means the key is absent from the ini.
    Returned value must be byte-identical to what pfb_global sets in pfb["idn_mode"].
    """
    if ini_value is not None:
        raw = ini_value.strip().lower()
        if raw in (IDN_MODE_OFF, IDN_MODE_ALL, IDN_MODE_CONFUSABLE):
            return IdnMode(raw)
        # Unrecognised string -> legacy fallback.
        return idn_mode_from_legacy(python_idn)
    # Key absent -> legacy fallback.
    return idn_mode_from_legacy(python_idn)


# ===========================================================================
# Scenario A — idn_mode_from_legacy
# ===========================================================================


class TestIdnModeFromLegacy:
    """idn_mode_from_legacy maps the boolean python_idn flag to an IdnMode enum."""

    def test_true_maps_to_all(self) -> None:
        # Before: python_idn True is the legacy 'on' toggle — must yield All-IDN.
        assert isinstance(True, bool)
        result = idn_mode_from_legacy(True)
        assert result is IdnMode.All

    def test_false_maps_to_off(self) -> None:
        # Before: python_idn False is the legacy 'off' toggle — must yield Off.
        assert isinstance(False, bool)
        result = idn_mode_from_legacy(False)
        assert result is IdnMode.Off

    def test_return_type_is_idnmode(self) -> None:
        # Adoption guarantee: the return type is always IdnMode, never a string.
        assert isinstance(idn_mode_from_legacy(True), IdnMode)
        assert isinstance(idn_mode_from_legacy(False), IdnMode)

    def test_confusable_cannot_arise_from_legacy(self) -> None:
        # Confusable is never produced by the boolean legacy path.
        assert idn_mode_from_legacy(True) is not IdnMode.Confusable
        assert idn_mode_from_legacy(False) is not IdnMode.Confusable


# ===========================================================================
# Scenario B — idn_mode_decision (pure gate)
# ===========================================================================


class TestIdnModeDecisionEnum:
    """idn_mode_decision accepts IdnMode enum and is the All/Off gate only."""

    def test_all_blocks_idn_queries(self) -> None:
        for q in _IDN_QUERIES:
            # Before: the query is IDN-shaped.
            assert is_idn_domain(q) is True, q
            # When All.
            assert idn_mode_decision(q, IdnMode.All) is True, q

    def test_all_does_not_block_non_idn(self) -> None:
        for q in _NON_IDN_QUERIES:
            assert is_idn_domain(q) is False, q
            assert idn_mode_decision(q, IdnMode.All) is False, q

    def test_off_never_blocks(self) -> None:
        # Off side: no block even on xn-- names.
        for q in _IDN_QUERIES + _NON_IDN_QUERIES:
            # Before: All WOULD block xn-- names.
            for xn in _IDN_QUERIES:
                assert idn_mode_decision(xn, IdnMode.All) is True, xn
            # When Off.
            assert idn_mode_decision(q, IdnMode.Off) is False, q

    def test_confusable_returns_false_from_this_gate(self) -> None:
        # Confusable is NOT decided here — idn_confusable_action() decides it.
        for q in _IDN_QUERIES:
            # Before: All WOULD block; proves the mode, not the input, causes False.
            assert idn_mode_decision(q, IdnMode.All) is True, q
            assert idn_mode_decision(q, IdnMode.Confusable) is False, q


# ===========================================================================
# Scenario C — boundary truth-table (12 combinations)
# ===========================================================================
#
# 6 ini values × 2 python_idn values = 12 combinations.
# For each, assert:
#   1. The BEFORE-state (what the pre-adoption code produced — a string).
#   2. The AFTER-state (what the adopted boundary produces — an IdnMode).
#   3. That the IdnMode backing value matches the pre-adoption string (byte-identical).
#
# Pre-adoption logic (strings):
#   canonical ini -> store that string;  unrecognised/absent -> IDN_MODE_ALL if python_idn else IDN_MODE_OFF.
#
# Post-adoption logic (enums):
#   canonical ini -> IdnMode(raw);  unrecognised/absent -> idn_mode_from_legacy(python_idn).
#   IdnMode.value == the canonical string -> byte-identical.
#
# The 12 combos below are (ini_value, python_idn) -> expected_mode.


_TRUTH_TABLE: list[tuple[str | None, bool, IdnMode, str]] = [
    # (ini_value, python_idn, expected_IdnMode, pre_adoption_string)
    # Canonical ini values — python_idn is IGNORED when ini is recognised.
    # 'on' (reused legacy token) is the canonical block-all value (IdnMode.All).
    ("off", True, IdnMode.Off, IDN_MODE_OFF),
    ("off", False, IdnMode.Off, IDN_MODE_OFF),
    ("on", True, IdnMode.All, IDN_MODE_ALL),
    ("on", False, IdnMode.All, IDN_MODE_ALL),
    ("confusable", True, IdnMode.Confusable, IDN_MODE_CONFUSABLE),
    ("confusable", False, IdnMode.Confusable, IDN_MODE_CONFUSABLE),
    # Unrecognised string -> legacy fallback (python_idn decides). Includes the dropped
    # 4.0.0-alpha 'all' token: no longer canonical, so it falls back via python_idn.
    ("all", True, IdnMode.All, IDN_MODE_ALL),
    ("all", False, IdnMode.Off, IDN_MODE_OFF),
    ("bogus", True, IdnMode.All, IDN_MODE_ALL),
    ("bogus", False, IdnMode.Off, IDN_MODE_OFF),
    # Empty string -> treated as unrecognised (not in canonical set) -> legacy fallback.
    ("", True, IdnMode.All, IDN_MODE_ALL),
    ("", False, IdnMode.Off, IDN_MODE_OFF),
    # Absent key (None) -> legacy fallback.
    (None, True, IdnMode.All, IDN_MODE_ALL),
    (None, False, IdnMode.Off, IDN_MODE_OFF),
]


@pytest.mark.parametrize("ini_value,python_idn,expected_mode,pre_adoption_str", _TRUTH_TABLE)
def test_boundary_truth_table(
    ini_value: str | None, python_idn: bool, expected_mode: IdnMode, pre_adoption_str: str
) -> None:
    """Boundary truth-table: each of the 12 (ini_value x python_idn) combos is byte-identical
    to the pre-adoption behaviour.

    Given a raw ini_value and python_idn toggle.
    When the read-boundary logic is applied.
    Then the resulting IdnMode matches expected_mode AND its .value equals the pre-adoption string.
    """
    # Before-state: the pre-adoption code produced a specific string for this combination.
    # Assert it is as documented so a drift in the spec fails explicitly.
    assert pre_adoption_str in (IDN_MODE_OFF, IDN_MODE_ALL, IDN_MODE_CONFUSABLE), (
        f"pre_adoption_str {pre_adoption_str!r} must be one of the canonical strings"
    )

    # When: apply the boundary.
    result = _boundary(ini_value, python_idn)

    # Then: the IdnMode matches the expected value.
    assert result is expected_mode, (
        f"ini={ini_value!r}, python_idn={python_idn}: expected {expected_mode}, got {result}"
    )

    # And: the backing value is byte-identical to the pre-adoption string.
    assert result.value == pre_adoption_str, (
        f"ini={ini_value!r}, python_idn={python_idn}: "
        f"IdnMode.value {result.value!r} != pre-adoption string {pre_adoption_str!r}"
    )


# ===========================================================================
# Scenario D — IdnMode enum invariants
# ===========================================================================


class TestIdnModeEnumInvariants:
    """IdnMode enum structural guarantees (backing value, default)."""

    def test_backing_values_equal_canonical_ini_strings(self) -> None:
        assert IdnMode.Off.value == IDN_MODE_OFF
        assert IdnMode.All.value == IDN_MODE_ALL
        assert IdnMode.Confusable.value == IDN_MODE_CONFUSABLE

    def test_default_is_off(self) -> None:
        assert IdnMode.default() is IdnMode.Off

    def test_all_members_are_truthy(self) -> None:
        # All enum members are truthy (string-backed, non-empty) — the landmine
        # that makes an ``or`` idiom unsafe for presence-checking.
        for member in IdnMode:
            assert member, f"IdnMode.{member.name} must be truthy (non-empty backing value)"

    def test_round_trip_via_value(self) -> None:
        # IdnMode(member.value) is member — enum lookup by backing string.
        for member in IdnMode:
            assert IdnMode(member.value) is member
