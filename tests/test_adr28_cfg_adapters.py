"""ADR-28 Phase 8 — IdnMode enum adoption in pfb_unbound.py.

Pins the ACTUAL adoption contract after the dead pfb_cfg_* helpers were removed
and the IdnMode enum is now the live in-memory representation for idn_mode.

Policy (ADR-28 §2.2):
  - The ini wire value stays the recognised string ('off'/'on'/'confusable');
    present empty is an explicit Off token at this boundary.
  - The in-memory value is IdnMode (converted at the read boundary).
  - Unrecognised / absent ini key falls back to idn_mode_from_legacy(python_idn)
    (NOT pfb_cfg_idn_mode_read semantics — the legacy fallback preserves python_idn).
  - IdnMode backing values remain the existing internal tokens; the PHP adapter owns
    canonical empty Off storage.

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

Scenario C — boundary truth-table: 14 combinations of ini value x python_idn.
  Background: the ini_read boundary in pfb_global converts raw string -> IdnMode,
    with a legacy fallback when the key is absent or unrecognised.
    Given idn_mode ini value in {'off','on','confusable','all','bogus','',ABSENT}
    And python_idn in {True, False}.
    When the boundary logic (as in pfb_global) is applied.
    Then the resulting IdnMode and backing token match the production read boundary.

Scenario D — IdnMode enum invariants.
  IdnMode.value retains the enum's internal token for each member.
  default() == Off.
"""

from __future__ import annotations

from typing import Any

import pytest
import unboundmodule

import pfb_unbound

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
# Helper: drive the actual init_standard() MAIN-section reader so the truth-table
# test exercises the production boundary rather than a copied implementation.
# ---------------------------------------------------------------------------


def _production_boundary(tmp_path: Any, monkeypatch: Any, ini_value: str | None, python_idn: bool) -> IdnMode:
    lines = ["[MAIN]", "python_enable = false", f"python_idn = {'true' if python_idn else 'false'}"]
    if ini_value is not None:
        lines.append(f"idn_mode = {ini_value}")
    (tmp_path / "pfb_unbound.ini").write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    pfb_unbound.pfb["mod_maxminddb_e"] = "stub"
    try:
        assert pfb_unbound.init_standard(0, unboundmodule.module_env()) is True
        return pfb_unbound.pfb["idn_mode"]
    finally:
        pfb_unbound.deinit(0)


def test_present_empty_idn_mode_is_explicit_off(tmp_path: Any, monkeypatch: Any) -> None:
    # Present idn_mode='' is the PHP gateway's empty Off token; it must not
    # fall back to python_idn as an absent key does.
    assert _production_boundary(tmp_path, monkeypatch, "", True) is IdnMode.Off
    assert _production_boundary(tmp_path, monkeypatch, "", False) is IdnMode.Off


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
# Scenario C — boundary truth-table (14 combinations)
# ===========================================================================
#
# 7 ini values × 2 python_idn values = 14 combinations.
# For each, assert:
#   1. The IdnMode selected by the production boundary.
#   2. The enum backing value used by existing runtime consumers.
#
# Current boundary logic:
#   canonical ini -> IdnMode(raw);  present empty -> Off; unrecognised/absent -> legacy fallback.
#   IdnMode.value remains the existing enum's internal token.


_TRUTH_TABLE: list[tuple[str | None, bool, IdnMode, str]] = [
    # (ini_value, python_idn, expected_IdnMode, expected_backing_value)
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
    # Present empty string -> explicit Off, independent of python_idn.
    ("", True, IdnMode.Off, IDN_MODE_OFF),
    ("", False, IdnMode.Off, IDN_MODE_OFF),
    # Absent key (None) -> legacy fallback.
    (None, True, IdnMode.All, IDN_MODE_ALL),
    (None, False, IdnMode.Off, IDN_MODE_OFF),
]


@pytest.mark.parametrize("ini_value,python_idn,expected_mode,expected_value", _TRUTH_TABLE)
def test_boundary_truth_table(
    tmp_path: Any,
    monkeypatch: Any,
    ini_value: str | None,
    python_idn: bool,
    expected_mode: IdnMode,
    expected_value: str,
) -> None:
    """Boundary truth-table: all 14 ``ini_value``/``python_idn`` combinations.

    Given a raw ini_value and python_idn toggle.
    When the production read boundary runs.
    Then the IdnMode and its existing backing value match the contract.
    """
    assert expected_value in (IDN_MODE_OFF, IDN_MODE_ALL, IDN_MODE_CONFUSABLE), (
        f"expected_value {expected_value!r} must be an enum backing token"
    )

    # When: execute the production init boundary.
    result = _production_boundary(tmp_path, monkeypatch, ini_value, python_idn)

    # Then: the IdnMode matches the expected value.
    assert result is expected_mode, (
        f"ini={ini_value!r}, python_idn={python_idn}: expected {expected_mode}, got {result}"
    )

    # And: the backing value remains the enum's existing internal token.
    assert result.value == expected_value, (
        f"ini={ini_value!r}, python_idn={python_idn}: IdnMode.value {result.value!r} != expected {expected_value!r}"
    )


# ===========================================================================
# Scenario D — IdnMode enum invariants
# ===========================================================================


class TestIdnModeEnumInvariants:
    """IdnMode enum structural guarantees (backing value, default)."""

    def test_backing_values_remain_internal_tokens(self) -> None:
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
