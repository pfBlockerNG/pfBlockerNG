"""ADR-08 Phase 3 baseline golden -- pins TODAY's IDN-feature behaviour.

This is the no-regression gate the later analyzer phases diff against. Phase 5 adds
the cross-script-homoglyph tier to the matcher's IDN branch; doing that on top of the
old inline block risks SILENTLY changing the two behaviour-preserving modes (Off and
All-IDN). So here we extract the inline decision into a pure unit and pin its contract
*before* any analyzer exists:

  - IDN_MODE_OFF        : the IDN feed never fires (every xn-- query resolves normally).
  - IDN_MODE_ALL        : EVERY xn-- query is blocked as feed="IDN"/group="DNSBL_IDN"
                          (pure prefix match, no punycode decode) -- byte-identical to the
                          pre-ADR ``cfg["python_idn"] and is_idn_domain(q_name)`` branch.
  - IDN_MODE_CONFUSABLE : INERT this phase -- behaves EXACTLY like OFF (no analyzer yet;
                          it is wired in Phase 5). Pinned so a later wiring change that
                          accidentally activated it on this branch goes red here first.

Non-IDN queries are unaffected in EVERY mode (no xn-- => the IDN branch is never taken).

The legacy on/off ``python_idn`` flag migrates to a mode via ``idn_mode_from_legacy``
('on' -> All-IDN, off -> Off, RESULTS/01 SS1); that migration is pinned too.
"""

from collections import defaultdict
from typing import Any

from pfb_unbound import (
    IDN_MODE_ALL,
    IDN_MODE_CONFUSABLE,
    IDN_MODE_OFF,
    evaluate_domain,
    idn_mode_decision,
    idn_mode_from_legacy,
    is_idn_domain,
)

# A representative set of IDN (xn--) query forms the All-IDN feed must catch and Off/
# Confusable must ignore: leading-label xn--, a deeper xn-- label, and the textbook
# Latin+Cyrillic homograph A-label (xn--pple-43d = аpple). The matcher's IDN test is a
# pure PREFIX match -- it must fire on ALL of these regardless of decode-ability.
_IDN_QUERIES = (
    "xn--evil.com",  # leading xn-- label
    "sub.xn--80akhbyknj4f.example",  # xn-- in a deeper label (".xn--" path)
    "xn--pple-43d.com",  # the аpple homograph A-label (a Phase-5 malicious case)
)

# Names with NO xn-- label anywhere -- the IDN branch must never touch these in any mode.
_NON_IDN_QUERIES = (
    "example.com",
    "plain.sub.example.org",
    "xnnot--prefix.com",  # "xn" without the "--" boundary: NOT an IDN label
)


def _make_cfg(**overrides: Any) -> dict:
    """Minimal evaluate_domain cfg with the IDN feed the only enabled stratum.

    Defaults leave every other matcher stratum off so a hit can ONLY come from the IDN
    branch -- isolating exactly the behaviour this golden pins.
    """
    base = {
        "python_blocking": True,
        "dataDB": False,
        "zoneDB": False,
        "python_tld": False,
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "regexDB": False,
        "whiteDB": False,
        "python_tld_seg": 2,
        "hstsDB": False,
        "hsts_tlds": (),
    }
    base.update(overrides)
    return base


def _make_containers() -> dict:
    return {
        "dataDB": {},
        "zoneDB": {},
        "whiteDB": {},
        "hstsDB": {},
        "regexDB": defaultdict(str),
        "feedGroupIndexDB": defaultdict(list),
    }


def _evaluate(q_name: str, **cfg_overrides: Any) -> Any:
    return evaluate_domain(q_name, q_name, "com", False, _make_cfg(**cfg_overrides), _make_containers())


# ---------------------------------------------------------------------------
# The pure extracted unit -- contract pinned directly (trivial mapping, plain asserts).
# ---------------------------------------------------------------------------


class TestIdnModeDecisionUnit:
    """``idn_mode_decision`` is the pure IDN feed decision lifted out of evaluate_domain.

    Every (mode x IDN-ness) cell is asserted -- the unit blocks IFF mode is All-IDN AND
    the name is an xn-- label, and nothing else.
    """

    def test_all_mode_blocks_every_idn_query(self) -> None:
        # All-IDN: the on side -- each xn-- form returns True (block as IDN feed).
        for q in _IDN_QUERIES:
            assert is_idn_domain(q) is True, q
            assert idn_mode_decision(q, IDN_MODE_ALL) is True, q

    def test_all_mode_ignores_non_idn_query(self) -> None:
        # All-IDN does NOT block a name without an xn-- label (the branch needs both).
        for q in _NON_IDN_QUERIES:
            assert is_idn_domain(q) is False, q
            assert idn_mode_decision(q, IDN_MODE_ALL) is False, q

    def test_off_mode_never_blocks(self) -> None:
        # Off: the off side -- no IDN block even for an xn-- query.
        for q in _IDN_QUERIES + _NON_IDN_QUERIES:
            assert idn_mode_decision(q, IDN_MODE_OFF) is False, q

    def test_confusable_mode_is_inert_this_phase(self) -> None:
        # Confusable is a RECOGNISED mode but behaves as OFF until the Phase-5 analyzer
        # lands: it must NOT block any xn-- query yet (would be a premature activation).
        for q in _IDN_QUERIES:
            # Sanity: All-IDN WOULD block these, so a green here proves Confusable is the
            # cause of the non-block, not an always-False input.
            assert idn_mode_decision(q, IDN_MODE_ALL) is True, q
            assert idn_mode_decision(q, IDN_MODE_CONFUSABLE) is False, q


class TestIdnModeFromLegacy:
    """The on/off ``python_idn`` -> mode migration (RESULTS/01 SS1)."""

    def test_legacy_on_maps_to_all_idn(self) -> None:
        # 'on' (python_idn True) must reproduce today's block-all-IDN behaviour.
        assert idn_mode_from_legacy(True) == IDN_MODE_ALL

    def test_legacy_off_maps_to_off(self) -> None:
        assert idn_mode_from_legacy(False) == IDN_MODE_OFF


# ---------------------------------------------------------------------------
# The matcher contract -- evaluate_domain end-to-end through the IDN branch.
# Scenario: the IDN feed decision inside evaluate_domain, across the three modes.
#   Background: a cfg with EVERY stratum but the IDN feed disabled, so any block can
#               only be the IDN branch; containers empty.
# ---------------------------------------------------------------------------


class TestEvaluateDomainIdnBaselineGolden:
    def test_all_idn_blocks_every_idn_query_as_idn_feed(self) -> None:
        # Given All-IDN mode; When each xn-- query is evaluated; Then it is found and
        # tagged feed="IDN"/group="DNSBL_IDN" -- byte-identical to pfb_unbound:4342 today.
        for q in _IDN_QUERIES:
            dec = _evaluate(q, idn_mode=IDN_MODE_ALL)
            assert dec.is_found is True, q
            assert dec.feed == "IDN", q
            assert dec.group == "DNSBL_IDN", q

    def test_off_lets_every_idn_query_resolve(self) -> None:
        # Given Off mode; When the SAME xn-- queries are evaluated; Then none is found
        # (the IDN feed never fires). Paired with the All-IDN case above, this proves the
        # mode -- not the input -- decides: identical queries, opposite verdicts.
        for q in _IDN_QUERIES:
            assert _evaluate(q, idn_mode=IDN_MODE_ALL).is_found is True, q  # before-state
            assert _evaluate(q, idn_mode=IDN_MODE_OFF).is_found is False, q

    def test_confusable_is_inert_and_resolves_like_off(self) -> None:
        # Given Confusable mode (INERT this phase); When an xn-- query is evaluated; Then
        # it resolves exactly as in Off -- the analyzer is not wired until Phase 5. The
        # All-IDN assertion first pins that these queries WOULD block, so green proves the
        # Confusable branch is the inert cause.
        for q in _IDN_QUERIES:
            assert _evaluate(q, idn_mode=IDN_MODE_ALL).is_found is True, q  # before-state
            assert _evaluate(q, idn_mode=IDN_MODE_CONFUSABLE).is_found is False, q

    def test_non_idn_unaffected_in_every_mode(self) -> None:
        # Non-IDN queries (no xn-- label) are never touched by the IDN branch, in ANY mode.
        for mode in (IDN_MODE_OFF, IDN_MODE_ALL, IDN_MODE_CONFUSABLE):
            for q in _NON_IDN_QUERIES:
                assert _evaluate(q, idn_mode=mode).is_found is False, (mode, q)

    def test_legacy_python_idn_cfg_still_blocks_all_idn(self) -> None:
        # Backward-compat: a cfg carrying ONLY the legacy python_idn=True (no idn_mode key,
        # as the pre-ADR callers/tests build it) must still block all IDN -- the matcher
        # derives the mode from python_idn when idn_mode is absent.
        cfg = _make_cfg(python_idn=True)
        for q in _IDN_QUERIES:
            dec = evaluate_domain(q, q, "com", False, cfg, _make_containers())
            assert dec.is_found is True, q
            assert dec.feed == "IDN", q
            assert dec.group == "DNSBL_IDN", q
        # And legacy python_idn=False (absent idn_mode) resolves -- the off side.
        cfg_off = _make_cfg(python_idn=False)
        for q in _IDN_QUERIES:
            assert evaluate_domain(q, q, "com", False, cfg_off, _make_containers()).is_found is False, q
