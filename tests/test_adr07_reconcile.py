"""ADR-07 Phase 5 -- production Stage-B reconcile (``pfb_unbound.reconcile``).

WHAT THIS PINS
--------------
``reconcile(rules, tlds, exclusion) -> ReconcileResult`` is the pure, reentrant
Stage-B step: it takes the typed ``Rule`` stream from Stage-A (``parse_abp``) and
produces the pre-emit rule sets -- $badfilter-pruned (feed-only; user-immune),
anchored-regex reduced to domain/wildcard, domain blocks classified data/zone,
and every surviving rule banded (1-6). It is NOT wired into ``build()`` / init and
NEVER compiles/executes a regex (compile/load is Phase 6).

The canonical TARGET is the Phase-2 oracle
(``tests/test_adr07_decision_spec.py``: ``reconcile`` / ``reduce_regex`` /
``priority`` / ``decide``); this suite asserts the production reconcile yields the
SAME net DNS decision as ``decide`` over the corpus + the precedence cases, plus
the $badfilter prune (feed vs user), the reduction equivalence, classify reuse,
band assignment, and reentrancy.

Pure pytest, stdlib only, no Unbound symbols (CI-runnable; ADR.md fact 4).
"""

from __future__ import annotations

import importlib.util
import os
from types import ModuleType

import pytest

import pfb_unbound as P
from tests import test_adr07_decision_spec as spec

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _spike() -> ModuleType:
    spike_path = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "spike_adr07_regex.py")
    s = importlib.util.spec_from_file_location("spike_adr07_regex", spike_path)
    assert s and s.loader
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def _corpus_lines() -> list[str]:
    base = os.path.join(os.path.dirname(__file__), "fixtures", "adr07_corpus")
    lines: list[str] = []
    for fn in ("abp_sample.txt", "regex_reducible.txt", "regex_irreducible.txt"):
        with open(os.path.join(base, fn), encoding="utf-8") as fh:
            lines += fh.read().splitlines()
    return lines


def _reducible_lines() -> list[str]:
    base = os.path.join(os.path.dirname(__file__), "fixtures", "adr07_corpus")
    with open(os.path.join(base, "regex_reducible.txt"), encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("!")]


def _irreducible_lines() -> list[str]:
    base = os.path.join(os.path.dirname(__file__), "fixtures", "adr07_corpus")
    with open(os.path.join(base, "regex_irreducible.txt"), encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("!")]


def _production_rules(lines: list[str], provenance: str = P.RULE_PROV_FEED) -> list[P.Rule]:
    """parse_abp each line (skip None) -> production Rule list."""
    out = []
    for ln in lines:
        r = P.parse_abp(ln, provenance=provenance)
        if r is not None:
            out.append(r)
    return out


# A tiny TLD oracle covering the corpus' registrable parents (so classify folds a
# ZONE block to its parent). Mirrors the ADR-06 tld master shape tlds[tld][suffix].
_TLDS: dict[str, dict[str, str]] = {
    "com": {"com": ""},
    "net": {"net": ""},
    "org": {"org": ""},
    "example": {"example": ""},
    "io": {"io": ""},
}
_EXCLUSION: set[str] = set()


def _reconcile(lines: list[str], provenance: str = P.RULE_PROV_FEED) -> P.ReconcileResult:
    return P.reconcile(_production_rules(lines, provenance), _TLDS, _EXCLUSION)


def _resolve(result: P.ReconcileResult, query: str) -> str:
    """Reduce a ReconcileResult + a query to the spec's {block, resolve, pass}
    label, using the SAME 6-band rule decide() uses: blocked iff a block matches
    AND block_band > allow_band (no ties). This is the production-side mirror of
    the oracle decide() -- the matcher in Phase 6 implements the live version.
    """
    q = query.strip(".").lower()
    bp = 0
    ap = 0
    matched = False

    def dom_match(domain: str, wildcard: bool) -> bool:
        if q == domain:
            return True
        return wildcard and q.endswith("." + domain)

    for b in result.block_domains:
        # zone keys cover subdomains; data keys are exact.
        wildcard = b.cls == P.DNSBL_CLASS_ZONE
        if dom_match(b.key, wildcard):
            matched = True
            bp = max(bp, b.band)
    for a in result.allow_domains:
        if dom_match(a.domain, a.wildcard):
            matched = True
            ap = max(ap, a.band)
    import re

    for rr in result.block_regex_irreducible:
        if re.search(rr.pattern, q):
            matched = True
            bp = max(bp, rr.band)
    for rr in result.allow_regex_irreducible:
        if re.search(rr.pattern, q):
            matched = True
            ap = max(ap, rr.band)

    if not matched:
        return "pass"
    if bp > ap:
        return "block"
    return "resolve"


# --------------------------------------------------------------------------- #
# 1. $badfilter prune: feed-only, user-immune
# --------------------------------------------------------------------------- #
class TestBadfilterPrune:
    def test_feed_badfilter_removes_matching_feed_block(self) -> None:
        res = _reconcile(["||y.example.com^", "||y.example.com^$badfilter"])
        # both feed rules are gone: the block is pruned, the badfilter never emits.
        assert _resolve(res, "y.example.com") == "pass"
        assert res.pruned == 1
        assert res.skipped_badfilter == 1
        assert res.block_domains == []

    def test_feed_badfilter_does_not_touch_user_rule(self) -> None:
        # USER block with the SAME signature must survive a FEED $badfilter (fact 7).
        rules = _production_rules(["||y.example.com^"], provenance=P.RULE_PROV_USER)
        rules += _production_rules(["||y.example.com^$badfilter"], provenance=P.RULE_PROV_FEED)
        res = P.reconcile(rules, _TLDS, _EXCLUSION)
        assert _resolve(res, "y.example.com") == "block"
        assert res.pruned == 0  # user rule never pruned
        assert any(b.band == P.PRIO_USER_BLOCK for b in res.block_domains)

    def test_badfilter_different_signature_not_pruned(self) -> None:
        # ||x^$important has signature ("x",("important",)); ||x^$badfilter has
        # ("x",()) -- different sig, so the $important block survives.
        res = _reconcile(["||x.example.com^$important", "||x.example.com^$badfilter"])
        assert _resolve(res, "x.example.com") == "block"
        assert res.pruned == 0

    def test_badfilter_only_prunes_its_signature(self) -> None:
        res = _reconcile(
            [
                "||a.example.com^",
                "||b.example.com^",
                "||a.example.com^$badfilter",
            ]
        )
        assert _resolve(res, "a.example.com") == "pass"
        assert _resolve(res, "b.example.com") == "block"

    def test_feed_badfilter_prunes_cross_feed_block(self) -> None:
        """A FEED ``$badfilter`` prunes a matching-signature block in a DIFFERENT feed.

        The prune collects ``$badfilter`` signatures across ALL feed rules and drops
        every feed rule with a matching signature -- it is scoped by PROVENANCE (feed,
        not user), NOT by feed identity. So feed A's ``$badfilter`` neutralizes feed B's
        block (matching uBlock Origin's cross-list ``$badfilter``). Transition test:
        feed B's block stands ALONE, then feed A's ``$badfilter`` prunes it.
        """
        block_b = P.parse_abp("||y.example.com^", provenance=P.RULE_PROV_FEED, feed="FeedB")
        bad_a = P.parse_abp("||y.example.com^$badfilter", provenance=P.RULE_PROV_FEED, feed="FeedA")
        assert block_b is not None and bad_a is not None
        assert block_b.feed == "FeedB" and bad_a.feed == "FeedA"  # genuinely two different feeds

        # BEFORE: feed B's block alone -> the name is blocked.
        before = P.reconcile([block_b], _TLDS, _EXCLUSION)
        assert _resolve(before, "y.example.com") == "block"
        assert before.pruned == 0

        # AFTER: add feed A's $badfilter (different feed, same signature) -> feed B's
        # block is pruned cross-feed and the name resolves.
        after = P.reconcile([block_b, bad_a], _TLDS, _EXCLUSION)
        assert _resolve(after, "y.example.com") == "pass"
        assert after.pruned == 1
        assert after.skipped_badfilter == 1

    def test_feed_badfilter_does_not_prune_cross_feed_user_block(self) -> None:
        """Cross-feed reach is PROVENANCE-bounded: a FEED ``$badfilter`` (feed A) does
        NOT prune a USER block in feed B with the same signature -- sovereignty holds
        across feeds, not only within one (the complement of the cross-feed prune above).
        """
        user_block_b = P.parse_abp("||y.example.com^", provenance=P.RULE_PROV_USER, feed="FeedB")
        bad_a = P.parse_abp("||y.example.com^$badfilter", provenance=P.RULE_PROV_FEED, feed="FeedA")
        assert user_block_b is not None and bad_a is not None
        res = P.reconcile([user_block_b, bad_a], _TLDS, _EXCLUSION)
        assert _resolve(res, "y.example.com") == "block"  # user block survives the cross-feed feed $badfilter
        assert res.pruned == 0
        assert any(b.band == P.PRIO_USER_BLOCK for b in res.block_domains)


# --------------------------------------------------------------------------- #
# 2. Regex reduction: reducible -> domain rule (== dict form); irreducible stays
# --------------------------------------------------------------------------- #
class TestRegexReduction:
    def test_reducible_block_folds_to_domain(self) -> None:
        res = _reconcile(["/^(.+\\.)?doubleclick\\.net$/"])
        assert res.block_regex_irreducible == []  # folded away
        assert res.reduced == 1
        # behaves like ||doubleclick.net^ (zone: domain + subs)
        assert _resolve(res, "doubleclick.net") == "block"
        assert _resolve(res, "ad.doubleclick.net") == "block"
        assert _resolve(res, "other.net") == "pass"

    def test_reducible_exact_folds_to_data(self) -> None:
        res = _reconcile(["/^pixel\\.example\\.com$/"])
        assert res.reduced == 1
        # exact: the domain blocks, a subdomain does NOT
        assert _resolve(res, "pixel.example.com") == "block"
        assert _resolve(res, "sub.pixel.example.com") == "pass"
        assert any(b.cls == P.DNSBL_CLASS_DATA for b in res.block_domains)

    def test_reducible_allow_folds_to_whitedb_wildcard(self) -> None:
        res = _reconcile(
            [
                "||example.com^",
                "@@/^(.+\\.)?cdn\\.example\\.com$/",
            ]
        )
        # the allow folds to a wildcard whiteDB entry that un-blocks cdn + subs
        assert _resolve(res, "cdn.example.com") == "resolve"
        assert _resolve(res, "deep.cdn.example.com") == "resolve"
        assert _resolve(res, "example.com") == "block"
        assert any(a.wildcard for a in res.allow_domains)

    def test_irreducible_block_stays_regex(self) -> None:
        res = _reconcile(["/ad[0-9]\\.example\\.com$/"])
        assert res.reduced == 0
        assert len(res.block_regex_irreducible) == 1
        assert res.block_regex_irreducible[0].pattern == "ad[0-9]\\.example\\.com$"
        assert _resolve(res, "ad7.example.com") == "block"

    def test_irreducible_allow_goes_to_allow_set(self) -> None:
        res = _reconcile(["@@/ad[0-9]\\.example\\.com$/"])
        assert len(res.allow_regex_irreducible) == 1
        assert res.block_regex_irreducible == []

    def test_reduction_matches_oracle_and_spike(self) -> None:
        spike = _spike()
        for inner in (
            "^(.+\\.)?doubleclick\\.net$",
            "^pixel\\.example\\.com$",
            "(^|\\.)tracker\\.net$",
            "^(www\\.)?simple\\.example\\.com$",
            "ad[0-9]\\.example\\.com$",  # irreducible
            "(a+)+$",  # irreducible
        ):
            prod = P._dnsbl_reduce_regex(inner)
            ora = spec.reduce_regex(inner)
            assert prod == ora, inner
            # spike takes the FULL /re/ + returns (cls, domain) or None.
            spk = spike.reduce_pattern("/" + inner + "/")
            if prod is None:
                assert spk is None, inner
            else:
                wildcard, domain = prod
                cls, sdom = spk
                assert domain == sdom, inner
                assert wildcard == (cls == "zone"), inner


# --------------------------------------------------------------------------- #
# 3. classify reuse: domain blocks -> data vs zone (ADR-06 classify)
# --------------------------------------------------------------------------- #
class TestClassify:
    def test_registrable_parent_is_zone(self) -> None:
        res = _reconcile(["||example.com^"])
        b = res.block_domains[0]
        assert (b.cls, b.key) == (P.DNSBL_CLASS_ZONE, "example.com")

    def test_subdomain_block_classifies_via_classify(self) -> None:
        # ||ads.example.com^ -> classify(ads.example.com) -> DATA (deeper sub) but
        # wildcard zone semantics come from the rule covering subs; verify classify
        # agreement directly.
        res = _reconcile(["||ads.example.com^"])
        b = res.block_domains[0]
        cls, key = P.classify("ads.example.com", _TLDS, _EXCLUSION)
        assert (b.cls, b.key) == (cls, key)

    def test_exact_fold_forces_data(self) -> None:
        # an exact /^D$/ fold (wildcard=False) must NOT be wildcarded into a zone.
        res = _reconcile(["/^pixel\\.example\\.com$/"])
        b = res.block_domains[0]
        assert b.cls == P.DNSBL_CLASS_DATA
        assert b.key == "pixel.example.com"


# --------------------------------------------------------------------------- #
# 4. Priority bands (ADR.md SS2 / RESULTS-P2 SS2; matches priority())
# --------------------------------------------------------------------------- #
class TestBands:
    def test_feed_block_band1(self) -> None:
        res = _reconcile(["||a.example.com^"])
        assert res.block_domains[0].band == P.PRIO_FEED_BLOCK

    def test_feed_allow_band2(self) -> None:
        res = _reconcile(["@@||a.example.com^"])
        assert res.allow_domains[0].band == P.PRIO_FEED_ALLOW

    def test_feed_block_important_band3(self) -> None:
        res = _reconcile(["||a.example.com^$important"])
        assert res.block_domains[0].band == P.PRIO_FEED_BLOCK_IMPORTANT

    def test_feed_allow_important_band4(self) -> None:
        res = _reconcile(["@@||a.example.com^$important"])
        assert res.allow_domains[0].band == P.PRIO_FEED_ALLOW_IMPORTANT

    def test_user_block_band5(self) -> None:
        res = _reconcile(["||a.example.com^"], provenance=P.RULE_PROV_USER)
        assert res.block_domains[0].band == P.PRIO_USER_BLOCK

    def test_user_allow_band6(self) -> None:
        res = _reconcile(["@@||a.example.com^"], provenance=P.RULE_PROV_USER)
        assert res.allow_domains[0].band == P.PRIO_USER_ALLOW

    def test_band_matches_oracle_priority(self) -> None:
        # production _dnsbl_rule_band == oracle priority() for every band.
        cases = [
            ("||a.example.com^", P.RULE_PROV_FEED, spec.Provenance.FEED),
            ("@@||a.example.com^", P.RULE_PROV_FEED, spec.Provenance.FEED),
            ("||a.example.com^$important", P.RULE_PROV_FEED, spec.Provenance.FEED),
            ("@@||a.example.com^$important", P.RULE_PROV_FEED, spec.Provenance.FEED),
            ("||a.example.com^", P.RULE_PROV_USER, spec.Provenance.USER),
            ("@@||a.example.com^", P.RULE_PROV_USER, spec.Provenance.USER),
        ]
        for line, prov, ora_prov in cases:
            pr = P.parse_abp(line, provenance=prov)
            orr = spec.parse_abp_line(line, ora_prov)
            assert pr is not None and orr is not None
            assert P._dnsbl_rule_band(pr) == spec.priority(orr), line


# --------------------------------------------------------------------------- #
# 5. Precedence cases vs the Phase-2 decide() oracle (incl. $important inversion
#    and user sovereignty)
# --------------------------------------------------------------------------- #
class TestPrecedenceVsOracle:
    def test_feed_allow_beats_feed_block(self) -> None:
        res = _reconcile(["||example.com^", "@@||cdn.example.com^"])
        assert _resolve(res, "cdn.example.com") == "resolve"
        assert _resolve(res, "example.com") == "block"

    def test_feed_important_block_beats_feed_allow(self) -> None:
        res = _reconcile(["||x.example.com^$important", "@@||x.example.com^"])
        assert _resolve(res, "x.example.com") == "block"

    def test_feed_important_allow_beats_feed_block(self) -> None:
        res = _reconcile(["@@||y.example.com^$important", "||y.example.com^"])
        assert _resolve(res, "y.example.com") == "resolve"

    def test_user_allow_beats_feed_important_block(self) -> None:
        rules = _production_rules(["||z.example.com^$important"], provenance=P.RULE_PROV_FEED)
        rules += _production_rules(["@@||z.example.com^"], provenance=P.RULE_PROV_USER)
        res = P.reconcile(rules, _TLDS, _EXCLUSION)
        assert _resolve(res, "z.example.com") == "resolve"  # user allow (6) > 3

    def test_user_block_beats_feed_important_allow(self) -> None:
        rules = _production_rules(["@@||w.example.com^$important"], provenance=P.RULE_PROV_FEED)
        rules += _production_rules(["||w.example.com^"], provenance=P.RULE_PROV_USER)
        res = P.reconcile(rules, _TLDS, _EXCLUSION)
        assert _resolve(res, "w.example.com") == "block"  # user block (5) > 4

    @pytest.mark.parametrize(
        "lines,query",
        [
            (["||example.com^", "@@||cdn.example.com^"], "cdn.example.com"),
            (["||example.com^", "@@||cdn.example.com^"], "example.com"),
            (["||x.example.com^$important", "@@||x.example.com^"], "x.example.com"),
            (["@@||y.example.com^$important", "||y.example.com^"], "y.example.com"),
            (["/^(.+\\.)?doubleclick\\.net$/"], "ad.doubleclick.net"),
            (["/ad[0-9]\\.example\\.com$/"], "ad7.example.com"),
            (["||example.com^", "@@/^(.+\\.)?cdn\\.example\\.com$/"], "cdn.example.com"),
            (["||a.example.com^", "||a.example.com^$badfilter"], "a.example.com"),
        ],
    )
    def test_matches_oracle_decide(self, lines: list[str], query: str) -> None:
        # production reconcile+resolve == oracle decide() on every feed-only case.
        res = _reconcile(lines)
        ora = spec.decide(spec.rules_from(lines), query)
        assert _resolve(res, query) == ora.outcome, (lines, query)


# --------------------------------------------------------------------------- #
# 6. important_rules fast-path flag
# --------------------------------------------------------------------------- #
class TestImportantRulesFlag:
    def test_plain_feed_blocks_keep_fast_path(self) -> None:
        res = _reconcile(["||a.example.com^", "||b.example.com^", "0.0.0.0 c.example.com"])
        assert res.important_rules is False

    def test_feed_important_engages_numeric_path(self) -> None:
        res = _reconcile(["||a.example.com^$important"])
        assert res.important_rules is True

    def test_feed_allow_engages_numeric_path(self) -> None:
        res = _reconcile(["@@||a.example.com^"])
        assert res.important_rules is True

    def test_feed_irreducible_regex_engages_numeric_path(self) -> None:
        res = _reconcile(["/ad[0-9]\\.example\\.com$/"])
        assert res.important_rules is True

    def test_user_rules_alone_keep_fast_path(self) -> None:
        # a pure user whitelist/block is handled by today's fast path (P3 SS3).
        res = _reconcile(["||a.example.com^", "@@||b.example.com^"], provenance=P.RULE_PROV_USER)
        assert res.important_rules is False


# --------------------------------------------------------------------------- #
# 7. Purity / reentrancy (ADR.md SS2 "Reentrancy"; phase VERIFICATION)
# --------------------------------------------------------------------------- #
class TestPurityReentrancy:
    def test_reconcile_twice_equal(self) -> None:
        lines = _corpus_lines()
        rules = _production_rules(lines)
        r1 = P.reconcile(rules, _TLDS, _EXCLUSION)
        r2 = P.reconcile(rules, _TLDS, _EXCLUSION)
        assert r1 == r2

    def test_reconcile_does_not_mutate_inputs(self) -> None:
        rules = _production_rules(["||a.example.com^", "||a.example.com^$badfilter"])
        before = list(rules)
        tlds_copy = {k: dict(v) for k, v in _TLDS.items()}
        excl_copy = set(_EXCLUSION)
        P.reconcile(rules, _TLDS, _EXCLUSION)
        assert rules == before  # input list untouched
        assert _TLDS == tlds_copy and _EXCLUSION == excl_copy

    def test_reconcile_does_not_compile_regex(self) -> None:
        # an irreducible pattern that is NOT valid regex still survives Stage B as a
        # RAW pattern (compile is Phase 6) -- proves Stage B never compiles.
        res = _reconcile(["/ad[0-9\\.broken$/"])  # unbalanced class
        assert len(res.block_regex_irreducible) == 1
        assert res.block_regex_irreducible[0].pattern == "ad[0-9\\.broken$"

    def test_no_global_mutation(self) -> None:
        # reconcile touches no matcher global (dataDB/zoneDB).
        before_data = dict(P.dataDB)
        before_zone = dict(P.zoneDB)
        _reconcile(_corpus_lines())
        assert dict(P.dataDB) == before_data
        assert dict(P.zoneDB) == before_zone


# --------------------------------------------------------------------------- #
# 8. Corpus-wide: production reconcile == oracle decide() for every feed line
# --------------------------------------------------------------------------- #
class TestCorpusEquivalence:
    def test_corpus_feed_decisions_match_oracle(self) -> None:
        lines = _corpus_lines()
        res = _reconcile(lines)
        ora_rules = spec.rules_from(lines)
        # probe a spread of queries derived from the reduced/irreducible sets.
        probes = set()
        for b in res.block_domains:
            probes.add(b.key)
            probes.add("sub." + b.key)
        for a in res.allow_domains:
            probes.add(a.domain)
            probes.add("sub." + a.domain)
        probes.update({"doubleclick.net", "ad.doubleclick.net", "unrelated.example", "example.com"})
        for q in sorted(probes):
            assert _resolve(res, q) == spec.decide(ora_rules, q).outcome, q
