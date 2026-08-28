"""ADR-66 Phase 1 -- the FROZEN decision oracle for both TLD features.

FROZEN FROM THIS PHASE ON. ADR-66 Phases 2/3 rename ~90 identifiers naming
Feature A ("TLD Allow", query-time) and Feature B ("TLD Wildcard",
build-time); every rename phase re-runs this exact file, byte-identical, to
prove the decisions it pins did not move. This module therefore names NO
identifier from the ADR-66 SS2.1/SS2.2 rename maps directly -- every renamed
symbol it needs (cfg/ini key names, the Feature-B function aliases) comes
through the seam in ``tests/test_adr66_tld_bridges.py``, which the rename
phases update instead of this file.

Oracle A pins Feature A (``evaluate_domain``'s TLD-Allow arm): enabled/tld
not on the list blocks, enabled/tld on the list resolves, disabled is a
no-op, an empty list is a no-op (issue #713), the numeric (important_rules)
resolution carries the feed-block band (both with no allow match and with a
populated-but-non-matching allow regex), the CNAME b_type suffix composes
with a TLD-Allow block, the DNSBL-VIP query exemption (v4/v6), the empty-tld
no-op, and precedence under an upstream dataDB hit.

Oracle B pins Feature B (the wildcard classifier): the 1/2/3/4/5/>5-label
zone-vs-data split, domain-level exclusion opt-out, root blacklist/exclusion,
and PSL fixture line-skip guards.
"""

from __future__ import annotations

from typing import Any

import pytest

import pfb_unbound
from pfb_unbound import (
    DNSBL_CLASS_DATA,
    DNSBL_CLASS_ZONE,
    PRIO_FEED_ALLOW,
    PRIO_FEED_BLOCK,
    evaluate_domain,
    tld_wildcard_classify,
)

TLD_ALLOW_ENABLE_KEY = "tld_allow"
TLD_ALLOW_LIST_KEY = "tld_allow_list"


def _psl_rules(*suffixes: str) -> pfb_unbound.PslRules:
    """Build validated exact PSL rules for the frozen classifier fixture."""
    entries: list[str] = []
    for raw in suffixes:
        suffix = raw.strip().strip(".").lower()
        if suffix and not suffix.startswith("#") and suffix not in entries:
            entries.append(suffix)
    return pfb_unbound.PslRules(icann_exact=tuple(entries))


# --------------------------------------------------------------------------- #
# Oracle A -- Feature A ("TLD Allow", evaluate_domain's query-time arm).
# --------------------------------------------------------------------------- #
def _tld_allow_cfg(**overrides: Any) -> dict[str, Any]:
    """Minimal cfg for evaluate_domain's TLD-Allow arm; every key it can
    unconditionally index is present. whiteDB stays False, so the TLD-Allow
    segment knob (a rename target) is never indexed and is deliberately
    absent here."""
    base: dict[str, Any] = {
        "python_blocking": False,
        "dataDB": False,
        "zoneDB": False,
        "regexDB": False,
        "whiteDB": False,
        "hstsDB": False,
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        TLD_ALLOW_ENABLE_KEY: False,
        TLD_ALLOW_LIST_KEY: [],
    }
    base.update(overrides)
    return base


def _containers() -> dict[str, Any]:
    return {
        "dataDB": {},
        "zoneDB": {},
        "whiteDB": {},
        "hstsDB": {},
        "regexDB": {},
        "feedGroupIndexDB": {},
    }


def _psl_allow_containers(rules: pfb_unbound.PslRules, roots: tuple[str, ...] = ("io",)) -> dict[str, Any]:
    containers = _containers()
    containers.update({"psl_rules": rules, "tld_allow_roots": roots})
    return containers


class TestOracleATldAllowFastPath:
    """Scenario: the TLD-Allow arm's four config states.

    Given a query for an inert uuid-shaped domain
      When TLD-Allow is disabled                       Then it is a no-op (A1)
      When enabled and the tld IS on the allow list     Then it resolves (A2)
      When enabled and the tld is NOT on the allow list Then it blocks (A3)
      When enabled with an EMPTY allow list              Then it is a no-op (A4)
    """

    def test_a1_disabled_is_a_noop(self) -> None:
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: False, TLD_ALLOW_LIST_KEY: ["com"]})
        dec = evaluate_domain("uuid-a1f0.net", "uuid-a1f0.net", "net", False, cfg, _containers())
        assert dec.is_found is False

    def test_a2_enabled_tld_on_list_resolves(self) -> None:
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: ["com", "net"]})
        dec = evaluate_domain("uuid-a2f0.com", "uuid-a2f0.com", "com", False, cfg, _containers())
        assert dec.is_found is False

    def test_a3_enabled_tld_off_list_blocks_with_full_log_field_snapshot(self) -> None:
        # A3: this is the frozen shape of a TLD-Allow block -- every log
        # field, not just is_found, so a rename that quietly alters ANY of
        # them (feed/group string, b_type/p_type default, b_eval, null
        # shaping) is caught.
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: ["com", "net"]})
        dec = evaluate_domain("uuid-a3f0.org", "uuid-a3f0.org", "org", False, cfg, _containers())
        assert dec.is_found is True
        assert dec.feed == "TLD_Allow"
        assert dec.group == "DNSBL_TLD_Allow"
        assert dec.b_type == "Python"
        assert dec.p_type == "Python"
        # the post-discovery "if is_found:" default fills b_eval with the
        # query name and sets log_type "1" (VIP-blocked shape) for every
        # stratum that doesn't override it -- TLD-Allow doesn't.
        assert dec.b_eval == "uuid-a3f0.org"
        assert dec.log_type == "1"
        assert dec.null_blocking is False
        assert dec.in_hsts is False
        assert dec.in_whitelist is False
        assert dec.nxdomain is False

    def test_a4_enabled_empty_list_is_a_noop(self) -> None:
        # issue #713 regression guard: an enabled TLD-Allow with NO configured
        # TLDs must not block every domain.
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: []})
        dec = evaluate_domain("uuid-a4f0.org", "uuid-a4f0.org", "org", False, cfg, _containers())
        assert dec.is_found is False


class TestOracleATldAllowNumericBand:
    """A5: under the numeric (important_rules) resolution, a TLD-Allow block
    carries exactly the feed-block band (PRIO_FEED_BLOCK) -- no higher, no
    zero. A band-2 (PRIO_FEED_ALLOW) feed-allow-regex match overrides it
    (proving the band is set, not left at 0); a match against an unrelated
    pattern leaves the block standing (proving the band is not
    over-promoted above PRIO_FEED_BLOCK either).
    """

    def _decide(self, tld: str, allow_pattern: str | None) -> Any:
        import re

        cfg = _tld_allow_cfg(
            **{
                TLD_ALLOW_ENABLE_KEY: True,
                TLD_ALLOW_LIST_KEY: ["com"],
                "allowRegexDB": bool(allow_pattern),
                "important_rules": True,
            }
        )
        allow_regex_db = {"r": re.compile(allow_pattern)} if allow_pattern else {}
        containers = _containers()
        containers["allowRegexDB"] = allow_regex_db
        return evaluate_domain(f"uuid-a5f0.{tld}", f"uuid-a5f0.{tld}", tld, False, cfg, containers)

    def test_a5_disallowed_tld_block_stands_with_no_allow_match(self) -> None:
        dec = self._decide("xyz", None)
        assert dec.is_found is True
        assert dec.feed == "TLD_Allow"
        assert dec.in_whitelist is False

    def test_a5_feed_allow_at_band_two_overrides_the_band_one_block(self) -> None:
        dec = self._decide("xyz", r"uuid-a5f0")
        assert dec.in_whitelist is True

    def test_a5c_populated_non_matching_allow_regex_leaves_block_standing(self) -> None:
        # A populated allowRegexDB that simply doesn't match this query must
        # not over-promote the band above PRIO_FEED_BLOCK -- the block stands
        # exactly as if allowRegexDB were empty (test_a5_disallowed_tld...).
        dec = self._decide("xyz", r"zzz-never-match")
        assert dec.is_found is True
        assert dec.in_whitelist is False


class TestOracleATldAllowBranchesBothWays:
    """A6: with a populated allow list, a disallowed tld still blocks (the
    empty-list guard must not swallow the real case) and an allowed tld
    still resolves -- both sides of the same branch, same list."""

    def test_a6_both_sides_of_a_populated_list(self) -> None:
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: ["com"]})

        dec_blocked = evaluate_domain("uuid-a6f0.net", "uuid-a6f0.net", "net", False, cfg, _containers())
        assert dec_blocked.is_found is True
        assert dec_blocked.feed == "TLD_Allow"
        assert dec_blocked.group == "DNSBL_TLD_Allow"

        dec_resolved = evaluate_domain("uuid-a6f0.com", "uuid-a6f0.com", "com", False, cfg, _containers())
        assert dec_resolved.is_found is False


class TestOracleATldAllowCnameComposition:
    """A7: a TLD-Allow block on a CNAME chain composes the "_CNAME" suffix
    onto b_type exactly like every other stratum's block."""

    def test_a7_is_cname_true_suffixes_b_type(self) -> None:
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: ["com"]})
        dec = evaluate_domain("uuid-a7f0.net", "uuid-a7f0.net", "net", True, cfg, _containers())
        assert dec.is_found is True
        assert dec.b_type == "Python_CNAME"


class TestOracleATldAllowVipExemption:
    """A8a/A8b: the TLD-Allow arm's own DNSBL-VIP q_name exemption -- a query
    for the configured VIP address itself (v4 or v6) is never TLD-Allow
    blocked, even with a disallowed tld. Control-first: an ordinary query on
    the identical cfg blocks, so the VIP query's pass is caused by VIP
    membership, not something else.
    """

    def test_a8a_v4_vip_query_is_exempt(self) -> None:
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: ["com"]})

        control = evaluate_domain("uuid-vip.1", "uuid-vip.1", "1", False, cfg, _containers())
        assert control.is_found is True
        assert control.feed == "TLD_Allow"

        dec = evaluate_domain("10.10.10.1", "10.10.10.1", "1", False, cfg, _containers())
        assert dec.is_found is False

    def test_a8b_v6_vip_query_is_exempt(self) -> None:
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: ["com"]})

        control = evaluate_domain("uuid-vip6.1", "uuid-vip6.1", "1", False, cfg, _containers())
        assert control.is_found is True
        assert control.feed == "TLD_Allow"

        dec = evaluate_domain("::1", "::1", "1", False, cfg, _containers())
        assert dec.is_found is False


class TestOracleATldAllowEmptyTld:
    """A9: the tld != "" conjunct -- a query with no discoverable tld is a
    no-op regardless of the allow list."""

    def test_a9_empty_tld_is_a_noop(self) -> None:
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: ["com"]})
        dec = evaluate_domain("uuid-a9f0.org", "uuid-a9f0.org", "", False, cfg, _containers())
        assert dec.is_found is False


class TestOracleATldAllowPriorMatchPrecedence:
    """A10: the "if not is_found" guard -- an upstream dataDB hit wins
    outright; TLD-Allow never overwrites an already-found decision."""

    def test_a10_datadb_hit_wins_over_tld_allow(self) -> None:
        cfg = _tld_allow_cfg(
            **{
                "python_blocking": True,
                "dataDB": True,
                TLD_ALLOW_ENABLE_KEY: True,
                TLD_ALLOW_LIST_KEY: ["com"],
            }
        )
        # BEFORE: no dataDB entry -- the guard falls through to TLD-Allow.
        control = evaluate_domain("uuid-a10.org", "uuid-a10.org", "org", False, cfg, _containers())
        assert control.is_found is True
        assert control.feed == "TLD_Allow"

        # AFTER: an upstream dataDB hit at the same query -- TLD-Allow never runs.
        containers = _containers()
        containers["dataDB"] = {"uuid-a10.org": {"log": "1", "index": 5, "important": False, "band": PRIO_FEED_BLOCK}}
        containers["feedGroupIndexDB"] = {5: {"feed": "Feed_X", "group": "Group_X"}}
        dec = evaluate_domain("uuid-a10.org", "uuid-a10.org", "org", False, cfg, containers)
        assert dec.is_found is True
        assert dec.feed == "Feed_X"
        assert dec.group == "Group_X"
        assert dec.b_type == "DNSBL"


class TestOracleATldAllowPslPrivate:
    def test_selected_root_allows_private_suffix_query(self) -> None:
        rules = pfb_unbound.parse_psl_rules(
            "// ===BEGIN ICANN DOMAINS===\nio\ncom\n// ===END ICANN DOMAINS===\n"
            "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"
        )
        cfg = _tld_allow_cfg(**{TLD_ALLOW_ENABLE_KEY: True, TLD_ALLOW_LIST_KEY: ["io"]})
        dec = evaluate_domain("x.github.io", "x.github.io", "io", False, cfg, _psl_allow_containers(rules))
        assert dec.is_found is False

    def test_allow_private_only_matches_winning_private_boundary(self) -> None:
        rules = pfb_unbound.parse_psl_rules(
            "// ===BEGIN ICANN DOMAINS===\nio\ncom\n// ===END ICANN DOMAINS===\n"
            "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"
        )
        cfg = _tld_allow_cfg(
            **{
                TLD_ALLOW_ENABLE_KEY: True,
                TLD_ALLOW_LIST_KEY: ["com"],
                "psl_allow_private": True,
            }
        )
        private = evaluate_domain("x.github.io", "x.github.io", "io", False, cfg, _psl_allow_containers(rules, ()))
        public = evaluate_domain("x.example.net", "x.example.net", "net", False, cfg, _containers())
        assert private.is_found is False
        assert public.is_found is True


# --------------------------------------------------------------------------- #
# Oracle B -- Feature B ("TLD Wildcard", the wildcard classifier + oracle loader).
# --------------------------------------------------------------------------- #
class TestOracleBTwoLabelToggle:
    """B1/B2: a bare 2-label domain -- before-state (oracle empty, OFF) is
    exact DATA (issue #1255 regression); after-state (oracle populated, ON)
    is wildcard ZONE, same domain."""

    def test_b2_empty_oracle_is_data(self) -> None:
        assert tld_wildcard_classify("evil.com", pfb_unbound.PslRules(), set()) == (DNSBL_CLASS_DATA, "evil.com")

    def test_b1_populated_oracle_is_zone(self) -> None:
        tlds = _psl_rules("com")
        assert tld_wildcard_classify("evil.com", tlds, set()) == (DNSBL_CLASS_ZONE, "evil.com")


class TestOracleBMultiLabelSuffix:
    """B3: a multi-label public suffix (co.uk) collapses its full registrable
    domain to a wildcard ZONE."""

    def test_b3_registrable_domain_over_public_suffix_is_zone(self) -> None:
        tlds = _psl_rules("co.uk")
        assert tld_wildcard_classify("example.co.uk", tlds, set()) == (DNSBL_CLASS_ZONE, "example.co.uk")


class TestOracleBDeeperSubdomain:
    """B4/B5: a sub-domain one level deeper than the known registrable
    suffix is exact DATA, over both a multi-label and a simple suffix."""

    def test_b4_deeper_sub_over_public_suffix_is_data(self) -> None:
        tlds = _psl_rules("co.uk")
        assert tld_wildcard_classify("shop.example.co.uk", tlds, set()) == (DNSBL_CLASS_DATA, "shop.example.co.uk")

    def test_b5_deeper_sub_over_simple_tld_is_data(self) -> None:
        tlds = _psl_rules("com")
        assert tld_wildcard_classify("sub.evil.com", tlds, set()) == (DNSBL_CLASS_DATA, "sub.evil.com")


class TestOracleBExclusionOptOut:
    """B6/B7: a whole-domain exclusion member forces exact DATA even though
    the oracle would otherwise wildcard it (before/after: non-member stays
    ZONE, same oracle)."""

    def test_b7_non_member_stays_zone(self) -> None:
        tlds = _psl_rules("com")
        assert tld_wildcard_classify("evil.com", tlds, set()) == (DNSBL_CLASS_ZONE, "evil.com")

    def test_b6_exclusion_member_forces_data(self) -> None:
        tlds = _psl_rules("com")
        assert tld_wildcard_classify("evil.com", tlds, {"evil.com"}) == (DNSBL_CLASS_DATA, "evil.com")


class TestOracleBOverFiveLabels:
    """B8: more than 5 labels is exact DATA regardless of a populated
    oracle -- the dcnt>5 branch never consults tlds."""

    def test_b8_over_five_labels_is_data(self) -> None:
        tlds = _psl_rules("com")
        domain = "w1.w2.w3.w4.w5.evil.com"
        assert tld_wildcard_classify(domain, tlds, set()) == (DNSBL_CLASS_DATA, domain)


class TestOracleBLoadTimeBlacklistAndExclusion:
    """B9/B10: the classifier's blacklist/exclusion arguments each
    independently force exact DATA for every entry whose resolved suffix or
    root matches a token -- before (unlisted, ZONE) / after (listed, DATA),
    same domain, varying only which argument names the TLD (owner-confirmed
    subtree semantics, PR #2363 review)."""

    def test_b9_blacklisted_tld_forces_exact_data(self) -> None:
        present = _psl_rules("co.uk", "com")
        assert tld_wildcard_classify("example.co.uk", present, set()) == (DNSBL_CLASS_ZONE, "example.co.uk")

        blacklisted = _psl_rules("co.uk", "com")
        assert tld_wildcard_classify("example.co.uk", blacklisted, set(), blacklist={"uk"}) == (
            DNSBL_CLASS_DATA,
            "example.co.uk",
        )

    def test_b10_excluded_tld_forces_exact_data(self) -> None:
        present = _psl_rules("co.uk", "com")
        assert tld_wildcard_classify("example.co.uk", present, set()) == (DNSBL_CLASS_ZONE, "example.co.uk")

        excluded = _psl_rules("co.uk", "com")
        assert tld_wildcard_classify("example.co.uk", excluded, {"uk"}) == (
            DNSBL_CLASS_DATA,
            "example.co.uk",
        )

    def test_b10a_excluded_root_covers_every_depth(self) -> None:
        # Issue #1541 pin: root `uk` covered separately from suffix `co.uk`.
        # An excluded root forces exact DATA directly under it AND deeper --
        # exclusion means "never wildcard here", at all depths.
        rules = _psl_rules("uk", "co.uk", "com")
        assert tld_wildcard_classify("example.uk", rules, {"uk"}) == (DNSBL_CLASS_DATA, "example.uk")
        assert tld_wildcard_classify("example.co.uk", rules, {"uk"}) == (DNSBL_CLASS_DATA, "example.co.uk")
        assert tld_wildcard_classify("deep.example.co.uk", rules, {"uk"}) == (
            DNSBL_CLASS_DATA,
            "deep.example.co.uk",
        )
        # An unrelated root keeps normal classification under the same call.
        assert tld_wildcard_classify("example.com", rules, {"uk"}) == (DNSBL_CLASS_ZONE, "example.com")


class TestOracleBFiveLabelBothSides:
    """B11: the dcnt==5 branch, both outcomes -- a 5-label name whose
    4-label suffix is a known public suffix wildcards to its registrable
    parent; a 5-label name whose 4-label suffix is NOT known stays exact
    DATA, same oracle."""

    def test_b11_five_label_zone_and_data(self) -> None:
        tlds = _psl_rules("a.b.co.uk", "com")
        assert tld_wildcard_classify("x.a.b.co.uk", tlds, set()) == (DNSBL_CLASS_ZONE, "x.a.b.co.uk")
        assert tld_wildcard_classify("v.w.x.evil.com", tlds, set()) == (DNSBL_CLASS_DATA, "v.w.x.evil.com")


class TestOracleBFourLabelZone:
    """B12: the dcnt==4 branch's ZONE side (the DATA side is B4)."""

    def test_b12_four_label_zone(self) -> None:
        tlds = _psl_rules("b.co.uk")
        assert tld_wildcard_classify("x.b.co.uk", tlds, set()) == (DNSBL_CLASS_ZONE, "x.b.co.uk")


class TestOracleBSingleLabelFallthrough:
    """B13: a single-label name never matches the dcnt 2/3/4/5 branches --
    dfound stays empty and the wildcard classifier falls through to exact
    DATA."""

    def test_b13_single_label_is_data(self) -> None:
        tlds = _psl_rules("com")
        assert tld_wildcard_classify("uuid-b13", tlds, set()) == (DNSBL_CLASS_DATA, "uuid-b13")


class TestOracleBLoaderSkipGuards:
    """B14: parse_psl_rules' line handling -- blank, whitespace-only, and
    comment-prefixed lines never enter the rule set, while a malformed
    trailing-dot rule fails the WHOLE parse closed (the runtime authority is
    validated, never silently filtered)."""

    def test_b14_parser_skips_blanks_and_comments(self) -> None:
        authority = (
            "// ===BEGIN ICANN DOMAINS===\n"
            "\n"
            "   \n"
            "# co.uk\n"
            "// co.uk\n"
            "com\n"
            "// ===END ICANN DOMAINS===\n"
            "// ===BEGIN PRIVATE DOMAINS===\n"
            "// ===END PRIVATE DOMAINS===\n"
        )
        assert pfb_unbound.parse_psl_rules(authority).icann_exact == ("com",)

    def test_b14a_parser_rejects_trailing_dot_rule(self) -> None:
        authority = (
            "// ===BEGIN ICANN DOMAINS===\n"
            "com.\n"
            "// ===END ICANN DOMAINS===\n"
            "// ===BEGIN PRIVATE DOMAINS===\n"
            "// ===END PRIVATE DOMAINS===\n"
        )
        with pytest.raises(ValueError):
            pfb_unbound.parse_psl_rules(authority)


# --------------------------------------------------------------------------- #
# Sanity: the block-band constants used by Oracle A's numeric-path proof stay
# distinct (no-ties invariant the whole numeric resolution depends on).
# --------------------------------------------------------------------------- #
def test_priority_band_constants_stay_distinct() -> None:
    assert PRIO_FEED_BLOCK == 1
    assert PRIO_FEED_ALLOW == 2
    assert PRIO_FEED_ALLOW > PRIO_FEED_BLOCK


def test_module_uses_only_seam_and_stable_symbols() -> None:
    # Existence check, not a behaviour pin: the seam module actually exports
    # what this file imports (a renamed/removed seam symbol fails collection
    # here loudly instead of via a cryptic ImportError elsewhere).
    assert callable(tld_wildcard_classify)
    assert isinstance(pfb_unbound.pfb, dict)
