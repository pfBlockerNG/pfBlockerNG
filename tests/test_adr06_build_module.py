"""ADR-06 Phase 3 -- unit tests for the pure ``pfb_unbound`` DNSBL build layer.

WHY THIS FILE EXISTS
--------------------
Phase 3 introduces the pure, stdlib-only, Unbound-symbol-free build layer
(``parse`` -> ``normalise`` -> ``classify`` -> ``build``) that reproduces today's
DNSBL preprocessing pipeline at the level of net DNS *decisions* (ADR.md SS2). This
module unit-tests every build function AND drives ``build()`` end-to-end against the
Phase-2 DECISION oracle: the SAME representative query set, the SAME golden labels
(``GOLDEN_TOP1M_DISABLED`` / ``GOLDEN_TOP1M_ENABLED_OVERRIDES``) and the SAME
extracted-IP expectations -- but now over the structures the NEW build produces.

The contract is decisions, NOT list contents/counts. ADR-06 drops the build-time
optimisations (dedup, subdomain collapse, user-whitelist removal, TOP1M removal),
so ``data_db`` / ``zone_db`` contents and the counts change BY DESIGN. The tests
therefore assert identical block/resolve/whitelist/HSTS/noAAAA/zone-subdomain
DECISIONS, reusing the same Phase-2 golden tables from
``tests/test_adr06_golden_oracle.py`` so the two layers cannot silently diverge.

WHAT THE TESTS COVER
--------------------
  * ``parse`` per format (hosts / plain / abp), incl. every IGNORED line
    type (``@@`` / ``##`` / ``$options`` / ``*`` / ``/`` / regex), comments, the
    hosts sink-IP strip, the leading-dot strip, and bare-IP skip (firewall path).
  * the ABP-ready ``kind`` seam: parse only ever emits ``DNSBL_KIND_BLOCK``.
  * ``normalise`` domain-shape gate (lower-case, label rules, IP/garbage rejected).
  * ``classify`` data/zone via the public-suffix oracle, incl. the multi-label
    public suffix (``co.uk``), deep-subdomain -> exact DATA, and TLD-exclusion ->
    forced exact DATA.
  * whitelist normalisation (www-strip, leading-dot wildcard, TOP1M-when-enabled).
  * ``build()`` end-to-end == the Phase-2 decision oracle, BOTH TOP1M scenarios,
    plus the noAAAA decisions and the no-IP-leak guarantee.
  * ``build()`` is PURE / REENTRANT: two calls yield equal structures and mutate
    no module global.
"""

from __future__ import annotations

from typing import Any

import pfb_unbound

# Reuse the Phase-2 oracle's fixtures, golden decision tables and decision driver so
# the new build layer is validated against the EXACT same contract, not a copy.
from tests.test_adr06_golden_oracle import (
    GOLDEN_ABP_CONFORMANT_OVERRIDES,
    GOLDEN_EXTRACTED_IPS,
    GOLDEN_TOP1M_DISABLED,
    GOLDEN_TOP1M_ENABLED_OVERRIDES,
    _build_cfg,
    _decision_label,
    _load_json,
    _read_lines,
)

# --------------------------------------------------------------------------- #
# Helpers: drive build() over the golden fixtures, then evaluate the PRODUCTION
# matcher decision functions over the build's structures (the Phase-2 oracle).
# --------------------------------------------------------------------------- #


def _build_config(config: dict[str, Any]) -> dict[str, Any]:
    """Shape the golden config.json into the build() config blob.

    The golden config.json carries ``tld_wildcard_master`` as a fixture file name; the
    build takes the suffix lines directly (no filesystem coupling), so expand it here.
    """
    return {
        "tld_wildcard_master": _read_lines("tld_master.txt"),
        "tld_wildcard_blacklist": config.get("tld_wildcard_blacklist", []),
        "tld_wildcard_exclusion": config.get("tld_wildcard_exclusion", []),
        "user_whitelist": config.get("user_whitelist", []),
        "top1m_list": config.get("top1m_list", []),
    }


def _run_build(*, top1m_enabled: bool) -> tuple[pfb_unbound.BuildResult, dict[str, Any]]:
    manifest = _load_json("manifest.json")
    config = _load_json("config.json")
    result = pfb_unbound.build(
        manifest,
        _build_config(config),
        line_reader=_read_lines,
        top1m_enabled=top1m_enabled,
    )
    return result, config


def _evaluate_build(result: pfb_unbound.BuildResult, config: dict[str, Any], q_name: str) -> dict[str, Any]:
    """Run the PRODUCTION ``evaluate_domain`` over the BUILD's structures."""
    containers = {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": {},
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": {d: 0 for d in config.get("hsts_domains", [])},
    }
    cfg = _build_cfg(config, has_white=bool(result.white_db))
    tld = q_name.rsplit(".", 1)[-1] if "." in q_name else q_name
    decision = pfb_unbound.evaluate_domain(q_name, q_name, tld, False, cfg, containers)
    return {
        "decision": _decision_label(decision),
        "b_type": decision.b_type,
        "feed": decision.feed,
        "group": decision.group,
        "b_eval": decision.b_eval,
    }


# --------------------------------------------------------------------------- #
# parse()
# --------------------------------------------------------------------------- #


class TestParse:
    """#1083 P4: parse() lost its format_hint dispatch -- an ABP-shaped line never
    reaches it any more (build()'s per-line capture guard routes those to
    parse_abp() first), so parse() is now the hosts/plain handler only.
    """

    def test_hosts_sink_ip_stripped(self) -> None:
        for line in ("0.0.0.0 tracker.org", "127.0.0.1 tracker.org"):
            entry = pfb_unbound.parse(line)
            assert entry is not None
            assert entry.value == "tracker.org"
            assert entry.kind == pfb_unbound.DNSBL_KIND_BLOCK

    def test_hosts_comment_skipped(self) -> None:
        assert pfb_unbound.parse("# a comment") is None

    def test_hosts_bare_ip_skipped(self) -> None:
        # Bare IP -> firewall path (PHP); parse() must NOT return it.
        assert pfb_unbound.parse("0.0.0.0 198.51.100.23") is None
        assert pfb_unbound.parse("203.0.113.45") is None

    def test_plain_domain(self) -> None:
        entry = pfb_unbound.parse("malware.com")
        assert entry is not None and entry.value == "malware.com"

    def test_plain_leading_dot_stripped(self) -> None:
        entry = pfb_unbound.parse(".wildcardish.org")
        assert entry is not None and entry.value == "wildcardish.org"

    def test_blank_line_skipped(self) -> None:
        assert pfb_unbound.parse("   ") is None
        assert pfb_unbound.parse("") is None

    def test_kind_is_always_block_this_phase(self) -> None:
        # The ABP-ready seam exists but only BLOCK is ever produced.
        for line in ("0.0.0.0 tracker.org", "malware.com"):
            entry = pfb_unbound.parse(line)
            assert entry is not None and entry.kind == pfb_unbound.DNSBL_KIND_BLOCK


# --------------------------------------------------------------------------- #
# normalise()
# --------------------------------------------------------------------------- #


class TestNormalise:
    def test_lowercases_and_trims(self) -> None:
        assert pfb_unbound.normalise(" Tracker.ORG. ") == "tracker.org"

    def test_rejects_single_label(self) -> None:
        assert pfb_unbound.normalise("localhost") is None

    def test_bare_ip_rejection_is_parse_not_normalise(self) -> None:
        # Mirroring the current pipeline (inc:7962-7973): an all-numeric dotted
        # string is rejected at PARSE via the is_ipaddrv4 check, before validation.
        # normalise() alone treats digits as valid label chars (matches the Phase-2
        # ReferencePipeline._validate_domain), so the IP guard MUST live in parse().
        assert pfb_unbound.parse("198.51.100.23") is None
        assert pfb_unbound.normalise("198.51.100.23") == "198.51.100.23"

    def test_rejects_edge_hyphen_and_bad_chars(self) -> None:
        assert pfb_unbound.normalise("-bad.com") is None
        assert pfb_unbound.normalise("bad-.com") is None
        assert pfb_unbound.normalise("emp..ty") is None
        assert pfb_unbound.normalise("sp ace.com") is None

    def test_accepts_valid_domain(self) -> None:
        assert pfb_unbound.normalise("deep.host.cleandata.com") == "deep.host.cleandata.com"

    def test_accepts_underscore_labels(self) -> None:
        # Underscore is DNS-legal (RFC 2181 s11) and standardized practice (RFC 8552:
        # _dmarc, _domainkey, SRV _sip._tcp); PHP's PFB_FILTER_DOMAIN accepts it, so the
        # Python build gate must too or feed entries silently vanish between the two
        # halves of the pipeline (#723).
        assert pfb_unbound.normalise("under_score.com") == "under_score.com"
        assert pfb_unbound.normalise("_dmarc.example.com") == "_dmarc.example.com"
        assert pfb_unbound.normalise("trailing_.example.com") == "trailing_.example.com"

    def test_length_caps_reject_unqueryable_names(self) -> None:
        # #753: normalise() enforces the PHP PFB_FILTER_DOMAIN length caps at the
        # queryable bound. Every entry it gates becomes an exact or wildcard match
        # key, and a name with a >63-char label or >253 chars total cannot be
        # encoded in a DNS query -- it could never match a lookup, so rejecting it
        # keeps unreachable dead weight out of the block dicts.
        # Label cap: 63 is the longest legal label; 64 is unencodable.
        assert pfb_unbound.normalise("a" * 63 + ".com") == "a" * 63 + ".com"
        assert pfb_unbound.normalise("a" * 64 + ".com") is None
        # Total cap: 253 is the longest queryable presentation; 254 is not.
        name_253 = ".".join(["b" * 61] * 4) + "." + "b" * 5
        name_254 = ".".join(["b" * 61] * 4) + "." + "b" * 6
        assert (len(name_253), len(name_254)) == (253, 254)
        assert pfb_unbound.normalise(name_253) == name_253
        assert pfb_unbound.normalise(name_254) is None
        # Dotted (FQDN) form of a max-length name still passes: the trailing dot
        # is stripped BEFORE the cap, mirroring PHP's 254-char dotted accept (#752).
        assert pfb_unbound.normalise(name_253 + ".") == name_253


class TestNormaliseVerdictBucket:
    """ADR-48 Phase 4 (#789): ``_normalise_verdict`` is the classified body
    ``normalise()`` wraps -- every reject class ``TestNormalise`` above pins as
    ``None`` here additionally pins WHICH of the two RESOLVED buckets ('shape' vs
    'wire_cap') it tallies as, since build()/parse_abp()/reconcile() rely on that
    split to avoid spamming a healthy feed's operator with the wrong reason.
    """

    def test_accept_returns_domain_and_no_bucket(self) -> None:
        assert pfb_unbound._normalise_verdict(" Tracker.ORG. ") == ("tracker.org", None)

    def test_no_dot_is_shape(self) -> None:
        assert pfb_unbound._normalise_verdict("localhost") == (None, "shape")

    def test_edge_hyphen_is_shape(self) -> None:
        assert pfb_unbound._normalise_verdict("-bad.com") == (None, "shape")
        assert pfb_unbound._normalise_verdict("bad-.com") == (None, "shape")

    def test_empty_label_is_shape(self) -> None:
        assert pfb_unbound._normalise_verdict("emp..ty") == (None, "shape")

    def test_bad_char_is_shape(self) -> None:
        assert pfb_unbound._normalise_verdict("sp ace.com") == (None, "shape")

    def test_over_label_cap_is_wire_cap(self) -> None:
        # #753: 64-char label -- well-shaped (a dot IS present) but unqueryable.
        assert pfb_unbound._normalise_verdict("a" * 64 + ".com") == (None, "wire_cap")

    def test_over_total_cap_is_wire_cap(self) -> None:
        name_254 = ".".join(["b" * 61] * 4) + "." + "b" * 6
        assert pfb_unbound._normalise_verdict(name_254) == (None, "wire_cap")


# --------------------------------------------------------------------------- #
# tld_wildcard_classify()
# --------------------------------------------------------------------------- #


class TestClassify:
    def _tlds(self) -> dict[str, dict[str, str]]:
        return pfb_unbound._dnsbl_load_tld_wildcard_master(_read_lines("tld_master.txt"), [], [])

    def test_two_label_is_zone(self) -> None:
        cls, key = pfb_unbound.tld_wildcard_classify("tracker.org", self._tlds(), set())
        assert (cls, key) == (pfb_unbound.DNSBL_CLASS_ZONE, "tracker.org")

    def test_multi_label_public_suffix_is_zone_on_registrable(self) -> None:
        # co.uk is a public suffix -> shop.co.uk is the registrable parent.
        cls, key = pfb_unbound.tld_wildcard_classify("shop.co.uk", self._tlds(), set())
        assert (cls, key) == (pfb_unbound.DNSBL_CLASS_ZONE, "shop.co.uk")

    def test_deep_subdomain_unknown_parent_is_data(self) -> None:
        # cleandata.com is NOT a public suffix -> only the exact name is DATA.
        cls, key = pfb_unbound.tld_wildcard_classify("deep.host.cleandata.com", self._tlds(), set())
        assert (cls, key) == (pfb_unbound.DNSBL_CLASS_DATA, "deep.host.cleandata.com")

    def test_tld_exclusion_forces_exact_data(self) -> None:
        cls, key = pfb_unbound.tld_wildcard_classify("excluded.com", self._tlds(), {"excluded.com"})
        assert (cls, key) == (pfb_unbound.DNSBL_CLASS_DATA, "excluded.com")


# --------------------------------------------------------------------------- #
# whitelist normalisation
# --------------------------------------------------------------------------- #


class TestWhitelistNormalisation:
    # ADR-07 P3 widened the whiteDB value from a bare wildcard bool to
    # {"wildcard": bool, "important": bool}; ADR-07 P6 added the numeric ``band``
    # (user whitelist + TOP1M are user allows -> important=True, band 6, the
    # sovereign user-allow band). The net DNS decision is unchanged (pinned by the
    # oracle).
    def test_www_strip_and_exact(self) -> None:
        wl = pfb_unbound._dnsbl_normalise_whitelist(["www.adblock.com"], [], False)
        assert wl == {"adblock.com": {"wildcard": False, "important": True, "band": pfb_unbound.PRIO_USER_ALLOW}}

    def test_leading_dot_wildcard(self) -> None:
        wl = pfb_unbound._dnsbl_normalise_whitelist([".wildwhite.org"], [], False)
        assert wl == {"wildwhite.org": {"wildcard": True, "important": True, "band": pfb_unbound.PRIO_USER_ALLOW}}

    def test_top1m_only_when_enabled(self) -> None:
        disabled = pfb_unbound._dnsbl_normalise_whitelist([], ["popularcdn.com"], False)
        assert "popularcdn.com" not in disabled
        enabled = pfb_unbound._dnsbl_normalise_whitelist([], ["popularcdn.com"], True)
        assert enabled.get("popularcdn.com") == {
            "wildcard": False,
            "important": True,
            "band": pfb_unbound.PRIO_USER_ALLOW,
        }


# --------------------------------------------------------------------------- #
# build() end-to-end vs the Phase-2 DECISION oracle
# --------------------------------------------------------------------------- #


class TestBuildDecisionsTop1mDisabled:
    """The build's structures reproduce EVERY Phase-2 golden decision (TOP1M off).
    Decisions -- not list contents/counts -- are the oracle (ADR.md SS2)."""

    def test_decisions(self) -> None:
        result, config = _run_build(top1m_enabled=False)
        expected_map = dict(GOLDEN_TOP1M_DISABLED)
        expected_map.update(GOLDEN_ABP_CONFORMANT_OVERRIDES)  # conformant ABP zones (#718)
        failures: list[str] = []
        for q_name, expected in expected_map.items():
            got = _evaluate_build(result, config, q_name)
            for k, v in expected.items():
                if got[k] != v:
                    failures.append(f"{q_name}: {k} expected {v!r} got {got[k]!r}")
        assert not failures, "Build decision mismatch:\n" + "\n".join(failures)


class TestBuildDecisionsTop1mEnabled:
    """With TOP1M enabled the popular domain flips to 'whitelist'; all other
    decisions are unchanged -- identical to the Phase-2 oracle."""

    def test_decisions(self) -> None:
        result, config = _run_build(top1m_enabled=True)
        expected_map = dict(GOLDEN_TOP1M_DISABLED)
        expected_map.update(GOLDEN_TOP1M_ENABLED_OVERRIDES)
        expected_map.update(GOLDEN_ABP_CONFORMANT_OVERRIDES)  # conformant ABP zones (#718)
        failures: list[str] = []
        for q_name, expected in expected_map.items():
            got = _evaluate_build(result, config, q_name)
            for k, v in expected.items():
                if got[k] != v:
                    failures.append(f"{q_name}: {k} expected {v!r} got {got[k]!r}")
        assert not failures, "Build decision mismatch (TOP1M enabled):\n" + "\n".join(failures)

    def test_top1m_disabled_blocks_popular_domain(self) -> None:
        result, config = _run_build(top1m_enabled=False)
        got = _evaluate_build(result, config, "popularcdn.com")
        assert got["decision"] == "block-null"


class TestBuildNoAAAA:
    """noAAAA decisions are independent of the blocklist; the build does not touch
    the noAAAA list, but the matcher decision over the golden noAAAA list is pinned
    here too so the full decision surface is covered by the build-module tests."""

    def _noaaaa_db(self, config: dict[str, Any]) -> dict[str, Any]:
        return {dom: wild == "1" for dom, wild in config.get("noaaaa_domains", [])}

    def test_noaaaa_decisions(self) -> None:
        _, config = _run_build(top1m_enabled=False)
        db = self._noaaaa_db(config)
        assert pfb_unbound.evaluate_noaaaa("noaaaa.com", db) is True
        assert pfb_unbound.evaluate_noaaaa("host.noaaaawild.net", db) is True
        assert pfb_unbound.evaluate_noaaaa("noaaaawild.net", db) is True
        assert pfb_unbound.evaluate_noaaaa("sub.noaaaa.com", db) is False
        assert pfb_unbound.evaluate_noaaaa("totally-unrelated.com", db) is False


class TestBuildNoIpLeak:
    """The build never emits firewall input: no extracted IP leaks into the dicts.
    (IP extraction stays in PHP -- Phase 5.) Same IP set the Phase-2 oracle records."""

    def test_no_ip_leaked_into_block_lists(self) -> None:
        result, _ = _run_build(top1m_enabled=False)
        for ip in GOLDEN_EXTRACTED_IPS:
            assert ip not in result.data_db
            assert ip not in result.zone_db


# --------------------------------------------------------------------------- #
# build() structure-set sanity (NOT the oracle -- guards a broken build model)
# --------------------------------------------------------------------------- #


class TestBuildStructureSanity:
    def test_zone_and_data_populated(self) -> None:
        result, _ = _run_build(top1m_enabled=False)
        assert "tracker.org" in result.zone_db
        assert "malware.com" in result.zone_db
        assert "shop.co.uk" in result.zone_db
        assert "deep.host.cleandata.com" in result.data_db
        assert "deep.path.cleanmal.com" in result.data_db
        # TLD-exclusion forces a would-be-zone 2-label into data_db (exact).
        assert "excluded.com" in result.data_db
        assert "excluded.com" not in result.zone_db
        # TLD-blacklist synthetic zone entry, attributed to DNSBL_TLD.
        assert "zip" in result.zone_db
        idx = result.zone_db["zip"]["index"]
        assert result.feed_group_index_db[idx] == {"feed": "DNSBL_TLD", "group": "DNSBL_TLD"}

    def test_cross_feed_duplicate_last_wins(self) -> None:
        # tracker.org is in BOTH the hosts feed (Ads) and the plain feed (Malware);
        # the build keeps LAST (dict assignment; ADR-06 SS2 attribution change).
        result, _ = _run_build(top1m_enabled=False)
        idx = result.zone_db["tracker.org"]["index"]
        assert result.feed_group_index_db[idx] == {"feed": "PlainFeed", "group": "Malware"}

    def test_log_flag_carried_per_feed(self) -> None:
        # The log_flag '2' feed (NoLog) carries through to the entry payload.
        result, _ = _run_build(top1m_enabled=False)
        assert result.zone_db["silentblock.com"]["log"] == "2"

    def test_counts_is_loaded_total(self) -> None:
        # ADR-06 redefines pfb_py_count to the LOADED total (no dedup/collapse).
        result, _ = _run_build(top1m_enabled=False)
        assert result.counts == len(result.data_db) + len(result.zone_db)
        assert result.counts > 0

    def test_no_build_time_whitelist_pruning(self) -> None:
        # Whitelisted domains STAY in the lists (un-blocked at query time only).
        result, _ = _run_build(top1m_enabled=False)
        assert "phishing.net" in result.zone_db  # whitelisted but still listed
        assert "adblock.com" in result.zone_db

    def test_no_build_time_subdomain_collapse(self) -> None:
        # An exact DATA entry under a listed ZONE is NOT collapsed away at build time.
        # (deep.host.cleandata.com stays in data_db even though no parent zone covers
        # it; and a redundant subdomain of a zone would also stay -- no collapse pass.)
        result, _ = _run_build(top1m_enabled=False)
        assert "deep.host.cleandata.com" in result.data_db


# --------------------------------------------------------------------------- #
# build() purity / reentrancy
# --------------------------------------------------------------------------- #


class TestBuildPurity:
    def test_two_calls_yield_equal_structures(self) -> None:
        r1, _ = _run_build(top1m_enabled=False)
        r2, _ = _run_build(top1m_enabled=False)
        assert r1.data_db == r2.data_db
        assert r1.zone_db == r2.zone_db
        assert r1.feed_group_index_db == r2.feed_group_index_db
        assert r1.white_db == r2.white_db
        assert r1.counts == r2.counts

    def test_returns_fresh_structures_not_aliased(self) -> None:
        r1, _ = _run_build(top1m_enabled=False)
        r2, _ = _run_build(top1m_enabled=False)
        # Distinct objects (a future zero-downtime swap relies on this).
        assert r1.data_db is not r2.data_db
        assert r1.zone_db is not r2.zone_db
        assert r1.feed_group_index_db is not r2.feed_group_index_db
        assert r1.white_db is not r2.white_db

    def test_does_not_mutate_module_globals(self) -> None:
        # build() must touch no module global (it operates only on locals it returns).
        before_data = dict(pfb_unbound.dataDB)
        before_zone = dict(pfb_unbound.zoneDB)
        before_white = dict(pfb_unbound.whiteDB)
        before_fgi = dict(pfb_unbound.feedGroupIndexDB)
        result, _ = _run_build(top1m_enabled=False)
        assert pfb_unbound.dataDB == before_data
        assert pfb_unbound.zoneDB == before_zone
        assert pfb_unbound.whiteDB == before_white
        assert pfb_unbound.feedGroupIndexDB == before_fgi
        # And the returned structures are NOT the module globals.
        assert result.data_db is not pfb_unbound.dataDB
        assert result.zone_db is not pfb_unbound.zoneDB


# --------------------------------------------------------------------------- #
# ADR-48 Phase 4 (#789) -- build()'s per-entry reject tally.
#
# A synthetic in-memory manifest + line_reader (the ``_manifest``/``lambda raw:
# [...]`` idiom already used by TestBuildBranches in test_branch_coverage_gaps.py)
# gives EXACT control over how many shape/wire_cap rejects a feed carries -- the
# golden-fixture-driven ``_run_build()`` helper above is deliberately NOT reused
# here: its feed contents are tuned for the ADR-06 decision oracle, not for
# pinning an exact reject count, and coupling this test to that fixture's byte
# content would make it fragile to unrelated fixture edits.
# --------------------------------------------------------------------------- #


class TestEntryRejectTally:
    """``build()`` tallies every domain-target entry the normalise() domain-shape
    gate rejects (bucket 'shape' | 'wire_cap', ADR §2 item 4) so an operator can
    explain a feed-size vs dict-size discrepancy from one grep instead of
    guessing (issue #789). RED on pre-Phase-4 code: ``BuildResult`` carried no
    ``rejects`` field at all (``AttributeError``).
    """

    def test_abp_feed_tallies_exact_shape_and_wire_cap_counts(self) -> None:
        # Given: an ABP feed with EXACTLY 2 shape-rejectable entries (no-dot host,
        # edge-hyphen label) and 2 wire-cap-rejectable entries (a 64-char label, a
        # >253-char total name) among otherwise-healthy accepted entries.
        long_label = "a" * 64
        name_254 = ".".join(["b" * 61] * 4) + "." + "b" * 6
        feed_row = {"feed": "RejFeed", "group": "RejGroup", "log_flag": "1", "raw": "r"}
        lines = [
            "||good.example.com^",  # accepted -- must not be counted
            "||no-dot-host^",  # shape: no "." in host
            "||-bad.example.com^",  # shape: edge-hyphen label
            f"||{long_label}.com^",  # wire_cap: 64-char label
            f"||{name_254}^",  # wire_cap: >253-char total
        ]
        # When: build() runs the feed through parse_abp() -> reconcile().
        result = pfb_unbound.build(
            {"feeds": [feed_row], "config": {}},
            {},
            line_reader=lambda raw: lines,
        )
        # Then: the tally holds EXACTLY the crafted counts, keyed (feed, group);
        # the accepted entry landed in the block structures, not in the tally.
        assert result.rejects == {("RejFeed", "RejGroup"): {"shape": 2, "wire_cap": 2}}
        assert "good.example.com" in result.data_db or "good.example.com" in result.zone_db

    def test_plain_feed_tallies_normalise_reject(self) -> None:
        # Given: a plain (non-ABP) feed with exactly 1 shape-rejectable line --
        # proves the plain build path (not just the ABP path) counts too.
        feed_row = {"feed": "PlainFeed", "group": "PlainGroup", "log_flag": "1", "raw": "r"}
        result = pfb_unbound.build(
            {"feeds": [feed_row], "config": {}},
            {},
            line_reader=lambda raw: ["good.example.com", "no-dot-host"],
        )
        assert result.rejects == {("PlainFeed", "PlainGroup"): {"shape": 1, "wire_cap": 0}}


class TestSkipClassesTallyZero:
    """ADR-48 §7 reject-criterion pin: a deliberate ABP SKIP (comment, cosmetic/
    element-hiding, path/wildcard anchor, IP-valued anchor, non-DNS $options,
    $badfilter) is NOT a reject -- it must tally NOTHING, or a perfectly healthy
    feed built entirely of such lines would log spurious REJECT lines. The lines
    below are the deliberate-skip subset of tests/test_adr07_parser.py::TestSkip's
    corpus (its test_skip_invalid_domain lines are EXCLUDED on purpose: those ARE
    genuine normalise() shape rejects, not skips, and must tally -- reusing them
    here would defeat the point of this test).

    #1083 P4: three lines are NOT ABP-shaped per _dnsbl_is_abp_rule_line() (a bare
    "[...]" control header, and two freeform non-domain strings) -- the capture
    guard only recognises ||/@@/element-hiding/regex shapes, so these fall to the
    plain validator like any other malformed line and DO tally (pre-existing
    per-line-capture-guard behaviour for every feed; format_hint's now-retired
    whole-feed dispatch used to mask it in this synthetic all-ABP fixture).
    """

    def test_skip_only_feed_tallies_nothing(self) -> None:
        feed_row = {"feed": "SkipFeed", "group": "SkipGroup", "log_flag": "1", "raw": "r"}
        skip_lines = [
            "",
            "   ",
            "! Title: comment",
            "# plain comment",
            "example.com##.ad-banner",
            "##.global-ad",
            "example.net#@#.whitelisted-ad",
            "example.org#?#div:has(> .ad)",
            "example.com#%#//scriptlet('x')",
            "example.com#$#body { color: red; }",
            "||example.com/ads/*",
            "||cdn.example.net/track.js",
            "||shop.example^/affiliate?id=",
            "||wild.*^",
            "||203.0.113.7^",  # IP-valued anchor -> PHP firewall path
            "||198.51.100.42^",
            "0.0.0.0 203.0.113.99",
            "127.0.0.1 10.0.0.1",
            "||gone.example^$badfilter",  # parses to a Rule, pruned in reconcile()
        ]
        # Not ABP-shaped -> fall to the plain validator -> genuine shape rejects.
        not_abp_shaped_junk = ["[Adblock Plus 2.0]", "not a domain at all", "/banners/*.gif"]

        result = pfb_unbound.build(
            {"feeds": [feed_row], "config": {}},
            {},
            line_reader=lambda raw: skip_lines + not_abp_shaped_junk,
        )
        assert result.rejects == {("SkipFeed", "SkipGroup"): {"shape": 3, "wire_cap": 0}}
