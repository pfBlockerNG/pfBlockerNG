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
  * ``parse`` per format (hosts / plain / abp / csv:pon), incl. every IGNORED line
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

    The golden config.json carries ``tld_master`` as a fixture file name; the build
    takes the suffix lines directly (no filesystem coupling), so expand it here.
    """
    return {
        "tld_master": _read_lines("tld_master.txt"),
        "tld_blacklist": config.get("tld_blacklist", []),
        "tld_exclusion": config.get("tld_exclusion", []),
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
    def test_hosts_sink_ip_stripped(self) -> None:
        for line in ("0.0.0.0 tracker.org", "127.0.0.1 tracker.org"):
            entry = pfb_unbound.parse("hosts", line)
            assert entry is not None
            assert entry.value == "tracker.org"
            assert entry.kind == pfb_unbound.DNSBL_KIND_BLOCK

    def test_hosts_comment_skipped(self) -> None:
        assert pfb_unbound.parse("hosts", "# a comment") is None

    def test_hosts_bare_ip_skipped(self) -> None:
        # Bare IP -> firewall path (PHP); parse() must NOT return it.
        assert pfb_unbound.parse("hosts", "0.0.0.0 198.51.100.23") is None
        assert pfb_unbound.parse("plain", "203.0.113.45") is None

    def test_plain_domain(self) -> None:
        entry = pfb_unbound.parse("plain", "malware.com")
        assert entry is not None and entry.value == "malware.com"

    def test_plain_leading_dot_stripped(self) -> None:
        entry = pfb_unbound.parse("plain", ".wildcardish.org")
        assert entry is not None and entry.value == "wildcardish.org"

    def test_blank_line_skipped(self) -> None:
        assert pfb_unbound.parse("plain", "   ") is None
        assert pfb_unbound.parse("abp", "") is None

    def test_abp_block_line(self) -> None:
        entry = pfb_unbound.parse("abp", "||abpblocked.com^")
        assert entry is not None
        assert entry.value == "abpblocked.com"
        assert entry.kind == pfb_unbound.DNSBL_KIND_BLOCK

    def test_abp_deep_block_line(self) -> None:
        entry = pfb_unbound.parse("abp", "||sub.abpzone.net^")
        assert entry is not None and entry.value == "sub.abpzone.net"

    def test_abp_ignored_lines(self) -> None:
        # Each of these is IGNORED today and must yield None (NOT an allow/regex kind).
        ignored = [
            "[Adblock Plus 2.0]",  # control header
            "! Title: comment",  # comment
            "@@||abpallowed.com^",  # exception
            "||abpoptions.com^$third-party",  # $options
            "example.com##.ad-banner",  # element-hiding
            "||abpwildcard.*^",  # wildcard '*'
            "||abppath.com/ads^",  # path '/'
            "/regex-rule[0-9]/",  # standalone regex
        ]
        for line in ignored:
            assert pfb_unbound.parse("abp", line) is None, line

    def test_csv_pon_domain_from_col2(self) -> None:
        line = "2026-01-01T00:00:00Z,x,ponmocup.com,a,b,c,d,e,f"
        entry = pfb_unbound.parse("csv:pon", line)
        assert entry is not None and entry.value == "ponmocup.com"

    def test_csv_pon_col0_ip_row_still_yields_col2_domain(self) -> None:
        # col0 is an IP (PHP firewall path) but the col2 domain is STILL kept.
        line = "198.51.100.77,x,ponip.net,a,b,c,d,e,f"
        entry = pfb_unbound.parse("csv:pon", line)
        assert entry is not None and entry.value == "ponip.net"

    def test_csv_pon_header_and_comment_skipped(self) -> None:
        assert pfb_unbound.parse("csv:pon", "timestamp,ignored,domain,c3,c4,c5,c6,c7,c8") is None
        assert pfb_unbound.parse("csv:pon", "! comment") is None

    def test_csv_pon_wrong_column_count_skipped(self) -> None:
        assert pfb_unbound.parse("csv:pon", "a,b,c") is None

    def test_kind_is_always_block_this_phase(self) -> None:
        # The ABP-ready seam exists but only BLOCK is ever produced.
        for fmt, line in [
            ("hosts", "0.0.0.0 tracker.org"),
            ("plain", "malware.com"),
            ("abp", "||abpblocked.com^"),
            ("csv:pon", "x,x,ponmocup.com,a,b,c,d,e,f"),
        ]:
            entry = pfb_unbound.parse(fmt, line)
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
        assert pfb_unbound.parse("plain", "198.51.100.23") is None
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


# --------------------------------------------------------------------------- #
# classify()
# --------------------------------------------------------------------------- #


class TestClassify:
    def _tlds(self) -> dict[str, dict[str, str]]:
        return pfb_unbound._dnsbl_load_tld_master(_read_lines("tld_master.txt"), [], [])

    def test_two_label_is_zone(self) -> None:
        cls, key = pfb_unbound.classify("tracker.org", self._tlds(), set())
        assert (cls, key) == (pfb_unbound.DNSBL_CLASS_ZONE, "tracker.org")

    def test_multi_label_public_suffix_is_zone_on_registrable(self) -> None:
        # co.uk is a public suffix -> shop.co.uk is the registrable parent.
        cls, key = pfb_unbound.classify("shop.co.uk", self._tlds(), set())
        assert (cls, key) == (pfb_unbound.DNSBL_CLASS_ZONE, "shop.co.uk")

    def test_deep_subdomain_unknown_parent_is_data(self) -> None:
        # cleandata.com is NOT a public suffix -> only the exact name is DATA.
        cls, key = pfb_unbound.classify("deep.host.cleandata.com", self._tlds(), set())
        assert (cls, key) == (pfb_unbound.DNSBL_CLASS_DATA, "deep.host.cleandata.com")

    def test_tld_exclusion_forces_exact_data(self) -> None:
        cls, key = pfb_unbound.classify("excluded.com", self._tlds(), {"excluded.com"})
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
