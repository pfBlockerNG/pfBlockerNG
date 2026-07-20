"""ADR-65 Oracle A: pin what the production manifest-built matcher
decides + would log TODAY.

WHY THIS FILE EXISTS
--------------------
ADR-65 retires the legacy `.txt` interchange-file fallback and adds a read-only
query channel (ADR.md SS2). Every later change's "net PRODUCTION decisions
are unchanged" claim needs a falsification harness that exists BEFORE any code
moves (ADR.md SS2 items 1-2). This module drives the REAL decision function,
``evaluate_domain`` (``pfb_unbound.py:6038``, called by ``operate()`` for every
DNS query), over one representative input per decision arm, and freezes the
verdict + the exact fields a block would log (``b_type``/``group``/``b_eval``/
``feed``/``p_type`` -- the same set ``dnsbl.log``'s ``csv_line`` carries,
ADR.md SS1.4).

Two vehicles, per arm:
  * DIRECT container construction (mirrors ``test_adr08_confusable_matcher.py``):
    hand-built ``dataDB``/``zoneDB``/``whiteDB``/``regexDB``/``hstsDB`` payloads in
    the exact shape ``BuildResult`` documents (``pfb_unbound.py:3673-3697``) for
    arms ``evaluate_domain`` itself decides (data/zone/regex discovery, the
    numeric 6-band precedence, HSTS, IDN, TLD_Allow, NXDOMAIN, CNAME) -- this
    pins the matcher's OWN contract precisely, without re-deriving ABP
    parse/reconcile semantics for every combination.
  * The REAL manifest ``build()``/``dnsbl_build_from_manifest()`` pipeline,
    reusing existing committed corpora (``tests/fixtures/dnsbl_corpus/``,
    ``tests/fixtures/adr06_golden/``) for the arms that are genuinely
    build-pipeline concerns: ABP zone/data-class emission (A4) and the
    TLD-Wildcard toggle's plain-path classification (A17-19), reusing the
    ADR-06 Phase-4 harness helpers (``_build_from_manifest``/
    ``_write_onbox_manifest``) so this oracle does not invent a new pattern.

Frozen literals throughout -- every expectation is hand-derived from the cited
line ranges / fixture content, never computed from the code under test.
"""

from __future__ import annotations

import re
from typing import Any

import pfb_unbound
from pfb_unbound import (
    IDN_FEED_MALICIOUS,
    IDN_GROUP_MALICIOUS,
    IDN_MODE_ALL,
    IDN_MODE_CONFUSABLE,
    PRIO_FEED_ALLOW,
    PRIO_FEED_BLOCK,
    PRIO_FEED_BLOCK_IMPORTANT,
)
from tests.test_adr06_golden_oracle import _load_json
from tests.test_adr06_init_from_raw import _build_from_manifest, _evaluate_result, _write_onbox_manifest
from tests.test_adr08_confusable_matcher import MALICIOUS_NAME, SUSPICIOUS_NAME
from tests.test_issue1083_dnsbl_interchange_semantic_oracle import _run_corpus_build

# One shared synthetic feed/group attribution for the direct-construction arms
# that need SOME index -- the value itself is not the point (feed/group naming
# just proves resolve_feed_group() wires it through), so one constant index
# suffices everywhere it is used.
_FGI = {0: {"feed": "TestFeed", "group": "TestGroup"}}


def _containers(
    *,
    data: dict[str, Any] | None = None,
    zone: dict[str, Any] | None = None,
    white: dict[str, Any] | None = None,
    regex: dict[str, Any] | None = None,
    allow_regex: dict[str, Any] | None = None,
    feed_group_index: dict[int, Any] | None = None,
    hsts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The ``containers`` dict ``evaluate_domain`` reads (pfb_unbound.py:6070-6076)."""
    return {
        "dataDB": data or {},
        "zoneDB": zone or {},
        "whiteDB": white or {},
        "regexDB": regex or {},
        "allowRegexDB": allow_regex or {},
        "feedGroupIndexDB": feed_group_index or {},
        "hstsDB": hsts or {},
    }


def _containers_from_result(result: pfb_unbound.BuildResult) -> dict[str, Any]:
    return {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": result.regex_db,
        "allowRegexDB": result.allow_regex_db,
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": {},
    }


def _cfg(**overrides: Any) -> dict[str, Any]:
    """cfg blob shaped like pfb_unbound.pfb's per-query view, for evaluate_domain()."""
    base: dict[str, Any] = {
        "python_blocking": True,
        "dataDB": True,
        "zoneDB": True,
        "whiteDB": True,
        "regexDB": True,
        "allowRegexDB": True,
        "hstsDB": True,
        "tld_allow": False,
        "tld_allow_list": [],
        "python_idn": False,
        "python_tld_seg": 2,
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "hsts_tlds": (),
        "important_rules": False,
    }
    base.update(overrides)
    return base


def _build_manifest_off(tmp_path: Any) -> pfb_unbound.BuildResult:
    """OFF-toggle counterpart of ``_build_from_manifest`` (test_adr06_init_from_raw,
    which always stages the TLD oracle ON): same on-box manifest + staged oracle
    file, but ``python_tld_wildcard`` forced False right before the build reads it
    -- the #1255 empty-oracle guard (pfb_unbound.py:4328) then forces exact DATA
    for every plain domain."""
    manifest_path = _write_onbox_manifest(tmp_path, top1m_enabled=False)
    pfb_unbound.pfb["python_tld_wildcard"] = False
    result = pfb_unbound.dnsbl_build_from_manifest(manifest_path)
    assert result is not None
    return result


# --------------------------------------------------------------------------- #
# A1/A2/A3 -- the three feed-stratum block sources evaluate_domain discovers
# (pfb_unbound.py:6082-6205): exact dataDB, the wildcard zoneDB suffix walk, and
# a compiled feed block-regex -- each attributed to its feed/group, VIP-logged
# (block-null, log_type '1').
# --------------------------------------------------------------------------- #


class TestDataZoneRegexDecisionArms:
    def test_a1_data_db_exact_hit_blocks_and_attributes(self) -> None:
        q = "exact-hit.uuid1001.com"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        containers = _containers(data=data, feed_group_index=_FGI)
        d = pfb_unbound.evaluate_domain(q, q, "com", False, _cfg(), containers)
        assert d.is_found is True
        assert d.b_type == "DNSBL"
        assert d.b_eval == q
        assert (d.feed, d.group) == ("TestFeed", "TestGroup")
        assert d.null_blocking is False  # log '1' -> VIP, not null-routed

    def test_a2_zone_db_suffix_hit_blocks_subdomain_and_attributes_to_parent(self) -> None:
        parent = "zone-parent.uuid1002.net"
        child = "deep.sub." + parent
        zone = {parent: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        containers = _containers(zone=zone, feed_group_index=_FGI)
        d = pfb_unbound.evaluate_domain(child, child, "net", False, _cfg(), containers)
        assert d.is_found is True
        assert d.b_type == "TLD"
        assert d.b_eval == parent  # matched suffix, not the queried child
        assert (d.feed, d.group) == ("TestFeed", "TestGroup")

    def test_a3_feed_block_regex_hit_blocks_and_attributes(self) -> None:
        pattern = re.compile(r"^regex-hit-\d+\.uuid1003\.org$")
        regex_db = {"MyBlockRegex": {"re": pattern, "important": False, "band": PRIO_FEED_BLOCK}}
        q = "regex-hit-42.uuid1003.org"
        d = pfb_unbound.evaluate_domain(q, q, "org", False, _cfg(), _containers(regex=regex_db))
        assert d.is_found is True
        assert d.feed == "MyBlockRegex"
        assert d.group == "DNSBL_Regex"
        assert d.b_eval == q


# --------------------------------------------------------------------------- #
# A4 -- ABP block rows through the REAL manifest build (reused
# tests/fixtures/dnsbl_corpus/raw/abp_feed.raw): '||domain^' emits a wildcard
# ZONE at the anchor (reconcile():4610); an ABP regex with no wildcard prefix
# folds to an EXACT literal (data-class), never a zone.
# --------------------------------------------------------------------------- #


class TestAbpBuildDrivenArm:
    def test_abp_anchor_emits_zone_class_and_blocks(self) -> None:
        result = _run_corpus_build()
        assert "anchor.abp.example" in result.zone_db  # ZONE-class, not exact
        cfg = _cfg(important_rules=result.important_rules)
        d = pfb_unbound.evaluate_domain(
            "anchor.abp.example", "anchor.abp.example", "example", False, cfg, _containers_from_result(result)
        )
        assert d.is_found is True
        assert d.b_type == "TLD"
        assert (d.feed, d.group) == ("abp_feed", "grp_abp")

    def test_abp_exact_regex_fold_emits_data_class_and_blocks(self) -> None:
        """``/^regexblock\\.abp\\.example$/`` has no wildcard prefix
        (``_DNSBL_RX_WILDCARD_PREFIXES``) -> ``_dnsbl_reduce_regex`` folds it to an
        EXACT domain, not a zone (pfb_unbound.py:4396-4403)."""
        result = _run_corpus_build()
        assert "regexblock.abp.example" in result.data_db  # DATA-class (exact ABP)
        cfg = _cfg(important_rules=result.important_rules)
        d = pfb_unbound.evaluate_domain(
            "regexblock.abp.example",
            "regexblock.abp.example",
            "example",
            False,
            cfg,
            _containers_from_result(result),
        )
        assert d.is_found is True
        assert d.b_type == "DNSBL"
        assert (d.feed, d.group) == ("abp_feed", "grp_abp")


# --------------------------------------------------------------------------- #
# A5/A6/A8 -- whiteDB overriding a block, and the numeric 6-band resolution's
# $important-vs-plain-allow precedence (evaluate_domain:6217-6267,
# _resolve_numeric_allow:5998).
# --------------------------------------------------------------------------- #


class TestAllowBlockPrecedenceArms:
    def test_a6_fast_path_whitelist_overrides_a_block(self) -> None:
        """important_rules False (no ABP $important/@@/regex loaded) -> the
        historical 'any whiteDB hit overrides any block' fast path (:6224-6227)."""
        q = "fastpath-allow.uuid1006.net"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        white = {q: True}  # legacy bare-bool whiteDB shape (exact, non-wildcard)
        containers = _containers(data=data, white=white, feed_group_index=_FGI)
        d = pfb_unbound.evaluate_domain(q, q, "net", False, _cfg(important_rules=False), containers)
        assert d.is_found is True
        assert d.in_whitelist is True

    def test_a5_abp_allow_overrides_a_block_via_numeric_band(self) -> None:
        """A feed @@ allow (band 2) beats a plain feed block (band 1) once the
        numeric path engages (important_rules True, :6229-6267)."""
        q = "allow-wins.uuid1005.com"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        white = {q: {"wildcard": False, "important": False, "band": PRIO_FEED_ALLOW}}
        containers = _containers(data=data, white=white, feed_group_index=_FGI)
        d = pfb_unbound.evaluate_domain(q, q, "com", False, _cfg(important_rules=True), containers)
        assert d.is_found is True
        assert d.in_whitelist is True  # allow_band(2) >= block_band(1) -> resolves

    def test_a8_important_block_beats_a_plain_allow(self) -> None:
        """A $important feed block (band 3) beats a plain feed @@ allow (band 2)."""
        q = "important-wins.uuid1008.org"
        data = {q: {"log": "1", "index": 0, "important": True, "band": PRIO_FEED_BLOCK_IMPORTANT}}
        white = {q: {"wildcard": False, "important": False, "band": PRIO_FEED_ALLOW}}
        containers = _containers(data=data, white=white, feed_group_index=_FGI)
        d = pfb_unbound.evaluate_domain(q, q, "org", False, _cfg(important_rules=True), containers)
        assert d.is_found is True
        assert d.in_whitelist is False  # allow_band(2) < block_band(3) -> block stands
        assert d.null_blocking is False  # VIP block (log '1', not in_hsts)


# --------------------------------------------------------------------------- #
# A7 -- TOP1M whitelist (manifest config top1m_enabled + fixed sidecar), through
# the REAL manifest build (reused tests/fixtures/adr06_golden/ -- the adr06
# exemplar config's historical top1m_list seeds pfb_py_top1m.txt).
# --------------------------------------------------------------------------- #


class TestTop1mWhitelistArm:
    def test_a7_top1m_enabled_unblocks_the_popular_domain(self, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=True)
        config = _load_json("config.json")
        got = _evaluate_result(result, config, "popularcdn.com")
        assert got["decision"] == "whitelist"

    def test_a7_top1m_disabled_blocks_the_same_domain(self, tmp_path: Any) -> None:
        """Guard the flip is real: with TOP1M disabled the same domain blocks."""
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        config = _load_json("config.json")
        got = _evaluate_result(result, config, "popularcdn.com")
        assert got["decision"] == "block-null"


# --------------------------------------------------------------------------- #
# A9 -- HSTS: an in-hstsDB blocked name resolves real (null-blocking forced
# OFF), attributed p_type "HSTS" (evaluate_domain:6269-6277). Staged directly
# with an inert uuid-style name (never an HSTS-preload name).
# --------------------------------------------------------------------------- #


class TestHstsArm:
    def test_a9_hsts_listed_name_resolves_real_with_hsts_attribution(self) -> None:
        q = "hsts-listed.uuid1009.com"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        hsts = {q: 0}
        containers = _containers(data=data, hsts=hsts, feed_group_index=_FGI)
        d = pfb_unbound.evaluate_domain(q, q, "com", False, _cfg(), containers)
        assert d.is_found is True
        assert d.in_hsts is True
        assert d.p_type == "HSTS"
        assert d.null_blocking is True  # HSTS forces the null-override OFF (:6273)


# --------------------------------------------------------------------------- #
# A10/A11/A12 -- the ADR-08 IDN feed: All-IDN (unconditional xn-- block),
# Confusable BLOCK (dual-form attribution), Confusable ALERT (non-blocking).
# Names reused verbatim from the ADR-08 corpus (test_adr08_confusable_matcher)
# -- never hand-invented homoglyph labels.
# --------------------------------------------------------------------------- #


class TestIdnArms:
    def test_a10_confusable_block_attributes_malicious_dual_form(self) -> None:
        cfg = _cfg(idn_mode=IDN_MODE_CONFUSABLE, python_idn_block_malicious=True)
        d = pfb_unbound.evaluate_domain(MALICIOUS_NAME, MALICIOUS_NAME, "com", False, cfg, _containers())
        assert d.is_found is True
        assert (d.feed, d.group) == (IDN_FEED_MALICIOUS, IDN_GROUP_MALICIOUS)
        assert d.b_eval != MALICIOUS_NAME  # dual-form (xn-- [decoded] script), not the bare label

    def test_a11_all_idn_blocks_any_xn_dash_dash_query(self) -> None:
        q = "xn--any1234.uuid1011.com"
        cfg = _cfg(idn_mode=IDN_MODE_ALL)
        d = pfb_unbound.evaluate_domain(q, q, "com", False, cfg, _containers())
        assert d.is_found is True
        assert (d.feed, d.group) == ("IDN", "DNSBL_IDN")

    def test_a12_confusable_alert_does_not_block_but_records_attribution(self) -> None:
        cfg = _cfg(idn_mode=IDN_MODE_CONFUSABLE, python_idn_escalate_suspicious=False)
        d = pfb_unbound.evaluate_domain(SUSPICIOUS_NAME, SUSPICIOUS_NAME, "com", False, cfg, _containers())
        assert d.is_found is False  # ALERT never blocks -- the name still resolves
        assert d.idn_alert is not None


# --------------------------------------------------------------------------- #
# A13 -- TLD_Allow: a query whose TLD is outside the allow-list blocks, feed
# "TLD_Allow" / group "DNSBL_TLD_Allow" (evaluate_domain:6103-6118).
# --------------------------------------------------------------------------- #


class TestTldAllowArm:
    def test_a13_disallowed_tld_blocks_via_tld_allow(self) -> None:
        q = "anything.uuid1013.org"
        cfg = _cfg(tld_allow=True, tld_allow_list=["com", "net"])
        d = pfb_unbound.evaluate_domain(q, q, "org", False, cfg, _containers())
        assert d.is_found is True
        assert (d.feed, d.group) == ("TLD_Allow", "DNSBL_TLD_Allow")


# --------------------------------------------------------------------------- #
# A14 -- NXDOMAIN (log '3'): bypasses the HSTS null-override entirely and
# clears any HSTS attribution, even for a name ALSO present in hstsDB
# (evaluate_domain:6282-6288).
# --------------------------------------------------------------------------- #


class TestNxdomainArm:
    def test_a14_nxdomain_log_flag_clears_hsts_and_sets_nxdomain(self) -> None:
        q = "nx-listed.uuid1014.com"
        data = {q: {"log": "3", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        hsts = {q: 0}  # even HSTS-listed, NXDOMAIN wins
        containers = _containers(data=data, hsts=hsts, feed_group_index=_FGI)
        d = pfb_unbound.evaluate_domain(q, q, "com", False, _cfg(), containers)
        assert d.is_found is True
        assert d.nxdomain is True
        assert d.null_blocking is True
        assert d.p_type == "Python"
        assert d.in_hsts is False


# --------------------------------------------------------------------------- #
# A15 -- CNAME: b_type gets a "_CNAME" suffix (evaluate_domain:6287-6288).
# --------------------------------------------------------------------------- #


class TestCnameArm:
    def test_a15_cname_suffixes_b_type(self) -> None:
        q = "cname-target.uuid1015.net"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        containers = _containers(data=data, feed_group_index=_FGI)
        d = pfb_unbound.evaluate_domain(q, q, "net", True, _cfg(), containers)
        assert d.b_type == "DNSBL_CNAME"


# --------------------------------------------------------------------------- #
# A16 -- clean pass-through: a name on no list resolves, no attribution.
# --------------------------------------------------------------------------- #


class TestCleanNotBlocked:
    def test_a16_unlisted_name_resolves(self) -> None:
        q = "totally-clean.uuid1016.com"
        d = pfb_unbound.evaluate_domain(q, q, "com", False, _cfg(), _containers())
        assert d.is_found is False


# --------------------------------------------------------------------------- #
# A17/A18/A19 -- the TLD-Wildcard toggle gates plain-path classification
# (tld_wildcard_classify:4316, staging :5323-5330, #1255 empty-oracle guard
# :4328). Reuses tests/fixtures/adr06_golden/ (com/net/org/co.uk oracle) via the
# ADR-06 Phase-4 harness (_build_from_manifest ON; _build_manifest_off here).
# --------------------------------------------------------------------------- #


class TestTldWildcardToggleClassification:
    def test_a17_two_label_domain_classifies_zone_when_on(self, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)  # always TLD ON
        config = _load_json("config.json")
        got = _evaluate_result(result, config, "malware.com")
        assert got["b_type"] == "TLD"

    def test_a18_same_two_label_domain_classifies_data_when_off(self, tmp_path: Any) -> None:
        result = _build_manifest_off(tmp_path)
        config = _load_json("config.json")
        got = _evaluate_result(result, config, "malware.com")
        assert got["b_type"] == "DNSBL"

    def test_a19_multilabel_public_suffix_zone_when_on_data_when_off(self, tmp_path: Any) -> None:
        config = _load_json("config.json")

        on_result = _build_from_manifest(tmp_path, top1m_enabled=False)
        got_on = _evaluate_result(on_result, config, "shop.co.uk")
        assert got_on["b_type"] == "TLD"  # co.uk multi-label public suffix, registrable parent

        off_result = _build_manifest_off(tmp_path)
        got_off = _evaluate_result(off_result, config, "shop.co.uk")
        assert got_off["b_type"] == "DNSBL"

    def test_a19_deep_subdomain_with_unmatched_parent_stays_data_when_on(self, tmp_path: Any) -> None:
        """A POPULATED oracle that finds NO match (parent not a known public
        suffix) still yields DATA -- a distinct code path (dcnt==4 search-miss,
        :4340-4341) from the OFF empty-oracle guard, same outcome."""
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        config = _load_json("config.json")
        got = _evaluate_result(result, config, "deep.path.cleanmal.com")
        assert got["b_type"] == "DNSBL"
