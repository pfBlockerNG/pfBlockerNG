"""ADR-62 Phase 1 -- byte-identity corpus, Python build surface (a).

Drives the REAL ``build()`` (which threads every raw line through ``parse()``/
``parse_abp()``) over the fixtures in ``tests/fixtures/dnsbl_corpus/``: the
per-feed metadata in ``feeds.json`` plus the ``raw/<header>.raw`` files, which
are the ACTUAL bytes ``pfb_unbound_python_sources()`` produces (captured by
``tests/php/Adr62DnsblCorpusManifestTest.php`` running the real PHP function --
never hand-duplicated here). This pins the domain/allow-set per coverage-matrix
row, byte-identical to ``origin/devel`` modulo the ADR's delta table: D1
(``abp_feed``), D2, and D4 all assert their NEW outcome (the ``abp_feed``/
``mixed_plain``/``permit_feed`` fixtures were regenerated via the real
writer -- tagged by delta ID).

The DNSBL download loop itself has no off-appliance driver (ADR.md SS6 Phase 1);
the raw-feed -> ".txt"/".raw" step is DEFERRED to a live-VM smoke row (see the
Phase-1 handoff coverage matrix) -- this suite starts from the already-produced
``.raw`` bytes, exactly what ``build()`` consumes in production.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from typing import Any

import pfb_unbound as P

_CORPUS_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "dnsbl_corpus")


def _load_feeds() -> list[dict[str, Any]]:
    with open(os.path.join(_CORPUS_DIR, "feeds.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _corpus_manifest() -> dict[str, Any]:
    """The real per-feed manifest shape build() consumes, mirroring exactly what
    pfb_unbound_python_sources() would have written (feed/group/log_flag/
    provenance/mode -- format_hint retired #1083 P4) -- the ONLY difference from
    production is the ``raw`` reference resolves through the injected line_reader
    below instead of a chroot-relative file path."""
    feeds = []
    for f in _load_feeds():
        row = {
            "raw": f"{f['header']}.raw",
            "feed": f["header"],
            "group": f["group"],
            "provenance": f["provenance"],
            "log_flag": f["log"],
        }
        if "mode" in f:
            row["mode"] = f["mode"]
        feeds.append(row)
    return {"feeds": feeds}


def _corpus_line_reader() -> Callable[[str], Iterable[str]]:
    def reader(raw: str) -> list[str]:
        path = os.path.join(_CORPUS_DIR, "raw", raw)
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()

    return reader


def _run_corpus_build() -> P.BuildResult:
    config: dict[str, Any] = {
        "tld_master": [],
        "tld_blacklist": [],
        "tld_exclusion": [],
        "user_whitelist": [],
        "top1m_list": [],
    }
    return P.build(_corpus_manifest(), config, line_reader=_corpus_line_reader())


def _blocked(result: P.BuildResult, domain: str) -> bool:
    return domain in result.data_db or domain in result.zone_db


def _block_payload(result: P.BuildResult, domain: str) -> dict[str, Any]:
    return result.zone_db.get(domain) or result.data_db[domain]


def _allowed(result: P.BuildResult, domain: str) -> bool:
    return domain in result.white_db


# --------------------------------------------------------------------------- #
# 1. plain hosts feed -- post-loop bare domains reach dataDB/zoneDB
# --------------------------------------------------------------------------- #


def test_plain_hosts_feed_domains_are_blocked() -> None:
    result = _run_corpus_build()
    for domain in ("plainhost1.example", "plainhost2.example"):
        assert _blocked(result, domain), domain
        assert domain in result.zone_db, f"{domain}: 2-label domain must auto-zone"


# --------------------------------------------------------------------------- #
# 2. CSV types (pt/bbc/h3x/otx/pon/et) -- post-extraction domain reaches build()
# --------------------------------------------------------------------------- #


def test_csv_type_domains_are_blocked() -> None:
    result = _run_corpus_build()
    for domain in (
        "ptfeed.example",
        "bbcfeed.example",
        "h3xfeed.example",
        "otxfeed.example",
        "ponfeed.example",
        "etfeed.example",
    ):
        assert _blocked(result, domain), domain


# --------------------------------------------------------------------------- #
# 3. custom (liteparser) list -- provenance='user' -> USER block band
# --------------------------------------------------------------------------- #


def test_custom_list_domain_is_user_band() -> None:
    result = _run_corpus_build()
    assert _blocked(result, "customlist.example")
    assert _block_payload(result, "customlist.example")["band"] == P.PRIO_USER_BLOCK


# --------------------------------------------------------------------------- #
# 4. ABP/EasyList feed -- full shape set incl. delta D1 (bare domain -> ZONE)
# --------------------------------------------------------------------------- #


def test_abp_feed_anchor_block() -> None:
    result = _run_corpus_build()
    assert "anchor.abp.example" in result.zone_db
    assert result.zone_db["anchor.abp.example"]["important"] is False


def test_abp_feed_exception_allow() -> None:
    result = _run_corpus_build()
    assert _allowed(result, "exception.abp.example")


def test_abp_feed_regex_block_reduces_to_exact_data() -> None:
    # /^regexblock\.abp\.example$/ -- the '^...$' anchor form has no wildcard
    # prefix, so it reduces to an EXACT (non-wildcard) data-db entry (ADR.md SS2
    # regex-reduction rule; mirrors tests/fixtures/adr07_corpus/regex_reducible.txt).
    result = _run_corpus_build()
    assert "regexblock.abp.example" in result.data_db
    assert "regexblock.abp.example" not in result.zone_db


def test_abp_feed_regex_allow_reduces_to_exact_allow() -> None:
    result = _run_corpus_build()
    assert _allowed(result, "regexallow.abp.example")
    assert result.white_db["regexallow.abp.example"]["wildcard"] is False


def test_abp_feed_important_flag_carried() -> None:
    result = _run_corpus_build()
    assert "important.abp.example" in result.zone_db
    assert result.zone_db["important.abp.example"]["important"] is True


def test_abp_feed_badfilter_rule_emits_no_decision() -> None:
    # $badfilter never emits a block/allow itself (reconcile() Step 1) -- and
    # there is no matching non-badfilter rule in this corpus for it to prune.
    result = _run_corpus_build()
    assert not _blocked(result, "badf.abp.example")
    assert not _allowed(result, "badf.abp.example")


def test_abp_feed_element_hiding_line_produces_no_domain() -> None:
    # 'some.abp.example##.ad-banner' is a cosmetic (element-hiding) rule --
    # parse_abp() skips it entirely (no ',' in the '##' family reaches a Rule).
    result = _run_corpus_build()
    assert not _blocked(result, "some.abp.example")
    assert not _allowed(result, "some.abp.example")


def test_abp_feed_bare_registrable_parent_stays_zone_delta_d1() -> None:
    """delta D1 (ADR.md SS2), registrable-parent case: a bare 2-label line in a
    feed that WAS header-classified ABP used to reach a wildcard ZONE via
    parse_abp (#718); the classifier is now deleted, so the same line takes
    the plain classify() path -- a 2-label domain is UNCONDITIONALLY its own
    registrable parent, so the observable stays ZONE (same as before)."""
    result = _run_corpus_build()
    assert "abproot.example" in result.zone_db, (
        "delta D1: a registrable-parent bare line in a former-ABP feed must still "
        "land in zone_db under the plain classify() path"
    )


def test_abp_feed_bare_deeper_subdomain_flips_zone_to_data_delta_d1() -> None:
    """delta D1 (ADR.md SS2), deeper-sub case -- the REAL observable flip: a bare
    deeper sub-domain line in a former-ABP feed was wildcard ZONE at ANY depth
    via parse_abp (#718); the plain classify() path only ZONEs a registrable
    parent (a known public suffix's parent) -- with no matching suffix (this
    corpus's tld_master is empty) a deeper sub-domain is exact DATA instead."""
    result = _run_corpus_build()
    assert "bare-domain.abp.example" in result.data_db, (
        "delta D1: a deeper bare sub-domain in a former-ABP feed must land in "
        "data_db (exact), not zone_db (wildcard), under the plain classify() path"
    )
    assert "bare-domain.abp.example" not in result.zone_db, (
        "delta D1: the deeper bare sub-domain must NOT be wildcard-ZONE anymore "
        "-- that was parse_abp's #718 behaviour, now retired with the classifier"
    )


# --------------------------------------------------------------------------- #
# 5. mixed plain feed -- ADR-21 stray || anchor + delta D2 verbatim capture
# --------------------------------------------------------------------------- #


def test_mixed_plain_feed_ordinary_domain_blocked() -> None:
    result = _run_corpus_build()
    assert _blocked(result, "mixedhost.example")


def test_mixed_plain_feed_stray_abp_anchor_routes_to_parse_abp() -> None:
    # ADR-21: a '||domain^' line in a plain (never-ABP) feed's .txt/.raw is
    # captured verbatim and routed through parse_abp() at build() (@5090-5094).
    result = _run_corpus_build()
    assert "anchor.mixed.example" in result.zone_db


def test_mixed_plain_feed_hash_truncation_false_positive_fixed_delta_d2() -> None:
    """delta D2 NEW outcome (ADR.md SS2, Phase 4): 'falsepositive.example##.ad'
    is now captured VERBATIM by the broadened download-loop/manifest-writer
    predicate (pfb_dnsbl_is_abp_rule_line) instead of '#'-truncated into a live
    block -- the corpus fixture (tests/fixtures/dnsbl_corpus/txt/mixed_plain.txt)
    was regenerated via the real (now-broadened) pfb_unbound_python_sources()
    per the corpus README. Python's parse_abp() skips the '##' element-hiding
    marker, so NO domain is emitted at all -- the false positive is gone. This
    was PREVIOUSLY pinned as a TODAY-blocks assertion (Phase 1); Phase 3 proved
    the NEW outcome only on synthetic input (test_adr62_parity_oracle.py) since
    the committed corpus couldn't yet carry the verbatim shape -- this is that
    proof made corpus-real."""
    result = _run_corpus_build()
    assert not _blocked(result, "falsepositive.example"), (
        "delta D2 NEW: verbatim '##' capture must produce NO domain, not a block"
    )
    assert not _allowed(result, "falsepositive.example")


def test_mixed_plain_feed_regex_rule_now_honoured_delta_d2() -> None:
    """delta D2 NEW outcome: a bare '/re/' block-regex line in a never-ABP
    feed, previously '/'-truncated to nothing by the plain pipeline (dropped,
    no domain), is now captured verbatim and routed to parse_abp() -- an
    anchored '^...$' regex reduces to an exact data-db block (mirrors the
    abp_feed corpus row's regexblock.abp.example)."""
    result = _run_corpus_build()
    assert "regexplain.mixed.example" in result.data_db
    assert "regexplain.mixed.example" not in result.zone_db


def test_mixed_plain_feed_regex_important_flag_carried_delta_d2() -> None:
    """delta D2 NEW outcome: '/re/$important' in a never-ABP feed is captured
    verbatim and its $important flag survives parse_abp()'s $options parse."""
    result = _run_corpus_build()
    assert "importantregex.mixed.example" in result.data_db
    assert result.data_db["importantregex.mixed.example"]["important"] is True


def test_mixed_plain_feed_bare_at_allow_regex_now_honoured_delta_d2() -> None:
    """delta D2 NEW outcome: a bare '@@/re/' allow-regex line (the broadened
    '@@' prefix, NOT the pre-existing '@@||' shape) in a never-ABP feed is
    captured verbatim and produces a real allow -- proves the ADR's "regex
    rules in plain feeds now honoured" benefit end-to-end via the corpus."""
    result = _run_corpus_build()
    assert _allowed(result, "allowregex.mixed.example")
    assert result.white_db["allowregex.mixed.example"]["wildcard"] is False


# --------------------------------------------------------------------------- #
# 6. permit-mode feed (ADR-31) -- host -> allow + delta D4 verbatim capture
# --------------------------------------------------------------------------- #


def test_permit_feed_host_is_allow() -> None:
    result = _run_corpus_build()
    assert _allowed(result, "allowme.example")
    assert result.white_db["allowme.example"]["band"] == P.PRIO_FEED_ALLOW


def test_permit_feed_hash_truncation_accidental_allow_fixed_delta_d4() -> None:
    """delta D4 NEW outcome (ADR.md SS2, Phase 4): 'accidentalallow.example##.ad'
    is now captured VERBATIM by the broadened predicate instead of
    '#'-truncated into an ordinary host line -- the corpus fixture (tests/
    fixtures/dnsbl_corpus/txt/permit_feed.txt) was regenerated via the real
    broadened pfb_unbound_python_sources(). build()'s permit loop skips any
    ABP-shaped line (_dnsbl_is_abp_rule_line, Phase 3), so the accidental
    band-2 allow is gone. PREVIOUSLY pinned as a TODAY-allows assertion
    (Phase 1); Phase 3 proved the NEW outcome only on synthetic input -- this
    is that proof made corpus-real."""
    result = _run_corpus_build()
    assert not _allowed(result, "accidentalallow.example"), "delta D4 NEW: verbatim '##' capture must produce NO allow"
    assert not _blocked(result, "accidentalallow.example")


# --------------------------------------------------------------------------- #
# 7/8. #752 (KNOWN divergence, not a delta) / #753 (byte-identical boundary)
# --------------------------------------------------------------------------- #

_NAME_253 = ".".join(["b" * 61] * 4) + "." + "b" * 5
_NAME_254 = ".".join(["b" * 61] * 4) + "." + "b" * 6


def test_oversized_752_undotted_name_rejected_by_python() -> None:
    """#752 (ADR.md SS1.5, KNOWN pre-existing divergence -- NOT a delta): PHP's
    PFB_FILTER_DOMAIN accepts this 254-char undotted name into the .txt/.raw
    dialect (pinned PHP-side by
    Adr62DnsblCorpusManifestTest::testPhp752OversizedUndottedNameValidatesAsDomain);
    Python's normalise()/_dnsbl_within_wire_caps rejects it (len > 253) -- so it
    never reaches any DB, even though the .raw fixture (produced by the REAL
    PHP writer) carries it verbatim."""
    assert len(_NAME_254) == 254
    result = _run_corpus_build()
    assert not _blocked(result, _NAME_254)
    assert not _allowed(result, _NAME_254)
    assert result.rejects[("oversized_feed", "grp_edge")]["wire_cap"] == 1


def test_wirecap_753_boundary_name_accepted_by_python() -> None:
    """#753 boundary: the 253-char name is byte-identical accept on BOTH sides
    (not a divergence) -- confirms the wire-cap boundary itself, complementing
    the isolated unit pin in test_adr06_build_module.py."""
    assert len(_NAME_253) == 253
    result = _run_corpus_build()
    assert _blocked(result, _NAME_253)


# --------------------------------------------------------------------------- #
# 9. self-describing ||domain^ line parses regardless of any feed-level tag
# --------------------------------------------------------------------------- #


def test_reused_manifest_abp_shaped_line_still_parses() -> None:
    """#1083 P4: format_hint's whole-feed dispatch is retired -- the
    reused_manifest_abp corpus feed's ``||reused.example^`` line still routes to
    parse_abp() purely because the PERMANENT per-line capture guard
    (_dnsbl_is_abp_rule_line()) recognises its shape, independent of any
    feed-level tag."""
    result = _run_corpus_build()
    assert "reused.example" in result.zone_db
