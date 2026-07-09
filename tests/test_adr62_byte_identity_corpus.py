"""ADR-62 Phase 1 -- byte-identity corpus, Python build surface (a).

Drives the REAL ``build()`` (which threads every raw line through ``parse()``/
``parse_abp()``) over the fixtures in ``tests/fixtures/dnsbl_corpus/``: the
per-feed metadata in ``feeds.json`` plus the ``raw/<header>.raw`` files, which
are the ACTUAL bytes ``pfb_unbound_python_sources()`` produces (captured by
``tests/php/Adr62DnsblCorpusManifestTest.php`` running the real PHP function --
never hand-duplicated here). This pins TODAY's domain/allow-set per
coverage-matrix row so Phases 3-5 can prove byte-identity modulo the ADR's
delta table (D1/D2/D4 asserted here as TODAY's behaviour, tagged by delta ID).

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
    pfb_unbound_python_sources() would have written (feed/group/format_hint/
    log_flag/provenance/mode) -- the ONLY difference from production is the
    ``raw`` reference resolves through the injected line_reader below instead
    of a chroot-relative file path."""
    feeds = []
    for f in _load_feeds():
        row = {
            "raw": f"{f['header']}.raw",
            "feed": f["header"],
            "group": f["group"],
            "format_hint": f["format"],
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


def test_abp_feed_bare_domain_is_wildcard_zone_delta_d1() -> None:
    """delta D1 (ADR.md SS2): a bare hosts/plain line in an ABP-classified feed
    is TODAY a wildcard ZONE via parse_abp (#718) -- Phase 5 flips this to the
    plain classify() path (registrable-parent ZONE / deeper-sub DATA) once the
    feed-level classifier is deleted. This pins the BEFORE state."""
    result = _run_corpus_build()
    assert "bare-domain.abp.example" in result.zone_db, (
        "delta D1: TODAY a bare domain inside an ABP feed must be a wildcard ZONE key "
        "(parse_abp wildcard=True), not a classify()-derived registrable parent"
    )


# --------------------------------------------------------------------------- #
# 5. mixed plain feed -- ADR-21 stray || anchor + delta D2 false-positive
# --------------------------------------------------------------------------- #


def test_mixed_plain_feed_ordinary_domain_blocked() -> None:
    result = _run_corpus_build()
    assert _blocked(result, "mixedhost.example")


def test_mixed_plain_feed_stray_abp_anchor_routes_to_parse_abp() -> None:
    # ADR-21: a '||domain^' line in a plain (never-ABP) feed's .txt/.raw is
    # captured verbatim and routed through parse_abp() at build() (@5090-5094).
    result = _run_corpus_build()
    assert "anchor.mixed.example" in result.zone_db


def test_mixed_plain_feed_hash_truncation_false_positive_delta_d2() -> None:
    """delta D2 (ADR.md SS2): TODAY, an element-hiding line like
    'falsepositive.example##.ad' is '#'-truncated by the plain extraction
    pipeline (inc:16706-16707) into a LIVE block for 'falsepositive.example' --
    an accidental false positive the ADR fixes (verbatim capture + Python skip)
    in Phase 4. This corpus row pins the pre-truncated RESULT ('falsepositive.
    example', already in the .txt/.raw dialect) as TODAY's behaviour."""
    result = _run_corpus_build()
    assert _blocked(result, "falsepositive.example"), (
        "delta D2: TODAY's '#'-truncation false-positive block must still occur"
    )


# --------------------------------------------------------------------------- #
# 6. permit-mode feed (ADR-31) -- host -> allow + delta D4 accidental allow
# --------------------------------------------------------------------------- #


def test_permit_feed_host_is_allow() -> None:
    result = _run_corpus_build()
    assert _allowed(result, "allowme.example")
    assert result.white_db["allowme.example"]["band"] == P.PRIO_FEED_ALLOW


def test_permit_feed_hash_truncation_accidental_allow_delta_d4() -> None:
    """delta D4 (ADR.md SS2): TODAY, a permit-mode feed's plain extraction
    pipeline runs the SAME '#'-truncation as any plain feed, so an
    element-hiding leftover ('accidentalallow.example', from
    'accidentalallow.example##.ad') reaches the .txt/.raw as an ordinary host
    line -- and build()'s permit loop (@5029-5064) treats EVERY such line as a
    band-2 allow. Phase 4 fixes this (verbatim capture -> Python skips '##')."""
    result = _run_corpus_build()
    assert _allowed(result, "accidentalallow.example"), (
        "delta D4: TODAY's permit-mode accidental allow from '##'-truncation must still occur"
    )


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
# 9. reused feed / stale manifest still naming format_hint='abp' (Semantics #7)
# --------------------------------------------------------------------------- #


def test_stale_abp_format_hint_manifest_still_parses() -> None:
    """Semantics #7 (ADR.md SS2): a manifest row that still names
    format_hint='abp' (as a stale on-disk manifest from a pre-upgrade build
    would) is tolerated identically -- build() routes it through parse_abp()
    exactly as a freshly-tagged 'abp' feed. Phase 5 must keep this green even
    after format_hint collapses to 'plain' for every NEW build."""
    result = _run_corpus_build()
    assert "reused.example" in result.zone_db
