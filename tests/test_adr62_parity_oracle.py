"""ADR-62 Phases 3-4 -- parity oracle for build()'s extended per-line routing.

Two halves, per the Phase-3 brief:

1. **Corpus parity** (Semantics #1): re-runs the corpus
   (``tests/fixtures/dnsbl_corpus/``) through ``build()``'s extended routing
   and asserts the domain/allow SET produced is byte-identical to
   ``origin/devel``, modulo the delta table. D2/D4 (mixed_plain/permit_feed)
   and D1 (abp_feed, classifier now deleted) all carry their NEW outcome here
   -- see the golden-set comment below.

2. **Delta-NEW-outcome + hostile-input oracle**: a SYNTHETIC-raw-content
   oracle (bypassing the corpus/manifest writer entirely) that predates the
   Phase-4 wiring and still stands: it pins the FULL hostile-input matrix
   (every element-hiding marker variant, `/re/`+`$options`, bare anchors,
   etc.) at the ``build()`` level, a broader surface than the handful of
   shapes the corpus fixtures carry. Section 1's corpus-real assertions and
   this section's synthetic ones now agree on every delta outcome (D2/D4
   NEW); section 2 is kept for its wider hostile-input coverage.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from typing import Any

import pytest

import pfb_unbound as P
from pfb_unbound import _dnsbl_is_abp_rule_line

_CORPUS_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "dnsbl_corpus")

# --------------------------------------------------------------------------- #
# Section 1: corpus parity (reuses the Phase-1 fixture set -- NOT hand-edited,
# per Phase-1's carry-forward #5).
# --------------------------------------------------------------------------- #


def _load_feeds() -> list[dict[str, Any]]:
    with open(os.path.join(_CORPUS_DIR, "feeds.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _corpus_manifest() -> dict[str, Any]:
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
        "tld_wildcard_master": [],
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": [],
        "user_whitelist": [],
        "top1m_list": [],
    }
    return P.build(_corpus_manifest(), config, line_reader=_corpus_line_reader())


_NAME_253 = ".".join(["b" * 61] * 4) + "." + "b" * 5

# Golden per-feed domain/allow sets (Semantics #1): captured by running the
# REAL build() over the corpus's committed raw/*.raw bytes (the same fixtures
# Adr62DnsblCorpusManifestTest.php's PHP run produced) -- not hand-derived.
# Every entry equals origin/devel's value except mixed_plain/permit_feed
# (D2/D4) and abp_feed (D1, the classifier-deletion delta -- "abproot.example"
# is new; "bare-domain.abp.example" stays a member of the set but moves from
# zone_db to data_db, see test_adr62_byte_identity_corpus.py's dedicated
# assertion for that finer-grained split), each carrying its NEW outcome (the
# fixtures were regenerated via the real writer -- see feeds.json's "row" note).
_GOLDEN_PER_FEED: dict[str, dict[str, set[str]]] = {
    "plain_hosts": {"blocked": {"plainhost1.example", "plainhost2.example"}, "allowed": set()},
    "csv_pt": {"blocked": {"ptfeed.example"}, "allowed": set()},
    "csv_bbc": {"blocked": {"bbcfeed.example"}, "allowed": set()},
    "csv_h3x": {"blocked": {"h3xfeed.example"}, "allowed": set()},
    "csv_otx": {"blocked": {"otxfeed.example"}, "allowed": set()},
    "csv_pon": {"blocked": {"ponfeed.example"}, "allowed": set()},
    "csv_et": {"blocked": {"etfeed.example"}, "allowed": set()},
    "custom_list": {"blocked": {"customlist.example"}, "allowed": set()},
    "abp_feed": {
        "blocked": {
            "anchor.abp.example",
            "regexblock.abp.example",
            "important.abp.example",
            "abproot.example",
            "bare-domain.abp.example",
        },
        "allowed": {"exception.abp.example", "regexallow.abp.example"},
    },
    "mixed_plain": {
        "blocked": {
            "mixedhost.example",
            "anchor.mixed.example",
            "regexplain.mixed.example",
            "importantregex.mixed.example",
        },
        "allowed": {"allowregex.mixed.example"},
    },
    "permit_feed": {"blocked": set(), "allowed": {"allowme.example"}},
    "oversized_feed": {"blocked": set(), "allowed": set()},  # #752: rejected (wire_cap)
    "wirecap_feed": {"blocked": {_NAME_253}, "allowed": set()},
    "reused_manifest_abp": {"blocked": {"reused.example"}, "allowed": set()},
}


def test_corpus_domain_set_is_byte_identical_aggregate() -> None:
    """Semantics #1, aggregate: the WHOLE domain/allow set the extended routing
    produces over the corpus equals the golden set exactly, modulo the delta
    table (a stronger check than the per-domain membership assertions in
    test_adr62_byte_identity_corpus.py -- an unexpected EXTRA domain, from a
    mis-route, would also fail this)."""
    result = _run_corpus_build()
    actual_blocked = set(result.data_db) | set(result.zone_db)
    actual_allowed = set(result.white_db)
    golden_blocked = {d for row in _GOLDEN_PER_FEED.values() for d in row["blocked"]}
    golden_allowed = {d for row in _GOLDEN_PER_FEED.values() for d in row["allowed"]}
    assert actual_blocked == golden_blocked
    assert actual_allowed == golden_allowed


def test_corpus_domain_set_is_byte_identical_per_format() -> None:
    """Semantics #1, per row: same parity, broken out per coverage-matrix
    format so a future regression names the SPECIFIC format that drifted."""
    result = _run_corpus_build()
    all_blocked = set(result.data_db) | set(result.zone_db)
    all_allowed = set(result.white_db)
    for header, golden in _GOLDEN_PER_FEED.items():
        assert golden["blocked"] <= all_blocked, f"{header}: expected blocked domain(s) missing"
        assert golden["allowed"] <= all_allowed, f"{header}: expected allowed domain(s) missing"


# --------------------------------------------------------------------------- #
# Section 2: delta-NEW-outcome + hostile-input oracle (SYNTHETIC raw content).
# --------------------------------------------------------------------------- #


def _build_synthetic(feeds: list[dict[str, Any]], lines_by_header: dict[str, list[str]]) -> P.BuildResult:
    """Run build() over hand-supplied raw content, bypassing the corpus
    fixture files AND PHP's manifest writer entirely -- see the module
    docstring's blast-radius note for why this is the only legitimate way to
    exercise a shape PHP cannot yet place in a 'plain' feed's raw."""
    manifest = {"feeds": feeds}
    config: dict[str, Any] = {
        "tld_wildcard_master": [],
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": [],
        "user_whitelist": [],
        "top1m_list": [],
    }
    return P.build(manifest, config, line_reader=lambda raw: lines_by_header[raw])


def _plain_feed_row(header: str, *, mode: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "raw": header,
        "feed": header,
        "group": f"grp_{header}",
        "provenance": "feed",
        "log_flag": "1",
    }
    if mode is not None:
        row["mode"] = mode
    return row


def _blocked(result: P.BuildResult, domain: str) -> bool:
    return domain in result.data_db or domain in result.zone_db


def _allowed(result: P.BuildResult, domain: str) -> bool:
    return domain in result.white_db


# ---- delta D2 NEW outcome: element-hiding verbatim in a plain feed -> skip -- #


def test_delta_d2_new_element_hiding_verbatim_produces_no_false_positive_block() -> None:
    """delta D2 NEW on synthetic input; now corroborated corpus-real by
    test_adr62_byte_identity_corpus.py's
    test_mixed_plain_feed_hash_truncation_false_positive_fixed_delta_d2 (Phase
    4 wired the broadened PHP capture, so the corpus fixture itself now
    carries the untruncated line). Once the UNTRUNCATED line reaches Python,
    the extended predicate routes it to parse_abp(), which skips
    element-hiding -> NO block for the bare domain."""
    result = _build_synthetic(
        [_plain_feed_row("eh_new")],
        {"eh_new": ["falsepositive2.example##.ad-banner", "realblock.example"]},
    )
    assert not _blocked(result, "falsepositive2.example"), (
        "delta D2 NEW: a verbatim element-hiding line must never false-positive block"
    )
    assert _blocked(result, "realblock.example"), "an ordinary host line in the same feed still blocks"


@pytest.mark.parametrize("marker_line", ["a.example#@#b", "a.example#?#b", "a.example#%#b", "a.example#$#b"])
def test_delta_d2_new_every_element_hiding_marker_variant_produces_no_domain(marker_line: str) -> None:
    """Full element-hiding family (##, #@#, #?#, #%#, #$#), not just ##."""
    result = _build_synthetic([_plain_feed_row("eh_family")], {"eh_family": [marker_line]})
    assert not _blocked(result, "a.example")
    assert not _allowed(result, "a.example")


# ---- delta D4 NEW outcome: element-hiding verbatim in a permit feed -> skip - #


def test_delta_d4_new_element_hiding_verbatim_in_permit_feed_produces_no_accidental_allow() -> None:
    """delta D4 NEW on synthetic input; now corroborated corpus-real by
    test_adr62_byte_identity_corpus.py's
    test_permit_feed_hash_truncation_accidental_allow_fixed_delta_d4 (Phase 4
    wired the broadened PHP capture). Once the UNTRUNCATED line reaches
    Python, the permit loop's skip set (sharing _dnsbl_is_abp_rule_line with
    the plain-block loop) catches it BEFORE parse() ever runs -- no accidental
    band-2 allow."""
    result = _build_synthetic(
        [_plain_feed_row("permit_new", mode="permit")],
        {"permit_new": ["accidentalallow2.example##.ad-banner", "realallow.example"]},
    )
    assert not _allowed(result, "accidentalallow2.example"), (
        "delta D4 NEW: a verbatim element-hiding line in a permit feed must never accidentally allow"
    )
    assert _allowed(result, "realallow.example"), "an ordinary host line in the same permit feed still allows"


# ---- regex / $important / $badfilter verbatim in a plain feed (delta D2) --- #


def test_regex_and_options_verbatim_in_plain_feed_are_honoured() -> None:
    """delta D2 NEW: /regex/, @@/regex/, $important and $badfilter verbatim in
    a PLAIN (never-ABP) feed are captured and parsed by parse_abp() exactly as
    they would be in an ABP feed -- the ADR's thesis (self-identifying per
    line, not per feed)."""
    result = _build_synthetic(
        [_plain_feed_row("mixedshapes")],
        {
            "mixedshapes": [
                r"/^regexplain\.example$/",
                "||importantplain.example^$important",
                "||badfplain.example^$badfilter",
                r"@@/^regexallowplain\.example$/",
                "plainhost.example",
                "||anchorplain.example^",
            ]
        },
    )
    assert "regexplain.example" in result.data_db, "reducible block-regex -> exact data entry"
    assert "regexplain.example" not in result.zone_db
    assert result.zone_db["importantplain.example"]["important"] is True
    assert not _blocked(result, "badfplain.example") and not _allowed(result, "badfplain.example"), (
        "$badfilter emits no decision by itself"
    )
    assert _allowed(result, "regexallowplain.example")
    assert result.white_db["regexallowplain.example"]["wildcard"] is False
    # mixed: an ordinary plain-hosts line AND a stray ||anchor in the SAME feed
    # both block (hostile-input row "mixed plain+||").
    assert _blocked(result, "plainhost.example")
    assert _blocked(result, "anchorplain.example")


# ---- hostile-input table (REQUIRED, per brief) ------------------------------ #


def test_hostile_idn_punycode_boundary_not_a_python_conversion() -> None:
    """IDN/punycode (brief hostile row): PHP's idn_to_ascii already converted
    the name before it ever reaches Python's raw (the boundary) -- Python does
    NOT convert. A pre-converted punycode label blocks normally; a RAW
    non-ASCII label (simulating a bug upstream of this boundary) is rejected
    by normalise()'s ASCII-only shape gate, never silently accepted."""
    result = _build_synthetic(
        [_plain_feed_row("idn")],
        {"idn": ["xn--mnchen-3ya.example", "münchen.example"]},
    )
    assert _blocked(result, "xn--mnchen-3ya.example"), "already-punycode domain blocks like any bare domain"
    assert not _blocked(result, "münchen.example"), "raw non-ASCII must be rejected, never silently converted"


def test_hostile_752_oversized_undotted_unaffected_by_phase3() -> None:
    """#752 (brief hostile row, KNOWN divergence -- NOT a delta): the
    254-char undotted name is a bare domain, so _dnsbl_is_abp_rule_line()
    returns False (unaffected by this phase's routing extension) and Python's
    existing wire_cap rejection stands untouched. PHP still accepts it into
    .raw (Adr62DnsblCorpusManifestTest::testPhp752...); Python's rejection
    wins for the block decision, exactly as before this phase."""
    name_254 = ".".join(["b" * 61] * 4) + "." + "b" * 6
    assert len(name_254) == 254
    assert _dnsbl_is_abp_rule_line(name_254) is False
    result = _build_synthetic([_plain_feed_row("oversized")], {"oversized": [name_254]})
    assert not _blocked(result, name_254)
    assert result.rejects[("oversized", "grp_oversized")]["wire_cap"] == 1


def test_hostile_753_wire_cap_label_and_total_variants_reject() -> None:
    """#753 (brief hostile row): two DISTINCT wire-cap trips -- a single
    64-char label (per-label cap, RFC 1035) and a 254-char DOTTED total with
    every label <= 63 (the total cap) -- both reject, neither is a delta."""
    oversized_label = "a" * 64 + ".example.com"
    oversized_total = ".".join(["b" * 63, "b" * 63, "b" * 63, "b" * 62])
    assert len(oversized_total) == 254
    result = _build_synthetic(
        [_plain_feed_row("wirecaps")],
        {"wirecaps": [oversized_label, oversized_total]},
    )
    assert not _blocked(result, oversized_label)
    assert not _blocked(result, oversized_total)


def test_hostile_empty_whitespace_and_bom_led_lines_produce_no_domain() -> None:
    """empty / whitespace-only / BOM-led first line (brief hostile row): none
    produce a domain; the BOM case documents a PRODUCTION-IRRELEVANT gap (a
    BOM-led '||' line is NOT captured by the predicate, because Python's str
    strip() does not remove U+FEFF) -- harmless because PHP's download loop
    strips the BOM (pfb_dnsbl_strip_bom, inc:16364) BEFORE any capture site,
    so a raw BOM never survives to reach Python in production (same class of
    finding as the Phase-2 handoff's whitespace-untrimmed PROBE)."""
    result = _build_synthetic(
        [_plain_feed_row("blanks")],
        {"blanks": ["", "   ", "﻿||bomabp.example^"]},
    )
    assert result.data_db == {} and result.zone_db == {} and result.white_db == {}
    # The BOM-led line is production-irrelevant, but assert the boundary anyway:
    # unstripped, it is NOT recognised as an ABP anchor (documents the gap).
    assert _dnsbl_is_abp_rule_line("﻿||bomabp.example^") is False


def test_hostile_allow_and_regex_shapes_route_to_parse_abp_not_a_block() -> None:
    """'@@||exception.com^' (brief hostile row): an allow-rule via parse_abp,
    never a block domain."""
    result = _build_synthetic([_plain_feed_row("allow")], {"allow": ["@@||exception.com^"]})
    assert _allowed(result, "exception.com")
    assert not _blocked(result, "exception.com")


def test_hostile_regex_shapes_route_to_parse_abp() -> None:
    """'/regex/', '@@/re/', '/re/$important' (brief hostile row): all three
    regex shapes route through parse_abp(), never the plain host path."""
    for shape in (r"/^re1\.example$/", r"@@/^re2\.example$/", r"/^re3\.example$/$important"):
        assert _dnsbl_is_abp_rule_line(shape) is True, shape
    result = _build_synthetic(
        [_plain_feed_row("regexes")],
        {"regexes": [r"/^re1\.example$/", r"@@/^re2\.example$/", r"/^re3\.example$/$important"]},
    )
    assert _blocked(result, "re1.example")
    assert _allowed(result, "re2.example")
    assert result.zone_db.get("re3.example", {}).get("important") is True or "re3.example" in result.data_db


def test_hostile_banded_rules_preserve_domain() -> None:
    """'||domain.com^$important' and '$badfilter' (brief hostile row): the
    domain is preserved (important flag carried; badfilter emits nothing but
    does not corrupt the anchor parse)."""
    result = _build_synthetic(
        [_plain_feed_row("banded")],
        {"banded": ["||importantbanded.example^$important", "||badfbanded.example^$badfilter"]},
    )
    assert result.zone_db["importantbanded.example"]["important"] is True
    assert not _blocked(result, "badfbanded.example")


def test_hostile_control_lines_produce_no_domain() -> None:
    """'[Adblock Plus 2.0]' and '! Title: X' (brief hostile row): control
    lines never produce a spurious domain -- '!' is dropped by parse()
    itself; '[...]' is not captured by _dnsbl_is_abp_rule_line() (that is
    pfb_dnsbl_is_skippable_control_line()'s job, not this predicate's) but
    still yields no domain end-to-end via normalise()'s shape gate."""
    result = _build_synthetic(
        [_plain_feed_row("controls")],
        {"controls": ["[Adblock Plus 2.0]", "! Title: X"]},
    )
    assert result.data_db == {} and result.zone_db == {} and result.white_db == {}


def test_hostile_ip_anchored_and_bare_ipv6_never_emit_a_domain() -> None:
    """'||1.2.3.4^' and bare '2604:2dc0::' (brief hostile row): IP extraction
    is PHP's job (SS1.4) -- the routing must never emit either as a domain."""
    result = _build_synthetic(
        [_plain_feed_row("ips")],
        {"ips": ["||1.2.3.4^", "2604:2dc0::"]},
    )
    assert result.data_db == {} and result.zone_db == {}


def test_hostile_bare_deep_subdomain_stays_on_plain_path_delta_d1() -> None:
    """bare 'sub.deep.example.com' in a plain feed (brief hostile row, delta
    D1): _dnsbl_is_abp_rule_line() is False for a bare domain, so it takes
    tld_wildcard_classify() (deeper sub with no known public suffix -> exact DATA), NEVER
    parse_abp's wildcard=True ZONE. Mirrors the corpus's own former-ABP-feed
    case (test_adr62_byte_identity_corpus.py::
    test_abp_feed_bare_deeper_subdomain_flips_zone_to_data_delta_d1), now that
    the classifier is deleted and every feed takes this same plain path."""
    line = "sub.deep.example.com"
    assert _dnsbl_is_abp_rule_line(line) is False
    result = _build_synthetic([_plain_feed_row("bare_deep")], {"bare_deep": [line]})
    assert line in result.data_db, "D1: a plain feed's deep bare sub-domain is exact DATA, not a wildcard ZONE"
    assert line not in result.zone_db


def test_hostile_comment_slash_line_not_routed_to_parse_abp() -> None:
    """'//comment' (brief hostile row): predicate FALSE on both sides
    (Phase-2 PROBE) -- today's plain-path outcome (no domain, rejected by the
    no-dot shape gate) is preserved."""
    assert _dnsbl_is_abp_rule_line("//comment") is False
    result = _build_synthetic([_plain_feed_row("slashcomment")], {"slashcomment": ["//comment"]})
    assert result.data_db == {} and result.zone_db == {}


def test_cosmetic_prefix_guard_matches_php_row_for_row() -> None:
    """The element-hiding capture requires an ABP cosmetic domain-list prefix
    before the FIRST marker, and '//'-led lines are comments, never regex
    rules -- mirroring pfb_dnsbl_is_abp_rule_line() row for row (PR #1107
    review: an unanchored '##' substring capture silently dropped a hosts
    line's ' ## ' inline-comment block and CSV rows carrying '#'-fragment
    URLs, and '//path/' comments became live regex rules)."""
    not_capturable = [
        "0.0.0.0 example.com ## comment",
        "example.com ## seen 2024",
        "12345,http://evil.example/path##frag,phish,online",
        "http://example.com/##banner",
        "# note ## x",
        "# The Spamhaus Project Ltd ## marketing ## banner",
        "# c#@#d",
        "\thost.example##.ad",
        "//cdn.example.com/ads/",
        "//",
        "@stray.example",  # single-@ yHost prefix, not an '@@' allow anchor
        # issue #1067: a leading comma is never valid ABP syntax (an empty first
        # cosmetic domain-list entry) -- left uncaught, a comma-first verbatim
        # capture collides with the plain-CSV dialect on the read side.
        ",a,b,c,d##x",
        ",example.com,example.org##.ad",
        ",a,,1,RealFeed,x##y",  # crafted to mimic the plain-CSV field shape
        ",||x^",
        ",",
        ",,##x",
        # issue #1276: a hosts-dialect whole-line comment ('## Section', a marker
        # at position 0 followed by whitespace) shares its shape with a real
        # generic cosmetic rule -- must stay on the plain '#'-comment path.
        "## Section header",
        "##\tSection",
        "#@# note",
        "##",  # marker alone, nothing after -- no non-whitespace char to require
    ]
    capturable = [
        "####################",  # marker at pos 0: generic-rule shape (documented latent)
        "##.ad",
        "example.com##.ad",
        "a.com,b.com##.ad",
        "example.com,example.org##.ad",  # comma INSIDE the cosmetic prefix stays valid
        "~ex.com##.ad",
        "EXAMPLE.com##.ad",
        "/re/",
        "/re/$important",
        "#@#selector",  # marker+non-space, no space -- proves guard scope isn't a marker-family regression
    ]
    for line in not_capturable:
        assert _dnsbl_is_abp_rule_line(line) is False, f"must NOT capture: {line!r}"
    for line in capturable:
        assert _dnsbl_is_abp_rule_line(line) is True, f"must capture: {line!r}"
    # Behavioural half for the fail-open class: because the predicate does not
    # capture a ' ## ' inline-comment line, PHP's plain extraction keeps
    # producing the bare domain in the .raw (never a verbatim line that
    # parse_abp would return None for) -- and that bare domain still blocks.
    result = _build_synthetic([_plain_feed_row("inlinehash")], {"inlinehash": ["keepme.example"]})
    assert _blocked(result, "keepme.example")


def test_hostile_bare_anchors_route_to_parse_abp_and_crash_free() -> None:
    """bare '@@' / bare '||' (brief hostile row): structural capture (Phase-2
    contract) routes both to parse_abp(), which returns None (empty host
    after anchor-strip) -- no domain, no crash."""
    assert _dnsbl_is_abp_rule_line("@@") is True
    assert _dnsbl_is_abp_rule_line("||") is True
    result = _build_synthetic([_plain_feed_row("bare_anchors")], {"bare_anchors": ["@@", "||"]})
    assert result.data_db == {} and result.zone_db == {} and result.white_db == {}


# ---- permit-loop skip-set consistency (action item 2) ----------------------- #


def test_permit_loop_skip_set_covers_the_full_broadened_capture_shape_set() -> None:
    """Action item 2: the permit loop's skip set must cover every shape the
    broadened plain-block predicate now routes -- '@@', '||', '/regex/', and
    every element-hiding marker -- so NONE of them can become an accidental
    allow, only an ordinary host line can."""
    result = _build_synthetic(
        [_plain_feed_row("permit_full", mode="permit")],
        {
            "permit_full": [
                "@@||shouldnotallow1.example^",
                "||shouldnotallow2.example^",
                r"/^shouldnotallow3\.example$/",
                "shouldnotallow4.example##.ad",
                "realpermithost.example",
            ]
        },
    )
    assert result.white_db == {
        "realpermithost.example": {"wildcard": True, "important": False, "band": P.PRIO_FEED_ALLOW, "index": 0}
    }
