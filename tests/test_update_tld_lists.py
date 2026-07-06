"""Tests for scripts/misc/update_tld_lists.py -- the IANA TLD-list regeneration tool.

No network: every test drives the pure parse/classify/build/render functions
directly against small fake fixtures (a fake tlds-alpha-by-domain.txt body and a
fake existing $tld_list PHP snippet). The __main__ network fetch (fetch_tlds_alpha /
fetch_tlds_json) is intentionally not exercised here.

Loaded by path via importlib (scripts/ is not a package), same pattern as
tests/test_url_encoding_check.py.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "misc" / "update_tld_lists.py"
_spec = importlib.util.spec_from_file_location("update_tld_lists", _TOOL)
assert _spec is not None and _spec.loader is not None
utl = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = utl
_spec.loader.exec_module(utl)


# --------------------------------------------------------------------------- #
# classify() -- each of the three buckets
# --------------------------------------------------------------------------- #


def test_classify_punycode_prefix_is_itld() -> None:
    assert utl.classify("xn--abc") == "iTLD"


def test_classify_two_ascii_letters_is_cctld() -> None:
    assert utl.classify("de") == "ccTLD"


def test_classify_anything_else_is_gtld() -> None:
    assert utl.classify("com") == "gTLD"
    assert utl.classify("brandx") == "gTLD"


# --------------------------------------------------------------------------- #
# strip_count() -- drops ONLY the trailing '[registration count]' bracket;
# every other hand-curated bit of the label (markers, region/sponsor prefix,
# country name, native-script segment) survives verbatim
# --------------------------------------------------------------------------- #


def test_strip_count_drops_trailing_count_bracket() -> None:
    assert utl.strip_count("NET [15,033,024]") == "NET"


def test_strip_count_preserves_feed_star_marker() -> None:
    assert utl.strip_count("COM* [149,657,691]") == "COM*"


def test_strip_count_preserves_spamhaus_bang_marker_verbatim() -> None:
    assert utl.strip_count("( ! ) BADTLD [999]") == "( ! ) BADTLD"


def test_strip_count_preserves_country_name_and_star() -> None:
    assert utl.strip_count("DE* (Germany) [15,083,400]") == "DE* (Germany)"


def test_strip_count_preserves_region_sponsor_prefix() -> None:
    assert utl.strip_count("(s) MOBI [456,722]") == "(s) MOBI"
    assert utl.strip_count("(eu) LONDON [81,647]") == "(eu) LONDON"


def test_strip_count_preserves_native_script_segment() -> None:
    assert utl.strip_count("(cc) XN--P1AI - рф [820,042]") == "(cc) XN--P1AI - рф"


def test_strip_count_handles_label_with_no_count_bracket() -> None:
    assert utl.strip_count("EPSON") == "EPSON"


# --------------------------------------------------------------------------- #
# parse_tlds_alpha() -- drops the version comment + blanks, lowercases
# --------------------------------------------------------------------------- #


def test_parse_tlds_alpha_drops_comment_and_blanks_and_lowercases() -> None:
    text = "# Version 2026062302, Last Updated Wed Jun 24 07:07:01 2026 UTC\nCOM\n\nDE\n"
    assert utl.parse_tlds_alpha(text) == {"com", "de"}


# --------------------------------------------------------------------------- #
# Fixtures shared by the build/render/rewrite scenario tests
# --------------------------------------------------------------------------- #

_FAKE_EXISTING_PHP = """<?php
// header text untouched by the regeneration
$tld_list['gTLD'] = array(
'com' => 'COM* [149,657,691]',
'net' => 'NET [15,033,024]',
'badtld' => '( ! ) BADTLD [999]',
'mobi' => '(s) MOBI [456,722]',
'oldgone' => 'OLDGONE (retired by IANA) [1]'
);

$tld_list['ccTLD'] = array(
'de' => 'DE* (Germany) [15,083,400]',
'us' => 'US (United States) [2,408,864]'
);

$tld_list['iTLD'] = array(
'xn--abc' => 'XN--ABC - foo [1]'
);

$tld_list['bgTLD'] = array(
'brandx' => 'BRANDX [100]',
'brandy' => 'BRANDY [50]'
);
// footer text untouched by the regeneration
"""

# Deliberately NOT in alphabetical order -- proves the alphabetical output is the
# renderer's doing, not an accident of source order. Includes: gTLDs kept from
# the existing curation with their curation intact (com's star, badtld's Spamhaus
# bang, mobi's sponsor prefix), one gTLD dropped by IANA (oldgone is simply absent
# here), one brand-new gTLD (zzz), one bgTLD-curated brand that must be excluded
# from fresh gTLD (brandx), one ccTLD with a country name (de), and one iTLD with
# a native-script segment (xn--abc).
_FAKE_IANA_TLDS = {"zzz", "badtld", "com", "brandx", "net", "de", "xn--abc", "mobi"}


def _fresh() -> dict[str, dict[str, str]]:
    existing = utl.parse_existing_arrays(_FAKE_EXISTING_PHP)
    return utl.build_fresh_arrays(_FAKE_IANA_TLDS, existing)


# --------------------------------------------------------------------------- #
# Scenario: building the fresh arrays from IANA data + existing curation
# --------------------------------------------------------------------------- #


def test_fresh_gtld_excludes_bgtld_curated_keys() -> None:
    # Given: brandx is IANA-generic but already curated into bgTLD.
    # When: the fresh gTLD set is built.
    fresh = _fresh()
    # Then: brandx is excluded from gTLD (never duplicated) -- and bgTLD itself
    # is not rebuilt at all.
    assert "brandx" not in fresh["gTLD"]
    assert "bgTLD" not in fresh


def test_fresh_gtld_retained_tld_keeps_existing_label_verbatim_minus_count() -> None:
    # Given: retained TLDs whose existing labels carry curation beyond a bare
    # marker (a feed-star, a Spamhaus bang with its own formatting, a sponsor
    # prefix) plus a registration-count bracket.
    # When: the fresh gTLD set is built.
    fresh = _fresh()
    # Then: only the count bracket is dropped -- every other curated detail
    # (including exact spacing/parens) survives untouched.
    assert fresh["gTLD"]["com"] == "COM*"
    assert fresh["gTLD"]["badtld"] == "( ! ) BADTLD"
    assert fresh["gTLD"]["mobi"] == "(s) MOBI"


def test_fresh_gtld_plain_label_for_a_tld_with_no_prior_marker() -> None:
    fresh = _fresh()
    assert fresh["gTLD"]["net"] == "NET"


def test_fresh_gtld_new_tld_not_in_existing_curation_gets_a_plain_label() -> None:
    # zzz never appeared in the old array -- new/uncurated TLDs land in gTLD plain.
    fresh = _fresh()
    assert fresh["gTLD"]["zzz"] == "ZZZ"


def test_fresh_cctld_and_itld_classify_correctly_and_preserve_the_label_verbatim() -> None:
    # Given: a ccTLD label carrying a '(Country)' name and an iTLD label
    # carrying a ' - <native script>' segment, each with a trailing count.
    # When: the fresh sets are built.
    fresh = _fresh()
    # Then: classification is correct AND the country name / native script
    # survive -- only the count bracket is gone (a regression back to
    # marker-only labels would fail this).
    assert fresh["ccTLD"] == {"de": "DE* (Germany)"}
    assert fresh["iTLD"] == {"xn--abc": "XN--ABC - foo"}


def test_fresh_arrays_are_ordered_alphabetically_by_tld() -> None:
    fresh = _fresh()
    assert list(fresh["gTLD"].keys()) == sorted(fresh["gTLD"].keys())
    assert list(fresh["gTLD"].keys()) == ["badtld", "com", "mobi", "net", "zzz"]


# --------------------------------------------------------------------------- #
# render_array_block() -- matches the file's existing style byte-for-byte
# --------------------------------------------------------------------------- #


def test_render_array_block_no_indentation_and_no_trailing_comma_on_last_entry() -> None:
    body = utl.render_array_block({"com": "COM*", "net": "NET"})
    assert body == "'com' => 'COM*',\n'net' => 'NET'"


# --------------------------------------------------------------------------- #
# rewrite_php() -- the full in-place rewrite: gTLD/ccTLD/iTLD change, bgTLD and
# surrounding text stay byte-identical
# --------------------------------------------------------------------------- #


def test_rewrite_php_leaves_bgtld_block_untouched() -> None:
    fresh = _fresh()
    new_text = utl.rewrite_php(_FAKE_EXISTING_PHP, fresh)
    assert "$tld_list['bgTLD'] = array(\n'brandx' => 'BRANDX [100]',\n'brandy' => 'BRANDY [50]'\n);" in new_text


def test_rewrite_php_leaves_surrounding_text_untouched() -> None:
    fresh = _fresh()
    new_text = utl.rewrite_php(_FAKE_EXISTING_PHP, fresh)
    assert "// header text untouched by the regeneration" in new_text
    assert "// footer text untouched by the regeneration" in new_text


def test_rewrite_php_replaces_gtld_body_with_the_fresh_alphabetical_render() -> None:
    fresh = _fresh()
    new_text = utl.rewrite_php(_FAKE_EXISTING_PHP, fresh)
    assert (
        "$tld_list['gTLD'] = array(\n"
        "'badtld' => '( ! ) BADTLD',\n"
        "'com' => 'COM*',\n"
        "'mobi' => '(s) MOBI',\n"
        "'net' => 'NET',\n"
        "'zzz' => 'ZZZ'\n"
        ");" in new_text
    )
    # oldgone is gone (IANA no longer lists it) and brandx is excluded (bgTLD-curated).
    assert "oldgone" not in new_text
    assert "'brandx'" not in new_text.split("bgTLD")[0]
