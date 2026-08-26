"""Tests for scripts/misc/update_public_suffix_list.py -- the Public Suffix List
(ICANN + PRIVATE) sync tool for src/usr/local/pkg/pfblockerng/dnsbl_psl.

No network: every test drives the pure parse/convert functions (or main() with
fetch_psl monkeypatched) directly against small fake fixtures. The real network
fetch is never exercised here.

issue #1541: dnsbl_psl is the SOLE shipped PSL artifact. The flat dnsbl_tld
output/target was retired -- every test below targets dnsbl_psl only.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "misc" / "update_public_suffix_list.py"
_spec = importlib.util.spec_from_file_location("update_public_suffix_list", _TOOL)
assert _spec is not None and _spec.loader is not None
upsl = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = upsl
_spec.loader.exec_module(upsl)

_SHIPPED_TLD_FILE = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/dnsbl_tld"
_SHIPPED_PSL_FILE = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/dnsbl_psl"
_LOG_PHP = Path(__file__).resolve().parent.parent / "src/usr/local/www/pfblockerng/pfblockerng_log.php"


@pytest.fixture(autouse=True)
def _small_private_floor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_PRIVATE_SUFFIXES", 1, raising=False)
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", tmp_path / "dnsbl_psl", raising=False)


# --------------------------------------------------------------------------- #
# issue #1541: dnsbl_psl is the SOLE shipped PSL artifact -- the flat dnsbl_tld
# file and its pfblockerng_log.php logtype must both be absent.
# --------------------------------------------------------------------------- #


def test_shipped_tree_has_no_dnsbl_tld_file_and_log_php_lists_dnsbl_psl() -> None:
    assert not _SHIPPED_TLD_FILE.exists(), "the flat dnsbl_tld shipped file must be retired (issue #1541)"
    log_php = _LOG_PHP.read_text(encoding="utf-8")
    assert "'dnsbl_psl'" in log_php, "pfblockerng_log.php must carry the dnsbl_psl logtype"
    assert "'dnsbl_tld'" not in log_php, "pfblockerng_log.php must not carry the retired dnsbl_tld logtype"


def test_main_writes_only_dnsbl_psl_never_a_dnsbl_tld_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    psl_target = tmp_path / "dnsbl_psl"
    tld_target = tmp_path / "dnsbl_tld"
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", psl_target)
    monkeypatch.setattr(upsl, "DEFAULT_TLD_FILE", tld_target, raising=False)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1, raising=False)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)

    rc = upsl.main([])

    assert rc == 0
    assert psl_target.exists(), "main() must write the dnsbl_psl authority"
    assert not tld_target.exists(), "main() must never create/refresh a dnsbl_tld target (issue #1541)"


# --------------------------------------------------------------------------- #
# Shipped dnsbl_psl contract: sync header present, both section markers
# present, wildcard/exception rules preserved.
# --------------------------------------------------------------------------- #


def test_shipped_dnsbl_psl_has_sync_header() -> None:
    lines = _SHIPPED_PSL_FILE.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#")
    assert any(line.startswith("# COMMIT:") for line in lines[:10])


def test_shipped_dnsbl_psl_has_both_section_markers() -> None:
    text = _SHIPPED_PSL_FILE.read_text(encoding="utf-8")
    assert upsl.BEGIN_MARKER in text
    assert upsl.END_MARKER in text
    assert upsl.PRIVATE_BEGIN_MARKER in text
    assert upsl.PRIVATE_END_MARKER in text


def test_shipped_dnsbl_psl_has_wildcard_and_exception_rules() -> None:
    lines = _SHIPPED_PSL_FILE.read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("*.") for line in lines), "shipped dnsbl_psl must retain wildcard rules"
    assert any(line.startswith("!") for line in lines), "shipped dnsbl_psl must retain exception rules"


# --------------------------------------------------------------------------- #
# Fixture: a small fake PSL body exercising every ICANN-section line shape
# --------------------------------------------------------------------------- #

_FAKE_PSL_TEXT = (
    "// intro comment, before ICANN section -- must never leak into the body\n"
    "// VERSION: 2026-01-01_00-00-00_UTC\n"
    "// COMMIT: deadbeefcafefeed\n"
    "\n"
    "// ===BEGIN ICANN DOMAINS===\n"
    "\n"
    "// ac : http://nic.ac/rules.htm\n"
    "ac\n"
    "com.ac\n"
    "\n"
    "// idn ccTLD: raw unicode AND its already-punycode form are both real PSL entries\n"
    "xn--p1ai\n"
    "рф\n"
    "\n"
    "// mixed ascii+unicode multi-label suffix -- only the unicode label converts\n"
    "aéroport.ci\n"
    "\n"
    "// wildcard + exception rules -- PSL authority preserves both (issue #1541)\n"
    "*.ck\n"
    "!www.ck\n"
    "\n"
    "// a second dot-less bare TLD\n"
    "com\n"
    "// ===END ICANN DOMAINS===\n"
    "\n"
    "// ===BEGIN PRIVATE DOMAINS===\n"
    "// this PRIVATE-section entry must land in the PRIVATE rules, never ICANN\n"
    "blogspot.com\n"
    "// ===END PRIVATE DOMAINS===\n"
)


def _fake_sections() -> tuple[list[str], list[str]]:
    return upsl.extract_psl_sections(upsl.normalise_lines(_FAKE_PSL_TEXT))


def _fake_icann_rules() -> list[str]:
    icann_lines, _ = _fake_sections()
    return upsl.build_psl_section(icann_lines)


def _fake_private_rules() -> list[str]:
    _, private_lines = _fake_sections()
    return upsl.build_psl_section(private_lines)


# --------------------------------------------------------------------------- #
# Coverage matrix rows 1-3: conversion shapes
# --------------------------------------------------------------------------- #


def test_build_psl_section_plain_ascii_suffix_emitted_verbatim() -> None:
    assert "com.ac" in _fake_icann_rules()


def test_build_psl_section_raw_unicode_multi_label_suffix_encodes_only_the_unicode_label() -> None:
    assert "xn--aroport-bya.ci" in _fake_icann_rules()


def test_build_psl_section_already_punycode_label_passes_through_idempotently() -> None:
    # 'xn--p1ai' (already punycode) and 'рф' (raw unicode) both convert to the
    # SAME output -- proves the already-ASCII path is idempotent.
    assert _fake_icann_rules().count("xn--p1ai") == 2


# --------------------------------------------------------------------------- #
# Coverage matrix rows 4-8: lines dropped/preserved
# --------------------------------------------------------------------------- #


def test_build_psl_section_drops_comment_lines() -> None:
    rules = _fake_icann_rules()
    assert not any(s.startswith("//") for s in rules)
    assert "nic.ac" not in "".join(rules)


def test_build_psl_section_drops_blank_lines() -> None:
    icann_lines, _ = _fake_sections()
    assert "" in icann_lines  # fixture legitimately carries blank ICANN-section lines
    assert "" not in upsl.build_psl_section(icann_lines)


def test_build_psl_section_preserves_wildcard_rule() -> None:
    # Unlike the retired dnsbl_tld output, the PSL authority PRESERVES wildcard
    # rules with their '*.' prefix intact (issue #1541).
    assert "*.ck" in _fake_icann_rules()


def test_build_psl_section_preserves_exception_rule() -> None:
    # Unlike the retired dnsbl_tld output, the PSL authority PRESERVES exception
    # rules with their '!' prefix intact (issue #1541).
    assert "!www.ck" in _fake_icann_rules()


def test_build_psl_section_excludes_lines_outside_icann_markers() -> None:
    # Vacuity check: blogspot.com is real, convertible PRIVATE-section input that
    # WOULD show up in the ICANN rules if the BEGIN/END gate broke.
    icann_rules = _fake_icann_rules()
    assert "blogspot.com" not in icann_rules
    assert not any("intro comment" in s for s in icann_rules)
    # Positive proof: the same entry DOES land in the PRIVATE rules.
    assert "blogspot.com" in _fake_private_rules()


# --------------------------------------------------------------------------- #
# Coverage matrix row 9: dot-less bare TLD
# --------------------------------------------------------------------------- #


def test_build_psl_section_dotless_bare_tld_passes_through_unchanged() -> None:
    rules = _fake_icann_rules()
    assert "ac" in rules
    assert "com" in rules


# --------------------------------------------------------------------------- #
# Coverage matrix row 10: VERSION/COMMIT header extraction
# --------------------------------------------------------------------------- #


def test_extract_header_reads_version_and_commit() -> None:
    version, commit = upsl.extract_header(upsl.normalise_lines(_FAKE_PSL_TEXT))
    assert version == "2026-01-01_00-00-00_UTC"
    assert commit == "deadbeefcafefeed"


def test_extract_header_falls_back_to_unknown_when_absent() -> None:
    text = "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"
    version, commit = upsl.extract_header(upsl.normalise_lines(text))
    assert version == "unknown"
    assert commit == "unknown"


def test_render_psl_output_header_shape_then_sections() -> None:
    out = upsl.render_psl_output("v1", "c1", ["ac", "com"], ["private1"])
    lines = out.splitlines()
    assert lines[0].startswith("#")
    assert lines[1] == "# VERSION: v1"
    assert lines[2] == "# COMMIT: c1"
    assert lines[3].startswith("# Regenerated by")
    assert lines[4] == upsl.BEGIN_MARKER
    assert lines[5:7] == ["ac", "com"]
    assert lines[7] == upsl.END_MARKER
    assert lines[8] == upsl.PRIVATE_BEGIN_MARKER
    assert lines[9] == "private1"
    assert lines[10] == upsl.PRIVATE_END_MARKER


def test_existing_psl_body_strips_hash_and_blank_lines() -> None:
    text = "# header\n# COMMIT: x\nac\n\ncom\n"
    assert upsl.existing_psl_body(text) == ["ac", "com"]


# --------------------------------------------------------------------------- #
# Coverage matrix row 11: churn guard -- body-unchanged leaves the file
# untouched (both plain run and --check); body-changed rewrites (plain run
# only), --check reports it without touching the file.
# --------------------------------------------------------------------------- #

_FAKE_FETCH_BODY = (
    "// VERSION: new\n// COMMIT: newsha\n// ===BEGIN ICANN DOMAINS===\nac\ncom\n"
    "// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nprivate.example\n"
    "// ===END PRIVATE DOMAINS===\n"
)


def test_build_psl_authority_keeps_order_markers_and_rule_syntax() -> None:
    assert hasattr(upsl, "build_psl_section")
    assert hasattr(upsl, "extract_psl_sections")
    assert hasattr(upsl, "render_psl_output")
    lines = upsl.normalise_lines(
        "// ===BEGIN ICANN DOMAINS===\nCom\n*.CK\n!WWW.CK\n// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\nGitHub.IO\n// ===END PRIVATE DOMAINS===\n"
    )
    sections = upsl.extract_psl_sections(lines)
    assert upsl.build_psl_section(sections[0]) == ["com", "*.ck", "!www.ck"]
    assert upsl.build_psl_section(sections[1]) == ["github.io"]
    rendered = upsl.render_psl_output("v", "c", ["com"], ["github.io"])
    assert "// ===BEGIN ICANN DOMAINS===" in rendered
    assert "// ===END ICANN DOMAINS===" in rendered
    assert "// ===BEGIN PRIVATE DOMAINS===" in rendered
    assert "// ===END PRIVATE DOMAINS===" in rendered
    assert rendered.splitlines()[-4:] == [
        "// ===END ICANN DOMAINS===",
        "// ===BEGIN PRIVATE DOMAINS===",
        "github.io",
        "// ===END PRIVATE DOMAINS===",
    ]


def test_main_check_reports_out_of_date_and_leaves_file_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    psl_target = tmp_path / "dnsbl_psl"
    psl_target.write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", psl_target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)
    before_psl = psl_target.read_bytes()

    assert upsl.main(["--check"]) == 1
    assert psl_target.read_bytes() == before_psl


def test_main_writes_psl_authority_when_body_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    psl_target = tmp_path / "dnsbl_psl"
    psl_target.write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", psl_target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)

    assert upsl.main([]) == 0
    assert "private.example" in psl_target.read_text(encoding="utf-8")


def _fake_fetch(timeout: float = 15) -> str:
    return _FAKE_FETCH_BODY


def test_main_leaves_psl_file_untouched_when_body_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = (
        "# old header\n# COMMIT: old\n"
        "// ===BEGIN ICANN DOMAINS===\nac\ncom\n// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\nprivate.example\n// ===END PRIVATE DOMAINS===\n"
    )
    target = tmp_path / "dnsbl_psl"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)
    before_mtime = target.stat().st_mtime_ns

    rc = upsl.main([])

    assert rc == 0
    assert target.stat().st_mtime_ns == before_mtime  # no write happened, not just same bytes
    assert target.read_text(encoding="utf-8") == existing


def test_main_check_exits_zero_and_untouched_when_body_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = (
        "# old header\n# COMMIT: old\n"
        "// ===BEGIN ICANN DOMAINS===\nac\ncom\n// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\nprivate.example\n// ===END PRIVATE DOMAINS===\n"
    )
    target = tmp_path / "dnsbl_psl"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)
    before_mtime = target.stat().st_mtime_ns

    rc = upsl.main(["--check"])

    assert rc == 0
    assert target.stat().st_mtime_ns == before_mtime
    assert target.read_text(encoding="utf-8") == existing


def test_main_rewrites_psl_file_when_body_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = (  # missing 'com' -> ICANN body differs from the fetch
        "# old header\n"
        "// ===BEGIN ICANN DOMAINS===\nac\n// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\nprivate.example\n// ===END PRIVATE DOMAINS===\n"
    )
    target = tmp_path / "dnsbl_psl"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)

    rc = upsl.main([])

    assert rc == 0
    new_text = target.read_text(encoding="utf-8")
    assert new_text.splitlines()[0].startswith("#")
    assert upsl.existing_psl_body(new_text) == [
        upsl.BEGIN_MARKER,
        "ac",
        "com",
        upsl.END_MARKER,
        upsl.PRIVATE_BEGIN_MARKER,
        "private.example",
        upsl.PRIVATE_END_MARKER,
    ]


def test_main_check_exits_one_and_leaves_file_untouched_when_body_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = (
        "# old header\n"
        "// ===BEGIN ICANN DOMAINS===\nac\n// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\nprivate.example\n// ===END PRIVATE DOMAINS===\n"
    )
    target = tmp_path / "dnsbl_psl"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)

    rc = upsl.main(["--check"])

    assert rc == 1
    assert target.read_text(encoding="utf-8") == existing


# --------------------------------------------------------------------------- #
# Coverage matrix rows 12-13: safety floors -- refuse, file untouched
# --------------------------------------------------------------------------- #


def test_require_plausible_rejects_an_implausibly_small_body() -> None:
    with pytest.raises(SystemExit):
        upsl.require_plausible([])
    with pytest.raises(SystemExit):
        upsl.require_plausible([f"tld{i}" for i in range(upsl.MIN_PLAUSIBLE_SUFFIXES - 1)])


def test_require_plausible_accepts_a_realistic_suffix_count() -> None:
    upsl.require_plausible([f"tld{i}" for i in range(upsl.MIN_PLAUSIBLE_SUFFIXES)])


# --------------------------------------------------------------------------- #
# Hostile-input rows H1-H3: refused end-to-end through main(), file untouched
# --------------------------------------------------------------------------- #


def test_main_refuses_on_empty_fetch_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "dnsbl_psl"
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", target)
    monkeypatch.setattr(upsl, "fetch_psl", lambda timeout=15: "")

    with pytest.raises(SystemExit):
        upsl.main([])
    assert not target.exists()


def test_main_refuses_on_captive_portal_html(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "dnsbl_psl"
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", target)
    monkeypatch.setattr(
        upsl,
        "fetch_psl",
        lambda timeout=15: "<html><body>Please log in to the WiFi portal</body></html>",
    )

    with pytest.raises(SystemExit):
        upsl.main([])
    assert not target.exists()


def test_main_refuses_on_truncated_body_missing_end_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "dnsbl_psl"
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", target)
    monkeypatch.setattr(upsl, "fetch_psl", lambda timeout=15: "// ===BEGIN ICANN DOMAINS===\ncom\nnet\n")

    with pytest.raises(SystemExit):
        upsl.main([])
    assert not target.exists()


# --------------------------------------------------------------------------- #
# Hostile-input row H4: CRLF line endings handled identically to LF
# --------------------------------------------------------------------------- #


def test_normalise_lines_handles_crlf_identically_to_lf() -> None:
    assert upsl.normalise_lines("ac\r\ncom\r\n") == upsl.normalise_lines("ac\ncom\n")


# --------------------------------------------------------------------------- #
# Hostile-input row H5: tabs / consecutive spaces -> skipped
# --------------------------------------------------------------------------- #


def test_convert_suffix_skips_line_with_internal_space() -> None:
    assert upsl.convert_suffix("foo bar") is None


def test_convert_suffix_skips_line_with_tabs() -> None:
    assert upsl.convert_suffix("\tx\t") is None


# --------------------------------------------------------------------------- #
# Hostile-input row H6: uppercase ASCII lowercased
# --------------------------------------------------------------------------- #


def test_convert_suffix_lowercases_uppercase_ascii() -> None:
    assert upsl.convert_suffix("EXAMPLE.COM") == "example.com"


# --------------------------------------------------------------------------- #
# Hostile-input row H7 (issue #1306): oversized all-ASCII label skipped like
# the IDN path, not emitted verbatim -- no crash either way.
# --------------------------------------------------------------------------- #


def test_convert_suffix_skips_oversized_all_ascii_label_instead_of_emitting_unchanged() -> None:
    assert upsl.convert_suffix("a" * 4096) is None


def test_convert_suffix_keeps_all_ascii_label_at_the_63_octet_boundary() -> None:
    label = "a" * 63
    assert upsl.convert_suffix(label) == label


def test_convert_suffix_skips_all_ascii_label_one_octet_past_the_boundary() -> None:
    assert upsl.convert_suffix("a" * 64) is None


def test_convert_suffix_skips_name_past_the_253_octet_dns_cap() -> None:
    assert upsl.convert_suffix(".".join(["a" * 63] * 4)) is None


def test_render_psl_output_preserves_oversized_pre_validated_entry() -> None:
    # render_psl_output only formats an already-built rule list -- it never
    # re-validates label length, so a pre-validated oversized entry must still
    # render intact.
    junk = "a" * 4096
    out = upsl.render_psl_output("v", "c", ["ac", junk, "com"], ["priv"])
    assert junk in out.splitlines()


def test_convert_suffix_skips_oversized_non_ascii_label_instead_of_crashing() -> None:
    # A non-ASCII label past the 63-octet DNS cap makes the stdlib idna codec
    # raise; a malformed line must be skipped like the whitespace ones, never crash.
    assert upsl.convert_suffix("a." + "ä" * 64) is None


# --------------------------------------------------------------------------- #
# Hostile-input row H8 (issue #1306): exotic Unicode blanks / RFC 3454 Table
# B.1 "commonly mapped to nothing" characters skipped like ordinary whitespace
# -- str.isspace() plus stringprep.in_table_b1() (the exact predicate the
# stdlib idna codec's nameprep step uses internally) catches the whole class,
# not a hardcoded few, so idna's encoder never gets the chance to silently
# coalesce one away.
# --------------------------------------------------------------------------- #


def test_convert_suffix_skips_line_with_zero_width_space() -> None:
    # issue #1306 repro: U+200B was previously silently coalesced away by idna's
    # encoder instead of the line being treated as malformed.
    assert upsl.convert_suffix("a\u200bb.com") is None


def test_convert_suffix_skips_line_with_byte_order_mark() -> None:
    assert upsl.convert_suffix("a\ufeffb.com") is None


def test_convert_suffix_skips_line_with_word_joiner() -> None:
    # A Table B.1 member not explicitly named in the issue -- proves the fix
    # catches the whole ignorable-character class, not a hardcoded list.
    assert upsl.convert_suffix("a\u2060b.com") is None


def test_convert_suffix_skips_line_with_variation_selector() -> None:
    # issue #1306 follow-up: U+FE0F is Table B.1 but category Mn, not Cf -- a
    # category-Cf-only check misses it; stringprep.in_table_b1() catches it.
    assert upsl.convert_suffix("a\ufe0fb.com") is None


def test_convert_suffix_skips_line_with_combining_grapheme_joiner() -> None:
    # U+034F: Table B.1, category Mn -- same Cf-blind-spot class as the variation
    # selector above.
    assert upsl.convert_suffix("a\u034fb.com") is None


def test_convert_suffix_skips_line_with_mongolian_free_variation_selector() -> None:
    # U+180B: Table B.1, category Mn -- same Cf-blind-spot class.
    assert upsl.convert_suffix("a\u180bb.com") is None


def test_convert_suffix_still_encodes_combining_acute_not_in_table_b1() -> None:
    # U+0301 (combining acute) is category Mn like the Table B.1 members above,
    # but is NOT itself in Table B.1 -- must still punycode-encode, never be
    # skipped (proves the predicate isn't "skip every Mn character").
    label = "a" + "\u0301" + "b.com"
    assert upsl.convert_suffix(label) is not None


def test_convert_suffix_skips_line_with_non_breaking_space() -> None:
    # U+00A0 is already str.isspace() -- pins the pre-existing behaviour, no regression.
    assert upsl.convert_suffix("a\xa0b.com") is None


def test_convert_suffix_skips_line_with_ideographic_space() -> None:
    # U+3000 is already str.isspace() -- pins the pre-existing behaviour, no regression.
    assert upsl.convert_suffix("a\u3000b.com") is None


def test_convert_suffix_skips_empty_line() -> None:
    assert upsl.convert_suffix("") is None


# --------------------------------------------------------------------------- #
# Hostile-input row H9 (issue #1455): category-Cc control characters skipped,
# not emitted verbatim -- an ASCII-range Cc char (e.g. NUL, DEL) is neither
# str.isspace() nor stringprep.in_table_b1(), so it takes the isascii()
# passthrough branch in _punycode_label untouched instead of being rejected.
# --------------------------------------------------------------------------- #


def test_convert_suffix_skips_line_with_nul() -> None:
    # issue #1455 repro: raw NUL was previously emitted verbatim into the
    # generated file.
    assert upsl.convert_suffix("a\x00b.com") is None


def test_convert_suffix_skips_line_with_del() -> None:
    assert upsl.convert_suffix("a\x7fb.com") is None


def test_convert_suffix_skips_line_with_bell() -> None:
    # U+0007 (BEL) -- not one of the two codepoints named in the issue, proves
    # the fix catches the whole category-Cc class, not a hardcoded pair.
    assert upsl.convert_suffix("a\x07b.com") is None


# --------------------------------------------------------------------------- #
# Hostile-input row H10 (issue #1463): category-Cn (unassigned) codepoints
# skipped, not silently punycode-encoded -- the stdlib idna codec accepts an
# unassigned codepoint without error (probed: U+0378 encodes cleanly), so it
# rides through untouched unless _has_blank_or_ignorable_char() also rejects
# category-Cn.
# --------------------------------------------------------------------------- #


def test_convert_suffix_skips_line_with_unassigned_codepoint_mixed_nonascii() -> None:
    # issue #1463 reported shape: Cn (U+0378) mixed with another non-ASCII
    # label char (U+00E9, e-acute) in the same label.
    assert upsl.convert_suffix("a͸é.com") is None


def test_convert_suffix_skips_line_with_unassigned_codepoint_otherwise_ascii_label() -> None:
    # Cn is the ONLY non-ASCII char in an otherwise-ASCII label -- probed: no
    # ASCII-range (0x00-0x7F) codepoint is Cn, so this label is non-ASCII
    # overall and takes the idna path, never the isascii() passthrough branch
    # (unlike the Cc case in issue #1455, which DID pass through raw).
    assert upsl.convert_suffix("a͸b.com") is None


def test_convert_suffix_still_encodes_recently_assigned_codepoint_not_cn() -> None:
    # U+0526 (CYRILLIC CAPITAL LETTER PE WITH DESCENDER, assigned Unicode 5.1)
    # is "unassigned" under RFC 3454 Table A.1's frozen Unicode-3.2 baseline
    # (stringprep.in_table_a1 -> True) but is NOT category-Cn on this
    # interpreter's live Unicode data -- pins the tolerance decision: reject
    # unassigned-NOW (unicodedata.category(c) == "Cn"), not
    # unassigned-as-of-3.2 (stringprep.in_table_a1), which would false-positive
    # reject this valid, currently-assigned codepoint.
    assert upsl.convert_suffix("aԦb.com") == "xn--ab-e6c.com"


# --------------------------------------------------------------------------- #
# Strict PSL-rule grammar and section integrity.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "token",
    [
        "*",
        "**.ck",
        "*.foo.*.ck",
        "foo.*.bar",
        "!",
        "!*.ck",
        "a..b",
        "a.",
        "!a..b",
        "a$[b].com",
        "a|b.com",
        "a;$(id).com",
    ],
)
def test_convert_psl_rule_rejects_malformed_or_metacharacter_tokens(token: str) -> None:
    with pytest.raises(ValueError):
        upsl.convert_psl_rule(token)


def test_convert_psl_rule_accepts_token_before_first_whitespace() -> None:
    # PSL spec: a rule is the token up to the first whitespace; anything after
    # (registry comments, stray columns) is ignored, matching the runtime parser.
    assert upsl.convert_psl_rule("com // registry comment") == "com"
    assert upsl.convert_psl_rule("*.ck\t// wildcard note") == "*.ck"
    assert upsl.convert_psl_rule("!www.ck extra tokens") == "!www.ck"
    assert upsl.convert_psl_rule("foo bar") == "foo"


def test_build_psl_section_rejects_orphan_exception() -> None:
    with pytest.raises(ValueError, match="wildcard"):
        upsl.build_psl_section(["!orphan.example"])


def test_build_psl_section_requires_exception_wildcard_family() -> None:
    assert upsl.build_psl_section(["*.ck", "!www.ck"]) == ["*.ck", "!www.ck"]


@pytest.mark.parametrize(
    "missing",
    [
        upsl.BEGIN_MARKER,
        upsl.END_MARKER,
        upsl.PRIVATE_BEGIN_MARKER,
        upsl.PRIVATE_END_MARKER,
    ],
)
def test_extract_psl_sections_rejects_each_missing_marker(missing: str) -> None:
    markers = [upsl.BEGIN_MARKER, upsl.END_MARKER, upsl.PRIVATE_BEGIN_MARKER, upsl.PRIVATE_END_MARKER]
    lines = [marker for marker in markers if marker != missing]
    with pytest.raises(SystemExit):
        upsl.extract_psl_sections(lines)


@pytest.mark.parametrize(
    "duplicate",
    [
        upsl.BEGIN_MARKER,
        upsl.END_MARKER,
        upsl.PRIVATE_BEGIN_MARKER,
        upsl.PRIVATE_END_MARKER,
    ],
)
def test_extract_psl_sections_rejects_each_duplicate_marker(duplicate: str) -> None:
    lines = [upsl.BEGIN_MARKER, upsl.END_MARKER, upsl.PRIVATE_BEGIN_MARKER, upsl.PRIVATE_END_MARKER]
    lines.insert(lines.index(duplicate), duplicate)
    with pytest.raises(SystemExit):
        upsl.extract_psl_sections(lines)


def test_extract_psl_sections_rejects_out_of_order_markers() -> None:
    lines = [upsl.BEGIN_MARKER, upsl.PRIVATE_BEGIN_MARKER, upsl.END_MARKER, upsl.PRIVATE_END_MARKER]
    with pytest.raises(SystemExit):
        upsl.extract_psl_sections(lines)


def test_render_psl_output_has_exactly_one_final_newline() -> None:
    out = upsl.render_psl_output("v", "c", ["com"], ["example"])
    assert out.endswith("\n")
    assert not out.endswith("\n\n")


def test_module_docstring_and_check_help_describe_dnsbl_psl_only(capsys: pytest.CaptureFixture[str]) -> None:
    assert "PRIVATE" in (upsl.__doc__ or "")
    assert "dnsbl_tld" not in (upsl.__doc__ or "")
    with pytest.raises(SystemExit):
        upsl.main(["--help"])
    help_text = capsys.readouterr().out
    assert "dnsbl_psl" in help_text
    assert "dnsbl_tld" not in help_text


def test_main_private_floor_rejection_preserves_psl_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    psl_target = tmp_path / "dnsbl_psl"
    psl_target.write_bytes(b"old psl\n")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", psl_target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_PRIVATE_SUFFIXES", 2)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)
    before = psl_target.read_bytes()

    with pytest.raises(SystemExit):
        upsl.main([])

    assert psl_target.read_bytes() == before


@pytest.mark.parametrize("bad_rule", ["a..b", "xn--bad", "xn--abc"])
def test_main_malformed_rule_rejection_preserves_psl_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_rule: str
) -> None:
    psl_target = tmp_path / "dnsbl_psl"
    psl_target.write_bytes(b"old psl\n")
    malformed = _FAKE_FETCH_BODY.replace("ac\ncom\n", f"{bad_rule}\ncom\n")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", psl_target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_PRIVATE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", lambda timeout=15: malformed)
    before = psl_target.read_bytes()

    with pytest.raises(SystemExit, match="Refusing to rewrite"):
        upsl.main([])

    assert psl_target.read_bytes() == before


def test_fetch_psl_rejects_invalid_utf8_response(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b"// ===BEGIN ICANN DOMAINS===\n\xff"

    monkeypatch.setattr(upsl.urllib.request, "urlopen", lambda *args, **kwargs: _Response())
    with pytest.raises(UnicodeDecodeError):
        upsl.fetch_psl()


def test_main_invalid_utf8_rejection_preserves_psl_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    psl_target = tmp_path / "dnsbl_psl"
    psl_target.write_bytes(b"old psl\n")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", psl_target)

    def invalid_fetch(timeout: float = 15) -> str:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

    monkeypatch.setattr(upsl, "fetch_psl", invalid_fetch)
    before = psl_target.read_bytes()

    with pytest.raises(SystemExit):
        upsl.main([])

    assert psl_target.read_bytes() == before


def test_failed_psl_replace_preserves_existing_file_and_removes_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    psl_target = tmp_path / "dnsbl_psl"
    psl_target.write_bytes(b"old psl\n")
    monkeypatch.setattr(upsl, "DEFAULT_PSL_FILE", psl_target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_PRIVATE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)
    real_replace = __import__("os").replace

    def fail_psl_replace(source: str | Path, destination: str | Path) -> None:
        if Path(destination) == psl_target:
            raise OSError("simulated replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(upsl.os, "replace", fail_psl_replace)
    before_psl = psl_target.read_bytes()

    with pytest.raises(OSError):
        upsl.main([])

    assert psl_target.read_bytes() == before_psl
    assert not list(tmp_path.glob(f".{psl_target.name}.*"))


def test_atomic_write_preserves_existing_file_mode(tmp_path: Path) -> None:
    target = tmp_path / "dnsbl_psl"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o644)

    upsl._atomic_write(target, "new\n")

    assert target.stat().st_mode & 0o777 == 0o644


_INSTALL_INC = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfblockerng_install.inc"


def test_install_upgrade_removes_stale_chroot_oracle_copy() -> None:
    # The pre-PSL chroot copy (pfb_py_tld.txt) is unowned after upgrade and its
    # basename matches the pfb_py_* cache-save glob: the installer must remove it
    # once, since the retired staging/teardown paths no longer touch it.
    install_inc = _INSTALL_INC.read_text(encoding="utf-8")
    assert "unlink_if_exists('/var/unbound/pfb_py_tld.txt')" in install_inc
