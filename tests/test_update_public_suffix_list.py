"""Tests for scripts/misc/update_public_suffix_list.py -- the Public Suffix List
(ICANN-only) sync tool for src/usr/local/pkg/pfblockerng/dnsbl_tld.

No network: every test drives the pure parse/convert functions (or main() with
fetch_psl monkeypatched) directly against small fake fixtures. The real network
fetch is never exercised here.
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


# --------------------------------------------------------------------------- #
# issue #1272 red->green proof: the shipped dnsbl_tld predates this sync
# script (byte-identical since the repo's initial commit) and still carries
# the PRIVATE-section entries the owner decided to drop. FAILS on the
# untouched worktree; PASSES once the file is regenerated.
# --------------------------------------------------------------------------- #


def test_shipped_dnsbl_tld_has_sync_header() -> None:
    lines = _SHIPPED_TLD_FILE.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#")
    assert any(line.startswith("# COMMIT:") for line in lines[:10])


def test_shipped_dnsbl_tld_excludes_private_section() -> None:
    body_lines = _SHIPPED_TLD_FILE.read_text(encoding="utf-8").splitlines()
    assert not any(
        line == "blogspot.com" or line.startswith("blogspot.") or ".blogspot." in line for line in body_lines
    )


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
    "// wildcard + exception rules -- owner decision: skip both (issue #1272)\n"
    "*.ck\n"
    "!www.ck\n"
    "\n"
    "// a second dot-less bare TLD\n"
    "com\n"
    "// ===END ICANN DOMAINS===\n"
    "\n"
    "// ===BEGIN PRIVATE DOMAINS===\n"
    "// this PRIVATE-section entry WOULD be emitted if the BEGIN/END gate broke\n"
    "blogspot.com\n"
    "// ===END PRIVATE DOMAINS===\n"
)


def _fake_body() -> list[str]:
    return upsl.build_body(upsl.extract_icann_lines(upsl.normalise_lines(_FAKE_PSL_TEXT)))


# --------------------------------------------------------------------------- #
# Coverage matrix rows 1-3: conversion shapes
# --------------------------------------------------------------------------- #


def test_build_body_plain_ascii_suffix_emitted_verbatim() -> None:
    assert "com.ac" in _fake_body()


def test_build_body_raw_unicode_multi_label_suffix_encodes_only_the_unicode_label() -> None:
    assert "xn--aroport-bya.ci" in _fake_body()


def test_build_body_already_punycode_label_passes_through_idempotently() -> None:
    # 'xn--p1ai' (already punycode) and 'рф' (raw unicode) both convert to the
    # SAME output -- proves the already-ASCII path is idempotent.
    assert _fake_body().count("xn--p1ai") == 2


# --------------------------------------------------------------------------- #
# Coverage matrix rows 4-8: lines dropped
# --------------------------------------------------------------------------- #


def test_build_body_drops_comment_lines() -> None:
    body = _fake_body()
    assert not any(s.startswith("//") for s in body)
    assert "nic.ac" not in "".join(body)


def test_build_body_drops_blank_lines() -> None:
    icann_lines = upsl.extract_icann_lines(upsl.normalise_lines(_FAKE_PSL_TEXT))
    assert "" in icann_lines  # fixture legitimately carries blank ICANN-section lines
    assert "" not in _fake_body()


def test_build_body_drops_wildcard_rule() -> None:
    body = _fake_body()
    assert "*.ck" not in body
    assert not any(s.startswith("*.") for s in body)


def test_build_body_drops_exception_rule() -> None:
    body = _fake_body()
    assert "!www.ck" not in body
    assert not any(s.startswith("!") for s in body)


def test_build_body_excludes_lines_outside_icann_markers() -> None:
    # Vacuity check: blogspot.com is real, convertible PRIVATE-section input that
    # WOULD show up in the body if the BEGIN/END gate broke.
    body = _fake_body()
    assert "blogspot.com" not in body
    assert not any("intro comment" in s for s in body)


# --------------------------------------------------------------------------- #
# Coverage matrix row 9: dot-less bare TLD
# --------------------------------------------------------------------------- #


def test_build_body_dotless_bare_tld_passes_through_unchanged() -> None:
    body = _fake_body()
    assert "ac" in body
    assert "com" in body


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


def test_render_output_header_shape_then_one_suffix_per_line() -> None:
    out = upsl.render_output("v1", "c1", ["ac", "com"])
    lines = out.splitlines()
    assert lines[0].startswith("#")
    assert lines[1] == "# VERSION: v1"
    assert lines[2] == "# COMMIT: c1"
    assert lines[3].startswith("# Regenerated by")
    assert lines[4:] == ["ac", "com"]


def test_existing_body_strips_only_hash_lines() -> None:
    text = "# header\n# COMMIT: x\nac\ncom\n"
    assert upsl.existing_body(text) == ["ac", "com"]


# --------------------------------------------------------------------------- #
# Coverage matrix row 11: churn guard -- body-unchanged leaves the file
# untouched (both plain run and --check); body-changed rewrites (plain run
# only), --check reports it without touching the file.
# --------------------------------------------------------------------------- #

_FAKE_FETCH_BODY = (
    "// VERSION: new\n// COMMIT: newsha\n// ===BEGIN ICANN DOMAINS===\nac\ncom\n// ===END ICANN DOMAINS===\n"
)


def _fake_fetch(timeout: float = 15) -> str:
    return _FAKE_FETCH_BODY


def test_main_leaves_file_untouched_when_body_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = "# old header\n# COMMIT: old\nac\ncom\n"
    target = tmp_path / "dnsbl_tld"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_TLD_FILE", target)
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
    existing = "# old header\n# COMMIT: old\nac\ncom\n"
    target = tmp_path / "dnsbl_tld"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_TLD_FILE", target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)
    before_mtime = target.stat().st_mtime_ns

    rc = upsl.main(["--check"])

    assert rc == 0
    assert target.stat().st_mtime_ns == before_mtime
    assert target.read_text(encoding="utf-8") == existing


def test_main_rewrites_file_when_body_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = "# old header\nac\n"  # missing 'com' -> body differs from the fetch
    target = tmp_path / "dnsbl_tld"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_TLD_FILE", target)
    monkeypatch.setattr(upsl, "MIN_PLAUSIBLE_SUFFIXES", 1)
    monkeypatch.setattr(upsl, "fetch_psl", _fake_fetch)

    rc = upsl.main([])

    assert rc == 0
    new_text = target.read_text(encoding="utf-8")
    assert new_text.splitlines()[0].startswith("#")
    assert upsl.existing_body(new_text) == ["ac", "com"]


def test_main_check_exits_one_and_leaves_file_untouched_when_body_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = "# old header\nac\n"
    target = tmp_path / "dnsbl_tld"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(upsl, "DEFAULT_TLD_FILE", target)
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


def test_extract_icann_lines_raises_when_begin_marker_missing() -> None:
    with pytest.raises(SystemExit):
        upsl.extract_icann_lines(upsl.normalise_lines("com\nnet\n"))


def test_extract_icann_lines_raises_when_end_marker_missing_truncated() -> None:
    with pytest.raises(SystemExit):
        upsl.extract_icann_lines(upsl.normalise_lines("// ===BEGIN ICANN DOMAINS===\ncom\nnet\n"))


# --------------------------------------------------------------------------- #
# Hostile-input rows H1-H3: refused end-to-end through main(), file untouched
# --------------------------------------------------------------------------- #


def test_main_refuses_on_empty_fetch_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "dnsbl_tld"
    monkeypatch.setattr(upsl, "DEFAULT_TLD_FILE", target)
    monkeypatch.setattr(upsl, "fetch_psl", lambda timeout=15: "")

    with pytest.raises(SystemExit):
        upsl.main([])
    assert not target.exists()


def test_main_refuses_on_captive_portal_html(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "dnsbl_tld"
    monkeypatch.setattr(upsl, "DEFAULT_TLD_FILE", target)
    monkeypatch.setattr(
        upsl,
        "fetch_psl",
        lambda timeout=15: "<html><body>Please log in to the WiFi portal</body></html>",
    )

    with pytest.raises(SystemExit):
        upsl.main([])
    assert not target.exists()


def test_main_refuses_on_truncated_body_missing_end_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "dnsbl_tld"
    monkeypatch.setattr(upsl, "DEFAULT_TLD_FILE", target)
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


def test_render_output_stays_one_suffix_per_line_with_an_oversized_body_entry() -> None:
    # render_output only formats an already-built body list -- it never re-validates
    # label length, so a pre-validated oversized entry must still render as one line.
    junk = "a" * 4096
    out = upsl.render_output("v", "c", ["ac", junk, "com"])
    assert out.splitlines()[4:] == ["ac", junk, "com"]


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
    # issue #1455 repro: raw NUL was previously emitted verbatim into dnsbl_tld.
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
# rides into dnsbl_tld untouched unless _has_blank_or_ignorable_char() also
# rejects category-Cn.
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
