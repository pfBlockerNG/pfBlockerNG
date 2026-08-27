"""Tests for scripts/misc/update_hsts_preload_list.py -- the Chromium HSTS
preload list sync tool for src/usr/local/pkg/pfblockerng/pfb_py_hsts.txt.

No network: every test drives the pure parse/convert functions (or main() with
fetch_hsts_json monkeypatched) directly against small fake fixtures. The real
network fetch is never exercised here.
"""

from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "misc" / "update_hsts_preload_list.py"
_spec = importlib.util.spec_from_file_location("update_hsts_preload_list", _TOOL)
assert _spec is not None and _spec.loader is not None
uhpl = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = uhpl
_spec.loader.exec_module(uhpl)

_SHIPPED_HSTS_FILE = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_py_hsts.txt"


# --------------------------------------------------------------------------- #
# issue #1303 red->green proof: the shipped pfb_py_hsts.txt predates this sync
# script and carries no traceability header. FAILS on the untouched worktree;
# PASSES once the file is regenerated.
# --------------------------------------------------------------------------- #


def test_shipped_pfb_py_hsts_has_sync_header() -> None:
    lines = _SHIPPED_HSTS_FILE.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#")
    assert any(line.startswith("# License:") for line in lines[:10])


def test_shipped_pfb_py_hsts_is_sorted_ascii_and_deduplicated() -> None:
    body = uhpl.existing_body(_SHIPPED_HSTS_FILE.read_text(encoding="utf-8"))
    assert body == sorted(body)
    assert len(body) == len(set(body))
    assert all(name.isascii() for name in body)


# --------------------------------------------------------------------------- #
# Fixture: a small fake HSTS JSON body exercising every entry shape in the
# coverage matrix (mode filter, include_subdomains, dedup, case, IDN, whitespace)
# --------------------------------------------------------------------------- #

_OVERSIZED_NON_ASCII_LABEL = "ä" * 64  # > 63 octets once idna-encoded -- must be skipped, not crash
_OVERSIZED_ASCII_LABEL = "a" * 64  # issue #1306: all-ASCII past the 63-octet cap -- must be skipped too

_FAKE_HSTS_JSON = (
    "// Copyright 2012 The Chromium Authors\n"
    "// Use of this source code is governed by a BSD-style license that can be\n"
    "  // an indented comment line -- must be stripped too\n"
    "{\n"
    '  "entries": [\n'
    '    {"name": "EXAMPLE.com", "mode": "force-https"},\n'
    '    {"name": "sub.example.com", "mode": "force-https", "include_subdomains": true},\n'
    '    {"name": "sub.example.com", "mode": "force-https"},\n'
    '    {"name": "pinned-only.example", "policy": "bulk-1-year"},\n'
    '    {"name": "no-mode-field.example"},\n'
    '    {"name": "caf\\u00e9.example", "mode": "force-https"},\n'
    f'    {{"name": "a.{_OVERSIZED_NON_ASCII_LABEL}.example", "mode": "force-https"}},\n'
    f'    {{"name": "{_OVERSIZED_ASCII_LABEL}.example", "mode": "force-https"}},\n'
    '    {"name": "bad name.example", "mode": "force-https"},\n'
    '    {"name": "aaa.example", "mode": "force-https"}\n'
    "  ]\n"
    "}\n"
)


def _fake_entries() -> list[dict[str, object]]:
    return uhpl.parse_entries(uhpl.strip_json_comments(_FAKE_HSTS_JSON))


# --------------------------------------------------------------------------- #
# Coverage matrix row 1-2: base64 decode + '//' comment stripping (incl. indented)
# --------------------------------------------------------------------------- #


def test_decode_body_decodes_a_base64_payload() -> None:
    assert uhpl.decode_body(base64.b64encode(b'{"entries": []}').decode()) == '{"entries": []}'


def test_strip_json_comments_drops_plain_and_indented_comment_lines() -> None:
    stripped = uhpl.strip_json_comments(_FAKE_HSTS_JSON)
    assert "Copyright" not in stripped
    assert "indented comment" not in stripped
    assert '"entries"' in stripped


def test_parse_entries_parses_cleanly_after_comment_stripping() -> None:
    entries = _fake_entries()
    assert len(entries) == 10


# --------------------------------------------------------------------------- #
# Coverage matrix row 3: mode filter -- vacuity check (droppable entries are
# present in the fixture and WOULD be emitted if the filter broke)
# --------------------------------------------------------------------------- #


def test_extract_names_keeps_force_https_drops_no_mode_and_other_mode() -> None:
    names = uhpl.extract_names(_fake_entries())
    assert "EXAMPLE.com" in names
    assert "pinned-only.example" not in names
    assert "no-mode-field.example" not in names


# --------------------------------------------------------------------------- #
# Coverage matrix row 4: include_subdomains present -> ignored, name emitted once
# --------------------------------------------------------------------------- #


def test_build_body_emits_include_subdomains_entry_only_once() -> None:
    body = uhpl.build_body(_fake_entries())
    assert body.count("sub.example.com") == 1


# --------------------------------------------------------------------------- #
# Coverage matrix row 5-6: sorted LC-C + deduplicated + lowercased
# --------------------------------------------------------------------------- #


def test_build_body_sorted_deduplicated_and_lowercased() -> None:
    body = uhpl.build_body(_fake_entries())
    assert body == sorted(body)
    assert "example.com" in body  # EXAMPLE.com lowercased
    assert "EXAMPLE.com" not in body
    assert body.count("sub.example.com") == 1  # the duplicate entry collapses


# --------------------------------------------------------------------------- #
# Coverage matrix row 7: non-ASCII per-label punycode; oversized non-ASCII
# label skipped without crashing (PR #1300 lesson: pair oversized x IDN)
# --------------------------------------------------------------------------- #


def test_normalise_name_punycodes_non_ascii_label() -> None:
    assert uhpl.normalise_name("café.example") == "xn--caf-dma.example"


def test_normalise_name_skips_oversized_non_ascii_label_without_crashing() -> None:
    assert uhpl.normalise_name("a." + _OVERSIZED_NON_ASCII_LABEL + ".example") is None


def test_build_body_excludes_oversized_idn_entry() -> None:
    body = uhpl.build_body(_fake_entries())
    assert not any(_OVERSIZED_NON_ASCII_LABEL in name for name in body)
    assert "xn--caf-dma.example" in body


# --------------------------------------------------------------------------- #
# Coverage matrix row 7b (issue #1306): oversized all-ASCII label skipped like
# the IDN path, not emitted verbatim.
# --------------------------------------------------------------------------- #


def test_normalise_name_skips_oversized_all_ascii_label_instead_of_emitting_unchanged() -> None:
    assert uhpl.normalise_name(_OVERSIZED_ASCII_LABEL + ".example") is None


def test_normalise_name_keeps_all_ascii_label_at_the_63_octet_boundary() -> None:
    name = "a" * 63 + ".example"
    assert uhpl.normalise_name(name) == name


def test_normalise_name_skips_all_ascii_label_one_octet_past_the_boundary() -> None:
    assert uhpl.normalise_name("a" * 64 + ".example") is None


def test_build_body_excludes_oversized_ascii_entry() -> None:
    body = uhpl.build_body(_fake_entries())
    assert not any(_OVERSIZED_ASCII_LABEL in name for name in body)
    assert "aaa.example" in body


# --------------------------------------------------------------------------- #
# Coverage matrix row 8: whitespace-carrying name skipped
# --------------------------------------------------------------------------- #


def test_normalise_name_skips_name_with_internal_whitespace() -> None:
    assert uhpl.normalise_name("bad name.example") is None


def test_build_body_excludes_whitespace_carrying_entry() -> None:
    body = uhpl.build_body(_fake_entries())
    assert "bad name.example" not in body
    assert not any(" " in name for name in body)


# --------------------------------------------------------------------------- #
# Coverage matrix row 8b (issue #1306): exotic Unicode blanks / RFC 3454 Table
# B.1 "commonly mapped to nothing" characters skipped like ordinary whitespace
# -- str.isspace() plus stringprep.in_table_b1() (the exact predicate the
# stdlib idna codec's nameprep step uses internally) catches the whole class,
# not a hardcoded few, so idna's encoder never gets the chance to silently
# coalesce one away.
# --------------------------------------------------------------------------- #


def test_normalise_name_skips_name_with_zero_width_space() -> None:
    # issue #1306 repro: U+200B was previously silently coalesced away by idna's
    # encoder instead of the name being treated as malformed.
    assert uhpl.normalise_name("a\u200bb.example") is None


def test_normalise_name_skips_name_with_byte_order_mark() -> None:
    assert uhpl.normalise_name("a\ufeffb.example") is None


def test_normalise_name_skips_name_with_word_joiner() -> None:
    # A Table B.1 member not explicitly named in the issue -- proves the fix
    # catches the whole ignorable-character class, not a hardcoded list.
    assert uhpl.normalise_name("a\u2060b.example") is None


def test_normalise_name_skips_name_with_variation_selector() -> None:
    # issue #1306 follow-up: U+FE0F is Table B.1 but category Mn, not Cf -- a
    # category-Cf-only check misses it; stringprep.in_table_b1() catches it.
    assert uhpl.normalise_name("a\ufe0fb.example") is None


def test_normalise_name_skips_name_with_combining_grapheme_joiner() -> None:
    # U+034F: Table B.1, category Mn -- same Cf-blind-spot class as above.
    assert uhpl.normalise_name("a\u034fb.example") is None


def test_normalise_name_skips_name_with_mongolian_free_variation_selector() -> None:
    # U+180B: Table B.1, category Mn -- same Cf-blind-spot class.
    assert uhpl.normalise_name("a\u180bb.example") is None


def test_normalise_name_still_encodes_combining_acute_not_in_table_b1() -> None:
    # U+0301 (combining acute) is category Mn like the Table B.1 members above,
    # but is NOT itself in Table B.1 -- must still punycode-encode, never be
    # skipped (proves the predicate isn't "skip every Mn character").
    name = "a" + "\u0301" + "b.example"
    assert uhpl.normalise_name(name) is not None


def test_normalise_name_skips_name_with_non_breaking_space() -> None:
    # U+00A0 is already str.isspace() -- pins the pre-existing behaviour, no regression.
    assert uhpl.normalise_name("a\xa0b.example") is None


def test_normalise_name_skips_name_with_ideographic_space() -> None:
    # U+3000 is already str.isspace() -- pins the pre-existing behaviour, no regression.
    assert uhpl.normalise_name("a\u3000b.example") is None


def test_normalise_name_skips_empty_name() -> None:
    assert uhpl.normalise_name("") is None


# --------------------------------------------------------------------------- #
# Coverage matrix row 8c (issue #1455): category-Cc control characters skipped,
# not emitted verbatim -- an ASCII-range Cc char (e.g. NUL, DEL) is neither
# str.isspace() nor stringprep.in_table_b1(), so it takes the isascii()
# passthrough branch in _punycode_label untouched instead of being rejected.
# --------------------------------------------------------------------------- #


def test_normalise_name_skips_name_with_nul() -> None:
    # issue #1455 repro: raw NUL was previously emitted verbatim into pfb_py_hsts.txt.
    assert uhpl.normalise_name("a\x00b.example") is None


def test_normalise_name_skips_name_with_del() -> None:
    assert uhpl.normalise_name("a\x7fb.example") is None


def test_normalise_name_skips_name_with_bell() -> None:
    # U+0007 (BEL) -- not one of the two codepoints named in the issue, proves
    # the fix catches the whole category-Cc class, not a hardcoded pair.
    assert uhpl.normalise_name("a\x07b.example") is None


# --------------------------------------------------------------------------- #
# Coverage matrix row 8d (issue #1463): category-Cn (unassigned) codepoints
# skipped, not silently punycode-encoded -- the stdlib idna codec accepts an
# unassigned codepoint without error (probed: U+0378 encodes cleanly), so it
# rides into pfb_py_hsts.txt untouched unless _has_blank_or_ignorable_char()
# also rejects category-Cn.
# --------------------------------------------------------------------------- #


def test_normalise_name_skips_name_with_unassigned_codepoint_mixed_nonascii() -> None:
    # issue #1463 reported shape: Cn (U+0378) mixed with another non-ASCII
    # label char (U+00E9, e-acute) in the same label.
    assert uhpl.normalise_name("a͸é.example") is None


def test_normalise_name_skips_name_with_unassigned_codepoint_otherwise_ascii_label() -> None:
    # Cn is the ONLY non-ASCII char in an otherwise-ASCII label -- probed: no
    # ASCII-range (0x00-0x7F) codepoint is Cn, so this label is non-ASCII
    # overall and takes the idna path, never the isascii() passthrough branch
    # (unlike the Cc case in issue #1455, which DID pass through raw).
    assert uhpl.normalise_name("a͸b.example") is None


def test_normalise_name_still_encodes_recently_assigned_codepoint_not_cn() -> None:
    # U+0526 (CYRILLIC CAPITAL LETTER PE WITH DESCENDER, assigned Unicode 5.1)
    # is "unassigned" under RFC 3454 Table A.1's frozen Unicode-3.2 baseline
    # (stringprep.in_table_a1 -> True) but is NOT category-Cn on this
    # interpreter's live Unicode data -- pins the tolerance decision: reject
    # unassigned-NOW (unicodedata.category(c) == "Cn"), not
    # unassigned-as-of-3.2 (stringprep.in_table_a1), which would false-positive
    # reject this valid, currently-assigned codepoint.
    assert uhpl.normalise_name("aԦb.example") == "xn--ab-e6c.example"


# --------------------------------------------------------------------------- #
# Coverage matrix row 9: header exact 4-line shape incl. License + SYNCED date
# --------------------------------------------------------------------------- #


def test_render_output_header_shape() -> None:
    out = uhpl.render_output("2026-07-13", ["aaa.example", "example.com"])
    lines = out.splitlines()
    assert lines[0] == (
        "# HSTS preload list (force-https entries) - "
        "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json"
    )
    assert lines[1] == (
        "# License: BSD-style, The Chromium Authors - https://chromium.googlesource.com/chromium/src/+/main/LICENSE"
    )
    assert lines[2] == "# SYNCED: 2026-07-13"
    assert lines[3].startswith("# Regenerated by scripts/misc/update_hsts_preload_list.py")
    assert lines[4:] == ["aaa.example", "example.com"]


def test_existing_body_strips_only_hash_lines() -> None:
    text = "# header\n# SYNCED: x\naaa.example\nexample.com\n"
    assert uhpl.existing_body(text) == ["aaa.example", "example.com"]


# --------------------------------------------------------------------------- #
# Coverage matrix row 10: churn guard -- body-unchanged leaves the file
# untouched (both plain run and --check); body-changed rewrites (plain run
# only, header date refreshed), --check reports it without touching the file.
# --------------------------------------------------------------------------- #

_FAKE_FETCH_JSON = (
    '{"entries": [{"name": "aaa.example", "mode": "force-https"}, {"name": "example.com", "mode": "force-https"}]}'
)


def _fake_fetch(timeout: float = 15) -> str:
    return base64.b64encode(_FAKE_FETCH_JSON.encode()).decode()


def test_main_leaves_file_untouched_when_body_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = "# old header\naaa.example\nexample.com\n"
    target = tmp_path / "pfb_py_hsts.txt"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(uhpl, "DEFAULT_HSTS_FILE", target)
    monkeypatch.setattr(uhpl, "MIN_PLAUSIBLE_ENTRIES", 1)
    monkeypatch.setattr(uhpl, "fetch_hsts_json", _fake_fetch)
    before_mtime = target.stat().st_mtime_ns

    rc = uhpl.main([])

    assert rc == 0
    assert target.stat().st_mtime_ns == before_mtime  # no write happened, not just same bytes
    assert target.read_text(encoding="utf-8") == existing


def test_main_check_exits_zero_and_untouched_when_body_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = "# old header\naaa.example\nexample.com\n"
    target = tmp_path / "pfb_py_hsts.txt"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(uhpl, "DEFAULT_HSTS_FILE", target)
    monkeypatch.setattr(uhpl, "MIN_PLAUSIBLE_ENTRIES", 1)
    monkeypatch.setattr(uhpl, "fetch_hsts_json", _fake_fetch)
    before_mtime = target.stat().st_mtime_ns

    rc = uhpl.main(["--check"])

    assert rc == 0
    assert target.stat().st_mtime_ns == before_mtime
    assert target.read_text(encoding="utf-8") == existing


def test_main_rewrites_file_when_body_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = "# old header\naaa.example\n"  # missing 'example.com' -> body differs from the fetch
    target = tmp_path / "pfb_py_hsts.txt"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(uhpl, "DEFAULT_HSTS_FILE", target)
    monkeypatch.setattr(uhpl, "MIN_PLAUSIBLE_ENTRIES", 1)
    monkeypatch.setattr(uhpl, "fetch_hsts_json", _fake_fetch)

    rc = uhpl.main([])

    assert rc == 0
    new_text = target.read_text(encoding="utf-8")
    assert new_text.splitlines()[0].startswith("#")
    assert any(line.startswith("# SYNCED:") for line in new_text.splitlines()[:10])
    assert uhpl.existing_body(new_text) == ["aaa.example", "example.com"]


def test_main_check_exits_one_and_leaves_file_untouched_when_body_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = "# old header\naaa.example\n"
    target = tmp_path / "pfb_py_hsts.txt"
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(uhpl, "DEFAULT_HSTS_FILE", target)
    monkeypatch.setattr(uhpl, "MIN_PLAUSIBLE_ENTRIES", 1)
    monkeypatch.setattr(uhpl, "fetch_hsts_json", _fake_fetch)

    rc = uhpl.main(["--check"])

    assert rc == 1
    assert target.read_text(encoding="utf-8") == existing


# --------------------------------------------------------------------------- #
# Coverage matrix row 11: safety floors -- refuse, file untouched
# --------------------------------------------------------------------------- #


def test_require_plausible_rejects_an_implausibly_small_body() -> None:
    with pytest.raises(SystemExit):
        uhpl.require_plausible([])
    with pytest.raises(SystemExit):
        uhpl.require_plausible([f"name{i}.example" for i in range(uhpl.MIN_PLAUSIBLE_ENTRIES - 1)])


def test_require_plausible_accepts_a_realistic_entry_count() -> None:
    uhpl.require_plausible([f"name{i}.example" for i in range(uhpl.MIN_PLAUSIBLE_ENTRIES)])


def test_parse_entries_raises_when_entries_key_missing() -> None:
    with pytest.raises(SystemExit):
        uhpl.parse_entries('{"pinsets": []}')


def test_parse_entries_raises_when_entries_is_not_a_list() -> None:
    with pytest.raises(SystemExit):
        uhpl.parse_entries('{"entries": "not-a-list"}')


def test_parse_entries_raises_when_an_entry_row_is_not_a_dict() -> None:
    with pytest.raises(SystemExit):
        uhpl.parse_entries('{"entries": [{"name": "a.com", "mode": "force-https"}, "junk-row"]}')


def test_extract_names_raises_when_a_force_https_entry_lacks_a_string_name() -> None:
    with pytest.raises(SystemExit):
        uhpl.extract_names([{"mode": "force-https"}])
    with pytest.raises(SystemExit):
        uhpl.extract_names([{"mode": "force-https", "name": 7}])


def test_main_refuses_on_non_base64_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "pfb_py_hsts.txt"
    monkeypatch.setattr(uhpl, "DEFAULT_HSTS_FILE", target)
    monkeypatch.setattr(
        uhpl, "fetch_hsts_json", lambda timeout=15: "<html><body>Please log in to the WiFi portal</body></html>"
    )

    with pytest.raises(SystemExit):
        uhpl.main([])
    assert not target.exists()


def test_main_refuses_on_base64_of_html_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "pfb_py_hsts.txt"
    monkeypatch.setattr(uhpl, "DEFAULT_HSTS_FILE", target)
    html = "<html><body>Please log in to the WiFi portal</body></html>"
    monkeypatch.setattr(uhpl, "fetch_hsts_json", lambda timeout=15: base64.b64encode(html.encode()).decode())

    with pytest.raises(SystemExit):
        uhpl.main([])
    assert not target.exists()


def test_main_refuses_on_missing_entries_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "pfb_py_hsts.txt"
    monkeypatch.setattr(uhpl, "DEFAULT_HSTS_FILE", target)
    monkeypatch.setattr(uhpl, "fetch_hsts_json", lambda timeout=15: base64.b64encode(b'{"pinsets": []}').decode())

    with pytest.raises(SystemExit):
        uhpl.main([])
    assert not target.exists()


# --------------------------------------------------------------------------- #
# Coverage matrix row 12: output ends with exactly one trailing newline, no
# blank interior lines
# --------------------------------------------------------------------------- #


def test_render_output_single_trailing_newline_no_blank_interior_lines() -> None:
    out = uhpl.render_output("2026-07-13", ["aaa.example", "example.com"])
    assert out.endswith("\n")
    assert not out.endswith("\n\n")
    assert "" not in out.splitlines()
