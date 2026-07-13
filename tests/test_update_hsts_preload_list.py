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
    assert len(entries) == 9


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
# Coverage matrix row 8: whitespace-carrying name skipped
# --------------------------------------------------------------------------- #


def test_normalise_name_skips_name_with_internal_whitespace() -> None:
    assert uhpl.normalise_name("bad name.example") is None


def test_build_body_excludes_whitespace_carrying_entry() -> None:
    body = uhpl.build_body(_fake_entries())
    assert "bad name.example" not in body
    assert not any(" " in name for name in body)


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
