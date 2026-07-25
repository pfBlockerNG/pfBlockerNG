"""Issue #1718: opaque base64 regex transport reaches both Python load sites."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import unboundmodule

import pfb_unbound as P


def _manifest(path: Path) -> None:
    path.write_text(
        '{"version": 1, "config": {}, "feeds": []}\n',
        encoding="utf-8",
    )


def _ini(payload: str, *, legacy: str = "") -> str:
    body = "[MAIN]\npython_enable = true\nregex_list = {}\n".format(payload)
    if payload == "__ABSENT__":
        body = "[MAIN]\npython_enable = true\n"
    if legacy:
        body += "[REGEX]\nlegacy = {}\n".format(legacy)
    return body


def _initial_load(tmp_path: Path, monkeypatch: Any, ini_body: str) -> None:
    (tmp_path / "pfb_unbound.ini").write_text(ini_body, encoding="utf-8")
    _manifest(tmp_path / "pfb_py_sources.json")
    monkeypatch.chdir(tmp_path)
    P.pfb["mod_maxminddb_e"] = "stub"
    P.pfb["mod_threading_e"] = "stub"
    P.pfb["mod_sqlite3_e"] = "stub"
    P.pfb["mod_sqlite3"] = False
    P.pfb["mod_threading"] = False
    assert P.init_standard(0, unboundmodule.module_env()) is True


def test_initial_load_decodes_base64_rows_and_preserves_names(tmp_path: Path, monkeypatch: Any) -> None:
    text = '# full comment\r\n A%=:;"\\D#Foo desc \nB%=:;"\\D#Foo desc\n unnamed#Inline description\rblank\r\n'
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    try:
        _initial_load(tmp_path, monkeypatch, _ini(encoded))
        assert set(P.regexDB) == {"foo_desc", "foo_desc_2", "inline_description", "regex_4"}
        assert P.regexDB["foo_desc"]["re"].pattern == 'a%=:;"\\d'
        assert P.regexDB["foo_desc_2"]["re"].pattern == 'b%=:;"\\d'
        assert P.regexDB["inline_description"]["re"].pattern == "unnamed"
        assert P.regexDB["regex_4"]["re"].pattern == "blank"
    finally:
        P.deinit(0)


def test_swap_load_matches_initial_and_ignores_legacy_when_marker_present(tmp_path: Path, monkeypatch: Any) -> None:
    text = "alpha#Description\r\nbeta\n"
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    ini = tmp_path / "pfb_unbound.ini"
    manifest = tmp_path / "pfb_py_sources.json"
    _manifest(manifest)
    ini.write_text(_ini(encoded, legacy="stale"), encoding="utf-8")
    monkeypatch.setitem(P.pfb, "pfb_unbound.ini", str(ini))
    monkeypatch.setitem(P.pfb, "pfb_py_sources", str(manifest))
    initial = None
    try:
        _initial_load(tmp_path, monkeypatch, _ini(encoded, legacy="stale"))
        initial = {name: entry["re"].pattern for name, entry in P.regexDB.items()}
        swapped = P._build_swap_snapshot()
        assert swapped is not None
        assert {name: entry["re"].pattern for name, entry in swapped.regex_db.items()} == initial
        assert "stale" not in swapped.regex_db
    finally:
        P.deinit(0)


def test_present_malformed_or_non_utf8_marker_fails_closed_without_legacy_fallback(
    tmp_path: Path, monkeypatch: Any
) -> None:
    for payload in ("%%%", base64.b64encode(b"\xff").decode("ascii")):
        try:
            _initial_load(tmp_path, monkeypatch, _ini(payload, legacy="old"))
            assert P.regexDB == {}, "marker failure must not load stale legacy entries"
        finally:
            P.deinit(0)


def test_absent_marker_keeps_legacy_read_compatibility(tmp_path: Path, monkeypatch: Any) -> None:
    try:
        _initial_load(tmp_path, monkeypatch, _ini("__ABSENT__", legacy="old"))
        assert P.regexDB["legacy"]["re"].pattern == "old"
    finally:
        P.deinit(0)
