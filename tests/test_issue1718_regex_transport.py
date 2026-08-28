"""Issue #2079: opaque base64 regex transport reaches both Python load sites."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

import pytest
import unboundmodule

import pfb_unbound as P


def _manifest(path: Path) -> None:
    path.write_text(
        '{"version": 1, "config": {}, "feeds": []}\n',
        encoding="utf-8",
    )


def _ini(payload: str) -> str:
    body = "[MAIN]\npython_enable = true\nregex_list = {}\n".format(payload)
    if payload == "__ABSENT__":
        body = "[MAIN]\npython_enable = true\n"
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
        assert P.regexDB["foo_desc"]["re"].pattern == 'A%=:;"\\D'
        assert P.regexDB["foo_desc"]["re"].flags & re.IGNORECASE
        assert P.regexDB["foo_desc_2"]["re"].pattern == 'B%=:;"\\D'
        assert P.regexDB["foo_desc_2"]["re"].flags & re.IGNORECASE
        assert P.regexDB["inline_description"]["re"].pattern == "unnamed"
        assert P.regexDB["regex_4"]["re"].pattern == "blank"
    finally:
        P.deinit(0)


def test_swap_load_matches_initial(tmp_path: Path, monkeypatch: Any) -> None:
    text = "alpha#Description\r\nbeta\n"
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    ini = tmp_path / "pfb_unbound.ini"
    manifest = tmp_path / "pfb_py_sources.json"
    _manifest(manifest)
    ini.write_text(_ini(encoded), encoding="utf-8")
    monkeypatch.setitem(P.pfb, "pfb_unbound.ini", str(ini))
    monkeypatch.setitem(P.pfb, "pfb_py_sources", str(manifest))
    initial = None
    try:
        _initial_load(tmp_path, monkeypatch, _ini(encoded))
        initial = {name: entry["re"].pattern for name, entry in P.regexDB.items()}
        swapped = P._build_swap_snapshot()
        assert swapped is not None
        assert {name: entry["re"].pattern for name, entry in swapped.regex_db.items()} == initial
        assert all(entry["re"].flags & re.IGNORECASE for entry in swapped.regex_db.values())
    finally:
        P.deinit(0)


def test_issue2364_shape_gate_matches_initial_and_swap_user_loads(tmp_path: Path, monkeypatch: Any) -> None:
    unsafe = r"^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$"
    safe = r"^[a-z]+\.[a-z]+\.[a-z]+$"
    text = f"{unsafe}#unsafe\n{safe}#safe\n"
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    ini = tmp_path / "pfb_unbound.ini"
    manifest = tmp_path / "pfb_py_sources.json"
    _manifest(manifest)
    ini.write_text(_ini(encoded), encoding="utf-8")
    monkeypatch.setitem(P.pfb, "pfb_unbound.ini", str(ini))
    monkeypatch.setitem(P.pfb, "pfb_py_sources", str(manifest))
    try:
        _initial_load(tmp_path, monkeypatch, _ini(encoded))
        assert set(P.regexDB) == {"safe"}
        assert P.regexDB["safe"]["re"].pattern == safe

        swapped = P._build_swap_snapshot()
        assert swapped is not None
        assert set(swapped.regex_db) == {"safe"}
        assert swapped.regex_db["safe"]["re"].pattern == safe
    finally:
        P.deinit(0)


def test_present_malformed_or_non_utf8_marker_fails_closed(
    tmp_path: Path, monkeypatch: Any, caplog: pytest.LogCaptureFixture
) -> None:
    for payload in ("%%%", base64.b64encode(b"\xff").decode("ascii")):
        caplog.clear()
        try:
            _initial_load(tmp_path, monkeypatch, _ini(payload))
            assert P.regexDB == {}
            assert "Failed to decode MAIN.regex_list" in caplog.text
        finally:
            P.deinit(0)


def test_absent_marker_ignores_obsolete_regex_section(tmp_path: Path, monkeypatch: Any) -> None:
    ini_body = _ini("__ABSENT__") + "[REGEX]\nlegacy = old\n"
    try:
        _initial_load(tmp_path, monkeypatch, ini_body)
        assert P.regexDB == {}

        swapped = P._build_swap_snapshot()
        assert swapped is not None
        assert swapped.regex_db == {}
    finally:
        P.deinit(0)
