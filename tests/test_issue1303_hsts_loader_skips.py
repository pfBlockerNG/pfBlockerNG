"""issue #1303: the two HSTS preload loaders (_build_swap_snapshot's hsts_db and
_load_hsts_db's hstsDB) must skip blank/whitespace-only and '#'-comment lines --
the same contract _dnsbl_load_tld_wildcard_master() already has -- so a later step can ship
pfb_py_hsts.txt with a '#' traceability header. A falsy-but-valid line like '0' MUST
still survive: 'not suffix' is only safe because '' is the sole falsy str after
strip(); '0' is truthy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest

import pfb_unbound

# One fixture exercising every matrix row, loaded through EACH site's real code path.
_FIXTURE_LINES = [
    "# comment line",  # row 1: '#'-comment (with a space) -> not a key
    "#no-space",  # row 2: '#'-comment (no space) -> not a key
    "",  # row 3: blank line -> '' not a key
    "   ",  # row 4a: whitespace-only (spaces) -> not a key
    "\t",  # row 4b: whitespace-only (tab) -> not a key
    "example.com",  # row 5: normal domain -> key present, value 0
    "0",  # row 6: falsy-but-valid string -> key '0' PRESENT (the #1116-class trap)
    " x.com ",  # row 8: surrounding spaces -> stripped key 'x.com'
    "a.b\r",  # row 7: CRLF-ish trailing \r -> key without '\r'
]
_FIXTURE_TEXT = "\n".join(_FIXTURE_LINES) + "\n"
_EXPECTED_KEYS = {"example.com", "0", "x.com", "a.b"}
_JUNK_KEYS = {"# comment line", "#no-space", "", "   ", "\t", " x.com ", "a.b\r"}


def _load_via_site_b(hsts_path: Path) -> dict[str, Any]:
    """Drive _load_hsts_db() (site B) -- the global hstsDB it fills."""
    pfb_unbound.pfb["python_hsts"] = True
    pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
    pfb_unbound.pfb["pfb_py_status"] = str(hsts_path.parent / "pfb_py_status.json")
    pfb_unbound._load_hsts_db()
    return dict(pfb_unbound.hstsDB)


def _load_via_site_a(hsts_path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """Drive _build_swap_snapshot() (site A) -- stub the manifest build (unrelated to
    the HSTS loader under test) so only the HSTS ingest loop is exercised."""
    stub_result = pfb_unbound.BuildResult(data_db={}, zone_db={}, feed_group_index_db={}, white_db={}, counts=0)
    monkeypatch.setattr(pfb_unbound, "dnsbl_build_from_manifest", lambda _path: stub_result)
    pfb_unbound.pfb["pfb_py_sources"] = str(tmp_path / "unused_manifest.json")
    pfb_unbound.pfb["pfb_unbound.ini"] = str(tmp_path / "no_such.ini")
    pfb_unbound.pfb["python_hsts"] = True
    pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
    snap = pfb_unbound._build_swap_snapshot()
    assert snap is not None, "stubbed manifest build must not itself fail the swap"
    return dict(snap.hsts_db)


# (site label, loader) -- both must share the identical skip contract.
_SITES: list[tuple[str, Callable[[Path, pytest.MonkeyPatch, Path], dict[str, Any]]]] = [
    ("site_a_build_swap_snapshot", lambda p, mp, tp: _load_via_site_a(p, mp, tp)),
    ("site_b_load_hsts_db", lambda p, mp, tp: _load_via_site_b(p)),
]


@pytest.mark.parametrize("site_name,loader", _SITES, ids=[s[0] for s in _SITES])
def test_hsts_loader_skips_comment_and_blank_lines(
    site_name: str,
    loader: Callable[[Path, pytest.MonkeyPatch, Path], dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hsts_path = tmp_path / "pfb_py_hsts.txt"
    hsts_path.write_text(_FIXTURE_TEXT, encoding="utf-8")

    keys = set(loader(hsts_path, monkeypatch, tmp_path))

    assert keys == _EXPECTED_KEYS, "{}: got {}".format(site_name, keys)
    for junk in _JUNK_KEYS:
        assert junk not in keys, "{}: junk key {!r} leaked into the loaded dict".format(site_name, junk)


@pytest.mark.parametrize("site_name,loader", _SITES, ids=[s[0] for s in _SITES])
def test_hsts_loader_keeps_falsy_but_valid_zero_key(
    site_name: str,
    loader: Callable[[Path, pytest.MonkeyPatch, Path], dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The #1116-class trap: 'not suffix' must never be written as a check that
    # treats the truthy string '0' as absent.
    hsts_path = tmp_path / "pfb_py_hsts.txt"
    hsts_path.write_text("0\n", encoding="utf-8")

    keys = loader(hsts_path, monkeypatch, tmp_path)

    assert keys == {"0": 0}, "{}: got {}".format(site_name, keys)


@pytest.mark.parametrize("site_name,loader", _SITES, ids=[s[0] for s in _SITES])
def test_hsts_loader_strips_surrounding_whitespace(
    site_name: str,
    loader: Callable[[Path, pytest.MonkeyPatch, Path], dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hsts_path = tmp_path / "pfb_py_hsts.txt"
    hsts_path.write_text(" x.com \n", encoding="utf-8")

    keys = loader(hsts_path, monkeypatch, tmp_path)

    assert keys == {"x.com": 0}, "{}: got {} (current code keeps the surrounding spaces)".format(site_name, keys)


@pytest.mark.parametrize("site_name,loader", _SITES, ids=[s[0] for s in _SITES])
def test_hsts_loader_acceptance_matrix(
    site_name: str,
    loader: Callable[[Path, pytest.MonkeyPatch, Path], dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WHEN a fixture file with lines ['# h', '', '  ', 'example.com', '0', 'a.b\\r']
    loads through EACH site THEN keys == {'example.com', '0', 'a.b'}."""
    hsts_path = tmp_path / "pfb_py_hsts.txt"
    hsts_path.write_text("# h\n\n  \nexample.com\n0\na.b\r\n", encoding="utf-8")

    keys = set(loader(hsts_path, monkeypatch, tmp_path))

    assert keys == {"example.com", "0", "a.b"}, "{}: got {}".format(site_name, keys)
