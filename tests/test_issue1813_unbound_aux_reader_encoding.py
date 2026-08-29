"""issue #1813 (Front 2 of #1808): every file pfb_unbound.py reads at runtime must
decode as explicit UTF-8 with a defined failure mode, never depend on the process
locale.

Covers: the two HSTS preload loaders (_build_swap_snapshot's inline block -- site A --
and _load_hsts_db -- site B), the SafeSearch CSV loader (_load_safesearch_db), both
ConfigParser.read() call sites (the inline user-regex block in _build_swap_snapshot and
_load_ini_config), and the two watcher readers (_reload_read_generation,
_control_read_record) whose narrow ``except OSError:`` must widen to
``except (OSError, ValueError):`` -- a UnicodeDecodeError IS a ValueError and currently
escapes past their "best-effort, never raise" contract.

Small fixtures (well under one text-I/O read buffer) decode the WHOLE file in one shot
before yielding any line, so a bad byte anywhere aborts the parse with ZERO lines seen.
A bad byte needs to sit past the first buffer refill (~thousands of short lines in) to
actually reproduce a genuine *partial*-dict failure -- hence the large fixtures below.
"""

from __future__ import annotations

from configparser import ConfigParser
from pathlib import Path
from typing import Any, Callable

import pytest

import pfb_unbound

_BAD_BYTE = b"\xff"  # never valid as a UTF-8 start/continuation byte.
_MULTIBYTE_DOMAIN = "bücher.example"  # 'bücher.example' -- must survive unmangled.


def _big_valid_prefix(n: int) -> bytes:
    return "".join("valid{}.example\n".format(i) for i in range(n)).encode("utf-8")


# --------------------------------------------------------------------------------- #
# HSTS loaders: site A = _build_swap_snapshot's inline block, site B = _load_hsts_db.
# --------------------------------------------------------------------------------- #


def _load_hsts_site_b(hsts_path: Path) -> dict[str, Any]:
    pfb_unbound.pfb["python_hsts"] = True
    pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
    pfb_unbound.pfb["pfb_py_status"] = str(hsts_path.parent / "pfb_py_status.json")
    pfb_unbound._load_hsts_db()
    return dict(pfb_unbound.hstsDB)


def _load_hsts_site_a(hsts_path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    stub_result = pfb_unbound.BuildResult(data_db={}, zone_db={}, feed_group_index_db={}, white_db={}, counts=0)
    monkeypatch.setattr(pfb_unbound, "dnsbl_build_from_manifest", lambda _path: stub_result)
    pfb_unbound.pfb["pfb_py_sources"] = str(tmp_path / "unused_manifest.json")
    pfb_unbound.pfb["pfb_unbound.ini"] = str(tmp_path / "no_such.ini")
    pfb_unbound.pfb["python_hsts"] = True
    pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
    snap = pfb_unbound._build_swap_snapshot()
    assert snap is not None, "stubbed manifest build must not itself fail the swap"
    return dict(snap.hsts_db)


_HstsLoader = Callable[[Path, pytest.MonkeyPatch, Path], dict[str, Any]]
_HSTS_SITES: list[tuple[str, _HstsLoader]] = [
    ("site_a_build_swap_snapshot", lambda p, mp, tp: _load_hsts_site_a(p, mp, tp)),
    ("site_b_load_hsts_db", lambda p, mp, tp: _load_hsts_site_b(p)),
]


@pytest.mark.parametrize("site_name,loader", _HSTS_SITES, ids=[s[0] for s in _HSTS_SITES])
def test_hsts_loader_invalid_byte_mid_file_replaces_not_partial(
    site_name: str,
    loader: _HstsLoader,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad byte past the first read buffer must not truncate the load: lines before
    AND after it end up in the dict, the bad byte itself surfaces as U+FFFD, and a
    valid multibyte domain right after it survives unmangled."""
    hsts_path = tmp_path / "pfb_py_hsts.txt"
    body = _big_valid_prefix(2000) + _BAD_BYTE + b"badline.example\n" + _MULTIBYTE_DOMAIN.encode("utf-8") + b"\n"
    hsts_path.write_bytes(body)

    keys = set(loader(hsts_path, monkeypatch, tmp_path))

    assert "valid0.example" in keys, "{}: lines before the bad byte must load".format(site_name)
    assert "valid1999.example" in keys, "{}: lines after the bad byte's buffer must still load".format(site_name)
    assert "�badline.example" in keys, "{}: the bad byte must surface as U+FFFD, not abort".format(site_name)
    assert _MULTIBYTE_DOMAIN in keys, "{}: valid multibyte UTF-8 must survive unmangled".format(site_name)


@pytest.mark.parametrize("site_name,loader", _HSTS_SITES, ids=[s[0] for s in _HSTS_SITES])
def test_hsts_loader_invalid_byte_on_first_line(
    site_name: str,
    loader: _HstsLoader,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hsts_path = tmp_path / "pfb_py_hsts.txt"
    hsts_path.write_bytes(_BAD_BYTE + b"firstline.example\nsecond.example\n")

    keys = set(loader(hsts_path, monkeypatch, tmp_path))

    assert "�firstline.example" in keys, "{}: got {}".format(site_name, keys)
    assert "second.example" in keys, "{}: got {}".format(site_name, keys)


def test_load_hsts_db_ready_flag_set_after_invalid_byte(tmp_path: Path) -> None:
    """site B's pfb['hstsDB'] readiness flag only flips True once the for-loop
    completes -- with a bad byte it must still complete (replace, not abort)."""
    hsts_path = tmp_path / "pfb_py_hsts.txt"
    hsts_path.write_bytes(_BAD_BYTE + b"only.example\n")
    pfb_unbound.pfb["python_hsts"] = True
    pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
    pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

    pfb_unbound._load_hsts_db()

    assert pfb_unbound.pfb["hstsDB"] is True


# --------------------------------------------------------------------------------- #
# SafeSearch loader (_load_safesearch_db).
# --------------------------------------------------------------------------------- #


def _big_valid_ss_prefix(n: int) -> bytes:
    return "".join("valid{}.example,1.2.3.4,::1\n".format(i) for i in range(n)).encode("utf-8")


def test_safesearch_loader_invalid_byte_mid_file_replaces_not_partial(tmp_path: Path) -> None:
    ss_path = tmp_path / "pfb_py_ss.txt"
    body = (
        _big_valid_ss_prefix(2000)
        + _BAD_BYTE
        + "badrow.example,1.2.3.4,::1\n".encode("utf-8")
        + "{},5.6.7.8,::2\n".format(_MULTIBYTE_DOMAIN).encode("utf-8")
    )
    ss_path.write_bytes(body)
    pfb_unbound.pfb["pfb_py_ss"] = str(ss_path)
    pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

    pfb_unbound._load_safesearch_db()

    db = pfb_unbound.safeSearchDB
    assert db["valid0.example"] == {"A": "1.2.3.4", "AAAA": "::1"}, "lines before the bad byte must load"
    assert db["valid1999.example"] == {"A": "1.2.3.4", "AAAA": "::1"}, "lines past the bad byte's buffer must load"
    assert db["�badrow.example"] == {"A": "1.2.3.4", "AAAA": "::1"}, "the bad byte must surface as U+FFFD"
    assert db[_MULTIBYTE_DOMAIN] == {"A": "5.6.7.8", "AAAA": "::2"}, "valid multibyte UTF-8 must survive unmangled"


def test_safesearch_loader_invalid_byte_on_first_line(tmp_path: Path) -> None:
    ss_path = tmp_path / "pfb_py_ss.txt"
    ss_path.write_bytes(_BAD_BYTE + b"firstrow.example,1.2.3.4,::1\nsecond.example,5.6.7.8,::2\n")
    pfb_unbound.pfb["pfb_py_ss"] = str(ss_path)
    pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

    pfb_unbound._load_safesearch_db()

    db = pfb_unbound.safeSearchDB
    assert db["�firstrow.example"] == {"A": "1.2.3.4", "AAAA": "::1"}
    assert db["second.example"] == {"A": "5.6.7.8", "AAAA": "::2"}


def test_safesearch_load_ready_flag_set_after_invalid_byte(tmp_path: Path) -> None:
    ss_path = tmp_path / "pfb_py_ss.txt"
    ss_path.write_bytes(_BAD_BYTE + b"only.example,1.2.3.4,::1\n")
    pfb_unbound.pfb["pfb_py_ss"] = str(ss_path)
    pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

    pfb_unbound._load_safesearch_db()

    assert pfb_unbound.pfb["safeSearchDB"] is True


# --------------------------------------------------------------------------------- #
# ConfigParser.read() sites: the ini file gates through the SAME broad except at both
# call sites already, so a decode failure's fallback is already exercised by that
# broad except (mirrors the SafeSearch/HSTS mechanism above). What's new here is only
# that the read is deterministic (pinned utf-8) regardless of process locale -- proven
# by asserting the actual encoding= kwarg .read() is invoked with.
# --------------------------------------------------------------------------------- #


def _drive_ini_site_load_ini_config(ini_path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pfb_unbound.pfb["pfb_unbound.ini"] = str(ini_path)
    pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")
    pfb_unbound._load_ini_config()


def _drive_ini_site_build_swap_snapshot(ini_path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    stub_result = pfb_unbound.BuildResult(data_db={}, zone_db={}, feed_group_index_db={}, white_db={}, counts=0)
    monkeypatch.setattr(pfb_unbound, "dnsbl_build_from_manifest", lambda _path: stub_result)
    pfb_unbound.pfb["pfb_py_sources"] = str(tmp_path / "unused_manifest.json")
    pfb_unbound.pfb["pfb_unbound.ini"] = str(ini_path)
    pfb_unbound.pfb["python_hsts"] = False
    snap = pfb_unbound._build_swap_snapshot()
    assert snap is not None, "stubbed manifest build must not itself fail the swap"


_IniDriver = Callable[[Path, pytest.MonkeyPatch, Path], None]
_INI_SITES: list[tuple[str, _IniDriver]] = [
    ("site_load_ini_config", _drive_ini_site_load_ini_config),
    ("site_build_swap_snapshot_user_regex", _drive_ini_site_build_swap_snapshot),
]


@pytest.mark.parametrize("site_name,driver", _INI_SITES, ids=[s[0] for s in _INI_SITES])
def test_ini_configparser_read_called_with_explicit_utf8_encoding(
    site_name: str,
    driver: _IniDriver,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ini_path = tmp_path / "pfb_unbound.ini"
    ini_path.write_text("[MAIN]\n", encoding="utf-8")

    calls: list[Any] = []
    orig_read = ConfigParser.read

    def _spy_read(self: ConfigParser, filenames: Any, encoding: Any = None) -> Any:
        calls.append(encoding)
        return orig_read(self, filenames, encoding=encoding)

    monkeypatch.setattr(ConfigParser, "read", _spy_read)

    driver(ini_path, monkeypatch, tmp_path)

    assert calls, "{}: ConfigParser.read() must have been called".format(site_name)
    assert calls[-1] == "utf-8", "{}: expected encoding='utf-8', got {!r}".format(site_name, calls[-1])


# --------------------------------------------------------------------------------- #
# Watcher readers: except OSError: currently lets a UnicodeDecodeError (a ValueError)
# escape past the "absent/unreadable -> None" best-effort contract.
# --------------------------------------------------------------------------------- #


def test_reload_read_generation_invalid_utf8_byte_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "sentinel"
    p.write_bytes(_BAD_BYTE + b"42\n")

    assert pfb_unbound._reload_read_generation(str(p)) is None


def test_control_read_record_invalid_utf8_byte_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "ctl"
    p.write_bytes(_BAD_BYTE + b'{"seq": 1, "cmd": "enable"}\n')

    assert pfb_unbound._control_read_record(str(p)) is None
