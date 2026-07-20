from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P
from tests.test_issue1542_top1m_fixed_file import _manifest


def test_enabled_symlink_fixed_file_fails_closed(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    target = tmp_path / "target.txt"
    target.write_text("target.example\n", encoding="utf-8")
    (tmp_path / "pfb_py_top1m.txt").symlink_to(target)

    assert P.dnsbl_build_from_manifest(str(manifest)) is None


def test_enabled_replacement_between_lstat_and_open_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    replacement = tmp_path / "replacement.txt"
    path.write_text("old.example\n", encoding="utf-8")
    replacement.write_text("new.example\n", encoding="utf-8")
    real_open = P.os.open
    replaced = False

    def replacing_open(name: str | os.PathLike[str], flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal replaced
        if os.fspath(name) == os.fspath(path) and not replaced:
            os.replace(replacement, path)
            replaced = True
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(P.os, "open", replacing_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    assert replaced


def test_enabled_invalid_utf8_fixed_file_fails_closed(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_bytes(b"valid.example\n\xff\n")

    assert P.dnsbl_build_from_manifest(str(manifest)) is None


def test_enabled_in_place_truncation_during_iteration_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("".join("domain-{}.example\n".format(index) for index in range(10_000)), encoding="utf-8")
    real_open = open

    class TruncatingReader:
        def __init__(self, handle: Any) -> None:
            self._handle = handle
            self._truncated = False

        def __enter__(self) -> TruncatingReader:
            self._handle.__enter__()
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return bool(self._handle.__exit__(exc_type, exc, traceback))

        def fileno(self) -> int:
            return self._handle.fileno()

        def __iter__(self) -> Any:
            for line in self._handle:
                if not self._truncated:
                    os.truncate(path, 0)
                    self._truncated = True
                yield line

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        return TruncatingReader(handle) if os.fspath(name) == os.fspath(path) else handle

    monkeypatch.setattr("builtins.open", injected_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None


def test_enabled_atomic_rename_after_open_allows_old_complete_inode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    replacement = tmp_path / "replacement.txt"
    path.write_text("old.example\n", encoding="utf-8")
    replacement.write_text("new.example\n", encoding="utf-8")
    old_inode = path.stat().st_ino
    real_fstat = P.os.fstat
    renamed = False

    def renaming_fstat(fd: int) -> os.stat_result:
        nonlocal renamed
        result = real_fstat(fd)
        if not renamed and result.st_ino == old_inode:
            os.replace(replacement, path)
            renamed = True
        return result

    monkeypatch.setattr(P.os, "fstat", renaming_fstat)
    result = P.dnsbl_build_from_manifest(str(manifest))
    assert renamed
    assert result is not None
    assert set(result.white_db) == {"old.example"}
