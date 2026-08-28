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


def test_enabled_read_oserror_fixed_file_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("first.example\nsecond.example\n", encoding="utf-8")
    real_open = open
    failed = False

    class FailingReader:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __enter__(self) -> FailingReader:
            self._handle.__enter__()
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return bool(self._handle.__exit__(exc_type, exc, traceback))

        def fileno(self) -> int:
            return self._handle.fileno()

        def __iter__(self) -> Any:
            nonlocal failed
            yield "first.example\n"
            failed = True
            raise OSError("injected mid-read")

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        return FailingReader(handle) if os.fspath(name) == os.fspath(path) else handle

    monkeypatch.setattr("builtins.open", injected_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    assert failed


def test_enabled_in_place_truncation_during_iteration_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("".join("domain-{}.example\n".format(index) for index in range(10_000)), encoding="utf-8")
    real_open = open
    truncated = False

    class TruncatingReader:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __enter__(self) -> TruncatingReader:
            self._handle.__enter__()
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return bool(self._handle.__exit__(exc_type, exc, traceback))

        def fileno(self) -> int:
            return self._handle.fileno()

        def __iter__(self) -> Any:
            nonlocal truncated
            for line in self._handle:
                if not truncated:
                    os.truncate(path, 0)
                    truncated = True
                yield line

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        return TruncatingReader(handle) if os.fspath(name) == os.fspath(path) else handle

    monkeypatch.setattr("builtins.open", injected_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    assert truncated


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


def test_enabled_same_size_rewrite_with_restored_mtime_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_bytes(b"old.example\n")
    original = path.stat()
    real_open = open
    rewritten = False

    class RewritingReader:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __enter__(self) -> RewritingReader:
            self._handle.__enter__()
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return bool(self._handle.__exit__(exc_type, exc, traceback))

        def fileno(self) -> int:
            return self._handle.fileno()

        def __iter__(self) -> Any:
            nonlocal rewritten
            for line in self._handle:
                if not rewritten:
                    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
                    try:
                        os.write(fd, b"new.example\n")
                    finally:
                        os.close(fd)
                    os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
                    rewritten = True
                yield line

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        return RewritingReader(handle) if os.fspath(name) == os.fspath(path) else handle

    monkeypatch.setattr("builtins.open", injected_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    assert rewritten
    assert path.stat().st_mtime_ns == original.st_mtime_ns


def test_enabled_rewrite_after_iteration_with_stable_metadata_fails_closed(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_bytes(b"old.example\n")
    original = path.stat()
    real_fstat = P.os.fstat
    opened: os.stat_result | None = None
    rewritten = False

    def rewriting_fstat(fd: int) -> os.stat_result:
        nonlocal opened, rewritten
        current = real_fstat(fd)
        if current.st_ino != original.st_ino:
            return current
        if opened is None:
            opened = current
        elif not rewritten:
            rewrite_fd = os.open(path, os.O_WRONLY)
            try:
                os.pwrite(rewrite_fd, b"new.example\n", 0)
            finally:
                os.close(rewrite_fd)
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
            rewritten = True
        return opened

    monkeypatch.setattr(P.os, "fstat", rewriting_fstat)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    assert "TOP1M sidecar changed while reading" in capsys.readouterr().err
    assert rewritten
    assert path.stat().st_size == original.st_size
    assert path.stat().st_mtime_ns == original.st_mtime_ns


def test_enabled_unlink_during_iteration_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("old.example\n", encoding="utf-8")
    real_open = open
    unlinked = False

    class UnlinkingReader:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __enter__(self) -> UnlinkingReader:
            self._handle.__enter__()
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return bool(self._handle.__exit__(exc_type, exc, traceback))

        def fileno(self) -> int:
            return self._handle.fileno()

        def __iter__(self) -> Any:
            nonlocal unlinked
            for line in self._handle:
                if not unlinked:
                    path.unlink()
                    unlinked = True
                yield line

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        return UnlinkingReader(handle) if os.fspath(name) == os.fspath(path) else handle

    monkeypatch.setattr("builtins.open", injected_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    assert unlinked
