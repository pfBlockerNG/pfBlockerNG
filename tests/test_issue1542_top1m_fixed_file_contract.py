from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P
from tests.test_issue1542_top1m_fixed_file import _manifest


def test_enabled_fifo_fixed_file_fails_closed(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    os.mkfifo(tmp_path / "pfb_py_top1m.txt")

    assert P.dnsbl_build_from_manifest(str(manifest)) is None


@pytest.mark.parametrize("nofollow", [None, 0])
def test_enabled_without_nofollow_support_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, nofollow: int | None
) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_text("stable.example\n", encoding="utf-8")
    monkeypatch.setattr(P.os, "O_NOFOLLOW", nofollow)

    assert P.dnsbl_build_from_manifest(str(manifest)) is None


def test_enabled_multibyte_final_line_without_newline_consumes_exact_bytes(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_bytes("éxample.test\nlast.example".encode())

    result = P.dnsbl_build_from_manifest(str(manifest))
    assert result is not None
    assert set(result.white_db) == {"last.example"}


def test_enabled_uses_bounded_prepass_and_streaming_iterator(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("".join("domain-{}.example\n".format(index) for index in range(10_000)), encoding="utf-8")
    real_open = open
    real_read = P.os.read
    iterated = False
    read_sizes: list[int] = []

    class IteratorOnlyReader:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __enter__(self) -> IteratorOnlyReader:
            self._handle.__enter__()
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return bool(self._handle.__exit__(exc_type, exc, traceback))

        def fileno(self) -> int:
            return self._handle.fileno()

        def __iter__(self) -> Any:
            nonlocal iterated
            iterated = True
            yield from self._handle

        def read(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("TOP1M reader must not read the whole file")

        def readlines(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("TOP1M reader must not materialize all lines")

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        return IteratorOnlyReader(handle) if os.fspath(name) == os.fspath(path) else handle

    def bounded_read(fd: int, size: int) -> bytes:
        read_sizes.append(size)
        return real_read(fd, size)

    monkeypatch.setattr("builtins.open", injected_open)
    monkeypatch.setattr(P.os, "read", bounded_read)
    result = P.dnsbl_build_from_manifest(str(manifest))
    assert iterated
    assert len(read_sizes) > 1
    assert max(read_sizes) == 64 * 1024
    assert result is not None
    assert len(result.white_db) == 10_000


def test_enabled_prehash_read_error_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_bytes(b"domain.example\n" * 10_000)
    real_read = P.os.read
    reads = 0

    def failing_read(fd: int, size: int) -> bytes:
        nonlocal reads
        reads += 1
        if reads == 2:
            raise OSError("injected prehash read failure")
        return real_read(fd, size)

    monkeypatch.setattr(P.os, "read", failing_read)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    assert reads == 2
