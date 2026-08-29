from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P
from tests.test_issue1542_top1m_fixed_file import _manifest


def test_enabled_mutation_of_unread_bytes_before_atomic_replace_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    replacement = tmp_path / "replacement.txt"
    final_line = b"old.example\n"
    body = b"first.example\n" + (b"padding.example\n" * 100_000) + final_line
    path.write_bytes(body)
    replacement.write_text("replacement.example\n", encoding="utf-8")
    original = path.stat()
    final_offset = len(body) - len(final_line)
    real_open = open
    mutated = False

    class MutatingReader:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __enter__(self) -> MutatingReader:
            self._handle.__enter__()
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return bool(self._handle.__exit__(exc_type, exc, traceback))

        def fileno(self) -> int:
            return self._handle.fileno()

        def read(self, *args: Any, **kwargs: Any) -> Any:
            return self._handle.read(*args, **kwargs)

        def seek(self, *args: Any, **kwargs: Any) -> Any:
            return self._handle.seek(*args, **kwargs)

        def __iter__(self) -> Any:
            nonlocal mutated
            for index, line in enumerate(self._handle):
                yield line
                if index == 0:
                    fd = os.open(path, os.O_WRONLY)
                    try:
                        assert os.pwrite(fd, b"new.example\n", final_offset) == len(final_line)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
                    os.replace(replacement, path)
                    mutated = True

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        return MutatingReader(handle) if os.fspath(name) == os.fspath(path) else handle

    monkeypatch.setattr("builtins.open", injected_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    assert mutated
    assert path.read_text(encoding="utf-8") == "replacement.example\n"
