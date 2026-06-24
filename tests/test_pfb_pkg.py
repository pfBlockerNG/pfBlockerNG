"""Tests for scripts/pfb_pkg.py — the shared libpkg .pkg manifest reader.

Covers both branches of the zstd decoder (module fast-path vs binary fallback vs
neither) and every error path of read_compact_manifest, so the helper both
build-repo-portable.py and gen_landing.py now depend on is pinned in one place.
"""

from __future__ import annotations

import builtins
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pfb_pkg
import pytest


def _zstd_frame(data: bytes) -> bytes:
    """Compress with whatever zstd encoder is available (mirrors the decoder fallback)."""
    try:
        import zstandard

        return zstandard.ZstdCompressor().compress(data)
    except ImportError:
        zstd = shutil.which("zstd")
        if not zstd:  # pragma: no cover - CI/dev always has one encoder
            pytest.skip("no zstd encoder (binary or module) available to build the fixture")
        return subprocess.run([zstd, "-q", "-c"], input=data, stdout=subprocess.PIPE, check=True).stdout


def _tar_with(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, payload in members.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(payload)
            tf.addfile(ti, io.BytesIO(payload))
    return buf.getvalue()


def test_zstd_decompress_roundtrip() -> None:
    """A real zstd frame decompresses back to the original bytes."""
    original = b"the quick brown fox " * 50
    assert pfb_pkg.zstd_decompress(_zstd_frame(original)) == original


def test_zstd_decompress_passes_through_non_zstd() -> None:
    """Non-zstd input is returned verbatim (an already-uncompressed tar — defensive)."""
    plain = b"not a zstd frame"
    assert pfb_pkg.zstd_decompress(plain) == plain


def test_zstd_decompress_errors_when_no_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    """With neither the zstandard module nor the zstd binary, a clear PkgError naming both
    remedies — not a bare ImportError/OSError. Build the fixture while an encoder exists,
    then remove BOTH decoders."""
    frame = _zstd_frame(b"payload")
    real_import = builtins.__import__

    def _no_zstandard(name: str, *a: object, **k: object) -> object:
        if name == "zstandard":
            raise ImportError("forced: zstandard unavailable")
        return real_import(name, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _no_zstandard)
    monkeypatch.setattr(pfb_pkg.shutil, "which", lambda _name: None)
    with pytest.raises(pfb_pkg.PkgError, match="zstd"):
        pfb_pkg.zstd_decompress(frame)


def test_read_compact_manifest_roundtrip(tmp_path: Path) -> None:
    """The +COMPACT_MANIFEST (first tar member) is returned as a dict."""
    man = {"name": "pfSense-pkg-pfBlockerNG-devel", "version": "9.9.9", "abi": "FreeBSD:16:amd64"}
    pkg = tmp_path / "x.pkg"
    pkg.write_bytes(_zstd_frame(_tar_with({"+COMPACT_MANIFEST": json.dumps(man).encode()})))
    assert pfb_pkg.read_compact_manifest(pkg) == man


def test_read_compact_manifest_missing_member(tmp_path: Path) -> None:
    """A .pkg without a +COMPACT_MANIFEST member is a clear PkgError, not a KeyError."""
    pkg = tmp_path / "x.pkg"
    pkg.write_bytes(_zstd_frame(_tar_with({"other": b"x"})))
    with pytest.raises(pfb_pkg.PkgError, match="COMPACT_MANIFEST"):
        pfb_pkg.read_compact_manifest(pkg)


def test_read_compact_manifest_invalid_json(tmp_path: Path) -> None:
    """A non-JSON manifest is a clear PkgError, not a bare ValueError."""
    pkg = tmp_path / "x.pkg"
    pkg.write_bytes(_zstd_frame(_tar_with({"+COMPACT_MANIFEST": b"{not json"})))
    with pytest.raises(pfb_pkg.PkgError, match="JSON"):
        pfb_pkg.read_compact_manifest(pkg)


def test_read_compact_manifest_non_object(tmp_path: Path) -> None:
    """Valid JSON that is not an object (e.g. a list) is a clear PkgError."""
    pkg = tmp_path / "x.pkg"
    pkg.write_bytes(_zstd_frame(_tar_with({"+COMPACT_MANIFEST": b"[1, 2, 3]"})))
    with pytest.raises(pfb_pkg.PkgError, match="not an object"):
        pfb_pkg.read_compact_manifest(pkg)
