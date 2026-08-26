"""Regression tests for dependency-package reproducibility (issue #2716)."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "build-dep-pkg-portable.py"
SPEC = importlib.util.spec_from_file_location("issue2716_build_dep_pkg_portable", TOOL)
assert SPEC is not None and SPEC.loader is not None
bdp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bdp
SPEC.loader.exec_module(bdp)


def _wheel(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("demo/__init__.py", b"__version__ = '1.0'\n")
        archive.writestr("demo-1.0.dist-info/METADATA", b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
        archive.writestr(
            "demo-1.0.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nGenerator: bdist_wheel (0.45.1)\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )


def _args(out_dir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        ports=str(out_dir.parent / "ports"),
        port="textproc/py-demo",
        py_flavor="py311",
        freebsd_major="15",
        python_dep_version="0",
        ports_sha="d" * 40,
        source_date_epoch=1_700_000_000,
        out_dir=str(out_dir),
        compression="zstd",
    )


def test_fresh_builds_have_identical_hashes_under_hostile_ambient_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pinned inputs beat fresh roots, file mtimes, timezone, locale, and umask."""
    port = bdp.PortFacts(
        portname="demo",
        portversion="1.0",
        distname="demo-1.0",
        comment="demo",
        maintainer="maintainer@example.invalid",
        www="https://example.invalid/demo",
        license="MIT",
        categories=["textproc", "python"],
        master_sites=["https://example.invalid/"],
    )
    monkeypatch.setattr(bdp, "read_port", lambda _path: port)
    monkeypatch.setattr(bdp, "read_distinfo", lambda _path, _name: ("a" * 64, 123))
    monkeypatch.setattr(bdp, "read_descr", lambda _path, fallback: fallback)
    monkeypatch.setattr(bdp, "validate_build_toolchain", lambda: bdp.build_toolchain_identity())
    monkeypatch.setattr(bdp.bpp, "_attest_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        bdp.bpp,
        "_snapshot_checkout",
        lambda checkout, _sha, _dest, payload_root=None: checkout,
    )
    monkeypatch.setattr(
        bdp,
        "fetch_verified_sdist",
        lambda _port, dest, **_kwargs: dest / "demo-1.0.tar.gz",
    )

    def fake_build_wheel(_sdist: Path, work_dir: Path, *, source_date_epoch: int) -> Path:
        assert source_date_epoch == 1_700_000_000
        wheel = work_dir / "wheel" / "demo-1.0-py3-none-any.whl"
        _wheel(wheel)
        return wheel

    monkeypatch.setattr(bdp, "build_wheel", fake_build_wheel)
    real_stage = bdp.stage_wheel
    staged_mtime = 1_600_000_000

    def hostile_stage(wheel: Path, stage_dir: Path, py_dotted: str) -> tuple[list[Path], list[Path]]:
        site_files, script_files = real_stage(wheel, stage_dir, py_dotted)
        for path in site_files + script_files:
            os.utime(path, (staged_mtime, staged_mtime))
        return site_files, script_files

    monkeypatch.setattr(bdp, "stage_wheel", hostile_stage)
    first = bdp.build_dep_pkg(_args(tmp_path / "fresh root [a]" / "out"))

    staged_mtime = 1_800_000_000
    monkeypatch.setenv("TZ", "Pacific/Kiritimati")
    monkeypatch.setenv("LC_ALL", "C")
    previous_umask = os.umask(0o077)
    try:
        second = bdp.build_dep_pkg(_args(tmp_path / "fresh root ; $(b)" / "out"))
    finally:
        os.umask(previous_umask)

    first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
    second_hash = hashlib.sha256(second.read_bytes()).hexdigest()
    assert first_hash == second_hash, f"fresh builds differ: {first_hash} != {second_hash}"


def test_ambient_toolchain_drift_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host interpreter cannot silently replace the pinned build contract."""
    monkeypatch.setattr(
        bdp,
        "_installed_build_toolchain",
        lambda: {"python": "3.14.7", "pip": "26.2.1", "setuptools": "75.6.0", "wheel": "0.45.1"},
        raising=False,
    )

    with pytest.raises(bdp.DepPkgError, match=r"python.*3\.11\.15"):
        bdp.validate_build_toolchain()
