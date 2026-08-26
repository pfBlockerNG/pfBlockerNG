"""Issue #2717: release source archives are reproducible across host metadata."""

from __future__ import annotations

import gzip
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-source-archive.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SOURCE_EPOCH = 1_700_000_000
SAFE_MEMBER = "src/usr/local/pkg/config file [test];$HOME.inc"
EXEC_MEMBER = "src/usr/local/bin/run [safe];$(touch escaped).sh"
EXPECTED_MEMBERS = [
    "src",
    "src/etc",
    "src/etc/ordinary.conf",
    "src/usr",
    "src/usr/local",
    "src/usr/local/bin",
    EXEC_MEMBER,
    "src/usr/local/pkg",
    SAFE_MEMBER,
]


def _source_tree(parent: Path, *, mtime: int, ordinary_mode: int, executable_mode: int) -> Path:
    source = parent / "source tree [fixture];$VAR" / "src"
    ordinary = source / "etc" / "ordinary.conf"
    safe = source / SAFE_MEMBER.removeprefix("src/")
    executable = source / EXEC_MEMBER.removeprefix("src/")
    for path, contents in (
        (ordinary, b"ordinary\n"),
        (safe, b"metacharacters stay data\n"),
        (executable, b"#!/bin/sh\nexit 0\n"),
        (source / "ignored.pyc", b"bytecode"),
        (source / "__pycache__" / "ignored.cpython-311.pyc", b"cache"),
        (source / "._Finder", b"AppleDouble"),
        (source / ".DS_Store", b"Finder metadata"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    ordinary.chmod(ordinary_mode)
    safe.chmod(ordinary_mode)
    executable.chmod(executable_mode)

    xattr = shutil.which("xattr")
    if xattr:
        subprocess.run(
            [xattr, "-w", "com.apple.issue2717", "host-only", str(ordinary)],
            check=True,
            capture_output=True,
        )

    for path in sorted(source.rglob("*"), reverse=True):
        os.utime(path, (mtime, mtime), follow_symlinks=False)
    os.utime(source, (mtime, mtime), follow_symlinks=False)
    return source


def _build(source: Path, output: Path) -> bytes:
    result = subprocess.run(
        [
            sys.executable,
            str(BUILDER),
            "--source",
            str(source),
            "--output",
            str(output),
            "--epoch",
            str(SOURCE_EPOCH),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return output.read_bytes()


def test_fresh_trees_produce_identical_normalized_archives(tmp_path: Path) -> None:
    first_source = _source_tree(tmp_path / "first", mtime=1_600_000_000, ordinary_mode=0o600, executable_mode=0o700)
    second_source = _source_tree(tmp_path / "second", mtime=1_800_000_000, ordinary_mode=0o666, executable_mode=0o777)

    first = _build(first_source, tmp_path / "first output [x];$VAR.tar.gz")
    second = _build(second_source, tmp_path / "second output [x];$VAR.tar.gz")

    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()
    assert first[:4] == b"\x1f\x8b\x08\x00"
    assert int.from_bytes(first[4:8], "little") == SOURCE_EPOCH
    assert first[8:10] == b"\x02\xff"

    tar_bytes = gzip.decompress(first)
    assert tar_bytes[257:265] == b"ustar\x0000"
    assert b"LIBARCHIVE.xattr" not in tar_bytes
    assert b"SCHILY.xattr" not in tar_bytes
    with tarfile.open(tmp_path / "first output [x];$VAR.tar.gz", "r:gz") as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == EXPECTED_MEMBERS
        assert all(member.mtime == SOURCE_EPOCH for member in members)
        assert all((member.uid, member.gid, member.uname, member.gname) == (0, 0, "root", "root") for member in members)
        assert all(not member.pax_headers for member in members)
        assert all(member.mode == 0o755 for member in members if member.isdir() or member.name == EXEC_MEMBER)
        assert all(member.mode == 0o644 for member in members if member.isfile() and member.name != EXEC_MEMBER)
        safe_member = archive.extractfile(SAFE_MEMBER)
        assert safe_member is not None
        assert safe_member.read() == b"metacharacters stay data\n"
    assert not (first_source.parent / "escaped").exists()


def test_source_change_changes_hash_and_member_content(tmp_path: Path) -> None:
    source = _source_tree(tmp_path, mtime=1_600_000_000, ordinary_mode=0o644, executable_mode=0o755)
    first_path = tmp_path / "before.tar.gz"
    second_path = tmp_path / "after.tar.gz"
    first = _build(source, first_path)

    changed = source / "etc" / "ordinary.conf"
    changed.write_bytes(b"changed source\n")
    os.utime(changed, (1_900_000_000, 1_900_000_000))
    second = _build(source, second_path)

    assert hashlib.sha256(first).digest() != hashlib.sha256(second).digest()
    with tarfile.open(second_path, "r:gz") as archive:
        changed_member = archive.extractfile("src/etc/ordinary.conf")
        assert changed_member is not None
        assert changed_member.read() == b"changed source\n"
        assert [member.name for member in archive.getmembers()] == EXPECTED_MEMBERS


def test_release_workflow_pins_and_uses_the_source_archive_builder() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    release_job = workflow.split("  release:", 1)[1].split("\n  # ── 2b", 1)[0]
    archive_step = release_job.split("      - name: Build source archive", 1)[1].split("\n      - name:", 1)[0]

    assert "runs-on: ubuntu-24.04" in release_job
    assert "uses: actions/setup-python@v6" in release_job
    assert 'python-version: "3.11.15"' in release_job
    assert "set -eu" in archive_step
    assert 'SOURCE_EPOCH="$(git show -s --format=%ct HEAD)"' in archive_step
    assert 'python3 "${GITHUB_WORKSPACE}/pfblockerng-src/scripts/build-source-archive.py"' in archive_step
    assert '--source src --output "$ARCHIVE" --epoch "$SOURCE_EPOCH"' in archive_step
    assert "tar -czf" not in archive_step
