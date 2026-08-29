"""Issue #2717: release source archives are reproducible across host metadata."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests._workflow_steps import extract_before, extract_between

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


def _builder_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("issue2717_source_archive", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        (source / ".pyc" / "hidden.conf", b"exact pyc component"),
        (source / "cache.pyc" / "hidden.conf", b"pyc directory"),
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


def _run_builder(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
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


def _build(source: Path, output: Path) -> bytes:
    result = _run_builder(source, output)
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
        assert all(
            not any(part.endswith(".pyc") or part == "__pycache__" for part in Path(member.name).parts)
            for member in members
        )
        assert all(member.mtime == SOURCE_EPOCH for member in members)
        assert all((member.uid, member.gid, member.uname, member.gname) == (0, 0, "root", "root") for member in members)
        assert all(not member.pax_headers for member in members)
        assert all(member.mode == 0o755 for member in members if member.isdir() or member.name == EXEC_MEMBER)
        assert all(member.mode == 0o644 for member in members if member.isfile() and member.name != EXEC_MEMBER)
        safe_member = archive.extractfile(SAFE_MEMBER)
        assert safe_member is not None
        assert safe_member.read() == b"metacharacters stay data\n"
        executable_member = archive.extractfile(EXEC_MEMBER)
        assert executable_member is not None
        assert executable_member.read() == b"#!/bin/sh\nexit 0\n"
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


def test_source_root_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside-host-directory"
    outside.mkdir()
    (outside / "host-only.conf").write_text("host bytes\n", encoding="utf-8")
    source_link = tmp_path / "src"
    source_link.symlink_to(outside, target_is_directory=True)
    output = tmp_path / "archive.tar.gz"

    result = _run_builder(source_link, output)

    assert result.returncode != 0
    assert "source must be a real directory (not a symlink)" in result.stderr
    assert not output.exists()


def test_output_inside_source_is_rejected_without_clobbering_it(tmp_path: Path) -> None:
    source = _source_tree(tmp_path, mtime=1_600_000_000, ordinary_mode=0o644, executable_mode=0o755)
    output = source / "existing.tar.gz"
    output.write_bytes(b"existing archive")

    result = _run_builder(source, output)

    assert result.returncode != 0
    assert "output must be outside the source directory" in result.stderr
    assert output.read_bytes() == b"existing archive"


def test_case_alias_output_inside_source_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "Source"
    source.mkdir()
    (source / "ordinary.conf").write_text("ordinary\n", encoding="utf-8")
    alias = tmp_path / "source"
    if not alias.is_dir():
        alias.symlink_to(source, target_is_directory=True)
    assert os.path.samefile(source, alias)
    output = alias / "existing.tar.gz"
    output.write_bytes(b"existing archive")

    result = _run_builder(source, output)

    assert result.returncode != 0
    assert "output must be outside the source directory" in result.stderr
    assert output.read_bytes() == b"existing archive"
    assert not list(source.glob(f".{output.name}.*"))


def test_output_symlink_is_replaced_without_touching_its_target(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "ordinary.conf").write_text("ordinary\n", encoding="utf-8")
    target = tmp_path / "outside-target"
    target.write_bytes(b"outside bytes")
    output = tmp_path / "archive.tar.gz"
    output.symlink_to(target)

    result = _run_builder(source, output)

    assert result.returncode == 0, result.stderr
    assert target.read_bytes() == b"outside bytes"
    assert not output.is_symlink()
    with tarfile.open(output, "r:gz") as archive:
        assert [member.name for member in archive.getmembers()] == ["src", "src/ordinary.conf"]
    assert not list(tmp_path.glob(f".{output.name}.*"))


def test_unsupported_entry_failure_preserves_existing_output(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "ordinary.conf").write_text("ordinary\n", encoding="utf-8")
    os.mkfifo(source / "z-special")
    output = tmp_path / "existing.tar.gz"
    output.write_bytes(b"existing archive")

    result = _run_builder(source, output)

    assert result.returncode != 0
    assert "unsupported source entry" in result.stderr
    assert output.read_bytes() == b"existing archive"
    assert not list(tmp_path.glob(f".{output.name}.*"))


def test_socket_failure_is_contextual_and_preserves_existing_output() -> None:
    with tempfile.TemporaryDirectory(prefix="issue2717-", dir="/tmp") as directory:
        root = Path(directory)
        source = root / "src"
        source.mkdir()
        (source / "ordinary.conf").write_text("ordinary\n", encoding="utf-8")
        socket_path = source / "z.socket"
        output = root / "existing.tar.gz"
        output.write_bytes(b"existing archive")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix_socket:
            unix_socket.bind(str(socket_path))
            result = _run_builder(source, output)

        assert result.returncode != 0
        assert f"unsupported source entry: {socket_path}" in result.stderr
        assert "AttributeError" not in result.stderr
        assert output.read_bytes() == b"existing archive"
        assert not list(root.glob(f".{output.name}.*"))


@pytest.mark.parametrize("entry_kind", ["name", "link"])
def test_ustar_limits_fail_contextually_without_replacing_output(tmp_path: Path, entry_kind: str) -> None:
    source = tmp_path / "src"
    source.mkdir()
    if entry_kind == "name":
        (source / ("n" * 101)).write_bytes(b"too long")
    else:
        (source / "long-link").symlink_to("t" * 101)
    output = tmp_path / "existing.tar.gz"
    output.write_bytes(b"existing archive")

    result = _run_builder(source, output)

    assert result.returncode != 0
    assert "USTAR cannot encode source entry" in result.stderr
    assert "Traceback" not in result.stderr
    assert output.read_bytes() == b"existing archive"
    assert not list(tmp_path.glob(f".{output.name}.*"))


@pytest.mark.parametrize("entry_kind", ["file", "directory"])
def test_source_entry_swap_cannot_escape_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry_kind: str) -> None:
    source = tmp_path / "src"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = source / "victim"
    if entry_kind == "file":
        victim.write_bytes(b"PUBLIC")
        (outside / "secret").write_bytes(b"SECRET")
    else:
        victim.mkdir()
        (victim / "file").write_bytes(b"PUBLIC")
        (outside / "file").write_bytes(b"SECRET")
    output = tmp_path / "existing.tar.gz"
    output.write_bytes(b"existing archive")
    module = _builder_module()
    real_stat = module.os.stat
    swapped = False

    def racing_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal swapped
        result = real_stat(path, *args, **kwargs)
        if path == "victim" and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            if entry_kind == "file":
                victim.unlink()
                victim.symlink_to(outside / "secret")
            else:
                shutil.rmtree(victim)
                victim.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(module.os, "stat", racing_stat)
    with pytest.raises((OSError, module.ArchiveError)):
        module.build_archive(source, output, SOURCE_EPOCH)

    assert swapped
    assert output.read_bytes() == b"existing archive"
    assert not list(tmp_path.glob(f".{output.name}.*"))


def test_output_parent_retarget_uses_stable_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "ordinary.conf").write_text("ordinary\n", encoding="utf-8")
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    output_link = tmp_path / "output"
    output_link.symlink_to(first, target_is_directory=True)
    (first / "archive.tar.gz").write_bytes(b"old archive")
    (second / "archive.tar.gz").write_bytes(b"other archive")
    module = _builder_module()
    real_replace = module.os.replace

    def retargeting_replace(
        src: object,
        dst: object,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        output_link.unlink()
        output_link.symlink_to(second, target_is_directory=True)
        real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(module.os, "replace", retargeting_replace)
    module.build_archive(source, output_link / "archive.tar.gz", SOURCE_EPOCH)

    with tarfile.open(first / "archive.tar.gz", "r:gz") as archive:
        assert [member.name for member in archive.getmembers()] == ["src", "src/ordinary.conf"]
    assert (second / "archive.tar.gz").read_bytes() == b"other archive"
    assert not list(first.glob(".archive.tar.gz.*"))
    assert not list(second.glob(".archive.tar.gz.*"))


def test_resolved_output_directory_replacement_uses_opened_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "ordinary.conf").write_text("ordinary\n", encoding="utf-8")
    output_parent = tmp_path / "output"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "moved-output"
    output_parent.mkdir()
    replacement.mkdir()
    (output_parent / "archive.tar.gz").write_bytes(b"old archive")
    (replacement / "archive.tar.gz").write_bytes(b"other archive")
    module = _builder_module()
    real_gzip = module.gzip.GzipFile
    retargeted = False

    def retargeting_gzip(*args: Any, **kwargs: Any) -> Any:
        nonlocal retargeted
        if not retargeted:
            output_parent.rename(moved)
            output_parent.symlink_to(replacement, target_is_directory=True)
            retargeted = True
        return real_gzip(*args, **kwargs)

    monkeypatch.setattr(module.gzip, "GzipFile", retargeting_gzip)
    module.build_archive(source, output_parent / "archive.tar.gz", SOURCE_EPOCH)

    assert retargeted
    with tarfile.open(moved / "archive.tar.gz", "r:gz") as archive:
        assert [member.name for member in archive.getmembers()] == ["src", "src/ordinary.conf"]
    assert (replacement / "archive.tar.gz").read_bytes() == b"other archive"
    assert not list(moved.glob(".archive.tar.gz.*"))
    assert not list(replacement.glob(".archive.tar.gz.*"))


def _release_job() -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    return extract_between(workflow, "  release:", "\n  # ── 2b")


def _assert_archive_tool_pin_precedes_build(release_job: str) -> None:
    pin_name = "      - name: Pin source archive Python"
    archive_name = "      - name: Build source archive"
    pin_start = release_job.index(pin_name)
    archive_start = release_job.index(archive_name)
    pin_step = extract_before(release_job[pin_start:], "\n      - name:")

    assert "uses: actions/setup-python@v6" in pin_step
    assert 'python-version: "3.11.15"' in pin_step
    assert pin_start < archive_start, "the exact source-archive Python pin must precede the archive build"


def test_release_workflow_pins_and_uses_the_source_archive_builder() -> None:
    release_job = _release_job()
    archive_step = extract_between(release_job, "      - name: Build source archive", "\n      - name:")

    assert "runs-on: ubuntu-24.04" in release_job
    _assert_archive_tool_pin_precedes_build(release_job)
    assert "set -eu" in archive_step
    assert 'SOURCE_EPOCH="$(git show -s --format=%ct HEAD)"' in archive_step
    assert 'python3 "${GITHUB_WORKSPACE}/pfblockerng-src/scripts/build-source-archive.py"' in archive_step
    assert '--source src --output "$ARCHIVE" --epoch "$SOURCE_EPOCH"' in archive_step
    assert "tar -czf" not in archive_step


def test_moving_archive_python_pin_after_build_goes_red() -> None:
    release_job = _release_job()
    pin_start = release_job.index("      - name: Pin source archive Python")
    pin_end = release_job.index("\n      - name:", pin_start + 1)
    pin_step = release_job[pin_start:pin_end]
    without_pin = release_job[:pin_start] + release_job[pin_end:]
    archive_start = without_pin.index("      - name: Build source archive")
    archive_end = without_pin.index("\n      - name:", archive_start + 1)
    moved = without_pin[:archive_end] + "\n" + pin_step + without_pin[archive_end:]

    with pytest.raises(AssertionError, match="must precede"):
        _assert_archive_tool_pin_precedes_build(moved)
