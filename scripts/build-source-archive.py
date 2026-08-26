#!/usr/bin/env python3
"""Build the deterministic production source archive attached to releases."""

from __future__ import annotations

import argparse
import gzip
import os
import secrets
import stat
import tarfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

_MAX_GZIP_EPOCH = (1 << 32) - 1
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_TEMPORARY_ATTEMPTS = 100


class ArchiveError(Exception):
    """Source archive cannot be built without violating its fixed contract."""


def _epoch(value: str) -> int:
    try:
        epoch = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if not 0 <= epoch <= _MAX_GZIP_EPOCH:
        raise argparse.ArgumentTypeError(f"must be between 0 and {_MAX_GZIP_EPOCH}")
    return epoch


def _excluded(relative: Path) -> bool:
    return any(
        part.endswith(".pyc") or part in {"__pycache__", ".DS_Store"} or part.startswith("._")
        for part in relative.parts
    )


@contextmanager
def _open_directory(path: str | Path, *, dir_fd: int | None = None) -> Generator[int, None, None]:
    opened = os.open(path, _DIRECTORY_FLAGS, dir_fd=dir_fd)
    try:
        yield opened
    finally:
        os.close(opened)


def _same_directory(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _directory_is_within(directory_fd: int, ancestor_fd: int) -> bool:
    ancestor = os.fstat(ancestor_fd)
    current_fd = os.dup(directory_fd)
    try:
        while True:
            current = os.fstat(current_fd)
            if _same_directory(current, ancestor):
                return True
            parent_fd = os.open("..", _DIRECTORY_FLAGS, dir_fd=current_fd)
            parent = os.fstat(parent_fd)
            if _same_directory(current, parent):
                os.close(parent_fd)
                return False
            os.close(current_fd)
            current_fd = parent_fd
    finally:
        os.close(current_fd)


def _create_temporary(directory_fd: int, output_name: str) -> tuple[str, BinaryIO]:
    for _ in range(_TEMPORARY_ATTEMPTS):
        name = f".{output_name}.{secrets.token_hex(12)}"
        try:
            opened = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError:
            continue
        try:
            return name, os.fdopen(opened, "wb")
        except OSError:
            os.close(opened)
            os.unlink(name, dir_fd=directory_fd)
            raise
    raise ArchiveError("could not create a unique temporary archive")


def _unchanged(expected: os.stat_result, actual: os.stat_result, path: Path) -> None:
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(expected, field) != getattr(actual, field) for field in fields):
        raise ArchiveError(f"source entry changed while archiving: {path}")


def _tar_info(
    relative: Path,
    snapshot: os.stat_result,
    epoch: int,
    *,
    entry_type: bytes,
    linkname: str = "",
) -> tarfile.TarInfo:
    archive_name = "src" if relative == Path() else f"src/{relative.as_posix()}"
    info = tarfile.TarInfo(archive_name)
    info.type = entry_type
    info.linkname = linkname
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = epoch
    if entry_type == tarfile.DIRTYPE:
        info.mode = 0o755
    elif entry_type == tarfile.SYMTYPE:
        info.mode = 0o777
    else:
        info.mode = 0o755 if snapshot.st_mode & 0o111 else 0o644
        info.size = snapshot.st_size
    return info


def _add_member(
    archive: tarfile.TarFile,
    info: tarfile.TarInfo,
    path: Path,
    contents: BinaryIO | None = None,
) -> None:
    try:
        archive.addfile(info, contents)
    except ValueError as error:
        raise ArchiveError(f"USTAR cannot encode source entry {path}: {error}") from error


def _archive_directory(
    archive: tarfile.TarFile,
    directory_fd: int,
    relative: Path,
    snapshot: os.stat_result,
    epoch: int,
    source_path: Path,
) -> int:
    directory_path = source_path / relative
    _add_member(archive, _tar_info(relative, snapshot, epoch, entry_type=tarfile.DIRTYPE), directory_path)
    count = 1
    with os.scandir(directory_fd) as entries:
        names = sorted(entry.name for entry in entries)

    for name in names:
        child_relative = relative / name
        if _excluded(child_relative):
            continue
        display_path = source_path / child_relative
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            with _open_directory(name, dir_fd=directory_fd) as child_fd:
                opened = os.fstat(child_fd)
                _unchanged(before, opened, display_path)
                count += _archive_directory(archive, child_fd, child_relative, opened, epoch, source_path)
        elif stat.S_ISREG(before.st_mode):
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                opened = os.fstat(file_fd)
                _unchanged(before, opened, display_path)
                info = _tar_info(child_relative, opened, epoch, entry_type=tarfile.REGTYPE)
                with os.fdopen(file_fd, "rb", closefd=False) as contents:
                    _add_member(archive, info, display_path, contents)
                _unchanged(opened, os.fstat(file_fd), display_path)
                count += 1
            finally:
                os.close(file_fd)
        elif stat.S_ISLNK(before.st_mode):
            linkname = os.readlink(name, dir_fd=directory_fd)
            _unchanged(before, os.stat(name, dir_fd=directory_fd, follow_symlinks=False), display_path)
            info = _tar_info(child_relative, before, epoch, entry_type=tarfile.SYMTYPE, linkname=linkname)
            _add_member(archive, info, display_path)
            count += 1
        else:
            raise ArchiveError(f"unsupported source entry: {display_path}")

    _unchanged(snapshot, os.fstat(directory_fd), directory_path)
    return count


def build_archive(source: Path, output: Path, epoch: int) -> None:
    source_snapshot = os.stat(source, follow_symlinks=False)
    if not stat.S_ISDIR(source_snapshot.st_mode):
        raise ArchiveError(f"source must be a real directory (not a symlink): {source}")
    output_parent = output.parent.resolve(strict=True)
    with (
        _open_directory(source) as source_fd,
        _open_directory(output_parent) as output_fd,
    ):
        opened_source = os.fstat(source_fd)
        _unchanged(source_snapshot, opened_source, Path("src"))
        if _directory_is_within(output_fd, source_fd):
            raise ArchiveError(f"output must be outside the source directory: {output}")
        temporary_name, temporary = _create_temporary(output_fd, output.name)
        try:
            with (
                temporary as raw_archive,
                gzip.GzipFile(
                    filename="",
                    mode="wb",
                    compresslevel=9,
                    fileobj=raw_archive,
                    mtime=epoch,
                ) as compressed,
                tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
            ):
                count = _archive_directory(archive, source_fd, Path(), opened_source, epoch, source)
            os.replace(
                temporary_name,
                output.name,
                src_dir_fd=output_fd,
                dst_dir_fd=output_fd,
            )
        finally:
            try:
                os.unlink(temporary_name, dir_fd=output_fd)
            except FileNotFoundError:
                pass

    print(f"built {output} from {count} normalized entries at source epoch {epoch}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="production src/ directory")
    parser.add_argument("--output", required=True, type=Path, help="output .tar.gz path")
    parser.add_argument("--epoch", required=True, type=_epoch, help="source commit timestamp")
    args = parser.parse_args()
    try:
        build_archive(args.source, args.output, args.epoch)
    except (ArchiveError, OSError, tarfile.TarError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
