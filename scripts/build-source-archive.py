#!/usr/bin/env python3
"""Build the deterministic production source archive attached to releases."""

from __future__ import annotations

import argparse
import gzip
import os
import tarfile
import tempfile
from pathlib import Path

_MAX_GZIP_EPOCH = (1 << 32) - 1


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


def build_archive(source: Path, output: Path, epoch: int) -> None:
    if source.is_symlink() or not source.is_dir():
        raise ArchiveError(f"source must be a real directory (not a symlink): {source}")
    output_location = output.parent.resolve() / output.name
    if output_location.is_relative_to(source.resolve()):
        raise ArchiveError(f"output must be outside the source directory: {output}")

    paths = [source]
    paths.extend(
        sorted(
            (path for path in source.rglob("*") if not _excluded(path.relative_to(source))),
            key=lambda path: path.relative_to(source).as_posix(),
        )
    )

    temporary = tempfile.NamedTemporaryFile(mode="wb", prefix=f".{output.name}.", dir=output.parent, delete=False)
    temporary_path = Path(temporary.name)
    try:
        with (
            temporary as raw_archive,
            gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw_archive, mtime=epoch) as compressed,
            tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
        ):
            for path in paths:
                relative = path.relative_to(source)
                archive_name = "src" if relative == Path() else f"src/{relative.as_posix()}"
                info = archive.gettarinfo(str(path), arcname=archive_name)
                if info is None:
                    raise ArchiveError(f"unsupported source entry: {path}")
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = epoch
                info.pax_headers = {}
                if info.isdir():
                    info.mode = 0o755
                    archive.addfile(info)
                elif info.isfile():
                    info.mode = 0o755 if info.mode & 0o111 else 0o644
                    with path.open("rb") as contents:
                        archive.addfile(info, contents)
                elif info.issym():
                    info.mode = 0o777
                    archive.addfile(info)
                else:
                    raise ArchiveError(f"unsupported source entry: {path}")
        os.replace(temporary_path, output)
    finally:
        temporary_path.unlink(missing_ok=True)

    print(f"built {output} from {len(paths)} normalized entries at source epoch {epoch}")


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
