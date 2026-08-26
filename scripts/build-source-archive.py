#!/usr/bin/env python3
"""Build the deterministic production source archive attached to releases."""

from __future__ import annotations

import argparse
import gzip
import tarfile
from pathlib import Path

_MAX_GZIP_EPOCH = (1 << 32) - 1


def _epoch(value: str) -> int:
    try:
        epoch = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if not 0 <= epoch <= _MAX_GZIP_EPOCH:
        raise argparse.ArgumentTypeError(f"must be between 0 and {_MAX_GZIP_EPOCH}")
    return epoch


def _excluded(relative: Path) -> bool:
    return (
        relative.suffix == ".pyc"
        or relative.name == ".DS_Store"
        or any(part == "__pycache__" or part.startswith("._") for part in relative.parts)
    )


def build_archive(source: Path, output: Path, epoch: int) -> None:
    if not source.is_dir():
        raise ValueError(f"source directory does not exist: {source}")

    paths = [source]
    paths.extend(
        sorted(
            (path for path in source.rglob("*") if not _excluded(path.relative_to(source))),
            key=lambda path: path.relative_to(source).as_posix(),
        )
    )

    with (
        output.open("wb") as raw_archive,
        gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw_archive, mtime=epoch) as compressed,
        tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for path in paths:
            relative = path.relative_to(source)
            archive_name = "src" if relative == Path() else f"src/{relative.as_posix()}"
            info = archive.gettarinfo(str(path), arcname=archive_name)
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
                raise ValueError(f"unsupported source entry: {path}")

    print(f"built {output} from {len(paths)} normalized entries at source epoch {epoch}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="production src/ directory")
    parser.add_argument("--output", required=True, type=Path, help="output .tar.gz path")
    parser.add_argument("--epoch", required=True, type=_epoch, help="source commit timestamp")
    args = parser.parse_args()
    try:
        build_archive(args.source, args.output, args.epoch)
    except (OSError, tarfile.TarError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
