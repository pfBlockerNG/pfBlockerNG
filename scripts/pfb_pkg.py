"""Shared libpkg .pkg helpers — zstd framing + the +COMPACT_MANIFEST reader.

A libpkg .pkg is a zstd-compressed tar whose first member is +COMPACT_MANIFEST
(the package metadata). Both scripts/build-repo-portable.py and
scripts/gen_landing.py read those manifests off-FreeBSD; this module is the one
copy of that logic. Both run as `python3 .../scripts/<tool>.py`, so the script's
directory (scripts/) is on sys.path and `import pfb_pkg` resolves here.

stdlib-only, with an optional fast path: the `zstandard` module if installed,
else the `zstd` binary.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class PkgError(Exception):
    """A .pkg could not be read (no zstd decoder available, or malformed)."""


def zstd_decompress(data: bytes) -> bytes:
    """Decompress a zstd frame. Non-zstd input is returned as-is (an already
    uncompressed tar — defensive). Prefers the `zstandard` module, falls back to
    the `zstd` binary; raises PkgError if neither is available."""
    if data[:4] != ZSTD_MAGIC:
        return data
    try:
        import zstandard

        return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    except ImportError:
        zstd = shutil.which("zstd")
        if not zstd:
            raise PkgError(
                "a .pkg is zstd-compressed; install the `zstd` binary or the python `zstandard` module"
            ) from None
        return subprocess.run([zstd, "-dc"], input=data, stdout=subprocess.PIPE, check=True).stdout


def read_compact_manifest(pkg_path: str | Path) -> dict:
    """Return the +COMPACT_MANIFEST JSON object of a .pkg (pure Python, no libpkg)."""
    pkg_path = Path(pkg_path)
    tar_bytes = zstd_decompress(pkg_path.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        try:
            member = tf.extractfile("+COMPACT_MANIFEST")
        except KeyError:
            member = None
        if member is None:
            raise PkgError(f"{pkg_path.name}: no +COMPACT_MANIFEST member — not a libpkg .pkg?")
        data = member.read()
    try:
        obj = json.loads(data)
    except ValueError as e:
        raise PkgError(f"{pkg_path.name}: +COMPACT_MANIFEST is not valid JSON/UCL: {e}") from None
    if not isinstance(obj, dict):
        raise PkgError(f"{pkg_path.name}: +COMPACT_MANIFEST is not an object")
    return obj
