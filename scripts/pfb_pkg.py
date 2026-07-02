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
import re
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


# --------------------------------------------------------------------------- #
# Version sort key — shared by build-repo-portable.py (release/nightly retention)
# and gen_landing.py (the landing page's "newest build" picks).
# --------------------------------------------------------------------------- #

# FreeBSD pkg ranks a prerelease stage BELOW the bare release, and alpha < beta <
# rc between themselves (see scripts/release-version.sh, the tag scheme's single
# source of truth: vX.Y.Z(.alpha|beta|rc.N)?). A version with no stage keyword —
# a genuine stable release, a bare edition version like "2.8.1", or a nightly's
# all-numeric "<target>.YYYYMMDD.N" — ranks as RELEASE (highest).
_STAGE_RANK = {"alpha": 0, "beta": 1, "rc": 2}
_RELEASE_RANK = 3


def pkg_version_sort_key(version: str) -> list[int]:
    """Monotone sort key for a pfBlockerNG pkg VERSION string.

    Splits on ``.``/``_``/``,`` like a plain numeric-run compare, but a component
    matching one of the FreeBSD-pkg prerelease stage keywords (``alpha``/``beta``/
    ``rc``) is pulled OUT of the numeric base and turned into a stage rank + stage
    number, instead of being folded away. The historical bug this fixes: a plain
    ``re.findall(r"\\d+", v)``-style key drops the keyword entirely, so
    ``4.0.0.alpha.1`` / ``.beta.1`` / ``.rc.1`` all collapsed to the SAME key, and
    the bare ``4.0.0`` release (whose key was a *shorter* list) sorted BELOW every
    prerelease. This key instead reproduces pkg's real ordering::

        4.0.0.alpha.1 < 4.0.0.alpha.2 < 4.0.0.beta.1 < 4.0.0.rc.1 < 4.0.0

    A version with no stage keyword (a nightly's all-numeric
    ``<target>.YYYYMMDD.N``, a bare ``pfsense_version`` like ``2.8.1``, or a
    genuine stable release) keeps its full numeric run as the base and ranks as
    RELEASE — unchanged ordering vs. the historical key for that case. Any
    non-numeric, non-stage-keyword component maps to ``0`` (same fallback the
    historical key used), so a malformed component never raises.
    """
    parts = re.split(r"[._,]", version)
    base: list[int] = []
    stage_rank = _RELEASE_RANK
    stage_num = 0
    i = 0
    while i < len(parts):
        part = parts[i]
        rank = _STAGE_RANK.get(part.lower())
        if rank is not None:
            stage_rank = rank
            if i + 1 < len(parts) and parts[i + 1].isdigit():
                stage_num = int(parts[i + 1])
                i += 2
            else:
                i += 1
            continue
        base.append(int(part) if part.isdigit() else 0)
        i += 1
    return [*base, stage_rank, stage_num]
