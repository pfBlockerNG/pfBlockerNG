"""Regenerate one channel/varver catalogue directly from the .pkg files already
sitting on disk: the tree itself IS the state.

Scope: no ledger, no git, no network, no scratch tree, no backup/rollback. The
retired design staged a whole multi-catalogue ``Plan`` into a scratch tree and
moved it into place with a recoverable per-target swap; that machinery existed
to protect a durable ledger this repo no longer has. Under the corrected
architecture (see the design doc landed alongside this change) the release
job itself IS the transaction: it drops verified ``.pkg`` assets straight into
``site_root/<channel>/<varver>/``, calls ``regenerate_catalogue`` to rebuild
that one directory from whatever is now present, and commits ``site_root`` to
``main`` — a failed run simply never reaches that commit, so there is nothing
here to roll back.

stdlib-only, Python 3.11. The engine (``pfb_pkg.py`` + ``build-repo-portable.py``)
is the already-built ``publish_catalogues.Engine`` handed in by the caller — this
module never loads it a second time. Emission (manifest reading, ABI/collision
checks, the catalog descriptor) is entirely the engine's ``build_repo``; this
module adds only directory-scoped staging (working around ``build_repo``'s own
``*.pkg`` glob re-picking up its own ``data.pkg``/``packagesite.pkg`` on a second
pass — see ``regenerate_catalogue``), retention, and the multi-destination
byte/checksum/provenance identity post-condition ``build_repo`` itself has no
reason to know about.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from publish_catalogues import Engine


class CatalogueAssemblyError(Exception):
    """A validation/staging/post-condition failure this module itself detected.

    Engine errors (``BuildRepoError`` from a mixed/concrete ABI or a name/version
    collision, ``PkgError`` from a corrupt archive) propagate UNWRAPPED — this module
    never re-derives a check ``build_repo``/``_emit_catalog_from_paths`` already makes.
    """


# The closed set of channels this repo's catalogue tree ever serves. Not derived from
# publish_catalogues.py's destination tuples (those are per-run subsets a tagged/nightly
# intake may target); this is the full universe a (channel, varver) pair must belong to.
_KNOWN_CHANNELS: frozenset[str] = frozenset({"stable", "testing", "edge", "nightly"})

# NAME_MAX on every mainstream filesystem (ext4, APFS, HFS+, most FUSE ports) is 255
# bytes/codepoints. The engine's own _validate_catalog_name enforces character shape
# only (its regex has no length cap) — an accepted-but-oversized varver would still be
# an unusable directory component on the filesystem that ultimately serves it. This
# guard is this module's own; the engine has no reason to know about NAME_MAX.
_MAX_VARVER_LENGTH = 255

# The retained-generation count for a (channel, varver) with no special-cased override.
# A later ticket pinning an EOL'd varver to keep=1 only has to teach
# `retention_keep_count` a lookup — no caller reshaping.
DEFAULT_RETENTION_KEEP = 5


def _validate_channel(channel: str) -> None:
    if channel not in _KNOWN_CHANNELS:
        raise CatalogueAssemblyError(f"unknown channel {channel!r}: must be one of {sorted(_KNOWN_CHANNELS)!r}")


def _validate_varver(varver: str, engine: Engine) -> None:
    if len(varver) > _MAX_VARVER_LENGTH:
        raise CatalogueAssemblyError(f"varver exceeds {_MAX_VARVER_LENGTH} characters ({len(varver)}): {varver!r}")
    brp = engine.build_repo_portable
    try:
        brp._validate_catalog_name(varver, single_segment=True)
    except brp.BuildRepoError as exc:
        raise CatalogueAssemblyError(f"invalid varver {varver!r}: {exc}") from exc


def _catalogue_dir(site_root: Path, channel: str, varver: str, engine: Engine) -> Path:
    """Validate ``channel``/``varver`` and return the existing catalogue directory.

    Everything checked here runs BEFORE any staging/build work — a rejected
    (channel, varver) touches nothing beyond this existence check. A missing
    directory (including the case where ``site_root`` itself is not a directory —
    ``Path.is_dir()`` returns ``False`` rather than raising for any invalid
    ancestor) is a hard error: this module never creates the catalogue directory
    itself, the caller (the release job) owns dropping assets into place first.
    """
    _validate_channel(channel)
    _validate_varver(varver, engine)
    catalogue_dir = Path(site_root) / channel / varver
    if not catalogue_dir.is_dir():
        raise CatalogueAssemblyError(f"{channel}/{varver}: catalogue directory does not exist: {catalogue_dir}")
    return catalogue_dir


def _stage(paths: Sequence[Path], stage_dir: Path) -> None:
    """Link (or copy) ``paths`` into a fresh ``stage_dir`` under their own basenames.

    Every ``paths`` entry is already a uniquely-named ``.pkg`` file discovered by
    globbing ONE catalogue directory (``regenerate_catalogue``'s own pool
    collection), so a basename collision is structurally impossible here.
    Staging exists for a narrower reason: ``build_repo`` globs ``*.pkg`` in
    whatever directory it is given rather than accepting an explicit file list,
    so the only way to hand it a pool that excludes the catalog's own
    ``data.pkg``/``packagesite.pkg`` is to first copy that pool somewhere
    ``build_repo`` will re-glob and find nothing else. ``os.link`` preserves the
    source mtime for free (same inode); the ``shutil.copy2`` fallback preserves
    it explicitly when ``stage_dir`` is cross-device from the source.
    """
    stage_dir.mkdir(parents=True, exist_ok=True)
    for path in paths:
        target = stage_dir / path.name
        try:
            os.link(path, target)
        except OSError:
            shutil.copy2(path, target)


def regenerate_catalogue(site_root: str | Path, channel: str, varver: str, *, engine: Engine) -> None:
    """Rebuild ``site_root/channel/varver`` from whatever ``.pkg`` files already
    sit in that directory — canonical and dependency alike, no distinction made
    here (that distinction only matters to ``prune_retained``).

    The trap this function exists to dodge: ``build_repo`` globs ``*.pkg`` in its
    input directory, so a second regeneration pass over the SAME directory would
    otherwise swallow the ``data.pkg``/``packagesite.pkg`` the FIRST pass just
    wrote there and die trying to read a catalog-descriptor archive as if it were
    a libpkg package. Collecting the pool with ``build_repo_portable``'s own
    ``_CATALOG_PKG_FILES`` exclusion and staging ONLY that pool into a directory
    ``build_repo`` has never seen before is what makes regeneration idempotent.

    Writes directly into ``site_root`` (via ``build_repo``'s own
    ``catalog_name=f"{channel}/{varver}"`` routing) — no scratch tree, no backup,
    no rollback. ``build_repo``'s own ``_write_catalog_dir`` reads every staged
    source's bytes before wiping/rebuilding the destination, so a VALIDATION
    fault (a corrupt pool member, a mixed/concrete ABI, an unreadable archive)
    always raises before anything is deleted, leaving the directory untouched.

    That is not the only fault window, though: a write-back fault AFTER the
    wipe (mid-loop I/O error, disk full, process kill) can still leave the
    directory in a genuine third state — wiped and partially rebuilt, missing
    some of ``meta.conf``/``data.pkg``/``packagesite.pkg``/its ``.pkg`` files.
    This function does not contain that window by itself; it propagates
    whatever the engine raises, UNWRAPPED, exactly as for a validation fault.
    Containment is the CALLER's job: the caller must treat any exception from
    this call as fatal to the whole run and abort before staging, committing,
    or pushing anything — a half-written catalogue must never reach a commit.
    """
    site_root = Path(site_root)
    catalogue_dir = _catalogue_dir(site_root, channel, varver, engine)
    brp = engine.build_repo_portable
    pool = sorted(p for p in catalogue_dir.glob("*.pkg") if p.is_file() and p.name not in brp._CATALOG_PKG_FILES)
    if not pool:
        raise CatalogueAssemblyError(f"{channel}/{varver}: empty pool")

    with tempfile.TemporaryDirectory(prefix="catalogue-assembly-") as stage_str:
        stage_dir = Path(stage_str)
        _stage(pool, stage_dir)
        brp.build_repo(stage_dir, site_root, catalog_name=f"{channel}/{varver}")


def retention_keep_count(channel: str, varver: str) -> int:
    """Resolve the retained-generation count for one (channel, varver).

    Seam for a later ticket: pinning an EOL'd varver (one we have also EOL'd on
    our side) to keep=1 only has to teach this function a lookup — no caller
    reshaping. Today every (channel, varver) gets ``DEFAULT_RETENTION_KEEP``.
    """
    return DEFAULT_RETENTION_KEEP


def prune_retained(
    site_root: str | Path,
    channel: str,
    varver: str,
    *,
    engine: Engine,
    keep_count_for: Callable[[str, str], int] = retention_keep_count,
) -> tuple[Path, ...]:
    """Delete every CANONICAL ``.pkg`` in ``site_root/channel/varver`` beyond the
    newest ``keep_count_for(channel, varver)`` generations, newest-first by
    ``engine.pfb_pkg.pkg_version_sort_key``. Returns the deleted paths.

    Scoped to the canonical package only (manifest ``name`` ==
    ``pfb_pkg.CANONICAL_EMITTED_IDENTITY``): a dependency ``.pkg`` sitting in the
    same directory (e.g. ``py311-charset-normalizer-3.4.0.pkg``) has no
    independent retention count of its own and is never touched here, and
    neither is the catalog's own ``data.pkg``/``packagesite.pkg``. Call this
    BEFORE ``regenerate_catalogue`` so an evicted generation never reaches the
    rebuilt catalog; never mutates ``.pkg`` bytes, only removes whole files.
    """
    catalogue_dir = _catalogue_dir(Path(site_root), channel, varver, engine)
    keep = keep_count_for(channel, varver)
    if type(keep) is not int or keep < 1:
        raise CatalogueAssemblyError(f"retention keep-count for {channel}/{varver} must be a positive integer")

    pfb_pkg = engine.pfb_pkg
    brp = engine.build_repo_portable
    canonical: list[tuple[object, Path]] = []
    for path in sorted(catalogue_dir.glob("*.pkg")):
        if not path.is_file() or path.name in brp._CATALOG_PKG_FILES:
            continue
        manifest = pfb_pkg.read_compact_manifest(path)
        if manifest.get("name") != pfb_pkg.CANONICAL_EMITTED_IDENTITY:
            continue
        canonical.append((pfb_pkg.pkg_version_sort_key(manifest["version"]), path))

    canonical.sort(key=lambda item: item[0], reverse=True)
    evicted = tuple(path for _, path in canonical[keep:])
    for path in evicted:
        path.unlink()
    return evicted


def verify_multi_destination_identity(
    engine: Engine,
    site_root: str | Path,
    source_index: Mapping[Path, Sequence[tuple[str, str]]],
) -> None:
    """Hard-fail if a fanned-out source's emitted bytes/checksum/record ever diverge.

    ``source_index`` maps a resolved source ``.pkg`` path to every
    ``(channel, varver)`` catalogue it was dropped into (a caller's own
    bookkeeping — this module has no ledger to derive it from). A source
    appearing at only one destination is not a fan-out and is skipped. Every
    listed destination is expected to already be a REGENERATED catalogue under
    ``site_root`` — this reads the real, published directories, not a scratch
    tree; there is no scratch tree in this design.

    Every multi-destination source is dropped as the SAME file into every one of
    its destinations, and ``build_repo`` writes staged bytes verbatim — so a
    divergence here means something upstream of this check went wrong (wrong
    file dropped, a canonical-name collision overwritten by the wrong package,
    ...). This is the ticket's byte/checksum/provenance identity requirement as
    an executable post-condition, not only a test assertion.
    """
    site_root = Path(site_root)
    pfb_pkg = engine.pfb_pkg
    brp = engine.build_repo_portable
    for source_path, destinations in source_index.items():
        if len(destinations) < 2:
            continue
        manifest = pfb_pkg.read_compact_manifest(source_path)
        canonical_name = f"{manifest['name']}-{manifest['version']}.pkg"

        baseline: tuple[bytes, str, object] | None = None
        for channel, varver in destinations:
            dest_path = site_root / channel / varver / canonical_name
            if not dest_path.is_file():
                raise CatalogueAssemblyError(
                    f"{canonical_name}: missing at destination {channel}/{varver}, "
                    f"expected from fan-out of {source_path}"
                )
            data = dest_path.read_bytes()
            sha256 = hashlib.sha256(data).hexdigest()
            dest_manifest = pfb_pkg.read_compact_manifest(dest_path)
            record = brp._canonical_build_record(dest_path, dest_manifest)
            current = (data, sha256, record)
            if baseline is None:
                baseline = current
                continue
            if current != baseline:
                raise CatalogueAssemblyError(
                    f"{canonical_name}: multi-destination identity violation across "
                    f"{destinations!r} — bytes/sha256/provenance record diverged"
                )
