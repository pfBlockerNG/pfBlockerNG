"""Tagged-release publisher — CLI entry point (issue #2146 step R2).

Wires the already-gated S1/S3 pieces into a working publisher: parse the tagged-run
intake, verify every downloaded ``.pkg`` asset (``publish_catalogues.verify_asset`` /
``verify_run``), then for each destination channel x each varver this run's canonical
assets target, drop the verified assets into ``<pkg>/docs/<channel>/<varver>/``, prune
per retention, and regenerate that catalogue (``catalogue_assembly.prune_retained`` /
``regenerate_catalogue``) — finally checking the byte/checksum/provenance identity of
any asset fanned out to more than one destination
(``catalogue_assembly.verify_multi_destination_identity``).

Never edits ``publish_catalogues.py`` / ``catalogue_assembly.py`` (both gated) — this
module only calls their public contracts. Never runs git: the caller (the release
workflow) owns staging exactly the touched directories, committing, and pushing —
this module only reports which ``(channel, varver)`` directories it touched.

No-op behaviour: a ``(channel, varver)`` target whose desired files (this run's
canonical asset + any dependency assets that ABI-match its ROUTE row and whose
origin is listed in that row's ``extra_pkgs``) are already
present, byte-identical, at the destination AND whose catalog descriptor
(meta.conf/data.pkg/packagesite.pkg) is complete is left untouched entirely — no
copy, no prune, no regenerate. There is no ledger; "already published" is read
straight off the files already on disk. A destination whose descriptor is
incomplete (a prior run's write-back fault) is regenerated even when the ``.pkg``
payload itself is unchanged. A destination file sharing an incoming asset's
canonical name but carrying DIFFERENT bytes is never overwritten: same
name/version with different bytes, source, or provenance raises
``DestinationConflictError`` instead.

Nightly intake is not handled here: ``run()`` accepts only ``kind == "tagged"`` intake
and fails closed otherwise.

Asset checksums: ``verify_asset`` requires an independently-sourced ``expected_sha256``
per asset (never recomputed from the same download it is meant to check). This CLI
reads that from a ``digests.json`` sidecar inside ``--assets-dir`` — ``{"<filename>":
"<sha256 hex>", ...}`` — that the caller (the release workflow) is expected to populate
from the GitHub Releases API's own per-asset ``digest`` field before downloading.

stdlib-only, Python 3.11. The engine is loaded via ``publish_catalogues.load_engine()``
— explicit ``src_root`` or the ``PFB_SRC`` environment variable (the calling workflow
sets ``PFB_SRC`` to the source-repo checkout it already has).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# scripts/ is not a package (no __init__.py); catalogue_assembly.py itself imports
# publish_catalogues with a bare `from publish_catalogues import Engine`, so every
# caller — including this one — needs scripts/ directly on sys.path. Running this file
# directly already gets that for free (Python prepends the script's own directory);
# this insert only matters when another module imports publish_release without having
# done that itself first.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import catalogue_assembly as ca
import publish_catalogues as pc

_SITE_SUBDIR = "docs"
_DIGESTS_FILENAME = "digests.json"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PublishReleaseError(Exception):
    """A digest-sidecar, target-resolution, or CLI-level failure this module itself
    detected. Engine errors (``pc.PublishError`` / ``ca.CatalogueAssemblyError`` /
    the dynamically-loaded ``pfb_pkg.PkgError`` / ``build_repo_portable.BuildRepoError``)
    propagate UNWRAPPED — this module never re-derives a check those already make."""


class DestinationConflictError(PublishReleaseError):
    """An existing destination file shares its canonical name with an incoming
    asset but carries different bytes — same name/version, different source or
    provenance. A distinct subclass (rather than a generic PublishReleaseError)
    so an operator can tell "the catalogue already holds a different build of
    this exact version" apart from a digest-sidecar or target-resolution
    failure by exception type alone."""


# --------------------------------------------------------------------------- #
# Digest sidecar + asset discovery.
# --------------------------------------------------------------------------- #


def _load_digests(assets_dir: Path) -> dict[str, str]:
    path = assets_dir / _DIGESTS_FILENAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PublishReleaseError(f"cannot read {path}: {exc}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PublishReleaseError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise PublishReleaseError(f"{path} must be a non-empty JSON object of {{filename: sha256-hex}}")
    for name, value in parsed.items():
        if not isinstance(name, str) or not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise PublishReleaseError(f"{path}: entry {name!r} must map to 64 lowercase hex characters")
    return parsed


def _discover_assets(assets_dir: Path, digests: Mapping[str, str]) -> tuple[tuple[str, Path], ...]:
    found = sorted(p for p in assets_dir.glob("*.pkg") if p.is_file())
    found_names = {p.name for p in found}
    if not found_names:
        raise PublishReleaseError(f"no .pkg assets found under {assets_dir}")
    missing_digest = sorted(found_names - set(digests))
    if missing_digest:
        raise PublishReleaseError(f"asset(s) with no {_DIGESTS_FILENAME} entry: {missing_digest}")
    missing_file = sorted(set(digests) - found_names)
    if missing_file:
        raise PublishReleaseError(f"{_DIGESTS_FILENAME} entries with no matching asset file: {missing_file}")
    return tuple((p.name, p) for p in found)


def _verify_all_assets(
    engine: pc.Engine,
    intake: pc.Intake,
    assets_dir: Path,
    digests: Mapping[str, str],
    work_dir: Path,
) -> list[pc.VerifiedAsset]:
    """Verify every discovered asset, each into its OWN subdirectory of ``work_dir``.

    ``_verify_canonical_asset`` derives its ``work_path`` from
    ``CANONICAL_EMITTED_IDENTITY``-``canonical_package_version`` alone — no
    row/variant component — and ``verify_run``'s own axes 4/6 REQUIRE every
    canonical asset in one run to share that exact version. A multi-varver tagged
    run (this ticket's central scenario: ce-2.8 + plus-26.03 + plus-26.07 all on
    one tag) therefore produces several canonical assets whose engine-computed
    work_path would be byte-identical if they shared one work_dir — verifying them
    one after another would silently overwrite each with the next, so every
    ``VerifiedAsset.work_path`` after the last call would resolve to the LAST
    asset's bytes. Scoping one subdirectory per asset keeps their work_paths
    distinct regardless of name collisions.
    """
    return [
        pc.verify_asset(
            engine,
            path,
            name,
            intake=intake,
            expected_sha256=digests[name],
            work_dir=work_dir / f"asset-{index}",
        )
        for index, (name, path) in enumerate(_discover_assets(assets_dir, digests))
    ]


# --------------------------------------------------------------------------- #
# Target resolution — one (channel, varver) target per canonical asset's own
# matrix_row, dependency assets fanned in by ABI + extra_pkgs match against
# THIS RUN's targets.
# --------------------------------------------------------------------------- #


@dataclass
class _Target:
    row: Mapping[str, object]
    canonical: pc.VerifiedAsset
    dependencies: list[pc.VerifiedAsset] = field(default_factory=list)


def _row_declares_dep(row: Mapping[str, object], dep: pc.VerifiedAsset) -> bool:
    """True iff this ROUTE/BUILD row lists the dependency's origin in extra_pkgs."""
    extras = row.get("extra_pkgs")
    return isinstance(extras, list) and dep.manifest.get("origin") in extras


def _build_targets(engine: pc.Engine, run_result: pc.RunResult) -> dict[str, _Target]:
    brp = engine.build_repo_portable
    targets: dict[str, _Target] = {}
    for asset in run_result.canonical_assets:
        row = pc._canonical_record(asset)["matrix_row"]
        varver = brp.catalog_name_from_version(row["pfsense_version"], row["variant"])
        if varver in targets:
            raise PublishReleaseError(
                f"two canonical assets resolve to the same varver {varver!r}: "
                f"{targets[varver].canonical.declared_name!r} and {asset.declared_name!r}"
            )
        targets[varver] = _Target(row=row, canonical=asset)

    for dep in run_result.dependency_assets:
        # Same-major ABI is not enough: a CE extra must not land in a Plus
        # catalogue whose extra_pkgs is empty (issue #2383).
        matched = [
            varver
            for varver, target in targets.items()
            if brp._pkg_matches_abi(dep.manifest, f"FreeBSD:{target.row['freebsd_major']}:*")
            and _row_declares_dep(target.row, dep)
        ]
        if not matched:
            raise PublishReleaseError(
                f"dependency asset {dep.declared_name!r} ABI-matches no varver targeted "
                "by this run's own canonical assets"
            )
        for varver in matched:
            targets[varver].dependencies.append(dep)

    return targets


def _asset_map(target: _Target) -> dict[str, Path]:
    mapping = {target.canonical.canonical_name: target.canonical.work_path}
    for dep in target.dependencies:
        existing = mapping.get(dep.canonical_name)
        if existing is not None:
            # A tagged run declares its dependency assets per row, so the SAME
            # artifact legitimately arrives under several declared names — those
            # deduplicate byte-identically. DIFFERENT bytes under one canonical
            # name must fail closed here: keying the map silently last-wins
            # otherwise, publishing one build and dropping the other with no
            # conflict check at all (issue #2231).
            if _files_identical(existing, dep.work_path):
                continue
            raise DestinationConflictError(
                f"{dep.canonical_name}: two verified assets share this canonical name "
                f"with different bytes — "
                f"existing sha256={hashlib.sha256(existing.read_bytes()).hexdigest()}, "
                f"incoming sha256={hashlib.sha256(dep.work_path.read_bytes()).hexdigest()}"
            )
        mapping[dep.canonical_name] = dep.work_path
    return mapping


# --------------------------------------------------------------------------- #
# Drop assets in place, prune + regenerate only what actually changed.
# --------------------------------------------------------------------------- #


def _files_identical(a: Path, b: Path) -> bool:
    """True iff ``a`` and ``b`` hold the same bytes.

    Checks size first: the common case (a genuinely new build) almost always
    differs there, so most calls never read either file's contents."""
    if a.stat().st_size != b.stat().st_size:
        return False
    return a.read_bytes() == b.read_bytes()


def _drop_assets(dest_dir: Path, asset_map: Mapping[str, Path]) -> bool:
    """Copy every ``asset_map`` entry into ``dest_dir`` under its own name.

    Returns True iff at least one entry was missing at the destination — the
    caller uses this to decide whether this target needs
    ``prune_retained``/``regenerate_catalogue`` at all (the no-op contract: an
    already-identical destination is left completely untouched, never re-copied,
    re-pruned, or re-regenerated).

    An existing destination file with the SAME canonical name but DIFFERENT
    bytes is a hard failure, never an overwrite: issue #2146's contract is that
    a name/version collision with different bytes, source, or provenance fails
    closed instead of silently replacing the published artifact."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    changed = False
    for name, src in asset_map.items():
        dest = dest_dir / name
        if dest.is_file():
            if _files_identical(dest, src):
                continue
            raise DestinationConflictError(
                f"{dest}: already publishes a different build of {name} — "
                f"existing sha256={hashlib.sha256(dest.read_bytes()).hexdigest()}, "
                f"incoming sha256={hashlib.sha256(src.read_bytes()).hexdigest()}"
            )
        shutil.copy2(src, dest)
        changed = True
    return changed


def _catalogue_descriptor_complete(dest_dir: Path, engine: pc.Engine) -> bool:
    """True iff every catalog descriptor artifact ``build_repo`` emits is present
    in ``dest_dir``.

    catalogue_assembly.regenerate_catalogue's own docstring names the fault
    window this closes: a write-back fault after the destination wipe can leave
    the directory missing meta.conf/data.pkg/packagesite.pkg even though the
    ``.pkg`` payload alone (all ``_drop_assets`` compares) is untouched and
    byte-identical on a rerun — which would otherwise report a NOOP over an
    unservable catalogue. ``_CATALOG_PKG_FILES`` is the engine's own name for
    the two ``*.pkg``-named descriptor files; the engine has no equivalent
    constant for ``meta.conf`` (only its CONTENT, ``META_CONF``), so that name
    is listed directly here."""
    brp = engine.build_repo_portable
    return all((dest_dir / name).is_file() for name in (*brp._CATALOG_PKG_FILES, "meta.conf"))


@dataclass(frozen=True)
class PublishReport:
    """What this run actually did — the workflow stages exactly ``touched``."""

    touched: tuple[tuple[str, str], ...]

    @property
    def noop(self) -> bool:
        return not self.touched

    def describe(self) -> list[str]:
        if not self.touched:
            return ["NOOP: every destination already matches this run's verified assets"]
        return [f"updated {channel}/{varver}" for channel, varver in self.touched]


def publish(engine: pc.Engine, run_result: pc.RunResult, pkg_repo: str | Path) -> PublishReport:
    """Assemble every (channel, varver) target this run's assets cover.

    ``run_result`` must already be axis-1-13-verified (``publish_catalogues.verify_run``).
    Never runs git — the caller commits/pushes exactly ``PublishReport.touched``.
    """
    intake = run_result.intake
    site_root = Path(pkg_repo) / _SITE_SUBDIR
    targets = _build_targets(engine, run_result)

    touched: list[tuple[str, str]] = []
    source_index: dict[Path, list[tuple[str, str]]] = {}
    for varver in sorted(targets):
        target = targets[varver]
        asset_map = _asset_map(target)
        for channel in intake.destinations:
            dest_dir = site_root / channel / varver
            changed = _drop_assets(dest_dir, asset_map)
            if not changed and not _catalogue_descriptor_complete(dest_dir, engine):
                changed = True
            for src in asset_map.values():
                source_index.setdefault(src.resolve(), []).append((channel, varver))
            if changed:
                ca.prune_retained(site_root, channel, varver, engine=engine)
                ca.regenerate_catalogue(site_root, channel, varver, engine=engine)
                touched.append((channel, varver))

    if source_index:
        ca.verify_multi_destination_identity(engine, site_root, source_index)

    return PublishReport(touched=tuple(touched))


# --------------------------------------------------------------------------- #
# run() — intake -> verify -> publish. main() is a thin CLI wrapper around it.
# --------------------------------------------------------------------------- #


def run(
    *,
    source_repository: str,
    release_id: str,
    release_tag: str,
    destinations: str,
    source_run_id: str,
    assets_dir: str | Path,
    pkg_repo: str | Path,
    route_matrix: str,
    engine: pc.Engine | None = None,
) -> PublishReport:
    intake = pc.parse_intake(source_repository, release_id, release_tag, destinations, source_run_id)
    if intake.kind != "tagged":
        raise PublishReleaseError(
            f"publish_release.py only handles tagged intake; got kind={intake.kind!r} — "
            "Nightly publishing is not implemented here"
        )

    try:
        route_matrix_rows = json.loads(route_matrix)
    except json.JSONDecodeError as exc:
        raise PublishReleaseError(f"--route-matrix is not valid JSON: {exc}") from exc
    if not isinstance(route_matrix_rows, list) or not route_matrix_rows:
        raise PublishReleaseError("--route-matrix must be a non-empty JSON array")

    engine = engine if engine is not None else pc.load_engine()

    assets_dir = Path(assets_dir)
    digests = _load_digests(assets_dir)

    with tempfile.TemporaryDirectory(prefix="publish-release-verify-") as work_dir:
        verified_assets = _verify_all_assets(engine, intake, assets_dir, digests, Path(work_dir))
        run_result = pc.verify_run(engine, intake, verified_assets, route_matrix_rows)
        # publish() reads VerifiedAsset.work_path, which lives under work_dir — must
        # run to completion BEFORE this context manager tears work_dir down.
        return publish(engine, run_result, pkg_repo)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a tagged release's .pkg assets and publish them into the "
            "pfBlockerNG/pkg catalogue tree (never runs git)."
        )
    )
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--destinations", required=True, help="compact JSON array")
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument(
        "--assets-dir",
        required=True,
        help="directory of downloaded .pkg assets + digests.json sidecar",
    )
    parser.add_argument(
        "--pkg-repo",
        required=True,
        help="the checked-out pfBlockerNG/pkg working tree (site is <pkg-repo>/docs)",
    )
    parser.add_argument("--route-matrix", required=True, help="compact JSON array")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        engine = pc.load_engine()
    except pc.EngineError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    try:
        report = run(
            source_repository=args.source_repository,
            release_id=args.release_id,
            release_tag=args.release_tag,
            destinations=args.destinations,
            source_run_id=args.source_run_id,
            assets_dir=args.assets_dir,
            pkg_repo=args.pkg_repo,
            route_matrix=args.route_matrix,
            engine=engine,
        )
    except (
        PublishReleaseError,
        pc.PublishError,
        ca.CatalogueAssemblyError,
        engine.pfb_pkg.PkgError,
        engine.build_repo_portable.BuildRepoError,
    ) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    for line in report.describe():
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
