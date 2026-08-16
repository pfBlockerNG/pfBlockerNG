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

Dependency identity (issue #2468): a dependency ``.pkg``'s identity is its filename
alone (``<name>-<version>.pkg``, e.g. ``py311-charset-normalizer-3.4.0.pkg``) — a
tagged Release asset's ``-<Variant>-<pfsense_version>`` suffix (``VerifiedAsset.
release_suffix``) routes it to the varver of ITS OWN suffix row (``_build_targets``:
that row must be one of this run's own canonical targets, must declare the dep's
origin in ``extra_pkgs``, and its ABI must match — never by ABI-matching every
same-major declaring row). A dependency already present at a destination is left
exactly as-is — never read, never byte-compared, never overwritten — and one missing
is copied in (``_drop_assets``). The canonical package keeps the strict rule below.
Because a dependency is place-if-missing, it never feeds the multi-destination
identity check (``_asset_map``/``publish``'s ``source_index``) — fan-out byte
identity stays a canonical-package invariant only; a dep already differing at one
destination but freshly placed at another is expected, not a divergence.

No-op behaviour: a ``(channel, varver)`` target whose canonical asset is already
present, byte-identical, at the destination (dependency assets are irrelevant to this
check — see above) AND whose catalog descriptor (meta.conf/data.pkg/packagesite.pkg)
is complete is left untouched entirely — no copy, no prune, no regenerate. There is no
ledger; "already published" is read straight off the files already on disk. A
destination whose descriptor is incomplete (a prior run's write-back fault) is
regenerated even when the ``.pkg`` payload itself is unchanged. A destination
CANONICAL file sharing an incoming asset's canonical name but carrying DIFFERENT
bytes is never overwritten: same name/version with different bytes, source, or
provenance raises ``DestinationConflictError`` instead.

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
_PY_FLAVOR_ORIGIN = re.compile(r"^(py)(?:\d+)?-")


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


@dataclass
class _Target:
    row: Mapping[str, object]
    canonical: pc.VerifiedAsset
    dependencies: list[pc.VerifiedAsset] = field(default_factory=list)


def _origin_key(value: object) -> tuple[str, str] | None:
    """(category, unflavored last) for a port origin.

    extra_pkgs lists port origins (textproc/py-charset-normalizer). Some
    manifests and test fixtures use the flavored package origin
    (textproc/py311-charset-normalizer). Those name the same extra.
    Category is part of the identity: www/py-foo is not textproc/py-foo
    (issue #2403).
    """
    if not isinstance(value, str) or "/" not in value:
        return None
    category, last = value.rsplit("/", 1)
    if not category or not last:
        return None
    stripped = _PY_FLAVOR_ORIGIN.sub("", last, count=1)
    return (category, stripped or last)


def _row_declares_origin(row: Mapping[str, object], origin: object) -> bool:
    """True iff this ROUTE/BUILD row lists ``origin`` in extra_pkgs."""
    extras = row.get("extra_pkgs")
    if not isinstance(extras, list):
        return False
    if origin in extras:
        return True
    key = _origin_key(origin)
    if key is None:
        return False
    return any(_origin_key(extra) == key for extra in extras)


def _row_declares_dep(row: Mapping[str, object], dep: pc.VerifiedAsset) -> bool:
    """True iff this ROUTE/BUILD row lists the dependency's origin in extra_pkgs."""
    return _row_declares_origin(row, dep.manifest.get("origin"))


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
        # issue #2468: routes to the varver of the dep's OWN suffix row only — never
        # by ABI-match against every same-major declaring row. That row must be a
        # canonical target of this run, declare the dep's origin, and match ABI.
        reject = PublishReleaseError(
            f"dependency asset {dep.declared_name!r} matches no varver targeted "
            "by this run's own canonical assets (per-suffix routing, ABI, and "
            "extra_pkgs declaration)"
        )
        if dep.release_suffix is None:
            raise reject
        variant, pfsense_version = dep.release_suffix
        varver = brp.catalog_name_from_version(pfsense_version, variant)
        target = targets.get(varver)
        if target is None:
            raise reject
        if not brp._pkg_matches_abi(dep.manifest, f"FreeBSD:{target.row['freebsd_major']}:*"):
            raise reject
        if not _row_declares_dep(target.row, dep):
            raise reject
        target.dependencies.append(dep)

    return targets


def _asset_map(target: _Target) -> dict[str, pc.VerifiedAsset]:
    mapping: dict[str, pc.VerifiedAsset] = {target.canonical.canonical_name: target.canonical}
    for dep in target.dependencies:
        existing = mapping.get(dep.canonical_name)
        if existing is not None:
            # issue #2468: two assets resolving to one canonical name always conflict
            # — no byte-compare-then-tolerate branch; dependency identity is the
            # filename alone, and per-suffix routing should make this unreachable.
            raise DestinationConflictError(
                f"{dep.canonical_name}: two verified assets share this canonical name — "
                f"{existing.declared_name!r} (sha256={existing.sha256}) and "
                f"{dep.declared_name!r} (sha256={dep.sha256})"
            )
        mapping[dep.canonical_name] = dep
    return mapping


def _files_identical(a: Path, b: Path) -> bool:
    if a.stat().st_size != b.stat().st_size:
        return False
    return a.read_bytes() == b.read_bytes()


def _evict_undeclared_deps(dest_dir: Path, *, engine: pc.Engine, row: Mapping[str, object]) -> bool:
    """Unlink non-catalog, non-canonical .pkg files this dest row does not declare.

    issue #2402: prune_retained never touches dependency .pkg files, so a stray
    extra already on an undeclaring dest survives attach and is re-indexed.
    Scoped to this dest directory only. A declared leftover is kept even when
    this run did not re-attach it.
    """
    if not dest_dir.is_dir():
        return False
    brp = engine.build_repo_portable
    pfb_pkg = engine.pfb_pkg
    evicted = False
    for path in sorted(dest_dir.glob("*.pkg")):
        if not path.is_file() or path.name in brp._CATALOG_PKG_FILES:
            continue
        manifest = pfb_pkg.read_compact_manifest(path)
        if manifest.get("name") == pfb_pkg.CANONICAL_EMITTED_IDENTITY:
            continue
        if _row_declares_origin(row, manifest.get("origin")):
            continue
        path.unlink()
        evicted = True
    return evicted


def _drop_assets(dest_dir: Path, asset_map: Mapping[str, pc.VerifiedAsset]) -> bool:
    dest_dir.mkdir(parents=True, exist_ok=True)
    changed = False
    for name, asset in asset_map.items():
        dest = dest_dir / name
        src = asset.work_path
        if dest.is_file():
            if asset.asset_class == "dependency":
                # issue #2468: a dependency .pkg's identity IS its filename — place
                # it only when missing, never byte-compare or overwrite an existing one.
                continue
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
    brp = engine.build_repo_portable
    return all((dest_dir / name).is_file() for name in (*brp._CATALOG_PKG_FILES, "meta.conf"))


@dataclass(frozen=True)
class PublishReport:
    touched: tuple[tuple[str, str], ...]

    @property
    def noop(self) -> bool:
        return not self.touched

    def describe(self) -> list[str]:
        if not self.touched:
            return ["NOOP: every destination already matches this run's verified assets"]
        return [f"updated {channel}/{varver}" for channel, varver in self.touched]


def publish(engine: pc.Engine, run_result: pc.RunResult, pkg_repo: str | Path) -> PublishReport:
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
            if _evict_undeclared_deps(dest_dir, engine=engine, row=target.row):
                changed = True
            if not changed and not _catalogue_descriptor_complete(dest_dir, engine):
                changed = True
            # Heal historical holes before prune: copy every canonical version
            # still on a slower tagged channel (never nightly) onto this dest.
            copied = ca.backfill_from_slower_channels(site_root, channel, varver, engine=engine)
            if copied:
                changed = True
                for src, destinations in copied.items():
                    bucket = source_index.setdefault(src, [])
                    for dest in destinations:
                        if dest not in bucket:
                            bucket.append(dest)
            # issue #2468: only the canonical asset feeds the fan-out identity index —
            # a place-if-missing dependency skipped at one destination but placed
            # fresh at another would otherwise falsely trip verify_multi_destination_identity.
            source_index.setdefault(target.canonical.work_path.resolve(), []).append((channel, varver))
            if changed:
                ca.prune_retained(site_root, channel, varver, engine=engine)
                ca.regenerate_catalogue(site_root, channel, varver, engine=engine)
                touched.append((channel, varver))

    if source_index:
        ca.verify_multi_destination_identity(engine, site_root, source_index)

    return PublishReport(touched=tuple(touched))


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
