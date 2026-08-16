"""Nightly-handoff publisher — CLI entry point (issue #2146 step S2).

Consumes the already-verified Nightly handoff (``nightly_provenance.build_handoff``'s
own return shape, read back from disk as untrusted JSON) and assembles it into the
``nightly/<varver>/`` catalogues: re-validate the handoff's own shape/identity, verify
every referenced ``.pkg`` artifact from BYTES (never trusting the handoff's own literal
``record``/``matrix_row``/``artifact`` echoes — those are audit trail, not proof), fan
each per-FreeBSD-major build out to every ROUTE varver sharing that major, then drop,
prune, and regenerate exactly like ``publish_release.py`` does for a tagged run.

Per-major fan-out (``scripts/read-version-matrix.sh`` header, "why builds are per-major
but ROUTE is per-version"): every ``pfSense-pkg-pfBlockerNG`` port is NO_ARCH, so ONE
wildcard-ABI Nightly build serves every pfSense edition/version sharing a FreeBSD
major — unlike a tagged run's ROUTE matrix (one canonical asset per EXACT version), a
Nightly leg's canonical asset is targeted at every build-role ROUTE row whose
``freebsd_major`` matches. Two Plus versions on the same major (e.g. 26.03 + 26.07)
therefore both receive the SAME canonical bytes — a genuine multi-destination fan-out,
verified byte/checksum/provenance-identical by
``catalogue_assembly.verify_multi_destination_identity`` exactly as a tagged run's own
fan-out is.

Staleness guard: this publisher runs inside the SAME workflow run that produced the
handoff (``handoff["run_id"] == --source-run-id``); an inequality means a stale or
foreign handoff replay and is rejected before any other check. There is still no
durable ledger here (issue #2146's tree-is-state doctrine, same as
``catalogue_assembly.py``): "already published" is read straight off
``nightly/<varver>/`` itself. Because Nightly's version starts with one run-wide UTC
timestamp, a destination
already holding a NEWER canonical version than this run's own is refused outright
(``StaleNightlyError``) rather than silently skipped or overwritten — a stale rerun of
an old workflow attempt must never regress a catalogue a newer run already advanced.

Tagged intake is not handled here: ``publish_release.py`` owns it, and this module never
imports git or touches any tagged-flow paths.

Never edits ``publish_catalogues.py`` / ``catalogue_assembly.py`` / ``publish_release.py``
/ ``nightly_provenance.py`` (all frozen/gated) — this module only calls their public
contracts, plus established private cross-module seams in the same spirit as
``catalogue_assembly.py``'s own engine-private dereferences
(``publish_catalogues._canonical_record``/``_normalize_route_matrix``/
``_validate_asset_name``, ``publish_release._Target``/``_asset_map``/``_drop_assets``/
``_catalogue_descriptor_complete``, ``nightly_provenance._validate_artifacts``/
``_DIGEST``) — never copies their logic.

Dependency assets (issue #2454): this module never places, verifies, or routes
one — ``scripts/publish_deps.py`` builds and places every ROUTE build row's
``extra_pkgs`` dependency, in its own earlier step. A handoff build entry carries
only ``matrix_row``/``record``/``artifact``; a legacy dependency file already
sitting at a Nightly destination is left exactly as-is, whatever its bytes, and
survives retention untouched by ``pr._evict_undeclared_deps`` for as long as its
ROUTE row still declares its origin.

stdlib-only, Python 3.11. The engine is loaded via ``publish_catalogues.load_engine()``
— explicit ``src_root`` or the ``PFB_SRC`` environment variable, same as
``publish_release.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

# Same sys.path idiom as publish_release.py — scripts/ is not a package, and running
# this file directly only puts ITS OWN directory on sys.path for free.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import catalogue_assembly as ca
import nightly_provenance as np
import publish_catalogues as pc
import publish_release as pr

_CHANNEL = "nightly"
_LEG_DIR_PREFIX = "nightly-result-"


class PublishNightlyError(Exception):
    """A handoff-shape, routing, or CLI-level failure this module itself detected.

    Engine errors (``pc.PublishError`` / ``ca.CatalogueAssemblyError`` /
    ``pr.PublishReleaseError`` (incl. its ``DestinationConflictError`` subclass, raised
    by the reused ``pr._drop_assets``/``pr._asset_map``) / ``np.ProvenanceError`` / the
    dynamically-loaded ``pfb_pkg.PkgError``/``build_repo_portable.BuildRepoError``)
    propagate UNWRAPPED — this module never re-derives a check those already make."""


class StaleNightlyError(PublishNightlyError):
    """A destination already holds a canonical version NEWER than this run's own, and
    this run's version is not already present there. A stale rerun must never regress
    a catalogue a newer run already advanced past it."""


# --------------------------------------------------------------------------- #
# Handoff validation — re-checks the shape/identity nightly_provenance.build_handoff
# already enforced at handoff-creation time, because this reads the handoff back as
# untrusted JSON off disk, not the in-memory value build_handoff returned.
# --------------------------------------------------------------------------- #

_HANDOFF_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "run_id",
        "source_ref",
        "ports_repo",
        "ports_ref",
        "pkg_version",
        "input_digest",
        "source_sha",
        "ports_sha",
        "tools_sha",
        "matrix_sha",
        "matrix_digest",
        "build_matrix",
        "route_matrix",
        "builds",
    }
)
_BUILD_ENTRY_FIELDS = frozenset({"matrix_row", "record", "artifact"})


@dataclass(frozen=True)
class _ValidatedHandoff:
    pkg_version: str
    source_sha: str
    ports_sha: str
    route_matrix: list[Mapping[str, object]]
    # Each entry: {"matrix_row": normalized dict, "artifact": {abi,name,sha256}}. The
    # handoff's own literal "record" field is intentionally NOT carried past the shape
    # check below — this module never trusts it; per-canonical provenance is always
    # re-derived from the downloaded .pkg's own annotation by
    # publish_catalogues.verify_asset instead.
    builds: list[dict[str, object]]


def _validate_handoff(handoff: object, *, engine: pc.Engine, source_run_id: str) -> _ValidatedHandoff:
    if not isinstance(handoff, dict):
        raise PublishNightlyError("handoff must be a JSON object")
    keys = set(handoff)
    if keys != _HANDOFF_FIELDS:
        missing = sorted(_HANDOFF_FIELDS - keys)
        unknown = sorted(keys - _HANDOFF_FIELDS)
        raise PublishNightlyError(f"handoff exact fields required (missing={missing}, unknown={unknown})")
    if handoff["schema"] != 1:
        raise PublishNightlyError(f"handoff schema must be 1, got {handoff['schema']!r}")
    if handoff["kind"] != "nightly-handoff":
        raise PublishNightlyError(f"handoff kind must be 'nightly-handoff', got {handoff['kind']!r}")
    run_id = handoff["run_id"]
    if run_id != source_run_id:
        raise PublishNightlyError(
            f"handoff run_id {run_id!r} does not match --source-run-id {source_run_id!r} — "
            "this publisher only accepts the handoff produced by its OWN workflow run "
            "(a mismatch is a stale or foreign handoff replay)"
        )

    source_sha = handoff["source_sha"]
    ports_sha = handoff["ports_sha"]
    if not isinstance(source_sha, str) or not isinstance(ports_sha, str):
        raise PublishNightlyError("handoff source_sha/ports_sha must be strings")

    pkg_version = handoff["pkg_version"]
    try:
        np.validate_nightly_version(pkg_version, source_sha=source_sha)
    except ValueError as exc:
        raise PublishNightlyError(str(exc)) from exc

    # Re-run the input-digest cross-check nightly_provenance.build_handoff itself
    # performs at handoff-creation time: nothing else in this handoff's shape ties
    # matrix_digest to input_digest, so without this a forged
    # matrix_digest would sail through untouched.
    matrix_digest = handoff["matrix_digest"]
    if not isinstance(matrix_digest, str) or not np._DIGEST.fullmatch(matrix_digest):
        raise PublishNightlyError("handoff matrix_digest must be lowercase 64-character hex")
    expected_input_digest = np.combined_nightly_input_digest(source_sha, ports_sha, matrix_digest)
    if handoff["input_digest"] != expected_input_digest:
        raise PublishNightlyError(
            "handoff input_digest does not match source_sha/ports_sha/matrix_digest (tampered or corrupt handoff)"
        )

    builds_raw = handoff["builds"]
    if not isinstance(builds_raw, list) or not builds_raw:
        raise PublishNightlyError("handoff builds must be a non-empty list")

    pfb_pkg = engine.pfb_pkg
    normalized_builds: list[dict[str, object]] = []
    majors: set[str] = set()
    for entry in builds_raw:
        if not isinstance(entry, dict) or set(entry) != _BUILD_ENTRY_FIELDS:
            raise PublishNightlyError(f"handoff build entry exact fields required: {sorted(_BUILD_ENTRY_FIELDS)}")
        matrix_row = pfb_pkg.validate_build_matrix_row(entry["matrix_row"])
        major = str(matrix_row["freebsd_major"])
        if major in majors:
            raise PublishNightlyError(f"handoff builds contain duplicate FreeBSD major {major!r}")
        majors.add(major)
        # Same per-result shape nightly_provenance.build_handoff itself validates —
        # reused verbatim rather than re-deriving the artifact rule.
        artifact = np._validate_artifacts([entry["artifact"]])[0]
        normalized_builds.append({"matrix_row": matrix_row, "artifact": artifact})

    route_matrix = handoff["route_matrix"]
    if not isinstance(route_matrix, list) or not route_matrix:
        raise PublishNightlyError("handoff route_matrix must be a non-empty list")

    return _ValidatedHandoff(
        pkg_version=pkg_version,
        source_sha=source_sha,
        ports_sha=ports_sha,
        route_matrix=route_matrix,
        builds=normalized_builds,
    )


# --------------------------------------------------------------------------- #
# Asset discovery + verification — one leg directory per BUILD major.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Leg:
    major: str
    matrix_row: Mapping[str, object]
    canonical: pc.VerifiedAsset


def _verify_builds(
    engine: pc.Engine,
    intake: pc.Intake,
    validated: _ValidatedHandoff,
    results_dir: Path,
    work_dir: Path,
) -> list[_Leg]:
    """One ``_Leg`` per BUILD entry, canonical asset only (issue #2454) —
    ``scripts/publish_deps.py`` builds and places every ROUTE build row's
    ``extra_pkgs`` dependency as its own, earlier step; any OTHER file still
    sitting in a leg's results directory (e.g. a legacy dependency .pkg) is
    simply never looked at here."""
    legs: list[_Leg] = []
    for index, entry in enumerate(validated.builds):
        matrix_row = entry["matrix_row"]
        assert isinstance(matrix_row, Mapping)
        major = str(matrix_row["freebsd_major"])
        legdir = results_dir / f"{_LEG_DIR_PREFIX}{major}"
        artifact = entry["artifact"]
        assert isinstance(artifact, Mapping)

        # Reject a hostile name BEFORE it is ever joined onto legdir — the same
        # bare-filename guard verify_asset applies to its own `asset_name` argument,
        # invoked here proactively rather than after a path has already been built
        # from untrusted input.
        pc._validate_asset_name(artifact["name"])
        canonical_path = legdir / artifact["name"]
        if not canonical_path.is_file():
            raise PublishNightlyError(f"missing canonical asset for FreeBSD {major}: {canonical_path}")
        canonical_asset = pc.verify_asset(
            engine,
            canonical_path,
            artifact["name"],
            intake=intake,
            expected_sha256=artifact["sha256"],
            work_dir=work_dir / f"leg-{index}-canonical",
        )
        record = pc._canonical_record(canonical_asset)
        if record["canonical_package_version"] != validated.pkg_version:
            raise PublishNightlyError(
                f"FreeBSD {major} canonical asset version {record['canonical_package_version']!r} "
                f"does not match handoff pkg_version {validated.pkg_version!r}"
            )
        if record["source_sha"] != validated.source_sha:
            raise PublishNightlyError(f"FreeBSD {major} canonical asset source_sha does not match handoff source_sha")
        if record["freebsd_ports_sha"] != validated.ports_sha:
            raise PublishNightlyError(
                f"FreeBSD {major} canonical asset freebsd_ports_sha does not match handoff ports_sha"
            )
        if record["matrix_row"] != matrix_row:
            raise PublishNightlyError(
                f"FreeBSD {major} canonical asset matrix_row does not match this build entry's matrix_row"
            )

        legs.append(_Leg(major=major, matrix_row=matrix_row, canonical=canonical_asset))
    return legs


# --------------------------------------------------------------------------- #
# Route targeting — fan each leg out to every build-role ROUTE row sharing its
# FreeBSD major. Route-only rows are never targeted (no frozen Nightly assets).
# --------------------------------------------------------------------------- #


def _route_targets(
    engine: pc.Engine,
    route_matrix_rows: Sequence[Mapping[str, object]],
    legs: Sequence[_Leg],
) -> dict[str, pr._Target]:
    brp = engine.build_repo_portable
    build_rows, _route_only_rows = pc._normalize_route_matrix(engine, route_matrix_rows)

    targets: dict[str, pr._Target] = {}
    used_majors: set[str] = set()
    for row in build_rows.values():
        major = str(row["freebsd_major"])
        matches = [leg for leg in legs if leg.major == major]
        if not matches:
            raise PublishNightlyError(
                f"ROUTE build row {row['variant']}/{row['pfsense_version']} (FreeBSD {major}) has no built asset"
            )
        if len(matches) > 1:
            raise PublishNightlyError(
                f"ROUTE build row {row['variant']}/{row['pfsense_version']} (FreeBSD {major}) matches more than "
                "one built asset — forged handoff"
            )
        leg = matches[0]
        varver = brp.catalog_name_from_version(row["pfsense_version"], row["variant"])
        if varver in targets:
            raise PublishNightlyError(f"two ROUTE build rows resolve to the same varver {varver!r}")

        targets[varver] = pr._Target(row=row, canonical=leg.canonical)
        used_majors.add(major)

    unused = {leg.major for leg in legs} - used_majors
    if unused:
        raise PublishNightlyError(
            f"canonical asset(s) for FreeBSD major(s) {sorted(unused)!r} serve no ROUTE build row"
        )
    return targets


# --------------------------------------------------------------------------- #
# Stale-version tree check — BEFORE any write, for every target.
# --------------------------------------------------------------------------- #


def _reject_stale(site_root: Path, varver: str, engine: pc.Engine, incoming_version: str) -> None:
    catalogue_dir = site_root / _CHANNEL / varver
    if not catalogue_dir.is_dir():
        return  # first publish for this varver — nothing to be stale against
    pfb_pkg = engine.pfb_pkg
    brp = engine.build_repo_portable
    incoming_name = f"{pfb_pkg.CANONICAL_EMITTED_IDENTITY}-{incoming_version}.pkg"
    present = False
    newest_key = None
    for path in sorted(catalogue_dir.glob("*.pkg")):
        if not path.is_file() or path.name in brp._CATALOG_PKG_FILES:
            continue
        manifest = pfb_pkg.read_compact_manifest(path)
        if manifest.get("name") != pfb_pkg.CANONICAL_EMITTED_IDENTITY:
            continue
        if path.name == incoming_name:
            present = True
        version = manifest.get("version")
        if not isinstance(version, str) or not version:
            raise PublishNightlyError(f"corrupt published canonical package manifest (missing 'version'): {path}")
        key = pfb_pkg.pkg_version_sort_key(version)
        if newest_key is None or key > newest_key:
            newest_key = key
    if not present and newest_key is not None and pfb_pkg.pkg_version_sort_key(incoming_version) < newest_key:
        raise StaleNightlyError(
            f"{_CHANNEL}/{varver}: incoming version {incoming_version!r} is older than the newest already-published "
            "canonical version — stale run cannot replace newer catalogue state"
        )


# --------------------------------------------------------------------------- #
# Publish — mirrors publish_release.publish()'s body over a fixed "nightly" channel.
# --------------------------------------------------------------------------- #


def publish(
    engine: pc.Engine,
    pkg_repo: str | Path,
    targets: Mapping[str, pr._Target],
    incoming_version: str,
) -> pr.PublishReport:
    site_root = Path(pkg_repo) / pr._SITE_SUBDIR

    for varver in sorted(targets):
        _reject_stale(site_root, varver, engine, incoming_version)

    touched: list[tuple[str, str]] = []
    source_index: dict[Path, list[tuple[str, str]]] = {}
    for varver in sorted(targets):
        target = targets[varver]
        asset_map = pr._asset_map(target)
        dest_dir = site_root / _CHANNEL / varver
        changed = pr._drop_assets(dest_dir, asset_map)
        if pr._evict_undeclared_deps(dest_dir, engine=engine, row=target.row):
            changed = True
        if not changed and not pr._catalogue_descriptor_complete(dest_dir, engine):
            changed = True
        for src in asset_map.values():
            source_index.setdefault(src.resolve(), []).append((_CHANNEL, varver))
        if changed:
            ca.prune_retained(site_root, _CHANNEL, varver, engine=engine)
            ca.regenerate_catalogue(site_root, _CHANNEL, varver, engine=engine)
            touched.append((_CHANNEL, varver))

    if source_index:
        ca.verify_multi_destination_identity(engine, site_root, source_index)

    return pr.PublishReport(touched=tuple(touched))


# --------------------------------------------------------------------------- #
# run() — handoff -> verify -> route -> publish. main() is a thin CLI wrapper.
# --------------------------------------------------------------------------- #


def run(
    *,
    handoff_path: str | Path,
    results_dir: str | Path,
    pkg_repo: str | Path,
    source_run_id: str,
    engine: pc.Engine | None = None,
) -> pr.PublishReport:
    engine = engine if engine is not None else pc.load_engine()

    handoff_path = Path(handoff_path)
    try:
        raw = handoff_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PublishNightlyError(f"cannot read {handoff_path}: {exc}") from exc
    try:
        handoff_raw = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PublishNightlyError(f"{handoff_path} is not valid JSON: {exc}") from exc

    validated = _validate_handoff(handoff_raw, engine=engine, source_run_id=source_run_id)
    intake = pc.parse_intake(pc.EXPECTED_SOURCE_REPOSITORY, "", "", '["nightly"]', source_run_id)

    with tempfile.TemporaryDirectory(prefix="publish-nightly-verify-") as work_dir:
        legs = _verify_builds(engine, intake, validated, Path(results_dir), Path(work_dir))
        targets = _route_targets(engine, validated.route_matrix, legs)
        # publish() reads VerifiedAsset.work_path, which lives under work_dir — must
        # run to completion BEFORE this context manager tears work_dir down.
        return publish(engine, pkg_repo, targets, validated.pkg_version)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a Nightly handoff's .pkg assets and publish them into the "
            "pfBlockerNG/pkg nightly catalogue tree (never runs git)."
        )
    )
    parser.add_argument("--handoff", required=True, help="the verified nightly_provenance.build_handoff JSON")
    parser.add_argument("--results-dir", required=True, help="directory of downloaded nightly-result-<major>/ legs")
    parser.add_argument(
        "--pkg-repo",
        required=True,
        help="the checked-out pfBlockerNG/pkg working tree (site is <pkg-repo>/docs)",
    )
    parser.add_argument("--source-run-id", required=True, help="must equal the handoff's own run_id")
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
            handoff_path=args.handoff,
            results_dir=args.results_dir,
            pkg_repo=args.pkg_repo,
            source_run_id=args.source_run_id,
            engine=engine,
        )
    except (
        PublishNightlyError,
        pc.PublishError,
        ca.CatalogueAssemblyError,
        pr.PublishReleaseError,
        np.ProvenanceError,
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
