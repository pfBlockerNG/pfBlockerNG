"""Dependency flow — CLI entry point (issue #2454).

Given the pkg catalogue checkout, a FreeBSD-ports checkout, the pinned ROUTE matrix
and the channel(s) being built, finds every ``docs/<channel>/<varver>/
<py_flavor>-<PORTNAME>-<PORTVERSION>.pkg`` a ROUTE build row's ``extra_pkgs`` declares
that is MISSING there, builds each missing dependency ONCE per (origin, py_flavor,
freebsd_major) via ``build-dep-pkg-portable.py``, copies the result into every missing
destination of that build, and regenerates each touched destination's catalogue
descriptor. Nothing missing anywhere -> NOOP, no writes.

Identity rule: a dependency's canonical name is ``<py_flavor>-<PORTNAME>-<PORTVERSION>.pkg``,
derived from the port definition in the PINNED ports checkout this run was handed —
never from the archive's own bytes. Presence of that filename at a destination is
"already published"; an existing dependency file is never byte-compared, evicted, or
rebuilt to check it still matches (mirrors ``publish_release.py``'s no-ledger,
tree-is-state doctrine, and its own "never byte-compares an existing dep" rule).

This module knows only "I am building <channels>": it does not know or care whether
the run is a nightly, a tagged stage, or a republish, and it targets ROUTE BUILD rows
only (``publish_catalogues._normalize_route_matrix``'s ``build_rows`` — a route-only
row is a frozen catalogue with no build this run and is never targeted, even when it
declares ``extra_pkgs``). It publishes directly into ``<pkg-repo>/docs/`` — no staging,
no ledger. It never runs git: the caller (the wrapper script) owns staging,
committing, and pushing. Canonical packages are never touched, pruned, or evicted here.

stdlib-only, Python 3.11. The pfBlockerNG engine is loaded via
``publish_catalogues.load_engine()`` (``PFB_SRC`` env or an explicit ``src_root``),
exactly as ``publish_release.py``/``publish_nightly.py`` load it. Report shape mirrors
theirs too: ``publish_release.PublishReport`` and its ``describe()`` output contract
(``updated <channel>/<varver>`` lines, or one ``NOOP: ...`` line) are reused as-is.

A second, unrelated mode (issue #2454): ``--print-ports-sha --assets-dir
<dir>`` prints the single ``freebsd_ports_sha`` shared by every canonical ``.pkg``
under ``<dir>`` and exits — see ``ports_sha_from_assets``. Mutually exclusive with
the dependency-build mode above; ``--pkg-repo``/``--ports-dir``/``--route-matrix``/
``--channels`` are not required in this mode.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

# Same sys.path idiom as publish_release.py / publish_nightly.py — scripts/ is not a
# package, and running this file directly only puts ITS OWN directory on sys.path.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import catalogue_assembly as ca
import publish_catalogues as pc
import publish_release as pr

# build-dep-pkg-portable.py is hyphen-named (not import-able normally); load it as a
# module the same way it loads build-pkg-portable.py itself (register in sys.modules
# BEFORE exec_module — tests/test_build_dep_pkg_portable.py uses this identical idiom).
_DEP_BUILDER_PATH = _SCRIPTS_DIR / "build-dep-pkg-portable.py"
_dep_builder_spec = importlib.util.spec_from_file_location("publish_deps_dep_pkg_builder", _DEP_BUILDER_PATH)
assert _dep_builder_spec is not None and _dep_builder_spec.loader is not None
bdp: Any = importlib.util.module_from_spec(_dep_builder_spec)
sys.modules[_dep_builder_spec.name] = bdp
_dep_builder_spec.loader.exec_module(bdp)


class PublishDepsError(Exception):
    """A validation/build/CLI-level failure this module itself detected.

    Engine errors (``pc.PublishError`` / ``ca.CatalogueAssemblyError`` / the
    dynamically-loaded ``pfb_pkg.PkgError`` / ``build_repo_portable.BuildRepoError`` /
    ``build-dep-pkg-portable.py``'s own ``DepPkgError``) propagate UNWRAPPED — this
    module never re-derives a check those already make.
    """


# Builder seam: (origin, py_flavor, freebsd_major, out_dir) -> None, writing exactly one
# .pkg into out_dir. Tests inject a stub; the default drives build-dep-pkg-portable.py.
_Builder = Callable[[str, str, str, Path], None]


def _subprocess_builder(ports_dir: str | Path) -> _Builder:
    """The default builder: run build-dep-pkg-portable.py once per (origin, py_flavor,
    freebsd_major), exactly as the build legs do today."""
    ports_dir = str(ports_dir)

    def build(origin: str, py_flavor: str, freebsd_major: str, out_dir: Path) -> None:
        subprocess.run(
            [
                sys.executable,
                str(_DEP_BUILDER_PATH),
                "--ports",
                ports_dir,
                "--port",
                origin,
                "--py-flavor",
                py_flavor,
                "--freebsd-major",
                freebsd_major,
                "--out-dir",
                str(out_dir),
            ],
            check=True,
        )

    return build


def run(
    *,
    pkg_repo: str | Path,
    ports_dir: str | Path,
    route_matrix: str,
    channels: str,
    engine: pc.Engine | None = None,
    builder: _Builder | None = None,
) -> pr.PublishReport:
    engine = engine if engine is not None else pc.load_engine()
    channel_tuple = pc._parse_destinations(channels)

    try:
        route_matrix_rows = json.loads(route_matrix)
    except json.JSONDecodeError as exc:
        raise PublishDepsError(f"--route-matrix is not valid JSON: {exc}") from exc
    if not isinstance(route_matrix_rows, list) or not route_matrix_rows:
        raise PublishDepsError("--route-matrix must be a non-empty JSON array")

    build_rows, _route_only_rows = pc._normalize_route_matrix(engine, route_matrix_rows)

    ports_dir = Path(ports_dir)
    site_root = Path(pkg_repo) / pr._SITE_SUBDIR
    brp = engine.build_repo_portable

    port_facts: dict[str, Any] = {}  # origin -> PortFacts; one Makefile read per origin

    def facts_for(origin: str) -> Any:
        cached = port_facts.get(origin)
        if cached is not None:
            return cached
        port_dir = ports_dir / origin
        if not (port_dir / "Makefile").is_file():
            raise PublishDepsError(
                f"{origin}: port directory not found under {ports_dir} (expected {port_dir / 'Makefile'})"
            )
        facts = bdp.read_port(port_dir)
        for value, label in ((facts.portname, "PORTNAME"), (facts.portversion, "PORTVERSION")):
            if not brp._PKG_SEGMENT_RE.fullmatch(value):
                raise PublishDepsError(f"{origin}: port {label} {value!r} is not a safe path segment")
        port_facts[origin] = facts
        return facts

    # build_key = (origin, py_flavor, freebsd_major) -> (expected filename, portname, portversion)
    build_targets: dict[tuple[str, str, str], tuple[str, str, str]] = {}
    # build_key -> every (channel, varver) still missing that build's file
    missing: dict[tuple[str, str, str], list[tuple[str, str]]] = {}

    ordered_rows = sorted(
        build_rows.values(), key=lambda row: brp.catalog_name_from_version(row["pfsense_version"], row["variant"])
    )
    for row in ordered_rows:
        extra_pkgs = row["extra_pkgs"]
        if not extra_pkgs:
            continue
        varver = brp.catalog_name_from_version(row["pfsense_version"], row["variant"])
        for origin in extra_pkgs:
            facts = facts_for(origin)
            expected = f"{row['py_flavor']}-{facts.portname}-{facts.portversion}.pkg"
            build_key = (origin, row["py_flavor"], row["freebsd_major"])
            build_targets[build_key] = (expected, facts.portname, facts.portversion)
            for channel in channel_tuple:
                dest = site_root / channel / varver / expected
                if not dest.is_file():
                    missing.setdefault(build_key, []).append((channel, varver))

    if not missing:
        return pr.PublishReport(touched=())

    build = builder if builder is not None else _subprocess_builder(ports_dir)
    pfb_pkg = engine.pfb_pkg

    touched: set[tuple[str, str]] = set()
    for build_key in sorted(missing):
        origin, py_flavor, freebsd_major = build_key
        expected, portname, portversion = build_targets[build_key]
        with tempfile.TemporaryDirectory(prefix="publish-deps-build-") as out_dir_str:
            out_dir = Path(out_dir_str)
            build(origin, py_flavor, freebsd_major, out_dir)
            built_path = out_dir / expected
            if not built_path.is_file():
                raise PublishDepsError(
                    f"{origin}: builder did not produce the expected file {expected!r} under {out_dir} "
                    "— refusing to publish an unexpectedly-named result"
                )
            manifest = pfb_pkg.read_compact_manifest(built_path)
            expected_name = f"{py_flavor}-{portname}"
            if manifest.get("name") != expected_name:
                raise PublishDepsError(
                    f"{expected}: built package manifest name {manifest.get('name')!r} "
                    f"does not match expected {expected_name!r}"
                )
            if manifest.get("version") != portversion:
                raise PublishDepsError(
                    f"{expected}: built package manifest version {manifest.get('version')!r} "
                    f"does not match expected {portversion!r}"
                )
            row_abi = f"FreeBSD:{freebsd_major}:*"
            if not brp._pkg_matches_abi(manifest, row_abi):
                raise PublishDepsError(
                    f"{expected}: built package manifest abi {manifest.get('abi')!r} does not match {row_abi!r}"
                )
            for channel, varver in missing[build_key]:
                dest_dir = site_root / channel / varver
                dest_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(built_path, dest_dir / expected)
                touched.add((channel, varver))

    for channel, varver in sorted(touched):
        ca.regenerate_catalogue(site_root, channel, varver, engine=engine)

    return pr.PublishReport(touched=tuple(sorted(touched)))


def ports_sha_from_assets(engine: pc.Engine, assets_dir: str | Path) -> str:
    """The single ``freebsd_ports_sha`` shared by every canonical ``.pkg`` under
    ``assets_dir`` (needed to check out the dependency flow's FreeBSD-ports tree at
    the SAME ports commit the canonical build already used, without re-deriving that
    from anywhere else).

    Scans every ``*.pkg`` for its optional ``pfb_build_record`` annotation
    (``build_repo_portable._canonical_build_record``) — ``None`` (a dependency
    ``.pkg``, or an unannotated legacy canonical) is skipped, exactly as the
    retention/eviction code already treats a recordless package. Exactly one
    distinct ``freebsd_ports_sha`` among the remaining (canonical, annotated)
    packages is required: zero is an error (nothing to report), more than one is an
    error (the assets directory mixes ports checkouts across builds — never silently
    pick one).
    """
    assets_dir = Path(assets_dir)
    brp = engine.build_repo_portable
    pfb_pkg = engine.pfb_pkg
    by_sha: dict[str, list[str]] = {}
    for path in sorted(assets_dir.glob("*.pkg")):
        if not path.is_file():
            continue
        manifest = pfb_pkg.read_compact_manifest(path)
        record = brp._canonical_build_record(path, manifest)
        if record is None:
            continue
        by_sha.setdefault(record["freebsd_ports_sha"], []).append(path.name)
    if not by_sha:
        raise PublishDepsError(f"no canonical .pkg with build-record provenance found under {assets_dir}")
    if len(by_sha) > 1:
        detail = "; ".join(f"{sha}: {names}" for sha, names in sorted(by_sha.items()))
        raise PublishDepsError(f"canonical .pkg assets under {assets_dir} disagree on freebsd_ports_sha: {detail}")
    return next(iter(by_sha))


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build and place every ROUTE build row's extra_pkgs dependency .pkg missing "
            "from the given channel(s) (never runs git); or, with --print-ports-sha, print "
            "the freebsd_ports_sha shared by every canonical .pkg under --assets-dir."
        )
    )
    parser.add_argument(
        "--pkg-repo",
        help="the checked-out pfBlockerNG/pkg working tree (site is <pkg-repo>/docs) — required "
        "unless --print-ports-sha is given",
    )
    parser.add_argument("--ports-dir", help="FreeBSD-ports checkout root — required unless --print-ports-sha is given")
    parser.add_argument("--route-matrix", help="compact JSON array — required unless --print-ports-sha is given")
    parser.add_argument(
        "--channels",
        help="compact JSON array, e.g. '[\"nightly\"]' — required unless --print-ports-sha is given",
    )
    parser.add_argument(
        "--print-ports-sha",
        action="store_true",
        help="print the freebsd_ports_sha shared by every canonical .pkg under --assets-dir, then exit "
        "(mutually exclusive with the publish mode above)",
    )
    parser.add_argument("--assets-dir", help="directory of downloaded .pkg assets — only used with --print-ports-sha")
    return parser.parse_args(argv)


_PUBLISH_MODE_ARGS = ("pkg_repo", "ports_dir", "route_matrix", "channels")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        engine = pc.load_engine()
    except pc.EngineError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    if args.print_ports_sha:
        if not args.assets_dir:
            print("::error::--print-ports-sha requires --assets-dir", file=sys.stderr)
            return 1
        try:
            sha = ports_sha_from_assets(engine, args.assets_dir)
        except (PublishDepsError, engine.pfb_pkg.PkgError, engine.build_repo_portable.BuildRepoError) as exc:
            print(f"::error::{exc}", file=sys.stderr)
            return 1
        print(sha)
        return 0

    missing = [f"--{name.replace('_', '-')}" for name in _PUBLISH_MODE_ARGS if getattr(args, name) is None]
    if missing:
        print(f"::error::{', '.join(missing)} required unless --print-ports-sha is given", file=sys.stderr)
        return 1

    try:
        report = run(
            pkg_repo=args.pkg_repo,
            ports_dir=args.ports_dir,
            route_matrix=args.route_matrix,
            channels=args.channels,
            engine=engine,
        )
    except (
        PublishDepsError,
        pc.PublishError,
        ca.CatalogueAssemblyError,
        engine.pfb_pkg.PkgError,
        engine.build_repo_portable.BuildRepoError,
        subprocess.CalledProcessError,
        bdp.DepPkgError,
        bdp.bpp.BuildError,
    ) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    # report.describe()'s own NOOP line names publish_release.py's destination/asset
    # vocabulary, not this module's (dependency, not a run's canonical asset) — print
    # this mode's own wording instead; the "updated <channel>/<varver>" lines it
    # shares with the other publishers stay as-is.
    if report.noop:
        print("NOOP: every dependency already present at every destination")
    else:
        for line in report.describe():
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
