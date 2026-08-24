"""Tests for scripts/publish_nightly.py — issue #2146 step S2 (Nightly-handoff
publisher CLI): re-validate the verified Nightly handoff
(nightly_provenance.build_handoff's own shape, read back as untrusted JSON), verify
every referenced .pkg asset from BYTES (publish_catalogues.verify_asset — never
trusting the handoff's own literal record/matrix_row/artifact echoes), fan each
per-FreeBSD-major build out to every ROUTE varver sharing that major, then assemble
nightly/<varver>/ catalogues with retention
(catalogue_assembly.prune_retained/regenerate_catalogue/verify_multi_destination_identity
— reused, never re-derived). No git, no network.

Fixture .pkg archives mirror tests/test_publish_release.py's _wrap_canonical_pkg /
_wrap_dependency_pkg (duplicated here, matching this repo's per-file fixture
convention) but WITHOUT the tagged -<Variant>-<pfsense_version> suffix: Nightly's
canonical/dependency declared names equal the package's own manifest identity.
Build records and handoffs carry a stateless timestamp-plus-source-SHA version.
Handoffs are assembled via nightly_provenance.build_handoff itself wherever the
scenario is a legitimate one; hostile/forged scenarios mutate a valid handoff's OWN
dict after the fact (JSON round-tripped, `_mutate`), since build_handoff's own
validation would otherwise refuse to construct them honestly.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import itertools
import json
import os
import sys
import tarfile
import tempfile
import unittest
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalogue_assembly as ca
import nightly_provenance as np
import publish_catalogues as pc
import publish_nightly as pn
import publish_release as pr
import test_build_repo_portable as tbrp
from _srcrepo import SourceRepoError, resolve_src_root

try:
    _SRC_ROOT = resolve_src_root()
    _ENGINE = pc.load_engine(_SRC_ROOT)
    _ENGINE_SKIP_REASON = ""
except SourceRepoError as exc:  # pragma: no cover - environment gap, not a behaviour regression
    _SRC_ROOT = None
    _ENGINE = None
    _ENGINE_SKIP_REASON = str(exc)

_requires_engine = unittest.skipIf(_ENGINE is None, _ENGINE_SKIP_REASON)

_REPO = pc.EXPECTED_SOURCE_REPOSITORY
_RUN_ID = "555000111:1"
_SOURCE_SHA = "a" * 40
_PORTS_SHA = "b" * 40
_TOOLS_SHA = "e" * 40
_MATRIX_SHA = "d" * 40
_MATRIX_DIGEST = "c" * 64
_EPOCH = 1_800_000_000

_pkg_counter = itertools.count()


# --------------------------------------------------------------------------- #
# ROUTE/BUILD matrix rows — mirrors tests/test_publish_release.py's ROW_* shape.
# --------------------------------------------------------------------------- #


def _row(
    *,
    freebsd_major: str = "15",
    pfsense_version: str = "2.8",
    variant: str = "CE",
    extra_pkgs: Sequence[str] = (),
    role: str | None = None,
) -> dict[str, object]:
    row: dict[str, object] = {
        "pfsense_version": pfsense_version,
        "channel": variant,
        "freebsd_version": f"{freebsd_major}.0-RELEASE",
        "freebsd_major": freebsd_major,
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": variant,
        "status": "active",
        "extra_pkgs": list(extra_pkgs),
    }
    if role is not None:
        row["role"] = role
    return row


ROW_CE15 = _row(freebsd_major="15", pfsense_version="2.8", variant="CE", extra_pkgs=["textproc/py-charset-normalizer"])
ROW_CE15_NO_EXTRA = _row(freebsd_major="15", pfsense_version="2.8", variant="CE")
ROW_PLUS16_03 = _row(freebsd_major="16", pfsense_version="26.03", variant="Plus")
ROW_PLUS16_07 = _row(freebsd_major="16", pfsense_version="26.07", variant="Plus")
ROW_PLUS15_03 = _row(freebsd_major="15", pfsense_version="26.03", variant="Plus")
ROW_ROUTE_ONLY_17 = _row(freebsd_major="17", pfsense_version="17.0", variant="CE", role="route-only")
# Same major as ROW_CE15, ALSO declaring the charset extra — two build-role ROUTE
# rows sharing one leg, both declaring the dep (issue #2468 coverage).
ROW_CE15_29 = _row(
    freebsd_major="15", pfsense_version="2.9", variant="CE", extra_pkgs=["textproc/py-charset-normalizer"]
)


# --------------------------------------------------------------------------- #
# Snapshot + genuine .pkg archive fixture builders.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Snapshot:
    pkg_version: str
    source_sha: str
    ports_sha: str
    input_digest: str


def _snapshot(
    *,
    build_date: date = date(2026, 8, 4),
    source_sha: str = _SOURCE_SHA,
    ports_sha: str = _PORTS_SHA,
    matrix_digest: str = _MATRIX_DIGEST,
) -> _Snapshot:
    return _Snapshot(
        pkg_version=f"{build_date:%Y%m%d}120000.{source_sha[:7]}",
        source_sha=source_sha,
        ports_sha=ports_sha,
        input_digest=np.combined_nightly_input_digest(source_sha, ports_sha, matrix_digest),
    )


def _write_tar_pkg(path: Path, members: list[tuple[str, bytes, int, int]]) -> None:
    pfb_pkg = _ENGINE.pfb_pkg
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data, mode, mtime in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            info.mtime = mtime
            tf.addfile(info, io.BytesIO(data))
    path.write_bytes(pfb_pkg.zstd_compress(raw.getvalue(), pfb_pkg.PkgError, "zstd unavailable"))


def _wrap_canonical_pkg(directory: Path, record: dict, *, local_name: str) -> tuple[Path, str]:
    """A full, validate_project_pkg-shaped canonical .pkg carrying ``record`` as its
    pfb_build_record annotation, under its bare Nightly name (no -<Variant>-<version>
    suffix). Returns (path, sha256 of the bytes)."""
    pfb_pkg = _ENGINE.pfb_pkg
    row = record["matrix_row"]
    version = record["canonical_package_version"]
    epoch = record["source_date_epoch"]
    major = row["freebsd_major"]

    payload = {
        pfb_pkg._INFO_PATH: (
            f"<pfsensepkgs><package><name>pfBlockerNG</name><version>{version}</version></package></pfsensepkgs>"
        ).encode(),
        "/usr/local/pkg/pfblockerng/pfb_stub.py": b"print('ok')\n",
    }
    common = {
        "name": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "origin": "net/pfSense-pkg-pfBlockerNG",
        "version": version,
        "abi": f"FreeBSD:{major}:*",
        "arch": f"freebsd:{major}:*",
        "prefix": "/usr/local",
        "annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: json.dumps(record, separators=(",", ":"), sort_keys=True)},
    }
    php_dep = "php" + row["php_version"].replace(".", "")
    python_dep = "python" + row["py_flavor"][2:]
    deps = {
        php_dep: {"origin": f"lang/{php_dep}", "version": "1.0"},
        python_dep: {"origin": f"lang/{python_dep}", "version": "1.0"},
    }
    files = {
        name: {
            "sum": "1$" + hashlib.sha256(data).hexdigest(),
            "perm": "0644",
            "mtime": epoch,
            "size": len(data),
        }
        for name, data in payload.items()
    }
    full = {
        **common,
        "deps": deps,
        "files": files,
        "scripts": {
            "install": "#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n",
            "deinstall": "#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n",
        },
    }
    compact = {**common, "deps": deps}

    members = [
        ("+COMPACT_MANIFEST", json.dumps(compact, separators=(",", ":")).encode(), 0o644, 0),
        ("+MANIFEST", json.dumps(full, separators=(",", ":")).encode(), 0o644, 0),
    ]
    members.extend((name, data, 0o644, epoch) for name, data in payload.items())
    path = directory / local_name
    _write_tar_pkg(path, members)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _wrap_dependency_pkg(
    directory: Path,
    *,
    name: str,
    version: str,
    abi: str,
    local_name: str,
    origin: str | None = None,
    payload: dict[str, bytes] | None = None,
) -> tuple[Path, str]:
    manifest = {"name": name, "version": version, "abi": abi, "origin": origin or f"textproc/{name}"}
    compact = json.dumps(manifest, separators=(",", ":")).encode()
    members = [("+COMPACT_MANIFEST", compact, 0o644, 0)]
    # Extra members vary the archive BYTES under an identical manifest identity —
    # how a nightly rebuild of the same name-version ends up byte-distinct.
    members.extend((member, data, 0o644, 0) for member, data in (payload or {}).items())
    path = directory / local_name
    _write_tar_pkg(path, members)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# Leg / handoff assembly — one _LegSpec per BUILD major, folded into a genuine
# nightly_provenance.build_handoff() call.
# --------------------------------------------------------------------------- #


_CHARSET_DEP_SPEC: tuple[str, str] = ("py311-charset-normalizer", "3.4.0")
_CHARSET_ORIGIN = "textproc/py-charset-normalizer"


@dataclass(frozen=True)
class _LegSpec:
    row: dict[str, object]
    # None = derive from row extra_pkgs (issue #2405: count must match).
    dep_specs: Sequence[tuple[str, str]] | None = None
    source_date_epoch: int = _EPOCH
    # Extra archive member(s) so a rebuilt dep of the SAME name-version ends up
    # byte-distinct from a prior leg's — issue #2468's place-if-missing rule.
    dep_payload: dict[str, bytes] | None = None


def _resolved_dep_specs(spec: _LegSpec) -> Sequence[tuple[str, str]]:
    if spec.dep_specs is not None:
        return spec.dep_specs
    raw_extras = spec.row.get("extra_pkgs") or []
    extras = list(raw_extras) if isinstance(raw_extras, (list, tuple)) else []
    if extras == [_CHARSET_ORIGIN]:
        return (_CHARSET_DEP_SPEC,)
    if extras:
        raise AssertionError(f"fixture has no default dep for extra_pkgs={extras!r}")
    return ()


def _make_record(snapshot: _Snapshot, row: dict[str, object], epoch: int = _EPOCH) -> dict[str, object]:
    return np.make_build_record(
        pkg_version=snapshot.pkg_version,
        source_sha=snapshot.source_sha,
        ports_sha=snapshot.ports_sha,
        matrix_row=row,
        source_date_epoch=epoch,
    )


def _build_leg_result(snapshot: Any, spec: _LegSpec, *, assets_root: Path) -> dict[str, Any]:
    """Mint one leg's genuine record + canonical/dep .pkg archives under
    assets_root/nightly-result-<major>/, and return the handoff-shaped `result` dict
    nightly_provenance.build_handoff itself expects as one entry of `results`."""
    major = str(spec.row["freebsd_major"])
    legdir = assets_root / f"{pn._LEG_DIR_PREFIX}{major}"
    legdir.mkdir(parents=True, exist_ok=True)
    record = _make_record(snapshot, spec.row, spec.source_date_epoch)
    canonical_name = f"{_ENGINE.pfb_pkg.CANONICAL_EMITTED_IDENTITY}-{snapshot.pkg_version}.pkg"
    _path, digest = _wrap_canonical_pkg(legdir, record, local_name=canonical_name)
    dep_artifacts = []
    for name, version in _resolved_dep_specs(spec):
        dep_name = f"{name}-{version}.pkg"
        _dep_path, dep_digest = _wrap_dependency_pkg(
            legdir, name=name, version=version, abi=f"FreeBSD:{major}:*", local_name=dep_name, payload=spec.dep_payload
        )
        dep_artifacts.append({"abi": f"FreeBSD:{major}:*", "name": dep_name, "sha256": dep_digest})
    return {
        "matrix_row": spec.row,
        "record": record,
        "artifact": {"abi": f"FreeBSD:{major}:*", "name": canonical_name, "sha256": digest},
        "dep_artifacts": dep_artifacts,
    }


def _build_handoff(
    snapshot: Any,
    *,
    legs: Sequence[_LegSpec],
    route_rows: Sequence[dict[str, object]],
    assets_root: Path,
    run_id: str = _RUN_ID,
    source_sha: str = _SOURCE_SHA,
    ports_sha: str = _PORTS_SHA,
) -> dict[str, Any]:
    results = [_build_leg_result(snapshot, spec, assets_root=assets_root) for spec in legs]
    build_rows = [spec.row for spec in legs]
    return np.build_handoff(
        pkg_version=snapshot.pkg_version,
        build_rows=build_rows,
        route_rows=list(route_rows),
        results=results,
        source_sha=source_sha,
        ports_sha=ports_sha,
        tools_sha=_TOOLS_SHA,
        matrix_sha=_MATRIX_SHA,
        matrix_digest=_MATRIX_DIGEST,
        run_id=run_id,
    )


def _mutate(handoff: dict[str, Any]) -> dict[str, Any]:
    """A fully independent, mutable deep copy (JSON round-trip)."""
    return json.loads(json.dumps(handoff))


def _run(
    *,
    handoff: dict[str, Any],
    results_dir: Path,
    pkg_repo: Path,
    source_run_id: str = _RUN_ID,
    sign_key: Path | None = None,
) -> pr.PublishReport:
    handoff_path = results_dir.parent / f"handoff-{next(_pkg_counter)}.json"
    handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
    return pn.run(
        handoff_path=handoff_path,
        results_dir=results_dir,
        pkg_repo=pkg_repo,
        source_run_id=source_run_id,
        engine=_ENGINE,
        sign_key=sign_key,
    )


class _TempDirTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="pub-nightly-test-")
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.pkg_repo = self.tmp / "pkg-repo"
        self._dir_counter = itertools.count()

    def new_results_dir(self) -> Path:
        results_dir = self.tmp / f"results-{next(self._dir_counter)}"
        results_dir.mkdir(parents=True)
        return results_dir

    def base_handoff(self) -> tuple[dict[str, Any], Path, Any]:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir
        )
        return handoff, results_dir, snapshot


# --------------------------------------------------------------------------- #
# T1 — happy fan-out: 2 legs, 3 ROUTE rows -> 3 catalogues.
# --------------------------------------------------------------------------- #


class HappyFanOutTests(_TempDirTestCase):
    @_requires_engine
    def test_two_legs_three_route_rows_three_catalogues(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        legs = [
            _LegSpec(row=ROW_CE15, dep_specs=[("py311-charset-normalizer", "3.4.0")]),
            _LegSpec(row=ROW_PLUS16_03),
        ]
        route_rows = [ROW_CE15, ROW_PLUS16_03, ROW_PLUS16_07]
        handoff = _build_handoff(snapshot, legs=legs, route_rows=route_rows, assets_root=results_dir)

        report = _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)

        self.assertEqual(
            set(report.touched),
            {("nightly", "ce-2.8"), ("nightly", "plus-26.03"), ("nightly", "plus-26.07")},
        )
        docs = self.pkg_repo / "docs" / "nightly"
        canonical_name = f"pfSense-pkg-pfBlockerNG-{snapshot.pkg_version}.pkg"
        self.assertTrue((docs / "ce-2.8" / canonical_name).is_file())
        self.assertTrue((docs / "ce-2.8" / "py311-charset-normalizer-3.4.0.pkg").is_file())
        self.assertTrue((docs / "plus-26.03" / canonical_name).is_file())
        self.assertTrue((docs / "plus-26.07" / canonical_name).is_file())
        self.assertFalse((docs / "plus-26.03" / "py311-charset-normalizer-3.4.0.pkg").exists())
        self.assertFalse((docs / "plus-26.07" / "py311-charset-normalizer-3.4.0.pkg").exists())
        self.assertEqual(
            (docs / "plus-26.03" / canonical_name).read_bytes(),
            (docs / "plus-26.07" / canonical_name).read_bytes(),
        )
        for varver in ("ce-2.8", "plus-26.03", "plus-26.07"):
            self.assertTrue((docs / varver / "meta.conf").is_file(), varver)
            self.assertTrue((docs / varver / "data.pkg").is_file(), varver)
            self.assertTrue((docs / varver / "packagesite.pkg").is_file(), varver)


# --------------------------------------------------------------------------- #
# T2 — identical rerun is a NOOP.
# --------------------------------------------------------------------------- #


class NoopTests(_TempDirTestCase):
    @_requires_engine
    def test_identical_rerun_is_noop(self) -> None:
        handoff, results_dir, snapshot = self.base_handoff()
        first = _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertTrue(first.touched)

        catalogue_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        canonical_name = f"pfSense-pkg-pfBlockerNG-{snapshot.pkg_version}.pkg"
        before_mtime = (catalogue_dir / canonical_name).stat().st_mtime_ns
        before_bytes = (catalogue_dir / canonical_name).read_bytes()

        second = _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)

        self.assertEqual(second.touched, ())
        self.assertTrue(second.noop)
        self.assertEqual(
            second.describe(),
            ["NOOP: every destination already matches this run's verified assets"],
        )
        self.assertEqual((catalogue_dir / canonical_name).stat().st_mtime_ns, before_mtime)
        self.assertEqual((catalogue_dir / canonical_name).read_bytes(), before_bytes)


# --------------------------------------------------------------------------- #
# T3 — same version, different bytes already at a destination: fail closed.
# --------------------------------------------------------------------------- #


class ConflictTests(_TempDirTestCase):
    @_requires_engine
    def test_same_version_different_bytes_rejected(self) -> None:
        results_dir_1 = self.new_results_dir()
        snapshot = _snapshot()
        handoff_1 = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir_1
        )
        first = _run(handoff=handoff_1, results_dir=results_dir_1, pkg_repo=self.pkg_repo)
        self.assertEqual(first.touched, (("nightly", "ce-2.8"),))

        catalogue_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        canonical_name = f"pfSense-pkg-pfBlockerNG-{snapshot.pkg_version}.pkg"
        original_bytes = (catalogue_dir / canonical_name).read_bytes()

        # SAME snapshot (same day/version, same source_sha/ports_sha) but a
        # DIFFERENT source_date_epoch -- genuinely different archive bytes under the
        # identical canonical name, with every OTHER cross-checked field unchanged.
        results_dir_2 = self.new_results_dir()
        handoff_2 = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_CE15, source_date_epoch=_EPOCH + 1)],
            route_rows=[ROW_CE15],
            assets_root=results_dir_2,
        )

        with self.assertRaises(pr.DestinationConflictError) as ctx:
            _run(handoff=handoff_2, results_dir=results_dir_2, pkg_repo=self.pkg_repo)
        self.assertIn(str(catalogue_dir / canonical_name), str(ctx.exception))
        self.assertEqual((catalogue_dir / canonical_name).read_bytes(), original_bytes)


# --------------------------------------------------------------------------- #
# T4 — a destination holding a NEWER version rejects an older/absent incoming
# version BEFORE any write.
# --------------------------------------------------------------------------- #


class StaleTests(_TempDirTestCase):
    @_requires_engine
    def test_older_absent_version_rejected_before_any_write(self) -> None:
        newer_alloc = _snapshot(build_date=date(2026, 8, 10))
        results_dir_1 = self.new_results_dir()
        handoff_1 = _build_handoff(
            newer_alloc, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir_1
        )
        first = _run(handoff=handoff_1, results_dir=results_dir_1, pkg_repo=self.pkg_repo)
        self.assertTrue(first.touched)

        catalogue_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        before = {p.name: p.read_bytes() for p in catalogue_dir.iterdir()}

        older_alloc = _snapshot(build_date=date(2026, 8, 5))
        results_dir_2 = self.new_results_dir()
        handoff_2 = _build_handoff(
            older_alloc, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir_2
        )

        with self.assertRaises(pn.StaleNightlyError) as ctx:
            _run(handoff=handoff_2, results_dir=results_dir_2, pkg_repo=self.pkg_repo)
        self.assertIn("stale", str(ctx.exception).lower())

        after = {p.name: p.read_bytes() for p in catalogue_dir.iterdir()}
        self.assertEqual(after, before)

    @_requires_engine
    def test_published_manifest_missing_version_rejected_cleanly(self) -> None:
        """N3b: a catalogue-resident canonical .pkg whose manifest somehow lacks
        'version' (a corrupt or foreign write -- this publisher's own write
        path always carries one) must reject with a clean PublishNightlyError
        naming the corrupt file, not a raw KeyError out of
        manifest["version"]. The fixture writes the tar directly (bypassing
        _wrap_canonical_pkg, which always injects version) since that is the
        only way to construct this shape."""
        handoff, results_dir, _alloc = self.base_handoff()
        _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)

        catalogue_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        corrupt_name = "pfSense-pkg-pfBlockerNG-99.99.9999.pkg"
        corrupt_path = catalogue_dir / corrupt_name
        manifest = {"name": _ENGINE.pfb_pkg.CANONICAL_EMITTED_IDENTITY, "abi": "FreeBSD:15:*"}
        _write_tar_pkg(
            corrupt_path,
            [("+COMPACT_MANIFEST", json.dumps(manifest, separators=(",", ":")).encode(), 0o644, 0)],
        )

        newer_alloc = _snapshot(build_date=date(2026, 8, 20))
        results_dir_2 = self.new_results_dir()
        handoff_2 = _build_handoff(
            newer_alloc, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir_2
        )

        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=handoff_2, results_dir=results_dir_2, pkg_repo=self.pkg_repo)
        self.assertIn(str(corrupt_path), str(ctx.exception))


# --------------------------------------------------------------------------- #
# T5 — retention: keep+1 canonical generations published sequentially, oldest
# evicted; the charset extra (declared on every CE row, issue #2405) survives.
# --------------------------------------------------------------------------- #


class RetentionTests(_TempDirTestCase):
    @_requires_engine
    def test_retention_evicts_oldest_canonical_dep_survives(self) -> None:
        keep = ca.DEFAULT_RETENTION_KEEP
        catalogue_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        dep_name = "py311-charset-normalizer-3.4.0.pkg"
        first_version = None
        for seq in range(keep + 1):
            snapshot = _snapshot(build_date=date(2026, 8, 1 + seq))
            if seq == 0:
                first_version = snapshot.pkg_version
            results_dir = self.new_results_dir()
            handoff = _build_handoff(
                snapshot,
                legs=[_LegSpec(row=ROW_CE15)],
                route_rows=[ROW_CE15],
                assets_root=results_dir,
            )
            _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)

        remaining = sorted(p.name for p in catalogue_dir.glob("pfSense-pkg-pfBlockerNG-*.pkg"))
        self.assertEqual(len(remaining), keep)
        self.assertNotIn(f"pfSense-pkg-pfBlockerNG-{first_version}.pkg", remaining)
        self.assertTrue((catalogue_dir / dep_name).is_file())


# --------------------------------------------------------------------------- #
# issue #2468 nightly analogue: dependency identity = filename, place-if-missing,
# never byte-compared or overwritten. Nightly rebuilds its dep every run.
# --------------------------------------------------------------------------- #


class DependencyPlaceIfMissingTests(_TempDirTestCase):
    @_requires_engine
    def test_rebuilt_dependency_different_bytes_publishes_without_conflict(self) -> None:
        """RED CANARY (issue #2468), nightly analogue: Nightly rebuilds its
        dependency every run from whatever source commit triggered it — new archive
        bytes under the identical name-version is expected, not an error. A second
        Nightly run publishing a byte-different rebuild of the same dep must succeed
        without DestinationConflictError, and the already-published dep bytes must
        stay untouched (place-if-missing, never compared, never overwritten)."""
        handoff, results_dir, _snap = self.base_handoff()
        first = _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertTrue(first.touched)

        catalogue_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        dep_path = catalogue_dir / "py311-charset-normalizer-3.4.0.pkg"
        original_dep_bytes = dep_path.read_bytes()

        newer = _snapshot(build_date=date(2026, 8, 5))
        results_dir_2 = self.new_results_dir()
        handoff_2 = _build_handoff(
            newer,
            legs=[_LegSpec(row=ROW_CE15, dep_payload={"filler.bin": b"rebuilt-from-new-source-commit"})],
            route_rows=[ROW_CE15],
            assets_root=results_dir_2,
        )

        second = _run(handoff=handoff_2, results_dir=results_dir_2, pkg_repo=self.pkg_repo)

        self.assertTrue(second.touched)
        canonical_name = f"pfSense-pkg-pfBlockerNG-{newer.pkg_version}.pkg"
        self.assertTrue((catalogue_dir / canonical_name).is_file())
        self.assertEqual(dep_path.read_bytes(), original_dep_bytes)

    @_requires_engine
    def test_dep_already_different_at_one_varver_does_not_trip_identity_check(self) -> None:
        """issue #2468: two build-role ROUTE rows of one major (ce-2.8 + ce-2.9) both
        declare the dep, so one leg's dep artifact reaches two catalogues. When one of
        them already holds a byte-different build of that same name-version, the run
        must still succeed: dependency bytes are deliberately NOT part of the
        multi-destination fan-out identity invariant, which covers the canonical
        package alone."""
        stale_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        stale_dir.mkdir(parents=True)
        stale_path, _digest = _wrap_dependency_pkg(
            stale_dir,
            name=_CHARSET_NAME,
            version="3.4.0",
            abi="FreeBSD:15:*",
            local_name=_CHARSET_PKG,
            payload={"filler.bin": b"an-earlier-nights-build"},
        )
        stale_bytes = stale_path.read_bytes()

        results_dir = self.new_results_dir()
        handoff = _build_handoff(
            _snapshot(),
            legs=[_LegSpec(row=ROW_CE15)],
            route_rows=[ROW_CE15, ROW_CE15_29],
            assets_root=results_dir,
        )
        report = _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)

        self.assertEqual(set(report.touched), {("nightly", "ce-2.8"), ("nightly", "ce-2.9")})
        docs = self.pkg_repo / "docs" / "nightly"
        self.assertEqual((docs / "ce-2.8" / _CHARSET_PKG).read_bytes(), stale_bytes)  # left as it was
        fresh = docs / "ce-2.9" / _CHARSET_PKG
        self.assertTrue(fresh.is_file())
        self.assertNotEqual(fresh.read_bytes(), stale_bytes)  # this run's own build, placed where missing

    @_requires_engine
    def test_undeclared_same_name_leftover_replaced_by_this_runs_dependency(self) -> None:
        """A Nightly destination holding a same-name dependency whose origin the row no
        longer declares (the port moved category, issue #2403) must end ONE run
        advertising the dependency this run verified — place-if-missing and eviction
        together may never leave the catalogue with the extra silently absent."""
        dest = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        dest.mkdir(parents=True)
        _wrap_dependency_pkg(
            dest,
            name=_CHARSET_NAME,
            version="3.4.0",
            abi="FreeBSD:15:*",
            local_name=_CHARSET_PKG,
            origin="www/py-charset-normalizer",
            payload={"filler.bin": b"leftover-from-the-other-category"},
        )

        handoff, results_dir, _snap = self.base_handoff()
        report = _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)

        self.assertEqual(report.touched, (("nightly", "ce-2.8"),))
        published = dest / _CHARSET_PKG
        self.assertTrue(published.is_file(), "this run's verified dependency is missing from the catalogue")
        self.assertEqual(
            _ENGINE.pfb_pkg.read_compact_manifest(published)["origin"],
            f"textproc/{_CHARSET_NAME}",
        )
        self.assertIn(_CHARSET_NAME, _packagesite_names(dest))


# --------------------------------------------------------------------------- #
# T6 — handoff integrity rejections.
# --------------------------------------------------------------------------- #


class HandoffIntegrityTests(_TempDirTestCase):
    @_requires_engine
    def test_intake_kind_is_nightly(self) -> None:
        intake = pc.parse_intake(_REPO, "", "", '["nightly"]', _RUN_ID)
        self.assertEqual(intake.kind, "nightly")

    @_requires_engine
    def test_sha256_mismatch_vs_file_bytes_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        mutated["builds"][0]["artifact"]["sha256"] = "0" * 64
        with self.assertRaises(pc.AssetVerificationError):
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)

    @_requires_engine
    def test_record_version_mismatches_snapshot_rejected(self) -> None:
        results_dir = self.new_results_dir()
        real_alloc = _snapshot(build_date=date(2026, 8, 4))
        forged_alloc = _snapshot(build_date=date(2026, 8, 9))
        handoff = _build_handoff(
            real_alloc, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir
        )
        legdir = results_dir / f"{pn._LEG_DIR_PREFIX}15"
        forged_record = _make_record(forged_alloc, ROW_CE15)
        forged_name = f"pfSense-pkg-pfBlockerNG-{forged_alloc.pkg_version}.pkg"
        _path, forged_digest = _wrap_canonical_pkg(legdir, forged_record, local_name=forged_name)

        mutated = _mutate(handoff)
        mutated["builds"][0]["artifact"] = {"abi": "FreeBSD:15:*", "name": forged_name, "sha256": forged_digest}

        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("handoff pkg_version", str(ctx.exception))

    @_requires_engine
    def test_run_id_mismatch_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo, source_run_id="some-other-run")
        self.assertIn("run_id", str(ctx.exception))

    @_requires_engine
    def test_kind_wrong_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        mutated["kind"] = "tagged-handoff"
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("kind", str(ctx.exception))

    @_requires_engine
    def test_schema_wrong_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        mutated["schema"] = 2
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("schema", str(ctx.exception))

    @_requires_engine
    def test_top_level_field_missing_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        del mutated["source_ref"]
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("exact fields", str(ctx.exception))

    @_requires_engine
    def test_top_level_field_extra_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        mutated["bogus"] = "nope"
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("exact fields", str(ctx.exception))

    @_requires_engine
    def test_build_entry_field_missing_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        del mutated["builds"][0]["dep_artifacts"]
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("build entry", str(ctx.exception))

    @_requires_engine
    def test_build_entry_field_extra_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        mutated["builds"][0]["bogus"] = 1
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("build entry", str(ctx.exception))

    @_requires_engine
    def test_duplicate_build_majors_rejected(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_CE15), _LegSpec(row=ROW_PLUS16_03)],
            route_rows=[ROW_CE15, ROW_PLUS16_03],
            assets_root=results_dir,
        )
        mutated = _mutate(handoff)
        mutated["builds"][1]["matrix_row"]["freebsd_major"] = mutated["builds"][0]["matrix_row"]["freebsd_major"]
        mutated["builds"][1]["matrix_row"]["freebsd_version"] = mutated["builds"][0]["matrix_row"]["freebsd_version"]
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("duplicate", str(ctx.exception))

    @_requires_engine
    def test_snapshot_source_sha_mismatch_top_level_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        mutated["source_sha"] = "f" * 40
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("source SHA", str(ctx.exception))

    @_requires_engine
    def test_snapshot_ports_sha_mismatch_top_level_rejected(self) -> None:
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        mutated["ports_sha"] = "f" * 40
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("ports_sha", str(ctx.exception))

    @_requires_engine
    def test_tampered_matrix_digest_input_digest_mismatch_rejected(self) -> None:
        """N2: re-run nightly_provenance.build_handoff's OWN input-digest
        cross-check at publish time too -- a handoff whose matrix_digest was
        swapped for a different (still well-formed) value no longer matches
        snapshot.input_digest, which build_handoff computed from the
        ORIGINAL matrix_digest at handoff-creation time. Without this
        re-check, a forged matrix_digest sails through untouched: nothing else
        in the handoff shape depends on it."""
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        self.assertNotEqual(mutated["matrix_digest"], "d" * 64)
        mutated["matrix_digest"] = "d" * 64
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("input_digest", str(ctx.exception))

    @_requires_engine
    def test_matrix_digest_malformed_shape_rejected(self) -> None:
        """N2: matrix_digest shape (lowercase 64-character hex) is validated
        BEFORE it is ever fed to combined_nightly_input_digest."""
        handoff, results_dir, _alloc = self.base_handoff()
        mutated = _mutate(handoff)
        mutated["matrix_digest"] = "not-hex"
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("matrix_digest", str(ctx.exception))


# --------------------------------------------------------------------------- #
# T7 — routing rejections.
# --------------------------------------------------------------------------- #


class RoutingTests(_TempDirTestCase):
    @_requires_engine
    def test_route_row_major_has_no_asset_rejected(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15, ROW_PLUS16_03], assets_root=results_dir
        )
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("no built asset", str(ctx.exception))

    @_requires_engine
    def test_canonical_asset_serving_zero_route_rows_rejected(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_CE15), _LegSpec(row=ROW_PLUS16_03)],
            route_rows=[ROW_CE15],
            assets_root=results_dir,
        )
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("serve no ROUTE build row", str(ctx.exception))

    @_requires_engine
    def test_two_legs_same_major_rejected_via_route_targets(self) -> None:
        """The routing-level defensive duplicate-major guard, exercised directly
        (bypassing handoff validation, which already has its OWN dup-major test
        above) via two hand-built VerifiedAsset/_Leg objects sharing one major."""
        snapshot = _snapshot()
        record_a = _make_record(snapshot, ROW_CE15)
        record_b = _make_record(snapshot, ROW_CE15, _EPOCH + 1)
        asset_a = pc.VerifiedAsset(
            asset_class="canonical",
            declared_name="a.pkg",
            canonical_name="a.pkg",
            work_path=Path("a.pkg"),
            sha256="0" * 64,
            manifest={},
            record=record_a,
        )
        asset_b = pc.VerifiedAsset(
            asset_class="canonical",
            declared_name="b.pkg",
            canonical_name="b.pkg",
            work_path=Path("b.pkg"),
            sha256="1" * 64,
            manifest={},
            record=record_b,
        )
        leg_a = pn._Leg(major="15", matrix_row=ROW_CE15, canonical=asset_a, dependencies=())
        leg_b = pn._Leg(major="15", matrix_row=ROW_CE15, canonical=asset_b, dependencies=())

        with self.assertRaises(pn.PublishNightlyError) as ctx:
            pn._route_targets(_ENGINE, [ROW_CE15], [leg_a, leg_b])
        self.assertIn("more than one built asset", str(ctx.exception))

    @_requires_engine
    def test_dep_abi_mismatch_rejected_via_route_targets(self) -> None:
        """N3a: a leg's dependency manifest ABI that does NOT belong to that
        leg's own FreeBSD major (a forged handoff -- a genuine
        nightly_provenance.build_handoff run would never construct this
        shape, since _validate_dep_artifacts pins every dep to the leg's own
        wildcard ABI) is rejected by _route_targets's own ABI cross-check,
        exercised directly via hand-built _Leg/VerifiedAsset objects, same
        idiom as test_two_legs_same_major_rejected_via_route_targets above."""
        snapshot = _snapshot()
        record = _make_record(snapshot, ROW_CE15)
        canonical = pc.VerifiedAsset(
            asset_class="canonical",
            declared_name="a.pkg",
            canonical_name="a.pkg",
            work_path=Path("a.pkg"),
            sha256="0" * 64,
            manifest={},
            record=record,
        )
        mismatched_dep = pc.VerifiedAsset(
            asset_class="dependency",
            declared_name="dep.pkg",
            canonical_name="dep.pkg",
            work_path=Path("dep.pkg"),
            sha256="1" * 64,
            manifest={"abi": "FreeBSD:16:*"},
        )
        leg = pn._Leg(major="15", matrix_row=ROW_CE15, canonical=canonical, dependencies=(mismatched_dep,))

        with self.assertRaises(pn.PublishNightlyError) as ctx:
            pn._route_targets(_ENGINE, [ROW_CE15], [leg])
        self.assertIn("dependency ABI does not match FreeBSD major", str(ctx.exception))


# --------------------------------------------------------------------------- #
# T8 — dependency verification failures.
# --------------------------------------------------------------------------- #


class DependencyTests(_TempDirTestCase):
    @_requires_engine
    def test_dep_file_missing_from_leg_dir_rejected(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_CE15, dep_specs=[("py311-charset-normalizer", "3.4.0")])],
            route_rows=[ROW_CE15],
            assets_root=results_dir,
        )
        (results_dir / f"{pn._LEG_DIR_PREFIX}15" / "py311-charset-normalizer-3.4.0.pkg").unlink()
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("missing dependency asset", str(ctx.exception))

    @_requires_engine
    def test_dep_sha_mismatch_rejected(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_CE15, dep_specs=[("py311-charset-normalizer", "3.4.0")])],
            route_rows=[ROW_CE15],
            assets_root=results_dir,
        )
        mutated = _mutate(handoff)
        mutated["builds"][0]["dep_artifacts"][0]["sha256"] = "0" * 64
        with self.assertRaises(pc.AssetVerificationError):
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)

    @_requires_engine
    def test_dep_tagged_style_suffixed_name_rejected(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_CE15, dep_specs=[("py311-charset-normalizer", "3.4.0")])],
            route_rows=[ROW_CE15],
            assets_root=results_dir,
        )
        legdir = results_dir / f"{pn._LEG_DIR_PREFIX}15"
        suffixed_name = "py311-charset-normalizer-3.4.0-CE-2.8.pkg"
        (legdir / "py311-charset-normalizer-3.4.0.pkg").rename(legdir / suffixed_name)
        mutated = _mutate(handoff)
        mutated["builds"][0]["dep_artifacts"][0]["name"] = suffixed_name
        with self.assertRaises(pc.AssetVerificationError) as ctx:
            _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("declared name", str(ctx.exception))


# --------------------------------------------------------------------------- #
# T10 — a route-only row is never targeted, and errors on nothing.
# --------------------------------------------------------------------------- #


class RouteOnlyTests(_TempDirTestCase):
    @_requires_engine
    def test_route_only_row_not_targeted_no_error(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15, ROW_ROUTE_ONLY_17], assets_root=results_dir
        )
        report = _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertEqual(report.touched, (("nightly", "ce-2.8"),))
        self.assertFalse((self.pkg_repo / "docs" / "nightly" / "ce-17.0").exists())


# --------------------------------------------------------------------------- #
# T11 — missing results dir / missing canonical file -> a clean rejection, not a
# raw OSError traceback.
# --------------------------------------------------------------------------- #


class MissingFileTests(_TempDirTestCase):
    @_requires_engine
    def test_missing_results_dir_clean_error(self) -> None:
        scratch = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=scratch)
        missing_dir = self.tmp / "does-not-exist"
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=handoff, results_dir=missing_dir, pkg_repo=self.pkg_repo)
        self.assertIn("missing canonical asset", str(ctx.exception))

    @_requires_engine
    def test_missing_canonical_file_clean_error(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir
        )
        canonical_name = f"pfSense-pkg-pfBlockerNG-{snapshot.pkg_version}.pkg"
        (results_dir / f"{pn._LEG_DIR_PREFIX}15" / canonical_name).unlink()
        with self.assertRaises(pn.PublishNightlyError) as ctx:
            _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("missing canonical asset", str(ctx.exception))


# --------------------------------------------------------------------------- #
# T12 — hostile artifact names, rejected BEFORE any path join.
# --------------------------------------------------------------------------- #


class HostileNameTests(_TempDirTestCase):
    @_requires_engine
    def test_hostile_canonical_artifact_name_rejected(self) -> None:
        for hostile in ("../x.pkg", "a/b.pkg", "a\\b.pkg"):
            with self.subTest(hostile=hostile):
                results_dir = self.new_results_dir()
                snapshot = _snapshot()
                handoff = _build_handoff(
                    snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir
                )
                mutated = _mutate(handoff)
                mutated["builds"][0]["artifact"]["name"] = hostile
                with self.assertRaises((pc.AssetVerificationError, np.ProvenanceError)):
                    _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)

    @_requires_engine
    def test_hostile_dep_artifact_name_rejected(self) -> None:
        for hostile in ("../x.pkg", "a/b.pkg", "a\\b.pkg"):
            with self.subTest(hostile=hostile):
                results_dir = self.new_results_dir()
                snapshot = _snapshot()
                handoff = _build_handoff(
                    snapshot,
                    legs=[_LegSpec(row=ROW_CE15, dep_specs=[("py311-charset-normalizer", "3.4.0")])],
                    route_rows=[ROW_CE15],
                    assets_root=results_dir,
                )
                mutated = _mutate(handoff)
                mutated["builds"][0]["dep_artifacts"][0]["name"] = hostile
                with self.assertRaises((pc.AssetVerificationError, np.ProvenanceError)):
                    _run(handoff=mutated, results_dir=results_dir, pkg_repo=self.pkg_repo)


# --------------------------------------------------------------------------- #
# T13 — main() CLI wrapper.
# --------------------------------------------------------------------------- #


class MainCliTests(_TempDirTestCase):
    @_requires_engine
    def test_main_invalid_json_exit_1_with_error(self) -> None:
        results_dir = self.new_results_dir()
        handoff_path = self.tmp / "bad.json"
        handoff_path.write_text("not json", encoding="utf-8")
        argv = [
            "--handoff",
            str(handoff_path),
            "--results-dir",
            str(results_dir),
            "--pkg-repo",
            str(self.pkg_repo),
            "--source-run-id",
            _RUN_ID,
        ]
        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            code = pn.main(argv)
        self.assertEqual(code, 1)
        self.assertIn("::error::", err.getvalue())

    @_requires_engine
    def test_main_success_prints_updated_and_returns_zero(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir
        )
        handoff_path = self.tmp / "handoff.json"
        handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
        argv = [
            "--handoff",
            str(handoff_path),
            "--results-dir",
            str(results_dir),
            "--pkg-repo",
            str(self.pkg_repo),
            "--source-run-id",
            _RUN_ID,
        ]
        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            code = pn.main(argv)
        self.assertEqual(code, 0)
        self.assertIn("updated nightly/ce-2.8", out.getvalue())


# --------------------------------------------------------------------------- #
# --sign-key threading (issue #2675 step 1): run()/main() must reach
# catalogue_assembly.regenerate_catalogue with the caller's key, or with none at
# all when omitted. The signed wire format itself is test_catalogue_assembly.py's
# and test_build_repo_portable.py's own coverage — never re-derived here.
# --------------------------------------------------------------------------- #


class SignKeyThreadingTests(_TempDirTestCase):
    def _capture_sign_key(self) -> tuple[mock._patch, list[Path | None]]:
        seen: list[Path | None] = []
        real_regenerate = pn.ca.regenerate_catalogue

        def capturing_regenerate(
            site_root: str | Path, channel: str, varver: str, *, engine: pc.Engine, sign_key: Path | None = None
        ) -> None:
            seen.append(sign_key)
            real_regenerate(site_root, channel, varver, engine=engine)

        return mock.patch.object(pn.ca, "regenerate_catalogue", side_effect=capturing_regenerate), seen

    @_requires_engine
    def test_main_sign_key_flag_reaches_regenerate_catalogue(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir
        )
        handoff_path = self.tmp / "handoff.json"
        handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
        # A REAL key: publish() derives its public half up front, so a placeholder
        # would abort the run before the threading this test is about.
        key = tbrp._gen_key(self.tmp / "repo.key")
        argv = [
            "--handoff",
            str(handoff_path),
            "--results-dir",
            str(results_dir),
            "--pkg-repo",
            str(self.pkg_repo),
            "--source-run-id",
            _RUN_ID,
            "--sign-key",
            str(key),
        ]
        patcher, seen = self._capture_sign_key()
        with patcher, mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}):
            code = pn.main(argv)
        self.assertEqual(code, 0)
        self.assertEqual(seen, [key])

    @_requires_engine
    def test_main_without_sign_key_flag_passes_none(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir
        )
        handoff_path = self.tmp / "handoff.json"
        handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
        argv = [
            "--handoff",
            str(handoff_path),
            "--results-dir",
            str(results_dir),
            "--pkg-repo",
            str(self.pkg_repo),
            "--source-run-id",
            _RUN_ID,
        ]
        patcher, seen = self._capture_sign_key()
        with patcher, mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}):
            code = pn.main(argv)
        self.assertEqual(code, 0)
        self.assertEqual(seen, [None])


# --------------------------------------------------------------------------- #
# T14 — publish() must actually WIRE catalogue_assembly.verify_multi_destination_
# identity over a genuine Plus fan-out (plus-26.03 + plus-26.07, same canonical
# bytes), not merely have access to a function that works in isolation.
# --------------------------------------------------------------------------- #


class IdentityPostConditionTests(_TempDirTestCase):
    @_requires_engine
    def test_multi_destination_divergence_aborts_publish(self) -> None:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_PLUS16_03)],
            route_rows=[ROW_PLUS16_03, ROW_PLUS16_07],
            assets_root=results_dir,
        )
        canonical_name = f"pfSense-pkg-pfBlockerNG-{snapshot.pkg_version}.pkg"
        divergent_alloc = _snapshot(build_date=date(2026, 8, 20))
        divergent_dir = self.tmp / "divergent"
        divergent_dir.mkdir()
        divergent_record = _make_record(divergent_alloc, ROW_PLUS16_03)
        divergent_path, _digest = _wrap_canonical_pkg(divergent_dir, divergent_record, local_name="divergent.pkg")
        divergent_bytes = divergent_path.read_bytes()

        real_regenerate = pn.ca.regenerate_catalogue

        def corrupting_regenerate(
            site_root: str | Path, channel: str, varver: str, *, engine: pc.Engine, sign_key: Path | None = None
        ) -> None:
            real_regenerate(site_root, channel, varver, engine=engine)
            if varver == "plus-26.07":
                target = Path(site_root) / channel / varver / canonical_name
                target.write_bytes(divergent_bytes)

        with (
            mock.patch.object(pn.ca, "regenerate_catalogue", side_effect=corrupting_regenerate),
            self.assertRaises(pn.ca.CatalogueAssemblyError) as ctx,
        ):
            _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)
        self.assertIn("multi-destination identity violation", str(ctx.exception))


def _packagesite_names(catalogue_dir: Path) -> set[str]:
    catalog = catalogue_dir / "packagesite.pkg"
    data = _ENGINE.pfb_pkg.zstd_decompress(catalog.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        member = tf.extractfile("packagesite.yaml")
        assert member is not None
        raw = member.read().decode()
    return {json.loads(line)["name"] for line in raw.splitlines() if line}


_CHARSET_PKG = "py311-charset-normalizer-3.4.0.pkg"
_CHARSET_NAME = "py311-charset-normalizer"


class ExtraPkgsEvictionTests(_TempDirTestCase):
    """issue #2402: Nightly dest leftovers are unlinked before regenerate."""

    def _plant_charset(self, dest_dir: Path, *, major: str) -> None:
        dest_dir.mkdir(parents=True, exist_ok=True)
        _wrap_dependency_pkg(
            dest_dir,
            name=_CHARSET_NAME,
            version="3.4.0",
            abi=f"FreeBSD:{major}:*",
            local_name=_CHARSET_PKG,
        )

    @_requires_engine
    def test_stale_plus_extra_evicted_on_new_canonical(self) -> None:
        first = _snapshot(build_date=date(2026, 8, 4))
        results_1 = self.new_results_dir()
        handoff_1 = _build_handoff(
            first, legs=[_LegSpec(row=ROW_PLUS16_03)], route_rows=[ROW_PLUS16_03], assets_root=results_1
        )
        _run(handoff=handoff_1, results_dir=results_1, pkg_repo=self.pkg_repo)
        dest = self.pkg_repo / "docs" / "nightly" / "plus-26.03"
        self._plant_charset(dest, major="16")

        second = _snapshot(build_date=date(2026, 8, 5))
        results_2 = self.new_results_dir()
        handoff_2 = _build_handoff(
            second, legs=[_LegSpec(row=ROW_PLUS16_03)], route_rows=[ROW_PLUS16_03], assets_root=results_2
        )
        report = _run(handoff=handoff_2, results_dir=results_2, pkg_repo=self.pkg_repo)
        self.assertFalse(report.noop)
        self.assertFalse((dest / _CHARSET_PKG).exists())
        self.assertTrue((dest / f"pfSense-pkg-pfBlockerNG-{second.pkg_version}.pkg").is_file())
        self.assertNotIn(_CHARSET_NAME, _packagesite_names(dest))

    @_requires_engine
    def test_stale_plus_extra_evicted_on_exact_republish(self) -> None:
        snapshot = _snapshot()
        results_1 = self.new_results_dir()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_PLUS16_03)], route_rows=[ROW_PLUS16_03], assets_root=results_1
        )
        first = _run(handoff=handoff, results_dir=results_1, pkg_repo=self.pkg_repo)
        self.assertFalse(first.noop)
        dest = self.pkg_repo / "docs" / "nightly" / "plus-26.03"
        self._plant_charset(dest, major="16")

        results_2 = self.new_results_dir()
        handoff_2 = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_PLUS16_03)], route_rows=[ROW_PLUS16_03], assets_root=results_2
        )
        second = _run(handoff=handoff_2, results_dir=results_2, pkg_repo=self.pkg_repo)
        self.assertFalse(second.noop)
        self.assertFalse((dest / _CHARSET_PKG).exists())
        self.assertNotIn(_CHARSET_NAME, _packagesite_names(dest))

    @_requires_engine
    def test_declared_ce_extra_kept_on_new_canonical(self) -> None:
        first = _snapshot(build_date=date(2026, 8, 4))
        results_1 = self.new_results_dir()
        handoff_1 = _build_handoff(
            first,
            legs=[_LegSpec(row=ROW_CE15, dep_specs=[("py311-charset-normalizer", "3.4.0")])],
            route_rows=[ROW_CE15],
            assets_root=results_1,
        )
        _run(handoff=handoff_1, results_dir=results_1, pkg_repo=self.pkg_repo)
        dest = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        self.assertTrue((dest / _CHARSET_PKG).is_file())

        second = _snapshot(build_date=date(2026, 8, 5))
        results_2 = self.new_results_dir()
        handoff_2 = _build_handoff(second, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_2)
        _run(handoff=handoff_2, results_dir=results_2, pkg_repo=self.pkg_repo)
        self.assertTrue((dest / _CHARSET_PKG).is_file())
        self.assertIn(_CHARSET_NAME, _packagesite_names(dest))

    @_requires_engine
    def test_undeclared_ce_extra_evicted_when_row_drops_extra_pkgs(self) -> None:
        first = _snapshot(build_date=date(2026, 8, 4))
        results_1 = self.new_results_dir()
        handoff_1 = _build_handoff(
            first,
            legs=[_LegSpec(row=ROW_CE15, dep_specs=[("py311-charset-normalizer", "3.4.0")])],
            route_rows=[ROW_CE15],
            assets_root=results_1,
        )
        _run(handoff=handoff_1, results_dir=results_1, pkg_repo=self.pkg_repo)
        dest = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        self.assertTrue((dest / _CHARSET_PKG).is_file())

        second = _snapshot(build_date=date(2026, 8, 5))
        results_2 = self.new_results_dir()
        handoff_2 = _build_handoff(
            second, legs=[_LegSpec(row=ROW_CE15_NO_EXTRA)], route_rows=[ROW_CE15_NO_EXTRA], assets_root=results_2
        )
        _run(handoff=handoff_2, results_dir=results_2, pkg_repo=self.pkg_repo)
        self.assertFalse((dest / _CHARSET_PKG).exists())
        self.assertNotIn(_CHARSET_NAME, _packagesite_names(dest))


class SameMajorDestScopeTests(_TempDirTestCase):
    """issue #2403: one Nightly major fans to CE + Plus; extra follows extra_pkgs."""

    @_requires_engine
    def test_same_major_dep_not_published_to_row_with_empty_extra_pkgs(self) -> None:
        snapshot = _snapshot()
        results_dir = self.new_results_dir()
        handoff = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_CE15, dep_specs=[("py311-charset-normalizer", "3.4.0")])],
            route_rows=[ROW_CE15, ROW_PLUS15_03],
            assets_root=results_dir,
        )
        captured: dict[str, set[str]] = {}
        orig = pr._drop_assets

        def _spy(dest_dir: Path, asset_map: dict) -> bool:
            captured[dest_dir.name] = set(asset_map)
            return orig(dest_dir, asset_map)

        with mock.patch.object(pr, "_drop_assets", side_effect=_spy):
            _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)

        self.assertIn(_CHARSET_PKG, captured["ce-2.8"])
        self.assertNotIn(_CHARSET_PKG, captured["plus-26.03"])
        docs = self.pkg_repo / "docs" / "nightly"
        self.assertTrue((docs / "ce-2.8" / _CHARSET_PKG).is_file())
        self.assertFalse((docs / "plus-26.03" / _CHARSET_PKG).exists())
        self.assertIn(_CHARSET_NAME, _packagesite_names(docs / "ce-2.8"))
        self.assertNotIn(_CHARSET_NAME, _packagesite_names(docs / "plus-26.03"))

    @_requires_engine
    def test_two_same_major_rows_both_declaring_dep_both_receive_it(self) -> None:
        """issue #2468 coverage: two build-role ROUTE rows sharing one FreeBSD major
        (ce-2.8 + ce-2.9, both major 15), BOTH declaring the same extra_pkgs origin,
        both receive the identical dep bytes from the ONE leg that major built —
        _route_targets's existing per-row extra_pkgs gate is unchanged by this issue,
        only the place-if-missing rule for an already-published dep is new."""
        snapshot = _snapshot()
        results_dir = self.new_results_dir()
        handoff = _build_handoff(
            snapshot,
            legs=[_LegSpec(row=ROW_CE15)],
            route_rows=[ROW_CE15, ROW_CE15_29],
            assets_root=results_dir,
        )
        report = _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo)

        self.assertEqual(set(report.touched), {("nightly", "ce-2.8"), ("nightly", "ce-2.9")})
        docs = self.pkg_repo / "docs" / "nightly"
        self.assertTrue((docs / "ce-2.8" / _CHARSET_PKG).is_file())
        self.assertTrue((docs / "ce-2.9" / _CHARSET_PKG).is_file())
        self.assertEqual(
            (docs / "ce-2.8" / _CHARSET_PKG).read_bytes(),
            (docs / "ce-2.9" / _CHARSET_PKG).read_bytes(),
        )

    @_requires_engine
    def test_route_targets_continue_filter_required_for_same_major_plus(self) -> None:
        """Nightly dest attach must skip a dest whose row does not declare the extra."""
        source = inspect.getsource(pn._route_targets)
        self.assertIn("_row_declares_dep", source)
        self.assertIn("continue", source)


class ResignUnsignedCatalogueTests(_TempDirTestCase):
    """Nightly's mirror of publish_release's re-sign gate (issue #2675).

    Nightly rebuilds daily, so the unsigned-catalogue window is short here — but the
    gate lives in both publishers because a varver whose package set does not move
    (a retired FreeBSD major still being served) would otherwise never be re-signed.
    """

    def _publish(self, key: Path | None = None) -> pr.PublishReport:
        results_dir = self.new_results_dir()
        snapshot = _snapshot()
        handoff = _build_handoff(
            snapshot, legs=[_LegSpec(row=ROW_CE15)], route_rows=[ROW_CE15], assets_root=results_dir
        )
        return _run(handoff=handoff, results_dir=results_dir, pkg_repo=self.pkg_repo, sign_key=key)

    @_requires_engine
    def test_republish_with_a_key_signs_a_catalogue_that_has_no_signature(self) -> None:
        self.assertEqual(self._publish().touched, (("nightly", "ce-2.8"),))
        catalogue_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        self.assertEqual(tbrp._sig_members(catalogue_dir / "packagesite.pkg"), {})

        key = tbrp._gen_key(self.tmp / "repo.key")
        self.assertEqual(self._publish(key).touched, (("nightly", "ce-2.8"),))
        self.assertEqual(
            sorted(tbrp._sig_members(catalogue_dir / "packagesite.pkg")),
            ["packagesite.yaml.pub", "packagesite.yaml.sig"],
        )

    @_requires_engine
    def test_republish_with_the_same_key_is_a_noop(self) -> None:
        key = tbrp._gen_key(self.tmp / "repo.key")
        self.assertEqual(self._publish(key).touched, (("nightly", "ce-2.8"),))
        self.assertEqual(self._publish(key).touched, ())

    @_requires_engine
    def test_republish_after_key_rotation_resigns_with_the_new_key(self) -> None:
        catalogue_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        self._publish(tbrp._gen_key(self.tmp / "old.key"))
        first_pub = tbrp._sig_members(catalogue_dir / "packagesite.pkg")["packagesite.yaml.pub"]

        self.assertEqual(self._publish(tbrp._gen_key(self.tmp / "new.key")).touched, (("nightly", "ce-2.8"),))
        second_pub = tbrp._sig_members(catalogue_dir / "packagesite.pkg")["packagesite.yaml.pub"]
        self.assertNotEqual(first_pub, second_pub)


if __name__ == "__main__":
    unittest.main()
