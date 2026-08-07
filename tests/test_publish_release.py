"""Tests for scripts/publish_release.py — issue #2146 step R2 (tagged-release
publisher CLI): parse tagged intake, verify every downloaded .pkg asset against the
pinned ROUTE matrix (publish_catalogues.verify_asset/verify_run — S1, gated), then
assemble every (channel, varver) target this run's canonical assets cover
(catalogue_assembly.prune_retained/regenerate_catalogue/verify_multi_destination_identity
— S3, gated). No git — this module never shells out; the workflow owns commit/push.

No ledger — "already published" is read straight off the files already on disk, so
these tests exercise the tree as the source of truth: run publish_release.run() twice
with the same assets and assert nothing changes the second time, run it with a new
tag and assert the old generation survives retention, etc.

Fixture .pkg archives mirror tests/test_publish_catalogues.py's _wrap_canonical_pkg /
_wrap_dependency_pkg (full validate_project_pkg-shaped canonical archives, minimal
dependency archives) and _record (a genuine, build_input_digest-bound record) —
duplicated here rather than imported, matching this repo's existing per-file fixture
convention (test_catalogue_assembly.py does the same rather than cross-importing
test_publish_catalogues.py's private helpers).
"""

from __future__ import annotations

import hashlib
import io
import itertools
import json
import os
import sys
import tarfile
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalogue_assembly as ca
import publish_catalogues as pc
import publish_release as pr
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

# --------------------------------------------------------------------------- #
# The closed ROUTE matrix this ticket's coverage matrix names: ce-2.8 (FreeBSD 15,
# carries the one extra_pkgs dependency), plus-26.03 + plus-26.07 (both FreeBSD 16,
# no dependency) — plus one route-only row (a later-major frozen catalogue with no
# build this run) used only by the dependency-target-resolution rejection test.
# --------------------------------------------------------------------------- #

ROW_CE: dict[str, object] = {
    "pfsense_version": "2.8",
    "channel": "CE",
    "freebsd_version": "15.0-RELEASE",
    "freebsd_major": "15",
    "php_version": "8.3",
    "py_flavor": "py311",
    "variant": "CE",
    "status": "active",
    "extra_pkgs": ["textproc/py-charset-normalizer"],
}

ROW_CE_PATCH: dict[str, object] = {**ROW_CE, "pfsense_version": "2.8.1", "extra_pkgs": []}

ROW_PLUS_03: dict[str, object] = {
    "pfsense_version": "26.03",
    "channel": "Plus",
    "freebsd_version": "16.0-RELEASE",
    "freebsd_major": "16",
    "php_version": "8.3",
    "py_flavor": "py311",
    "variant": "Plus",
    "status": "active",
    "extra_pkgs": [],
}

ROW_PLUS_07: dict[str, object] = {**ROW_PLUS_03, "pfsense_version": "26.07"}

ROW_ROUTE_ONLY_17: dict[str, object] = {
    "pfsense_version": "17.0",
    "channel": "CE",
    "freebsd_version": "17.0-RELEASE",
    "freebsd_major": "17",
    "php_version": "8.3",
    "py_flavor": "py311",
    "variant": "CE",
    "status": "active",
    "extra_pkgs": [],
    "role": "route-only",
}

_THREE_ROWS = (ROW_CE, ROW_PLUS_03, ROW_PLUS_07)


# --------------------------------------------------------------------------- #
# Fixture builders — genuine records (build_input_digest via the engine), and
# pure-Python zstd-tar .pkg archives (mirrors test_publish_catalogues.py).
# --------------------------------------------------------------------------- #

_TAG_FOR_CHANNEL = {"stable": "v4.0.0", "testing": "v4.0.1.b1", "edge": "v4.0.0.b1"}
_pkg_counter = itertools.count()


def _record(
    *,
    channel: str = "edge",
    row: dict[str, object] | None = None,
    source_sha: str = "a" * 40,
    canonical_package_version: str | None = None,
    release_line: str | None = None,
    source_tag: str | None = None,
) -> dict:
    pfb_pkg = _ENGINE.pfb_pkg
    row = row or ROW_CE
    major_minor = ".".join(cast(str, row["pfsense_version"]).split(".")[:2])
    tag = source_tag or _TAG_FOR_CHANNEL[channel]
    info = pfb_pkg.parse_release_tag(tag, channel)
    native = (
        pfb_pkg.CANONICAL_EMITTED_IDENTITY if channel == "stable" else f"{pfb_pkg.CANONICAL_EMITTED_IDENTITY}-{channel}"
    )
    record = {
        "schema": 1,
        "channel": channel,
        "release_line": info.release_line if release_line is None else release_line,
        "classification": info.stage,
        "source_tag": tag,
        "source_sha": source_sha,
        "canonical_package_version": canonical_package_version or info.pkg_version,
        "native_recipe_identity": native,
        "emitted_identity": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "matrix_row": row,
        "freebsd_ports_sha": "b" * 64,
        "route": f"{channel}/{cast(str, row['variant']).lower()}-{major_minor}",
        "source_date_epoch": 0,
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    return record


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
    pfb_build_record annotation. Returns (path, sha256 of the bytes)."""
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
        (
            "+COMPACT_MANIFEST",
            json.dumps(compact, separators=(",", ":")).encode(),
            0o644,
            0,
        ),
        ("+MANIFEST", json.dumps(full, separators=(",", ":")).encode(), 0o644, 0),
    ]
    members.extend((name, data, 0o644, epoch) for name, data in payload.items())
    path = directory / local_name
    _write_tar_pkg(path, members)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _wrap_dependency_pkg(
    directory: Path,
    *,
    name: str = "py311-charset-normalizer",
    version: str = "3.4.0",
    abi: str = "FreeBSD:15:*",
    local_name: str,
    payload: dict[str, bytes] | None = None,
) -> tuple[Path, str]:
    manifest = {
        "name": name,
        "version": version,
        "abi": abi,
        "origin": f"textproc/{name}",
    }
    compact = json.dumps(manifest, separators=(",", ":")).encode()
    members = [("+COMPACT_MANIFEST", compact, 0o644, 0)]
    # Extra members vary the archive BYTES under an identical manifest identity —
    # how two builds of the same name-version end up byte-distinct.
    members.extend((member, data, 0o644, 0) for member, data in (payload or {}).items())
    path = directory / local_name
    _write_tar_pkg(path, members)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_declared_name(record: dict) -> str:
    row = record["matrix_row"]
    version = record["canonical_package_version"]
    return f"{_ENGINE.pfb_pkg.CANONICAL_EMITTED_IDENTITY}-{version}-{row['variant']}-{row['pfsense_version']}.pkg"


def _dependency_declared_name(*, name: str, version: str, row: dict) -> str:
    return f"{name}-{version}-{row['variant']}-{row['pfsense_version']}.pkg"


def _populate_assets_dir(
    assets_dir: Path,
    *,
    channel: str = "edge",
    rows: Sequence[dict[str, object]] = (ROW_CE,),
    source_tag: str | None = None,
    canonical_package_version: str | None = None,
    include_dependency: bool = True,
    dep_version: str = "3.4.0",
    dep_row: dict | None = None,
) -> dict[str, str]:
    """Write one canonical .pkg per row (+ one dependency .pkg, keyed to ``dep_row``
    or the first CE row) straight into ``assets_dir`` under their real declared
    Release-asset names, plus the digests.json sidecar. Returns the digests dict."""
    assets_dir.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}
    for row in rows:
        record = _record(
            channel=channel,
            row=row,
            source_tag=source_tag,
            canonical_package_version=canonical_package_version,
        )
        declared = _canonical_declared_name(record)
        _path, digest = _wrap_canonical_pkg(assets_dir, record, local_name=declared)
        digests[declared] = digest
    if include_dependency:
        row = dep_row or next(r for r in rows if r["variant"] == "CE")
        declared = _dependency_declared_name(name="py311-charset-normalizer", version=dep_version, row=row)
        _path, digest = _wrap_dependency_pkg(
            assets_dir,
            version=dep_version,
            abi=f"FreeBSD:{row['freebsd_major']}:*",
            local_name=declared,
        )
        digests[declared] = digest
    (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")
    return digests


def _run(
    *,
    pkg_repo: Path,
    assets_dir: Path,
    rows: Sequence[dict[str, object]],
    channel: str = "edge",
    destinations: str = '["edge"]',
    tag: str,
    release_id: str = "1",
    source_run_id: str = "10:1",
) -> pr.PublishReport:
    return pr.run(
        source_repository=_REPO,
        release_id=release_id,
        release_tag=tag,
        destinations=destinations,
        source_run_id=source_run_id,
        assets_dir=assets_dir,
        pkg_repo=pkg_repo,
        route_matrix=json.dumps(list(rows)),
        engine=_ENGINE,
    )


class _TempDirTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="pub-release-test-")
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.pkg_repo = self.tmp / "pkg-repo"
        self._assets_counter = itertools.count()

    def new_assets_dir(self) -> Path:
        return self.tmp / f"assets-{next(self._assets_counter)}"


# --------------------------------------------------------------------------- #
# Digest sidecar + asset discovery.
# --------------------------------------------------------------------------- #


class DigestSidecarTests(_TempDirTestCase):
    @_requires_engine
    def test_missing_digests_file_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                tag="v4.0.0.b1",
            )
        self.assertIn("cannot read", str(ctx.exception))

    @_requires_engine
    def test_malformed_json_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        (assets_dir / pr._DIGESTS_FILENAME).write_text("not json", encoding="utf-8")
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                tag="v4.0.0.b1",
            )
        self.assertIn("not valid JSON", str(ctx.exception))

    @_requires_engine
    def test_non_object_digests_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        (assets_dir / pr._DIGESTS_FILENAME).write_text("[]", encoding="utf-8")
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                tag="v4.0.0.b1",
            )
        self.assertIn("non-empty JSON object", str(ctx.exception))

    @_requires_engine
    def test_bad_sha_shape_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps({"a.pkg": "not-a-sha"}), encoding="utf-8")
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                tag="v4.0.0.b1",
            )
        self.assertIn("64 lowercase hex", str(ctx.exception))


class AssetDiscoveryTests(_TempDirTestCase):
    @_requires_engine
    def test_no_assets_at_all_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps({"phantom.pkg": "0" * 64}), encoding="utf-8")
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                tag="v4.0.0.b1",
            )
        self.assertIn("no .pkg assets found", str(ctx.exception))

    @_requires_engine
    def test_asset_missing_digest_entry_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        # Add a second .pkg with no corresponding digests.json entry.
        stray_record = _record(channel="edge", row=ROW_PLUS_03, source_tag="v4.0.0.b1")
        _wrap_canonical_pkg(assets_dir, stray_record, local_name="stray.pkg")
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE, ROW_PLUS_03),
                tag="v4.0.0.b1",
            )
        self.assertIn("no digests.json entry", str(ctx.exception))
        self.assertIn("stray.pkg", str(ctx.exception))
        self.assertTrue(digests)  # sanity: the fixture actually wrote something

    @_requires_engine
    def test_digest_entry_missing_file_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        digests["ghost.pkg"] = "0" * 64
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                tag="v4.0.0.b1",
            )
        self.assertIn("no matching asset file", str(ctx.exception))
        self.assertIn("ghost.pkg", str(ctx.exception))


# --------------------------------------------------------------------------- #
# Intake / ROUTE-matrix wiring rejections.
# --------------------------------------------------------------------------- #


class IntakeAndRouteMatrixTests(_TempDirTestCase):
    @_requires_engine
    def test_nightly_intake_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps({"x.pkg": "0" * 64}), encoding="utf-8")
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            pr.run(
                source_repository=_REPO,
                release_id="",
                release_tag="",
                destinations='["nightly"]',
                source_run_id="10:1",
                assets_dir=assets_dir,
                pkg_repo=self.pkg_repo,
                route_matrix=json.dumps([ROW_CE]),
                engine=_ENGINE,
            )
        self.assertIn("only handles tagged intake", str(ctx.exception))

    @_requires_engine
    def test_destination_outside_closed_five_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        with self.assertRaises(pc.IntakeError):
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                destinations='["stable","edge"]',
                tag="v4.0.0",
            )

    @_requires_engine
    def test_route_matrix_not_json_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            pr.run(
                source_repository=_REPO,
                release_id="1",
                release_tag="v4.0.0.b1",
                destinations='["edge"]',
                source_run_id="10:1",
                assets_dir=assets_dir,
                pkg_repo=self.pkg_repo,
                route_matrix="not json",
                engine=_ENGINE,
            )
        self.assertIn("not valid JSON", str(ctx.exception))

    @_requires_engine
    def test_route_matrix_empty_array_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            pr.run(
                source_repository=_REPO,
                release_id="1",
                release_tag="v4.0.0.b1",
                destinations='["edge"]',
                source_run_id="10:1",
                assets_dir=assets_dir,
                pkg_repo=self.pkg_repo,
                route_matrix="[]",
                engine=_ENGINE,
            )
        self.assertIn("non-empty JSON array", str(ctx.exception))


# --------------------------------------------------------------------------- #
# Rejections the coverage matrix names, proven to propagate through run().
# --------------------------------------------------------------------------- #


class RejectionPropagationTests(_TempDirTestCase):
    @_requires_engine
    def test_record_source_tag_disagrees_with_release_tag_rejected(self) -> None:
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        with self.assertRaises(pc.AssetVerificationError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                tag="v4.0.0.b2",
            )
        self.assertIn("source_tag", str(ctx.exception))

    @_requires_engine
    def test_missing_route_build_row_rejected(self) -> None:
        """An asset set missing a ROUTE build row: the pinned matrix names TWO build
        rows, this run only carries a canonical asset for one of them."""
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        with self.assertRaises(pc.RunVerificationError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE, ROW_PLUS_03),
                tag="v4.0.0.b1",
            )
        self.assertIn("with no asset", str(ctx.exception))

    @_requires_engine
    def test_extra_asset_matching_no_row_rejected(self) -> None:
        """An asset whose own matrix_row is absent from the pinned ROUTE matrix."""
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        with self.assertRaises(pc.RunVerificationError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_PLUS_03, ROW_PLUS_07),
                tag="v4.0.0.b1",
            )
        self.assertIn("not a build-role ROUTE row", str(ctx.exception))


# --------------------------------------------------------------------------- #
# publish_release.py's OWN target-resolution rejections (beyond S1's checks).
# --------------------------------------------------------------------------- #


class TargetResolutionTests(_TempDirTestCase):
    @_requires_engine
    def test_dependency_matches_no_run_target_rejected(self) -> None:
        """Axis 9 (verify_run) only requires a dependency's ABI to match SOME ROUTE
        row (build or route-only) in the pinned matrix — not necessarily one this
        run actually built. A dependency whose ABI matches only the route-only
        FreeBSD-17 row (no canonical asset this run targets) passes S1 but must be
        rejected by publish_release's OWN target-fan-in, since there is no
        (channel, varver) directory it could land in."""
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        declared = "py311-orphan-1.0.0-CE-17.0.pkg"
        _path, digest = _wrap_dependency_pkg(
            assets_dir,
            name="py311-orphan",
            version="1.0.0",
            abi="FreeBSD:17:*",
            local_name=declared,
        )
        digests[declared] = digest
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")

        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE, ROW_ROUTE_ONLY_17),
                tag="v4.0.0.b1",
            )
        self.assertIn("matches no varver targeted", str(ctx.exception))

    @_requires_engine
    def test_duplicate_varver_from_two_route_rows_rejected(self) -> None:
        """Two distinct ROUTE rows (pfsense_version 2.8 vs 2.8.1, both CE) that
        collapse to the SAME varver directory (catalog_name_from_version strips the
        patch component) — each legitimately gets its own canonical asset per S1
        (different (variant, pfsense_version) keys), but publish_release cannot
        place both under the one ce-2.8 directory without an explicit, loud
        rejection instead of silently letting the second overwrite the first."""
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        digests: dict[str, str] = {}
        for row in (ROW_CE, ROW_CE_PATCH):
            record = _record(channel="edge", row=row, source_tag="v4.0.0.b1")
            declared = _canonical_declared_name(record)
            _path, digest = _wrap_canonical_pkg(assets_dir, record, local_name=declared)
            digests[declared] = digest
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")

        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE, ROW_CE_PATCH),
                tag="v4.0.0.b1",
            )
        self.assertIn("same varver", str(ctx.exception))

    @_requires_engine
    def test_two_dependency_assets_same_canonical_name_different_bytes_rejected(self) -> None:
        """A tagged run declares its dependency assets per row, so two rows can both
        carry name-version X. The same artifact renamed twice is legitimate — but
        DIFFERENT bytes under one canonical name must fail closed: the per-target
        asset map keys by canonical name, and collapsing the pair last-wins would
        silently publish only the later asset with no conflict check at all
        (issue #2231)."""
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(
            assets_dir, rows=(ROW_PLUS_03, ROW_PLUS_07), source_tag="v4.0.0.b1", include_dependency=False
        )
        for row, filler in ((ROW_PLUS_03, b"built-by-leg-one"), (ROW_PLUS_07, b"built-by-leg-two")):
            declared = _dependency_declared_name(name="py311-twin", version="1.0.0", row=row)
            _path, digest = _wrap_dependency_pkg(
                assets_dir,
                name="py311-twin",
                version="1.0.0",
                abi="FreeBSD:16:*",
                local_name=declared,
                payload={"filler.bin": filler},
            )
            digests[declared] = digest
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")

        with self.assertRaises(pr.DestinationConflictError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_PLUS_03, ROW_PLUS_07),
                tag="v4.0.0.b1",
            )
        self.assertIn("different bytes", str(ctx.exception))

    @_requires_engine
    def test_same_dependency_renamed_per_row_with_identical_bytes_publishes(self) -> None:
        """The legitimate twin of the rejection above: ONE artifact attached under two
        per-row declared names (byte-identical) deduplicates and publishes into every
        matching varver — never a conflict."""
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(
            assets_dir, rows=(ROW_PLUS_03, ROW_PLUS_07), source_tag="v4.0.0.b1", include_dependency=False
        )
        for row in (ROW_PLUS_03, ROW_PLUS_07):
            declared = _dependency_declared_name(name="py311-twin", version="1.0.0", row=row)
            _path, digest = _wrap_dependency_pkg(
                assets_dir,
                name="py311-twin",
                version="1.0.0",
                abi="FreeBSD:16:*",
                local_name=declared,
            )
            digests[declared] = digest
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")

        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_PLUS_03, ROW_PLUS_07),
            tag="v4.0.0.b1",
        )
        self.assertFalse(report.noop)
        for varver in ("plus-26.03", "plus-26.07"):
            self.assertTrue(
                (self.pkg_repo / "docs/edge" / varver / "py311-twin-1.0.0.pkg").is_file(),
                f"dependency missing from {varver}",
            )

    @_requires_engine
    def test_canonical_asset_without_record_rejected(self) -> None:
        """A canonical VerifiedAsset with no record (never produced by verify_asset
        itself, but a convention nothing at the type level enforces — see
        publish_catalogues._canonical_record's own docstring) must raise the SAME
        named RunVerificationError that accessor raises, not a bare TypeError from
        an un-narrowed ``asset.record["matrix_row"]`` subscript."""
        asset = pc.VerifiedAsset(
            asset_class="canonical",
            declared_name="recordless.pkg",
            canonical_name="recordless.pkg",
            work_path=Path("recordless.pkg"),
            sha256="0" * 64,
            manifest={},
            record=None,
        )
        run_result = pc.RunResult(
            intake=pc.parse_intake(_REPO, "1", "v4.0.0.b1", '["edge"]', "10:1"),
            canonical_assets=(asset,),
            dependency_assets=(),
            build_route_rows=(ROW_CE,),
        )
        with self.assertRaises(pc.RunVerificationError) as ctx:
            pr._build_targets(_ENGINE, run_result)
        self.assertIn("expected a canonical asset with a record", str(ctx.exception))


class DestinationConflictTests(_TempDirTestCase):
    @_requires_engine
    def test_same_name_version_different_bytes_rejected(self) -> None:
        """Issue #2146's contract: same name/version with different bytes, source,
        or provenance fails closed instead of silently overwriting the published
        artifact. Re-publishing the identical tag+version with a different
        source_sha yields the SAME canonical filename but different .pkg bytes."""
        assets_dir_1 = self.new_assets_dir()
        _populate_assets_dir(
            assets_dir_1,
            rows=(ROW_CE,),
            source_tag="v4.0.0.b1",
            include_dependency=False,
        )
        first = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir_1,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )
        self.assertEqual(first.touched, (("edge", "ce-2.8"),))
        catalogue_dir = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        published = catalogue_dir / "pfSense-pkg-pfBlockerNG-4.0.0.b1.pkg"
        original_bytes = published.read_bytes()

        assets_dir_2 = self.new_assets_dir()
        assets_dir_2.mkdir(parents=True)
        divergent_record = _record(channel="edge", row=ROW_CE, source_tag="v4.0.0.b1", source_sha="c" * 40)
        declared = _canonical_declared_name(divergent_record)
        _path, digest = _wrap_canonical_pkg(assets_dir_2, divergent_record, local_name=declared)
        (assets_dir_2 / pr._DIGESTS_FILENAME).write_text(json.dumps({declared: digest}), encoding="utf-8")

        with self.assertRaises(pr.DestinationConflictError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir_2,
                rows=(ROW_CE,),
                tag="v4.0.0.b1",
            )
        message = str(ctx.exception)
        self.assertIn(str(published), message)
        self.assertIn("pfSense-pkg-pfBlockerNG-4.0.0.b1.pkg", message)
        self.assertEqual(published.read_bytes(), original_bytes)  # never overwritten


# --------------------------------------------------------------------------- #
# Basic publish flow — coverage matrix: varvers, dependency scoping, channels.
# --------------------------------------------------------------------------- #


class BasicPublishFlowTests(_TempDirTestCase):
    @_requires_engine
    def test_first_publish_single_varver_with_dependency(self) -> None:
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1")
        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )

        self.assertEqual(report.touched, (("edge", "ce-2.8"),))
        self.assertFalse(report.noop)
        catalogue_dir = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        self.assertTrue((catalogue_dir / "pfSense-pkg-pfBlockerNG-4.0.0.b1.pkg").is_file())
        self.assertTrue((catalogue_dir / "py311-charset-normalizer-3.4.0.pkg").is_file())
        self.assertTrue((catalogue_dir / "meta.conf").is_file())
        self.assertTrue((catalogue_dir / "data.pkg").is_file())
        self.assertTrue((catalogue_dir / "packagesite.pkg").is_file())

    @_requires_engine
    def test_first_publish_three_varvers_dependency_only_in_ce(self) -> None:
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=_THREE_ROWS, source_tag="v4.0.0.b1")
        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=_THREE_ROWS,
            tag="v4.0.0.b1",
        )

        self.assertEqual(
            set(report.touched),
            {("edge", "ce-2.8"), ("edge", "plus-26.03"), ("edge", "plus-26.07")},
        )
        docs = self.pkg_repo / "docs" / "edge"
        self.assertTrue((docs / "ce-2.8" / "py311-charset-normalizer-3.4.0.pkg").is_file())
        self.assertFalse((docs / "plus-26.03" / "py311-charset-normalizer-3.4.0.pkg").exists())
        self.assertFalse((docs / "plus-26.07" / "py311-charset-normalizer-3.4.0.pkg").exists())
        for varver in ("ce-2.8", "plus-26.03", "plus-26.07"):
            self.assertTrue((docs / varver / "data.pkg").is_file())

    @_requires_engine
    def test_multi_channel_fanout_same_bytes_both_channels(self) -> None:
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(
            assets_dir,
            channel="testing",
            rows=(ROW_CE,),
            source_tag="v4.0.1.b1",
            include_dependency=False,
        )
        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            channel="testing",
            destinations='["testing","edge"]',
            tag="v4.0.1.b1",
        )
        self.assertEqual(set(report.touched), {("testing", "ce-2.8"), ("edge", "ce-2.8")})
        testing_pkg = self.pkg_repo / "docs" / "testing" / "ce-2.8" / "pfSense-pkg-pfBlockerNG-4.0.1.b1.pkg"
        edge_pkg = self.pkg_repo / "docs" / "edge" / "ce-2.8" / "pfSense-pkg-pfBlockerNG-4.0.1.b1.pkg"
        self.assertTrue(testing_pkg.is_file())
        self.assertTrue(edge_pkg.is_file())
        self.assertEqual(testing_pkg.read_bytes(), edge_pkg.read_bytes())


# --------------------------------------------------------------------------- #
# Outcomes: exact republish (no-op), new version added, retention eviction.
# --------------------------------------------------------------------------- #


class OutcomeTests(_TempDirTestCase):
    @_requires_engine
    def test_exact_republish_is_noop(self) -> None:
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1")
        first = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )
        self.assertTrue(first.touched)

        second_assets_dir = self.new_assets_dir()
        _populate_assets_dir(second_assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1")
        second = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=second_assets_dir,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )
        self.assertEqual(second.touched, ())
        self.assertTrue(second.noop)
        self.assertEqual(
            second.describe(),
            ["NOOP: every destination already matches this run's verified assets"],
        )

    @_requires_engine
    def test_incomplete_descriptor_regenerated_on_identical_rerun(self) -> None:
        """A rerun with byte-identical assets must still regenerate the catalog
        descriptor if a prior run's write-back fault left it incomplete —
        catalogue_assembly.regenerate_catalogue's own docstring names this fault
        window. `changed=False` from the .pkg comparison alone must not report a
        NOOP over a destination missing packagesite.pkg/data.pkg/meta.conf."""
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        first = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )
        self.assertTrue(first.touched)
        catalogue_dir = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        (catalogue_dir / "packagesite.pkg").unlink()

        second_assets_dir = self.new_assets_dir()
        _populate_assets_dir(second_assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        second = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=second_assets_dir,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )
        self.assertEqual(second.touched, (("edge", "ce-2.8"),))
        self.assertFalse(second.noop)
        self.assertTrue((catalogue_dir / "packagesite.pkg").is_file())

    @_requires_engine
    def test_incomplete_descriptor_with_divergent_bytes_still_fails_closed(self) -> None:
        """The B1 fail-closed check runs BEFORE the descriptor-completeness repair:
        a missing packagesite.pkg never waives the different-bytes rejection."""
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )
        catalogue_dir = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        (catalogue_dir / "packagesite.pkg").unlink()

        divergent_assets_dir = self.new_assets_dir()
        divergent_assets_dir.mkdir(parents=True)
        divergent_record = _record(channel="edge", row=ROW_CE, source_tag="v4.0.0.b1", source_sha="d" * 40)
        declared = _canonical_declared_name(divergent_record)
        _path, digest = _wrap_canonical_pkg(divergent_assets_dir, divergent_record, local_name=declared)
        (divergent_assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps({declared: digest}), encoding="utf-8")

        with self.assertRaises(pr.DestinationConflictError):
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=divergent_assets_dir,
                rows=(ROW_CE,),
                tag="v4.0.0.b1",
            )

    @_requires_engine
    def test_new_version_added_alongside_retained_older(self) -> None:
        assets_dir_1 = self.new_assets_dir()
        _populate_assets_dir(
            assets_dir_1,
            rows=(ROW_CE,),
            source_tag="v4.0.0.b1",
            include_dependency=False,
        )
        _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir_1,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )

        assets_dir_2 = self.new_assets_dir()
        _populate_assets_dir(
            assets_dir_2,
            rows=(ROW_CE,),
            source_tag="v4.0.0.b2",
            include_dependency=False,
        )
        second = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir_2,
            rows=(ROW_CE,),
            tag="v4.0.0.b2",
        )

        self.assertEqual(second.touched, (("edge", "ce-2.8"),))
        catalogue_dir = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        self.assertTrue((catalogue_dir / "pfSense-pkg-pfBlockerNG-4.0.0.b1.pkg").is_file())
        self.assertTrue((catalogue_dir / "pfSense-pkg-pfBlockerNG-4.0.0.b2.pkg").is_file())

    @_requires_engine
    def test_retention_evicts_oldest_beyond_keep(self) -> None:
        catalogue_dir = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        for seq in range(1, ca_default_keep() + 2):
            tag = f"v4.0.0.b{seq}"
            assets_dir = self.new_assets_dir()
            _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag=tag, include_dependency=False)
            _run(pkg_repo=self.pkg_repo, assets_dir=assets_dir, rows=(ROW_CE,), tag=tag)

        remaining = sorted(p.name for p in catalogue_dir.glob("pfSense-pkg-pfBlockerNG-*.pkg"))
        self.assertEqual(len(remaining), ca_default_keep())
        self.assertNotIn("pfSense-pkg-pfBlockerNG-4.0.0.b1.pkg", remaining)
        self.assertIn(f"pfSense-pkg-pfBlockerNG-4.0.0.b{ca_default_keep() + 1}.pkg", remaining)


def ca_default_keep() -> int:
    return ca.DEFAULT_RETENTION_KEEP


# --------------------------------------------------------------------------- #
# publish() must actually WIRE catalogue_assembly.verify_multi_destination_
# identity, not merely have access to a function that works in isolation
# (test_catalogue_assembly.py's own job, unaffected by whether anything here
# still calls it).
# --------------------------------------------------------------------------- #


class IdentityPostConditionTests(_TempDirTestCase):
    @_requires_engine
    def test_multi_destination_divergence_aborts_publish(self) -> None:
        """Patches regenerate_catalogue to, after doing its real work, overwrite
        ONE of two fanned-out destinations (same canonical_name, same path shape)
        with a structurally valid but DIFFERENT record — same name/version, a
        different source_sha — simulating a genuine divergence the identity check
        exists to catch. run() must abort with the exact
        CatalogueAssemblyError the identity check itself raises."""
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(
            assets_dir,
            channel="testing",
            rows=(ROW_CE,),
            source_tag="v4.0.1.b1",
            include_dependency=False,
        )
        divergent_dir = self.tmp / "divergent"
        divergent_dir.mkdir()
        divergent_record = _record(channel="testing", row=ROW_CE, source_tag="v4.0.1.b1", source_sha="b" * 40)
        divergent_path, _digest = _wrap_canonical_pkg(divergent_dir, divergent_record, local_name="divergent.pkg")
        divergent_bytes = divergent_path.read_bytes()

        real_regenerate = pr.ca.regenerate_catalogue

        def corrupting_regenerate(site_root: str | Path, channel: str, varver: str, *, engine: pc.Engine) -> None:
            real_regenerate(site_root, channel, varver, engine=engine)
            if channel == "edge":
                target = Path(site_root) / channel / varver / "pfSense-pkg-pfBlockerNG-4.0.1.b1.pkg"
                target.write_bytes(divergent_bytes)

        with (
            mock.patch.object(pr.ca, "regenerate_catalogue", side_effect=corrupting_regenerate),
            self.assertRaises(pr.ca.CatalogueAssemblyError) as ctx,
        ):
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                channel="testing",
                destinations='["testing","edge"]',
                tag="v4.0.1.b1",
            )
        self.assertIn("multi-destination identity violation", str(ctx.exception))


# --------------------------------------------------------------------------- #
# main() — CLI wrapper: argv wiring, exit codes, stdout/stderr shape.
# --------------------------------------------------------------------------- #


class MainCliTests(_TempDirTestCase):
    @_requires_engine
    def test_main_success_prints_touched_and_returns_zero(self) -> None:
        assets_dir = self.new_assets_dir()
        _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        argv = [
            "--source-repository",
            _REPO,
            "--release-id",
            "1",
            "--release-tag",
            "v4.0.0.b1",
            "--destinations",
            '["edge"]',
            "--source-run-id",
            "10:1",
            "--assets-dir",
            str(assets_dir),
            "--pkg-repo",
            str(self.pkg_repo),
            "--route-matrix",
            json.dumps([ROW_CE]),
        ]
        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            code = pr.main(argv)
        self.assertEqual(code, 0)
        self.assertIn("updated edge/ce-2.8", out.getvalue())

    @_requires_engine
    def test_main_failure_prints_error_and_returns_one(self) -> None:
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        argv = [
            "--source-repository",
            _REPO,
            "--release-id",
            "1",
            "--release-tag",
            "v4.0.0.b1",
            "--destinations",
            '["edge"]',
            "--source-run-id",
            "10:1",
            "--assets-dir",
            str(assets_dir),
            "--pkg-repo",
            str(self.pkg_repo),
            "--route-matrix",
            json.dumps([ROW_CE]),
        ]
        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            code = pr.main(argv)
        self.assertEqual(code, 1)
        self.assertIn("::error::", err.getvalue())


if __name__ == "__main__":
    unittest.main()
