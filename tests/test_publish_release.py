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

# Twin dest tests declare textproc/py-twin themselves (issue #2403). Own lists —
# never mutate ROW_PLUS_03["extra_pkgs"] at import.
ROW_PLUS_03_TWIN: dict[str, object] = {**ROW_PLUS_03, "extra_pkgs": ["textproc/py-twin"]}
ROW_PLUS_07_TWIN: dict[str, object] = {**ROW_PLUS_07, "extra_pkgs": ["textproc/py-twin"]}

# Same-major dest scope (issue #2403): Plus shares CE's FreeBSD major, extra_pkgs=[].
ROW_PLUS_SAME_MAJOR: dict[str, object] = {
    **ROW_PLUS_03,
    "freebsd_version": "15.0-RELEASE",
    "freebsd_major": "15",
    "extra_pkgs": [],
}

ROW_CE_NO_EXTRA: dict[str, object] = {**ROW_CE, "extra_pkgs": []}

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

# A route-only row on FreeBSD 16 — lets a dependency's ABI clear axis 9 (S1's own
# "ABI matches SOME ROUTE row" check) via a row OTHER than the one its own suffix
# names, isolating publish_release's own suffix-row ABI cross-check (issue #2468).
ROW_ROUTE_ONLY_16: dict[str, object] = {
    "pfsense_version": "99.0",
    "channel": "CE",
    "freebsd_version": "16.0-RELEASE",
    "freebsd_major": "16",
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
    def test_same_dependency_renamed_per_row_with_identical_bytes_publishes(self) -> None:
        """The byte-identical twin of DependencyPlaceIfMissingTests's own
        same-major/different-bytes case: ONE artifact attached under two per-row
        declared names (byte-identical) also publishes into every matching varver —
        per-suffix routing (issue #2468) sends each to its own row's varver either
        way; this pins the identical-bytes case never regresses alongside it."""
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(
            assets_dir, rows=(ROW_PLUS_03_TWIN, ROW_PLUS_07_TWIN), source_tag="v4.0.0.b1", include_dependency=False
        )
        for row in (ROW_PLUS_03_TWIN, ROW_PLUS_07_TWIN):
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
            rows=(ROW_PLUS_03_TWIN, ROW_PLUS_07_TWIN),
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
# issue #2468 — dependency .pkg identity = filename: place-if-missing, never
# byte-compared or overwritten. Canonical packages keep the strict conflict check.
# --------------------------------------------------------------------------- #


class DependencyPlaceIfMissingTests(_TempDirTestCase):
    @_requires_engine
    def test_stale_destination_dependency_bytes_untouched_canonical_published(self) -> None:
        """RED CANARY (issue #2468): a destination already holding a byte-different
        same-name dependency .pkg (e.g. left over from an older release) must never
        block this run — the dependency's filename IS its identity; publishers place
        it only when missing and never compare or overwrite it. The canonical
        package still publishes normally alongside the untouched stale dependency."""
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        declared = _dependency_declared_name(name="py311-charset-normalizer", version="3.4.0", row=ROW_CE)
        _path, digest = _wrap_dependency_pkg(
            assets_dir,
            version="3.4.0",
            abi="FreeBSD:15:*",
            local_name=declared,
            payload={"filler.bin": b"incoming-build"},
        )
        digests[declared] = digest
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")

        catalogue_dir = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        stale_dir = self.tmp / "stale-dep-seed"
        stale_dir.mkdir()
        stale_path, _stale_digest = _wrap_dependency_pkg(
            stale_dir,
            version="3.4.0",
            abi="FreeBSD:15:*",
            local_name="py311-charset-normalizer-3.4.0.pkg",
            payload={"filler.bin": b"stale-build-from-an-older-release"},
        )
        stale_bytes = stale_path.read_bytes()
        catalogue_dir.mkdir(parents=True)
        (catalogue_dir / "py311-charset-normalizer-3.4.0.pkg").write_bytes(stale_bytes)

        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            tag="v4.0.0.b1",
        )

        self.assertFalse(report.noop)
        self.assertTrue((catalogue_dir / "pfSense-pkg-pfBlockerNG-4.0.0.b1.pkg").is_file())
        self.assertEqual((catalogue_dir / "py311-charset-normalizer-3.4.0.pkg").read_bytes(), stale_bytes)

    @_requires_engine
    def test_two_same_major_rows_each_own_dep_asset_lands_only_in_own_varver(self) -> None:
        """Two same-major rows (plus-26.03 + plus-26.07, both FreeBSD 16) each carry
        their OWN byte-different dep asset under the identical canonical name
        (py311-twin-1.0.0.pkg). Per-suffix routing (issue #2468) sends each asset to
        the varver of its OWN -<Variant>-<pfsense_version> suffix only — never by
        same-major ABI match against every declaring row — so the two never collide
        and the run succeeds, each varver holding only its own row's bytes."""
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(
            assets_dir, rows=(ROW_PLUS_03_TWIN, ROW_PLUS_07_TWIN), source_tag="v4.0.0.b1", include_dependency=False
        )
        twin_bytes: dict[str, bytes] = {}
        for row, filler in ((ROW_PLUS_03_TWIN, b"built-by-leg-one"), (ROW_PLUS_07_TWIN, b"built-by-leg-two")):
            declared = _dependency_declared_name(name="py311-twin", version="1.0.0", row=row)
            path, digest = _wrap_dependency_pkg(
                assets_dir,
                name="py311-twin",
                version="1.0.0",
                abi="FreeBSD:16:*",
                local_name=declared,
                payload={"filler.bin": filler},
            )
            digests[declared] = digest
            twin_bytes[str(row["pfsense_version"])] = path.read_bytes()
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")

        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_PLUS_03_TWIN, ROW_PLUS_07_TWIN),
            tag="v4.0.0.b1",
        )

        self.assertFalse(report.noop)
        for row in (ROW_PLUS_03_TWIN, ROW_PLUS_07_TWIN):
            row_varver = _ENGINE.build_repo_portable.catalog_name_from_version(row["pfsense_version"], row["variant"])
            dep_path = self.pkg_repo / "docs" / "edge" / row_varver / "py311-twin-1.0.0.pkg"
            self.assertTrue(dep_path.is_file(), row_varver)
            self.assertEqual(dep_path.read_bytes(), twin_bytes[str(row["pfsense_version"])], row_varver)

    @_requires_engine
    def test_dependency_abi_mismatching_its_suffix_row_major_rejected(self) -> None:
        """A dependency asset whose OWN suffix names a valid canonical target row,
        but whose manifest ABI does not match that row's FreeBSD major, is rejected
        — per-suffix routing never falls back to matching a DIFFERENT row by ABI.
        ROW_ROUTE_ONLY_16 lets the ABI clear axis 9 (S1's own "matches SOME ROUTE
        row" check) so this test isolates publish_release's own suffix-row check."""
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(assets_dir, rows=(ROW_CE,), source_tag="v4.0.0.b1", include_dependency=False)
        declared = _dependency_declared_name(name="py311-charset-normalizer", version="3.4.0", row=ROW_CE)
        _path, digest = _wrap_dependency_pkg(
            assets_dir,
            version="3.4.0",
            abi="FreeBSD:16:*",  # ROW_CE (its suffix row) is FreeBSD 15 — deliberate mismatch.
            local_name=declared,
        )
        digests[declared] = digest
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")

        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE, ROW_ROUTE_ONLY_16),
                tag="v4.0.0.b1",
            )
        self.assertIn("matches no varver targeted", str(ctx.exception))

    def test_asset_map_two_deps_same_canonical_name_rejected(self) -> None:
        """Unit test on _asset_map directly (issue #2468 coverage row 6): two
        dependency VerifiedAssets that resolve to the SAME canonical name always
        conflict — no byte-compare-then-tolerate branch, no file reads. Never
        reachable end-to-end from one tagged run (a real asset set cannot carry
        two on-disk files sharing one declared filename); reachable via nightly
        handoffs or direct API use."""
        canonical = pc.VerifiedAsset(
            asset_class="canonical",
            declared_name="pfSense-pkg-pfBlockerNG-4.0.0.b1-CE-2.8.pkg",
            canonical_name="pfSense-pkg-pfBlockerNG-4.0.0.b1.pkg",
            work_path=Path("pfSense-pkg-pfBlockerNG-4.0.0.b1.pkg"),
            sha256="a" * 64,
            manifest={},
            record={"matrix_row": ROW_CE},
        )
        dep_one = pc.VerifiedAsset(
            asset_class="dependency",
            declared_name="py311-twin-1.0.0-CE-2.8.pkg",
            canonical_name="py311-twin-1.0.0.pkg",
            work_path=Path("dep-one.pkg"),
            sha256="b" * 64,
            manifest={},
            release_suffix=("CE", "2.8"),
        )
        dep_two = pc.VerifiedAsset(
            asset_class="dependency",
            declared_name="py311-twin-1.0.0-CE-2.8-again.pkg",
            canonical_name="py311-twin-1.0.0.pkg",
            work_path=Path("dep-two.pkg"),
            sha256="c" * 64,
            manifest={},
            release_suffix=("CE", "2.8"),
        )
        target = pr._Target(row=ROW_CE, canonical=canonical, dependencies=[dep_one, dep_two])

        with self.assertRaises(pr.DestinationConflictError) as ctx:
            pr._asset_map(target)
        message = str(ctx.exception)
        self.assertIn(dep_one.declared_name, message)
        self.assertIn(dep_two.declared_name, message)
        self.assertIn(dep_one.sha256, message)
        self.assertIn(dep_two.sha256, message)

    @_requires_engine
    def test_multi_channel_fanout_dep_differs_at_one_channel_no_identity_violation(self) -> None:
        """issue #2468 coverage row 13: canonical is identical across a multi-channel
        fan-out (verify_multi_destination_identity still enforces THAT), but a
        dependency that already differs at ONE destination channel — because it was
        placed there by an earlier run and this run's dep is missing at the OTHER
        channel — must never trip the identity check. Dependencies are excluded
        from source_index: fan-out byte identity is a canonical-package invariant."""
        assets_dir = self.new_assets_dir()
        digests = _populate_assets_dir(
            assets_dir,
            channel="testing",
            rows=(ROW_CE,),
            source_tag="v4.0.1.b1",
            include_dependency=False,
        )
        declared = _dependency_declared_name(name="py311-charset-normalizer", version="3.4.0", row=ROW_CE)
        _path, digest = _wrap_dependency_pkg(
            assets_dir,
            version="3.4.0",
            abi="FreeBSD:15:*",
            local_name=declared,
            payload={"filler.bin": b"this-runs-build"},
        )
        digests[declared] = digest
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")

        testing_dir = self.pkg_repo / "docs" / "testing" / "ce-2.8"
        testing_dir.mkdir(parents=True)
        stale_dir = self.tmp / "stale-dep-seed"
        stale_dir.mkdir()
        stale_path, _stale_digest = _wrap_dependency_pkg(
            stale_dir,
            version="3.4.0",
            abi="FreeBSD:15:*",
            local_name="py311-charset-normalizer-3.4.0.pkg",
            payload={"filler.bin": b"an-earlier-runs-build"},
        )
        stale_bytes = stale_path.read_bytes()
        (testing_dir / "py311-charset-normalizer-3.4.0.pkg").write_bytes(stale_bytes)

        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            channel="testing",
            destinations='["testing","edge"]',
            tag="v4.0.1.b1",
        )

        self.assertEqual(set(report.touched), {("testing", "ce-2.8"), ("edge", "ce-2.8")})
        testing_pkg = testing_dir / "pfSense-pkg-pfBlockerNG-4.0.1.b1.pkg"
        edge_dir = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        edge_pkg = edge_dir / "pfSense-pkg-pfBlockerNG-4.0.1.b1.pkg"
        self.assertEqual(testing_pkg.read_bytes(), edge_pkg.read_bytes())  # canonical still identical

        testing_dep = testing_dir / "py311-charset-normalizer-3.4.0.pkg"
        edge_dep = edge_dir / "py311-charset-normalizer-3.4.0.pkg"
        self.assertEqual(testing_dep.read_bytes(), stale_bytes)  # untouched, already present
        self.assertTrue(edge_dep.is_file())
        self.assertNotEqual(edge_dep.read_bytes(), stale_bytes)  # placed fresh, missing before


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


# --------------------------------------------------------------------------- #
# Containment backfill (issue #2398): a slower-channel generation omitted from
# a faster catalogue must be copied byte-identically before prune. Nightly is
# outside this reconciliation.
# --------------------------------------------------------------------------- #


class ContainmentBackfillPublishTests(_TempDirTestCase):
    def _seed_canonical(self, channel: str, varver: str, record: dict) -> Path:
        """Drop one already-canonical .pkg into docs/<channel>/<varver>/."""
        dest_dir = self.pkg_repo / "docs" / channel / varver
        dest_dir.mkdir(parents=True, exist_ok=True)
        name = f"{_ENGINE.pfb_pkg.CANONICAL_EMITTED_IDENTITY}-{record['canonical_package_version']}.pkg"
        scratch = self.tmp / f"seed-{next(self._assets_counter)}"
        scratch.mkdir()
        src, _digest = _wrap_canonical_pkg(scratch, record, local_name=name)
        dest = dest_dir / name
        dest.write_bytes(src.read_bytes())
        return dest

    @_requires_engine
    def test_edge_heals_testing_version_omitted_from_edge(self) -> None:
        # Red canary: testing/ce-2.8 has 3.2.10, edge/ce-2.8 does not.
        # A new testing publish (destinations testing+edge) must copy it.
        seeded = self._seed_canonical(
            "testing",
            "ce-2.8",
            _record(channel="stable", row=ROW_CE, source_tag="v3.2.10"),
        )
        self.assertFalse((self.pkg_repo / "docs" / "edge" / "ce-2.8" / "pfSense-pkg-pfBlockerNG-3.2.10.pkg").exists())

        assets_dir = self.new_assets_dir()
        _populate_assets_dir(
            assets_dir,
            channel="testing",
            rows=(ROW_CE,),
            source_tag="v3.2.16.a1",
            include_dependency=False,
        )
        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            channel="testing",
            destinations='["testing","edge"]',
            tag="v3.2.16.a1",
        )

        self.assertEqual(set(report.touched), {("testing", "ce-2.8"), ("edge", "ce-2.8")})
        edge_pkg = self.pkg_repo / "docs" / "edge" / "ce-2.8" / "pfSense-pkg-pfBlockerNG-3.2.10.pkg"
        self.assertTrue(edge_pkg.is_file())
        self.assertEqual(edge_pkg.read_bytes(), seeded.read_bytes())
        self.assertTrue(
            (self.pkg_repo / "docs" / "edge" / "ce-2.8" / "pfSense-pkg-pfBlockerNG-3.2.16.a1.pkg").is_file()
        )

    @_requires_engine
    def test_nightly_catalogue_not_healed_by_tagged_publish(self) -> None:
        # publish_release rejects nightly dests (kind!=tagged). This case pins
        # that a tagged dest list does not walk an existing nightly tree.
        # backfill(channel="nightly") is catalogue_assembly's pin
        # (test_nightly_destination_copies_nothing). Mixing nightly into
        # tagged dests is IntakeError (test below).
        seeded = self._seed_canonical(
            "testing",
            "ce-2.8",
            _record(channel="stable", row=ROW_CE, source_tag="v3.2.10"),
        )
        nightly_dir = self.pkg_repo / "docs" / "nightly" / "ce-2.8"
        nightly_dir.mkdir(parents=True)

        assets_dir = self.new_assets_dir()
        _populate_assets_dir(
            assets_dir,
            channel="testing",
            rows=(ROW_CE,),
            source_tag="v3.2.16.a1",
            include_dependency=False,
        )
        _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_dir,
            rows=(ROW_CE,),
            channel="testing",
            destinations='["testing","edge"]',
            tag="v3.2.16.a1",
        )

        self.assertTrue(seeded.is_file())
        self.assertFalse((nightly_dir / "pfSense-pkg-pfBlockerNG-3.2.10.pkg").exists())
        self.assertFalse((nightly_dir / "pfSense-pkg-pfBlockerNG-3.2.16.a1.pkg").exists())

    @_requires_engine
    def test_tagged_destinations_cannot_include_nightly(self) -> None:
        assets_dir = self.new_assets_dir()
        assets_dir.mkdir()
        (assets_dir / pr._DIGESTS_FILENAME).write_text(json.dumps({"x.pkg": "0" * 64}), encoding="utf-8")
        with self.assertRaises(pc.IntakeError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets_dir,
                rows=(ROW_CE,),
                channel="testing",
                destinations='["testing","edge","nightly"]',
                tag="v3.2.16.a1",
            )
        self.assertIn("nightly must not be combined", str(ctx.exception))


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


def _packagesite_names(catalogue_dir: Path) -> set[str]:
    """Manifest `name` of every member in the dest's packagesite.pkg."""
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
    """issue #2402: undeclared dest leftovers are unlinked before regenerate."""

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
        assets_1 = self.new_assets_dir()
        _populate_assets_dir(assets_1, rows=(ROW_PLUS_03,), source_tag="v4.0.0.b1", include_dependency=False)
        _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_1,
            rows=(ROW_PLUS_03,),
            tag="v4.0.0.b1",
        )
        dest = self.pkg_repo / "docs" / "edge" / "plus-26.03"
        self._plant_charset(dest, major="16")
        self.assertTrue((dest / _CHARSET_PKG).is_file())

        assets_2 = self.new_assets_dir()
        _populate_assets_dir(assets_2, rows=(ROW_PLUS_03,), source_tag="v4.0.0.b2", include_dependency=False)
        report = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets_2,
            rows=(ROW_PLUS_03,),
            tag="v4.0.0.b2",
        )
        self.assertFalse(report.noop)
        self.assertFalse((dest / _CHARSET_PKG).exists())
        self.assertTrue((dest / "pfSense-pkg-pfBlockerNG-4.0.0.b2.pkg").is_file())
        self.assertNotIn(_CHARSET_NAME, _packagesite_names(dest))

    @_requires_engine
    def test_stale_plus_extra_evicted_on_exact_republish(self) -> None:
        assets = self.new_assets_dir()
        _populate_assets_dir(assets, rows=(ROW_PLUS_03,), source_tag="v4.0.0.b1", include_dependency=False)
        first = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets,
            rows=(ROW_PLUS_03,),
            tag="v4.0.0.b1",
        )
        self.assertFalse(first.noop)
        dest = self.pkg_repo / "docs" / "edge" / "plus-26.03"
        self._plant_charset(dest, major="16")

        second_assets = self.new_assets_dir()
        _populate_assets_dir(second_assets, rows=(ROW_PLUS_03,), source_tag="v4.0.0.b1", include_dependency=False)
        second = _run(
            pkg_repo=self.pkg_repo,
            assets_dir=second_assets,
            rows=(ROW_PLUS_03,),
            tag="v4.0.0.b1",
        )
        self.assertFalse(second.noop)
        self.assertFalse((dest / _CHARSET_PKG).exists())
        self.assertNotIn(_CHARSET_NAME, _packagesite_names(dest))

    @_requires_engine
    def test_declared_ce_extra_kept_on_new_canonical(self) -> None:
        assets_1 = self.new_assets_dir()
        _populate_assets_dir(assets_1, rows=(ROW_CE,), source_tag="v4.0.0.b1")
        _run(pkg_repo=self.pkg_repo, assets_dir=assets_1, rows=(ROW_CE,), tag="v4.0.0.b1")
        dest = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        self.assertTrue((dest / _CHARSET_PKG).is_file())

        assets_2 = self.new_assets_dir()
        _populate_assets_dir(assets_2, rows=(ROW_CE,), source_tag="v4.0.0.b2", include_dependency=False)
        _run(pkg_repo=self.pkg_repo, assets_dir=assets_2, rows=(ROW_CE,), tag="v4.0.0.b2")
        self.assertTrue((dest / _CHARSET_PKG).is_file())
        self.assertIn(_CHARSET_NAME, _packagesite_names(dest))

    @_requires_engine
    def test_undeclared_ce_extra_evicted_when_row_drops_extra_pkgs(self) -> None:
        assets_1 = self.new_assets_dir()
        _populate_assets_dir(assets_1, rows=(ROW_CE,), source_tag="v4.0.0.b1")
        _run(pkg_repo=self.pkg_repo, assets_dir=assets_1, rows=(ROW_CE,), tag="v4.0.0.b1")
        dest = self.pkg_repo / "docs" / "edge" / "ce-2.8"
        self.assertTrue((dest / _CHARSET_PKG).is_file())

        assets_2 = self.new_assets_dir()
        _populate_assets_dir(assets_2, rows=(ROW_CE_NO_EXTRA,), source_tag="v4.0.0.b2", include_dependency=False)
        _run(pkg_repo=self.pkg_repo, assets_dir=assets_2, rows=(ROW_CE_NO_EXTRA,), tag="v4.0.0.b2")
        self.assertFalse((dest / _CHARSET_PKG).exists())
        self.assertNotIn(_CHARSET_NAME, _packagesite_names(dest))

    @_requires_engine
    def test_untargeted_dest_extra_left_in_place(self) -> None:
        assets = self.new_assets_dir()
        _populate_assets_dir(assets, rows=(ROW_PLUS_03,), source_tag="v4.0.0.b1", include_dependency=False)
        _run(
            pkg_repo=self.pkg_repo,
            assets_dir=assets,
            rows=(ROW_PLUS_03,),
            tag="v4.0.0.b1",
        )
        other = self.pkg_repo / "docs" / "testing" / "plus-26.03"
        self._plant_charset(other, major="16")
        second_assets = self.new_assets_dir()
        _populate_assets_dir(second_assets, rows=(ROW_PLUS_03,), source_tag="v4.0.0.b2", include_dependency=False)
        _run(
            pkg_repo=self.pkg_repo,
            assets_dir=second_assets,
            rows=(ROW_PLUS_03,),
            tag="v4.0.0.b2",
        )
        self.assertTrue((other / _CHARSET_PKG).is_file())


class SameMajorDestScopeTests(_TempDirTestCase):
    """issue #2403: same-major CE extra must not land on Plus extra_pkgs=[]."""

    @_requires_engine
    def test_same_major_dep_not_published_to_row_with_empty_extra_pkgs(self) -> None:
        rows = (ROW_CE, ROW_PLUS_SAME_MAJOR)
        assets = self.new_assets_dir()
        _populate_assets_dir(assets, channel="stable", rows=rows, source_tag="v4.0.0")
        captured: dict[str, set[str]] = {}
        orig = pr._drop_assets

        def _spy(dest_dir: Path, asset_map: dict) -> bool:
            captured[f"{dest_dir.parent.name}/{dest_dir.name}"] = set(asset_map)
            return orig(dest_dir, asset_map)

        with mock.patch.object(pr, "_drop_assets", side_effect=_spy):
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets,
                rows=rows,
                channel="stable",
                tag="v4.0.0",
                destinations='["stable", "testing", "edge"]',
            )

        extra = _CHARSET_PKG
        for channel in ("stable", "testing", "edge"):
            self.assertIn(extra, captured[f"{channel}/ce-2.8"], channel)
            self.assertNotIn(extra, captured[f"{channel}/plus-26.03"], channel)
            ce_dir = self.pkg_repo / "docs" / channel / "ce-2.8"
            plus_dir = self.pkg_repo / "docs" / channel / "plus-26.03"
            self.assertTrue((ce_dir / extra).is_file(), channel)
            self.assertFalse((plus_dir / extra).exists(), channel)
            self.assertIn(_CHARSET_NAME, _packagesite_names(ce_dir))
            self.assertNotIn(_CHARSET_NAME, _packagesite_names(plus_dir))

    @_requires_engine
    def test_undeclared_twin_dep_against_empty_plus_extra_pkgs_rejected(self) -> None:
        """No import-time mutation: Plus extra_pkgs=[] does not accept py311-twin."""
        assets = self.new_assets_dir()
        digests = _populate_assets_dir(
            assets, rows=(ROW_PLUS_03, ROW_PLUS_07), source_tag="v4.0.0.b1", include_dependency=False
        )
        for row in (ROW_PLUS_03, ROW_PLUS_07):
            declared = _dependency_declared_name(name="py311-twin", version="1.0.0", row=row)
            _path, digest = _wrap_dependency_pkg(
                assets,
                name="py311-twin",
                version="1.0.0",
                abi="FreeBSD:16:*",
                local_name=declared,
            )
            digests[declared] = digest
        (assets / pr._DIGESTS_FILENAME).write_text(json.dumps(digests), encoding="utf-8")
        with self.assertRaises(pr.PublishReleaseError) as ctx:
            _run(
                pkg_repo=self.pkg_repo,
                assets_dir=assets,
                rows=(ROW_PLUS_03, ROW_PLUS_07),
                tag="v4.0.0.b1",
            )
        self.assertIn("matches no varver targeted", str(ctx.exception))
        for varver in ("plus-26.03", "plus-26.07"):
            self.assertFalse((self.pkg_repo / "docs/edge" / varver / "py311-twin-1.0.0.pkg").exists())


if __name__ == "__main__":
    unittest.main()
