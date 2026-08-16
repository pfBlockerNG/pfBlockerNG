"""Tests for scripts/publish_deps.py — issue #2454 step 1 (dependency flow): given
the pkg catalogue checkout, a FreeBSD-ports checkout, the pinned ROUTE matrix and the
channel(s) being built, find every ROUTE build row's extra_pkgs dependency .pkg missing
from a destination, build each missing one ONCE per (origin, py_flavor, freebsd_major),
copy it into every missing destination, regenerate those destinations' catalogue
descriptors, and report `updated <channel>/<varver>` lines — NOOP when nothing is
missing.

No ledger — "already published" is read straight off the files already on disk, same
doctrine as publish_release.py/publish_nightly.py. This module never touches canonical
packages and never byte-compares an existing dependency: presence of the filename IS
identity.

Fixture .pkg archives mirror tests/test_publish_release.py's _write_tar_pkg /
_wrap_dependency_pkg (duplicated here rather than imported, matching this repo's
per-file fixture convention). The fixture port Makefile/distinfo mirrors
tests/test_build_dep_pkg_portable.py's _port_makefile fixture (the real
textproc/py-charset-normalizer port).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalogue_assembly as ca
import publish_catalogues as pc
import publish_deps as pd
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

# --------------------------------------------------------------------------- #
# The closed ROUTE matrix this ticket's coverage matrix names.
# --------------------------------------------------------------------------- #

_ORIGIN = "textproc/py-charset-normalizer"
_PORTNAME = "charset-normalizer"
_PORTVERSION = "3.4.4"
_DEP_VERSION = "3.4.4"

ROW_CE_28: dict[str, object] = {
    "pfsense_version": "2.8",
    "channel": "CE",
    "freebsd_version": "15.0-RELEASE",
    "freebsd_major": "15",
    "php_version": "8.3",
    "py_flavor": "py311",
    "variant": "CE",
    "status": "active",
    "extra_pkgs": [_ORIGIN],
}

ROW_CE_29: dict[str, object] = {
    **ROW_CE_28,
    "pfsense_version": "2.9",
    "freebsd_version": "16.0-RELEASE",
    "freebsd_major": "16",
}

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
    "extra_pkgs": [_ORIGIN],
    "role": "route-only",
}

_ALL_ROWS = (ROW_CE_28, ROW_CE_29, ROW_PLUS_03, ROW_PLUS_07)
_EXPECTED_NAME = f"py311-{_PORTNAME}-{_PORTVERSION}.pkg"


# --------------------------------------------------------------------------- #
# Fixture port dir — same real textproc/py-charset-normalizer Makefile/distinfo
# shape as tests/test_build_dep_pkg_portable.py's _port_makefile.
# --------------------------------------------------------------------------- #


def _port_makefile(*, portname: str = _PORTNAME) -> str:
    return (
        f"PORTNAME=\t{portname}\n"
        f"PORTVERSION=\t{_PORTVERSION}\n"
        "CATEGORIES=\ttextproc python\n"
        "MASTER_SITES=\tPYPI\n"
        "PKGNAMEPREFIX=\t${PYTHON_PKGNAMEPREFIX}\n"
        f"DISTNAME=\tcharset_normalizer-{_PORTVERSION}\n"
        "\n"
        "MAINTAINER=\tsunpoet@FreeBSD.org\n"
        "COMMENT=\tReal First Universal Charset Detector\n"
        "WWW=\t\thttps://charset-normalizer.readthedocs.io/en/latest/\n"
        "\n"
        "LICENSE=\tMIT\n"
        "\n"
        "USES=\t\tpython\n"
        "USE_PYTHON=\tautoplist concurrent pep517\n"
        "\n"
        "NO_ARCH=\tyes\n"
        "\n"
        ".include <bsd.port.mk>\n"
    )


_REAL_DISTINFO = (
    "TIMESTAMP = 1759774719\n"
    f"SHA256 (charset_normalizer-{_PORTVERSION}.tar.gz) = "
    "94537985111c35f28720e43603b8e7b43a6ecfb2ce1d3058bbe955b73404e21a\n"
    f"SIZE (charset_normalizer-{_PORTVERSION}.tar.gz) = 129418\n"
)


def _write_port(ports_root: Path, *, origin: str = _ORIGIN, portname: str = _PORTNAME) -> Path:
    port_dir = ports_root / origin
    port_dir.mkdir(parents=True)
    (port_dir / "Makefile").write_text(_port_makefile(portname=portname))
    (port_dir / "distinfo").write_text(_REAL_DISTINFO)
    return port_dir


# --------------------------------------------------------------------------- #
# Fixture .pkg archives — mirrors test_publish_release.py's _write_tar_pkg /
# _wrap_dependency_pkg (duplicated here per this repo's per-file convention).
# --------------------------------------------------------------------------- #


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


def _wrap_dependency_pkg(
    directory: Path,
    *,
    name: str,
    version: str,
    abi: str,
    local_name: str,
    payload: dict[str, bytes] | None = None,
) -> Path:
    """A minimal .pkg carrying only +COMPACT_MANIFEST — sufficient for both a
    dependency and a stand-in canonical package here (build_repo/catalogue_assembly
    only ever call pfb_pkg.read_compact_manifest on a pool member; a manifest without
    a pfb_build_record annotation skips full provenance validation regardless of its
    `name`)."""
    manifest = {"name": name, "version": version, "abi": abi, "origin": f"textproc/{name}"}
    compact = json.dumps(manifest, separators=(",", ":")).encode()
    members = [("+COMPACT_MANIFEST", compact, 0o644, 0)]
    members.extend((member, data, 0o644, 0) for member, data in (payload or {}).items())
    path = directory / local_name
    _write_tar_pkg(path, members)
    return path


# --------------------------------------------------------------------------- #
# Genuine canonical build-record fixture (issue #2454 step 3a: --print-ports-sha
# reads build_repo_portable._canonical_build_record, so the manifest needs a real,
# validate_build_record-shaped pfb_build_record annotation — mirrors
# tests/test_publish_release.py's _record, trimmed to what ports_sha_from_assets
# actually reads: it only calls read_compact_manifest, never validate_project_pkg,
# so the archive itself only needs +COMPACT_MANIFEST).
# --------------------------------------------------------------------------- #

_TAG_FOR_CHANNEL = {"edge": "v4.0.0.b1"}


def _canonical_record(*, row: dict[str, object], ports_sha: str, source_sha: str = "a" * 40) -> dict[str, object]:
    pfb_pkg = _ENGINE.pfb_pkg
    channel = "edge"
    major_minor = ".".join(str(row["pfsense_version"]).split(".")[:2])
    tag = _TAG_FOR_CHANNEL[channel]
    info = pfb_pkg.parse_release_tag(tag, channel)
    record: dict[str, object] = {
        "schema": 1,
        "channel": channel,
        "release_line": info.release_line,
        "classification": info.stage,
        "source_tag": tag,
        "source_sha": source_sha,
        "canonical_package_version": info.pkg_version,
        "native_recipe_identity": f"{pfb_pkg.CANONICAL_EMITTED_IDENTITY}-{channel}",
        "emitted_identity": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "matrix_row": row,
        "freebsd_ports_sha": ports_sha,
        "route": f"{channel}/{str(row['variant']).lower()}-{major_minor}",
        "source_date_epoch": 0,
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    return record


def _wrap_canonical_pkg_with_record(directory: Path, record: dict[str, object], *, local_name: str) -> Path:
    """A minimal canonical .pkg carrying ``record`` as its pfb_build_record
    annotation — sufficient for ports_sha_from_assets, which only ever calls
    pfb_pkg.read_compact_manifest, never validate_project_pkg."""
    pfb_pkg = _ENGINE.pfb_pkg
    row = record["matrix_row"]
    assert isinstance(row, dict)
    manifest = {
        "name": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "version": record["canonical_package_version"],
        "abi": f"FreeBSD:{row['freebsd_major']}:*",
        "origin": "net/pfSense-pkg-pfBlockerNG",
        "annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: json.dumps(record, separators=(",", ":"), sort_keys=True)},
    }
    compact = json.dumps(manifest, separators=(",", ":")).encode()
    path = directory / local_name
    _write_tar_pkg(path, [("+COMPACT_MANIFEST", compact, 0o644, 0)])
    return path


class _TempDirTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="pub-deps-test-")
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.pkg_repo = self.tmp / "pkg-repo"
        self.ports_dir = self.tmp / "ports"
        _write_port(self.ports_dir)

    def dest_dir(self, channel: str, varver: str) -> Path:
        return self.pkg_repo / "docs" / channel / varver

    def seed_dest(
        self,
        channel: str,
        varver: str,
        *,
        major: str,
        canonical: bool = True,
        dependency: bool = False,
        other_dep: bool = False,
    ) -> Path:
        """Seed a pre-existing, fully-regenerated catalogue directory (mirrors what a
        prior publish_release/publish_nightly run would have already left behind)."""
        dest_dir = self.dest_dir(channel, varver)
        dest_dir.mkdir(parents=True, exist_ok=True)
        if canonical:
            _wrap_dependency_pkg(
                dest_dir,
                name=_ENGINE.pfb_pkg.CANONICAL_EMITTED_IDENTITY,
                version="4.0.0",
                abi=f"FreeBSD:{major}:*",
                local_name=f"{_ENGINE.pfb_pkg.CANONICAL_EMITTED_IDENTITY}-4.0.0.pkg",
            )
        if dependency:
            _wrap_dependency_pkg(
                dest_dir,
                name="py311-charset-normalizer",
                version=_DEP_VERSION,
                abi=f"FreeBSD:{major}:*",
                local_name=_EXPECTED_NAME,
            )
        if other_dep:
            _wrap_dependency_pkg(
                dest_dir,
                name="py311-other-dep",
                version="1.0",
                abi=f"FreeBSD:{major}:*",
                local_name="py311-other-dep-1.0.pkg",
            )
        ca.regenerate_catalogue(self.pkg_repo / "docs", channel, varver, engine=_ENGINE)
        return dest_dir


class _StubBuilder:
    """Records every call; writes a well-formed dependency .pkg by default."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, origin: str, py_flavor: str, freebsd_major: str, out_dir: Path) -> None:
        self.calls.append((origin, py_flavor, freebsd_major))
        _wrap_dependency_pkg(
            out_dir,
            name=f"{py_flavor}-{_PORTNAME}",
            version=_PORTVERSION,
            abi=f"FreeBSD:{freebsd_major}:*",
            local_name=f"{py_flavor}-{_PORTNAME}-{_PORTVERSION}.pkg",
        )


def _tree_sha_map(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not root.is_dir():
        return result
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _packagesite_names(catalogue_dir: Path) -> set[str]:
    catalog = catalogue_dir / "packagesite.pkg"
    data = _ENGINE.pfb_pkg.zstd_decompress(catalog.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        member = tf.extractfile("packagesite.yaml")
        assert member is not None
        raw = member.read().decode()
    names = set()
    for line in raw.splitlines():
        if line.strip():
            names.add(json.loads(line)["name"])
    return names


# --------------------------------------------------------------------------- #
# 1. NOOP — every destination already holds the dependency.
# --------------------------------------------------------------------------- #


class NoopTests(_TempDirTestCase):
    @_requires_engine
    def test_noop_when_every_destination_already_has_the_dependency(self) -> None:
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=True)
        self.seed_dest("nightly", "ce-2.9", major="16", dependency=True)
        before = _tree_sha_map(self.pkg_repo)

        stub = _StubBuilder()
        report = pd.run(
            pkg_repo=self.pkg_repo,
            ports_dir=self.ports_dir,
            route_matrix=json.dumps(_ALL_ROWS),
            channels='["nightly"]',
            engine=_ENGINE,
            builder=stub,
        )

        self.assertTrue(report.noop)
        self.assertEqual(report.touched, ())
        self.assertEqual(stub.calls, [])
        self.assertEqual(_tree_sha_map(self.pkg_repo), before)


# --------------------------------------------------------------------------- #
# 2/3/4/12. Missing-dependency placement across varvers/majors/channels.
# --------------------------------------------------------------------------- #


class PlacementTests(_TempDirTestCase):
    @_requires_engine
    def test_single_varver_missing_builds_once_and_reports_only_that_varver(self) -> None:
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=False)
        self.seed_dest("nightly", "ce-2.9", major="16", dependency=True)
        ce_29_before = _tree_sha_map(self.dest_dir("nightly", "ce-2.9"))

        stub = _StubBuilder()
        report = pd.run(
            pkg_repo=self.pkg_repo,
            ports_dir=self.ports_dir,
            route_matrix=json.dumps((ROW_CE_28, ROW_CE_29)),
            channels='["nightly"]',
            engine=_ENGINE,
            builder=stub,
        )

        self.assertEqual(stub.calls, [(_ORIGIN, "py311", "15")])
        self.assertEqual(report.touched, (("nightly", "ce-2.8"),))
        dest = self.dest_dir("nightly", "ce-2.8")
        self.assertTrue((dest / _EXPECTED_NAME).is_file())
        self.assertIn("py311-charset-normalizer", _packagesite_names(dest))
        # ce-2.9 already had the dep (seeded) — untouched means byte-identical, not
        # rebuilt/recopied, even though it shares FreeBSD major 16 with nothing built here.
        self.assertEqual(_tree_sha_map(self.dest_dir("nightly", "ce-2.9")), ce_29_before)

    @_requires_engine
    def test_two_majors_missing_builds_twice_once_per_major(self) -> None:
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=False)
        self.seed_dest("nightly", "ce-2.9", major="16", dependency=False)

        stub = _StubBuilder()
        report = pd.run(
            pkg_repo=self.pkg_repo,
            ports_dir=self.ports_dir,
            route_matrix=json.dumps((ROW_CE_28, ROW_CE_29)),
            channels='["nightly"]',
            engine=_ENGINE,
            builder=stub,
        )

        self.assertEqual(sorted(call[2] for call in stub.calls), ["15", "16"])
        self.assertEqual(len(stub.calls), 2)
        self.assertEqual(set(report.touched), {("nightly", "ce-2.8"), ("nightly", "ce-2.9")})
        self.assertTrue((self.dest_dir("nightly", "ce-2.8") / _EXPECTED_NAME).is_file())
        self.assertTrue((self.dest_dir("nightly", "ce-2.9") / _EXPECTED_NAME).is_file())

    @_requires_engine
    def test_same_major_two_channels_missing_builds_once_places_in_both(self) -> None:
        self.seed_dest("testing", "ce-2.9", major="16", dependency=False)
        self.seed_dest("edge", "ce-2.9", major="16", dependency=False)

        stub = _StubBuilder()
        report = pd.run(
            pkg_repo=self.pkg_repo,
            ports_dir=self.ports_dir,
            route_matrix=json.dumps((ROW_CE_29,)),
            channels='["testing","edge"]',
            engine=_ENGINE,
            builder=stub,
        )

        self.assertEqual(len(stub.calls), 1)
        self.assertEqual(set(report.touched), {("testing", "ce-2.9"), ("edge", "ce-2.9")})
        self.assertTrue((self.dest_dir("testing", "ce-2.9") / _EXPECTED_NAME).is_file())
        self.assertTrue((self.dest_dir("edge", "ce-2.9") / _EXPECTED_NAME).is_file())

    @_requires_engine
    def test_plus_rows_with_no_extra_pkgs_never_receive_the_dependency(self) -> None:
        # ce-2.9 (major 16) is missing the dep; plus-26.03 shares that major but its
        # extra_pkgs is empty and its dir also lacks the file — must stay untouched.
        self.seed_dest("nightly", "ce-2.9", major="16", dependency=False)
        self.seed_dest("nightly", "plus-26.03", major="16", dependency=False)

        stub = _StubBuilder()
        report = pd.run(
            pkg_repo=self.pkg_repo,
            ports_dir=self.ports_dir,
            route_matrix=json.dumps((ROW_CE_29, ROW_PLUS_03)),
            channels='["nightly"]',
            engine=_ENGINE,
            builder=stub,
        )

        self.assertEqual(report.touched, (("nightly", "ce-2.9"),))
        self.assertTrue((self.dest_dir("nightly", "ce-2.9") / _EXPECTED_NAME).is_file())
        self.assertFalse((self.dest_dir("nightly", "plus-26.03") / _EXPECTED_NAME).exists())

    @_requires_engine
    def test_route_only_row_with_extra_pkgs_is_never_targeted(self) -> None:
        stub = _StubBuilder()
        report = pd.run(
            pkg_repo=self.pkg_repo,
            ports_dir=self.ports_dir,
            route_matrix=json.dumps((ROW_ROUTE_ONLY_17,)),
            channels='["nightly"]',
            engine=_ENGINE,
            builder=stub,
        )
        self.assertTrue(report.noop)
        self.assertEqual(stub.calls, [])
        self.assertFalse((self.pkg_repo / "docs" / "nightly" / "ce-17.0").exists())


# --------------------------------------------------------------------------- #
# 5. First release into a brand-new channel dir (no prior varver directory).
# --------------------------------------------------------------------------- #


class NewDestinationTests(_TempDirTestCase):
    @_requires_engine
    def test_absent_varver_dir_is_created_with_dep_and_complete_descriptor(self) -> None:
        dest = self.dest_dir("edge", "ce-2.9")
        self.assertFalse(dest.exists())

        stub = _StubBuilder()
        report = pd.run(
            pkg_repo=self.pkg_repo,
            ports_dir=self.ports_dir,
            route_matrix=json.dumps((ROW_CE_29,)),
            channels='["edge"]',
            engine=_ENGINE,
            builder=stub,
        )

        self.assertEqual(report.touched, (("edge", "ce-2.9"),))
        self.assertTrue((dest / _EXPECTED_NAME).is_file())
        self.assertTrue((dest / "meta.conf").is_file())
        self.assertTrue((dest / "data.pkg").is_file())
        self.assertTrue((dest / "packagesite.pkg").is_file())
        self.assertTrue(pd.pr._catalogue_descriptor_complete(dest, _ENGINE))


# --------------------------------------------------------------------------- #
# 6-9. Hostile inputs — fail loud, no writes, builder never (mis)used.
# --------------------------------------------------------------------------- #


class HostileInputTests(_TempDirTestCase):
    @_requires_engine
    def test_missing_port_directory_fails_loud_with_no_writes(self) -> None:
        empty_ports_dir = self.tmp / "empty-ports"
        empty_ports_dir.mkdir()
        stub = _StubBuilder()

        with self.assertRaises((pd.PublishDepsError, pd.bdp.DepPkgError)) as ctx:
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=empty_ports_dir,
                route_matrix=json.dumps((ROW_CE_28,)),
                channels='["nightly"]',
                engine=_ENGINE,
                builder=stub,
            )
        self.assertIn(_ORIGIN, str(ctx.exception))
        self.assertEqual(stub.calls, [])
        self.assertFalse((self.pkg_repo / "docs").exists())

    @_requires_engine
    def test_builder_wrong_filename_rejected_no_dest_written(self) -> None:
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=False)

        def bad_builder(origin: str, py_flavor: str, freebsd_major: str, out_dir: Path) -> None:
            _wrap_dependency_pkg(
                out_dir,
                name=f"{py_flavor}-{_PORTNAME}",
                version=_PORTVERSION,
                abi=f"FreeBSD:{freebsd_major}:*",
                local_name="wrong-name.pkg",
            )

        with self.assertRaises(pd.PublishDepsError) as ctx:
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix=json.dumps((ROW_CE_28,)),
                channels='["nightly"]',
                engine=_ENGINE,
                builder=bad_builder,
            )
        self.assertIn("did not produce", str(ctx.exception))
        self.assertFalse((self.dest_dir("nightly", "ce-2.8") / _EXPECTED_NAME).exists())

    @_requires_engine
    def test_builder_version_mismatch_rejected_no_dest_written(self) -> None:
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=False)

        def wrong_version_builder(origin: str, py_flavor: str, freebsd_major: str, out_dir: Path) -> None:
            _wrap_dependency_pkg(
                out_dir,
                name=f"{py_flavor}-{_PORTNAME}",
                version="9.9.9",  # PORTVERSION pinned by the ports checkout is _PORTVERSION
                abi=f"FreeBSD:{freebsd_major}:*",
                local_name=_EXPECTED_NAME,
            )

        with self.assertRaises(pd.PublishDepsError) as ctx:
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix=json.dumps((ROW_CE_28,)),
                channels='["nightly"]',
                engine=_ENGINE,
                builder=wrong_version_builder,
            )
        self.assertIn("version", str(ctx.exception))
        self.assertFalse((self.dest_dir("nightly", "ce-2.8") / _EXPECTED_NAME).exists())

    @_requires_engine
    def test_builder_abi_mismatch_rejected_no_dest_written(self) -> None:
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=False)

        def wrong_abi_builder(origin: str, py_flavor: str, freebsd_major: str, out_dir: Path) -> None:
            _wrap_dependency_pkg(
                out_dir,
                name=f"{py_flavor}-{_PORTNAME}",
                version=_PORTVERSION,
                abi="FreeBSD:16:*",  # row asks for major 15
                local_name=_EXPECTED_NAME,
            )

        with self.assertRaises(pd.PublishDepsError) as ctx:
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix=json.dumps((ROW_CE_28,)),
                channels='["nightly"]',
                engine=_ENGINE,
                builder=wrong_abi_builder,
            )
        self.assertIn("abi", str(ctx.exception))
        self.assertFalse((self.dest_dir("nightly", "ce-2.8") / _EXPECTED_NAME).exists())

    @_requires_engine
    def test_hostile_portname_with_slash_rejected_before_path_join(self) -> None:
        hostile_ports_dir = self.tmp / "hostile-ports"
        _write_port(hostile_ports_dir, portname="../../evil")
        stub = _StubBuilder()

        with self.assertRaises(pd.PublishDepsError) as ctx:
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=hostile_ports_dir,
                route_matrix=json.dumps((ROW_CE_28,)),
                channels='["nightly"]',
                engine=_ENGINE,
                builder=stub,
            )
        self.assertIn("PORTNAME", str(ctx.exception))
        self.assertEqual(stub.calls, [])
        # Nothing created outside the ports checkout — no path escape.
        self.assertFalse((self.pkg_repo / "docs").exists())
        self.assertFalse((self.tmp / "evil").exists())


# --------------------------------------------------------------------------- #
# 10. Canonical package + other dependency in a touched dest survive untouched.
# --------------------------------------------------------------------------- #


class SurvivalTests(_TempDirTestCase):
    @_requires_engine
    def test_canonical_and_unrelated_dep_survive_byte_identical(self) -> None:
        dest = self.seed_dest("nightly", "ce-2.8", major="15", dependency=False, other_dep=True)
        canonical_path = dest / f"{_ENGINE.pfb_pkg.CANONICAL_EMITTED_IDENTITY}-4.0.0.pkg"
        other_dep_path = dest / "py311-other-dep-1.0.pkg"
        canonical_before = canonical_path.read_bytes()
        other_dep_before = other_dep_path.read_bytes()

        stub = _StubBuilder()
        report = pd.run(
            pkg_repo=self.pkg_repo,
            ports_dir=self.ports_dir,
            route_matrix=json.dumps((ROW_CE_28,)),
            channels='["nightly"]',
            engine=_ENGINE,
            builder=stub,
        )

        self.assertEqual(report.touched, (("nightly", "ce-2.8"),))
        self.assertEqual(canonical_path.read_bytes(), canonical_before)
        self.assertEqual(other_dep_path.read_bytes(), other_dep_before)
        self.assertTrue((dest / _EXPECTED_NAME).is_file())


# --------------------------------------------------------------------------- #
# 11. Invalid --channels / --route-matrix.
# --------------------------------------------------------------------------- #


class InvalidInputTests(_TempDirTestCase):
    @_requires_engine
    def test_channels_combining_nightly_with_another_destination_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix=json.dumps((ROW_CE_28,)),
                channels='["nightly","edge"]',
                engine=_ENGINE,
            )

    @_requires_engine
    def test_channels_empty_array_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix=json.dumps((ROW_CE_28,)),
                channels="[]",
                engine=_ENGINE,
            )

    @_requires_engine
    def test_channels_non_json_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix=json.dumps((ROW_CE_28,)),
                channels="not json",
                engine=_ENGINE,
            )

    @_requires_engine
    def test_route_matrix_empty_array_rejected(self) -> None:
        with self.assertRaises(pd.PublishDepsError):
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix="[]",
                channels='["nightly"]',
                engine=_ENGINE,
            )

    @_requires_engine
    def test_route_matrix_non_json_rejected(self) -> None:
        with self.assertRaises(pd.PublishDepsError):
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix="not json",
                channels='["nightly"]',
                engine=_ENGINE,
            )

    @_requires_engine
    def test_route_matrix_row_with_invalid_role_propagates_run_verification_error(self) -> None:
        bad_row = {**ROW_CE_28, "role": "bogus"}
        with self.assertRaises(pc.RunVerificationError):
            pd.run(
                pkg_repo=self.pkg_repo,
                ports_dir=self.ports_dir,
                route_matrix=json.dumps((bad_row,)),
                channels='["nightly"]',
                engine=_ENGINE,
            )


# --------------------------------------------------------------------------- #
# 13. main() CLI wiring — success and failure.
# --------------------------------------------------------------------------- #


class MainCliTests(_TempDirTestCase):
    @_requires_engine
    def test_main_success_prints_updated_line_and_returns_zero(self) -> None:
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=False)
        argv = [
            "--pkg-repo",
            str(self.pkg_repo),
            "--ports-dir",
            str(self.ports_dir),
            "--route-matrix",
            json.dumps((ROW_CE_28,)),
            "--channels",
            '["nightly"]',
        ]

        def fake_subprocess_builder(ports_dir: object) -> pd._Builder:
            return _StubBuilder()

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch.object(pd, "_subprocess_builder", side_effect=fake_subprocess_builder),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 0)
        self.assertIn("updated nightly/ce-2.8", out.getvalue())

    @_requires_engine
    def test_main_noop_prints_dependency_specific_wording_and_returns_zero(self) -> None:
        """issue #2454: report.describe()'s default NOOP line names
        publish_release.py's own destination/asset vocabulary -- this module
        prints its own wording instead when nothing was missing."""
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=True)
        argv = [
            "--pkg-repo",
            str(self.pkg_repo),
            "--ports-dir",
            str(self.ports_dir),
            "--route-matrix",
            json.dumps((ROW_CE_28,)),
            "--channels",
            '["nightly"]',
        ]

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().strip(), "NOOP: every dependency already present at every destination")

    @_requires_engine
    def test_main_failure_prints_error_and_returns_one(self) -> None:
        empty_ports_dir = self.tmp / "empty-ports"
        empty_ports_dir.mkdir()
        argv = [
            "--pkg-repo",
            str(self.pkg_repo),
            "--ports-dir",
            str(empty_ports_dir),
            "--route-matrix",
            json.dumps((ROW_CE_28,)),
            "--channels",
            '["nightly"]',
        ]

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 1)
        self.assertIn("::error::", err.getvalue())

    @_requires_engine
    def test_main_makefile_if_directive_returns_one_not_traceback(self) -> None:
        """issue #2454: the Makefile evaluator has no conditional/loop support and
        raises build_pkg_portable.BuildError for a .if-bearing dep port Makefile --
        main() must report that as ::error:: + rc 1, never let it escape as an
        uncaught traceback."""
        hostile_makefile = (
            f"PORTNAME=\t{_PORTNAME}\n"
            f"PORTVERSION=\t{_PORTVERSION}\n"
            ".if 1\n"
            "EXTRA_PATCHES=\tfiles/extra-patch\n"
            ".endif\n"
            "CATEGORIES=\ttextproc python\n"
            ".include <bsd.port.mk>\n"
        )
        (self.ports_dir / _ORIGIN / "Makefile").write_text(hostile_makefile)
        argv = [
            "--pkg-repo",
            str(self.pkg_repo),
            "--ports-dir",
            str(self.ports_dir),
            "--route-matrix",
            json.dumps((ROW_CE_28,)),
            "--channels",
            '["nightly"]',
        ]

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 1)
        self.assertIn("::error::", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


# --------------------------------------------------------------------------- #
# 14. --print-ports-sha / ports_sha_from_assets (issue #2454 step 3a): the single
# freebsd_ports_sha shared by every canonical .pkg under --assets-dir.
# --------------------------------------------------------------------------- #


class PrintPortsShaTests(_TempDirTestCase):
    @_requires_engine
    def test_single_canonical_prints_its_sha(self) -> None:
        assets_dir = self.tmp / "assets"
        assets_dir.mkdir()
        record = _canonical_record(row=ROW_CE_28, ports_sha="a" * 40)
        _wrap_canonical_pkg_with_record(assets_dir, record, local_name="canonical.pkg")

        sha = pd.ports_sha_from_assets(_ENGINE, assets_dir)

        self.assertEqual(sha, "a" * 40)

    @_requires_engine
    def test_dependency_pkg_is_skipped_canonical_sha_wins(self) -> None:
        assets_dir = self.tmp / "assets"
        assets_dir.mkdir()
        record = _canonical_record(row=ROW_CE_28, ports_sha="b" * 40)
        _wrap_canonical_pkg_with_record(assets_dir, record, local_name="canonical.pkg")
        _wrap_dependency_pkg(
            assets_dir,
            name="py311-charset-normalizer",
            version=_DEP_VERSION,
            abi="FreeBSD:15:*",
            local_name=_EXPECTED_NAME,
        )

        sha = pd.ports_sha_from_assets(_ENGINE, assets_dir)

        self.assertEqual(sha, "b" * 40)

    @_requires_engine
    def test_two_canonicals_same_sha_prints_once(self) -> None:
        assets_dir = self.tmp / "assets"
        assets_dir.mkdir()
        record_a = _canonical_record(row=ROW_CE_28, ports_sha="c" * 40)
        record_b = _canonical_record(row=ROW_PLUS_03, ports_sha="c" * 40)
        _wrap_canonical_pkg_with_record(assets_dir, record_a, local_name="a.pkg")
        _wrap_canonical_pkg_with_record(assets_dir, record_b, local_name="b.pkg")

        sha = pd.ports_sha_from_assets(_ENGINE, assets_dir)

        self.assertEqual(sha, "c" * 40)

    @_requires_engine
    def test_two_canonicals_different_sha_rejected(self) -> None:
        assets_dir = self.tmp / "assets"
        assets_dir.mkdir()
        record_a = _canonical_record(row=ROW_CE_28, ports_sha="c" * 40)
        record_b = _canonical_record(row=ROW_PLUS_03, ports_sha="d" * 40)
        _wrap_canonical_pkg_with_record(assets_dir, record_a, local_name="a.pkg")
        _wrap_canonical_pkg_with_record(assets_dir, record_b, local_name="b.pkg")

        with self.assertRaises(pd.PublishDepsError) as ctx:
            pd.ports_sha_from_assets(_ENGINE, assets_dir)
        self.assertIn("disagree", str(ctx.exception))

    @_requires_engine
    def test_no_canonical_rejected(self) -> None:
        assets_dir = self.tmp / "assets"
        assets_dir.mkdir()
        _wrap_dependency_pkg(
            assets_dir,
            name="py311-charset-normalizer",
            version=_DEP_VERSION,
            abi="FreeBSD:15:*",
            local_name=_EXPECTED_NAME,
        )

        with self.assertRaises(pd.PublishDepsError) as ctx:
            pd.ports_sha_from_assets(_ENGINE, assets_dir)
        self.assertIn("no canonical", str(ctx.exception))

    @_requires_engine
    def test_empty_dir_rejected(self) -> None:
        assets_dir = self.tmp / "assets"
        assets_dir.mkdir()

        with self.assertRaises(pd.PublishDepsError):
            pd.ports_sha_from_assets(_ENGINE, assets_dir)


class MainCliPrintPortsShaTests(_TempDirTestCase):
    @_requires_engine
    def test_main_prints_sha_and_returns_zero(self) -> None:
        assets_dir = self.tmp / "assets"
        assets_dir.mkdir()
        record = _canonical_record(row=ROW_CE_28, ports_sha="e" * 40)
        _wrap_canonical_pkg_with_record(assets_dir, record, local_name="canonical.pkg")
        argv = ["--print-ports-sha", "--assets-dir", str(assets_dir)]

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().strip(), "e" * 40)

    @_requires_engine
    def test_main_missing_assets_dir_flag_returns_one(self) -> None:
        argv = ["--print-ports-sha"]

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 1)
        self.assertIn("::error::", err.getvalue())
        self.assertIn("--assets-dir", err.getvalue())

    @_requires_engine
    def test_main_disagreeing_sha_returns_one(self) -> None:
        assets_dir = self.tmp / "assets"
        assets_dir.mkdir()
        record_a = _canonical_record(row=ROW_CE_28, ports_sha="c" * 40)
        record_b = _canonical_record(row=ROW_PLUS_03, ports_sha="d" * 40)
        _wrap_canonical_pkg_with_record(assets_dir, record_a, local_name="a.pkg")
        _wrap_canonical_pkg_with_record(assets_dir, record_b, local_name="b.pkg")
        argv = ["--print-ports-sha", "--assets-dir", str(assets_dir)]

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 1)
        self.assertIn("::error::", err.getvalue())

    @_requires_engine
    def test_main_publish_mode_missing_args_returns_one(self) -> None:
        """--print-ports-sha not given: --pkg-repo/--ports-dir/--route-matrix/
        --channels are required again — proven by omitting all but --pkg-repo."""
        argv = ["--pkg-repo", str(self.pkg_repo)]

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 1)
        self.assertIn("::error::", err.getvalue())
        self.assertIn("--ports-dir", err.getvalue())

    @_requires_engine
    def test_main_publish_mode_still_works_without_print_ports_sha(self) -> None:
        """--assets-dir is simply unused in the publish mode — pinning that its
        presence in argparse's namespace does not perturb the existing flow."""
        self.seed_dest("nightly", "ce-2.8", major="15", dependency=False)
        argv = [
            "--pkg-repo",
            str(self.pkg_repo),
            "--ports-dir",
            str(self.ports_dir),
            "--route-matrix",
            json.dumps((ROW_CE_28,)),
            "--channels",
            '["nightly"]',
        ]

        def fake_subprocess_builder(ports_dir: object) -> pd._Builder:
            return _StubBuilder()

        with (
            mock.patch.dict(os.environ, {"PFB_SRC": str(_SRC_ROOT)}),
            mock.patch.object(pd, "_subprocess_builder", side_effect=fake_subprocess_builder),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            code = pd.main(argv)

        self.assertEqual(code, 0)
        self.assertIn("updated nightly/ce-2.8", out.getvalue())


if __name__ == "__main__":
    unittest.main()
