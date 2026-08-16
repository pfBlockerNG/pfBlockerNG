"""Tests for scripts/publish_catalogues.py — issue #2146 step S1 (intake + per-asset
verification core for the four-channel staged publisher).

No network, no git, no tree assembly, no ledger — this pins parse_intake, verify_asset,
and verify_run against the pfBlockerNG source-repo engine loaded from PFB_SRC (see
tests/_srcrepo.py). Canonical .pkg fixtures are built in pure Python (mirrors the source
repo's tests/test_build_repo_portable.py make_pkg / tests/test_pfb_pkg.py _synthetic_pkg),
and every fixture record's build_input_digest is computed by the engine's own
pfb_pkg.build_input_digest — never hand-typed.
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
from types import ModuleType
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import publish_catalogues as pc
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
# Fixture builders — genuine records (build_input_digest via the engine), and
# pure-Python zstd-tar .pkg archives (no binary fixtures vendored).
# --------------------------------------------------------------------------- #


def _matrix_row(**overrides: object) -> dict:
    row: dict[str, object] = {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "extra_pkgs": [],
    }
    row.update(overrides)
    return row


# One release tag per channel satisfying pfb_pkg.parse_release_tag's own rules: a
# final tag requires "stable"; a preview tag requires "testing" (patch != 0) or
# "edge" (patch == 0).
_TAG_FOR_CHANNEL = {"stable": "v4.0.0", "testing": "v4.0.1.b1", "edge": "v4.0.0.b1"}


def _record(
    *,
    channel: str = "testing",
    row: dict | None = None,
    source_sha: str = "a" * 40,
    canonical_package_version: str | None = None,
    release_line: str | None = None,
    source_tag: str | None = None,
) -> dict:
    """A genuine, digest-bound build record — build_input_digest always recomputed
    via engine.pfb_pkg.build_input_digest, never hand-typed."""
    pfb_pkg = _ENGINE.pfb_pkg
    row = row or _matrix_row()
    major_minor = ".".join(row["pfsense_version"].split(".")[:2])
    if channel == "nightly":
        record = {
            "schema": 1,
            "channel": "nightly",
            "release_line": "nightly" if release_line is None else release_line,
            "classification": "nightly",
            "source_tag": None,
            "source_sha": source_sha,
            "canonical_package_version": canonical_package_version or f"20260805153045.{source_sha[:7]}",
            "native_recipe_identity": "pfSense-pkg-pfBlockerNG-nightly",
            "emitted_identity": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
            "matrix_row": row,
            "freebsd_ports_sha": "b" * 64,
            "route": f"nightly/{row['variant'].lower()}-{major_minor}",
            "source_date_epoch": 0,
            "build_input_digest": "",
        }
    else:
        tag = source_tag or _TAG_FOR_CHANNEL[channel]
        info = pfb_pkg.parse_release_tag(tag, channel)
        native = (
            pfb_pkg.CANONICAL_EMITTED_IDENTITY
            if channel == "stable"
            else f"{pfb_pkg.CANONICAL_EMITTED_IDENTITY}-{channel}"
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
            "route": f"{channel}/{row['variant'].lower()}-{major_minor}",
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


def _wrap_canonical_pkg(directory: Path, record: dict, *, local_name: str = "asset.pkg") -> tuple[Path, str]:
    """Write a full, validate_project_pkg-shaped canonical .pkg carrying ``record``
    as its pfb_build_record annotation. Returns (local path, sha256 of the bytes)."""
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
    local_name: str = "dep.pkg",
) -> tuple[Path, str]:
    manifest = {
        "name": name,
        "version": version,
        "abi": abi,
        "origin": f"textproc/{name}",
    }
    compact = json.dumps(manifest, separators=(",", ":")).encode()
    path = directory / local_name
    _write_tar_pkg(path, [("+COMPACT_MANIFEST", compact, 0o644, 0)])
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _fabricated_asset(
    record: dict | None,
    *,
    asset_class: str = "canonical",
    manifest: dict | None = None,
    declared_name: str = "fabricated.pkg",
    sha256: str = "0" * 64,
) -> pc.VerifiedAsset:
    """A VerifiedAsset built directly (no verify_asset call) for unit-testing
    verify_run's own aggregate logic against a hand-picked record/manifest, isolated
    from whatever verify_asset itself would have accepted or rejected upstream."""
    return pc.VerifiedAsset(
        asset_class=asset_class,
        declared_name=declared_name,
        canonical_name=declared_name,
        work_path=Path(declared_name),
        sha256=sha256,
        manifest=manifest or {},
        record=record,
    )


# --------------------------------------------------------------------------- #
# Engine loading
# --------------------------------------------------------------------------- #


class EngineLoadingTests(unittest.TestCase):
    def test_missing_src_root_and_env_raises(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PFB_SRC", None)
            with self.assertRaises(pc.EngineError):
                pc.load_engine(None)

    def test_nonexistent_directory_raises(self) -> None:
        with self.assertRaises(pc.EngineError):
            pc.load_engine("/nonexistent/path/does-not-exist")

    def test_incomplete_checkout_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "scripts").mkdir()
            (root / "scripts" / "pfb_pkg.py").write_text("# stub\n")
            # build-repo-portable.py deliberately absent.
            with self.assertRaises(pc.EngineError) as ctx:
                pc.load_engine(root)
            self.assertIn("build-repo-portable.py", str(ctx.exception))

    @_requires_engine
    def test_loads_real_engine(self) -> None:
        engine = pc.load_engine(_SRC_ROOT)
        self.assertTrue(hasattr(engine.pfb_pkg, "validate_project_pkg"))
        self.assertTrue(hasattr(engine.build_repo_portable, "_canonical_build_record"))

    @_requires_engine
    def test_mismatched_checkout_reload_raises(self) -> None:
        """load_engine caches both engine modules under a fixed name/key, so a
        second call naming a DIFFERENT checkout must fail loudly instead of
        silently handing back the first root's modules while claiming the second
        root. The module-level _ENGINE fixture already loaded _SRC_ROOT, so this
        only needs a second, distinct root whose two required files exist."""
        with tempfile.TemporaryDirectory() as td:
            other_root = Path(td)
            (other_root / "scripts").mkdir()
            (other_root / "scripts" / "pfb_pkg.py").write_text("# stub\n")
            (other_root / "scripts" / "build-repo-portable.py").write_text("# stub\n")
            with self.assertRaises(pc.EngineError) as ctx:
                pc.load_engine(other_root)
            message = str(ctx.exception)
            self.assertIn(str(Path(_ENGINE.pfb_pkg.__file__).resolve()), message)
            self.assertIn(str((other_root / "scripts" / "pfb_pkg.py").resolve()), message)


# --------------------------------------------------------------------------- #
# parse_intake
# --------------------------------------------------------------------------- #

_REPO = pc.EXPECTED_SOURCE_REPOSITORY


class IntakeDestinationsTests(unittest.TestCase):
    """Valid destination tuples the ticket names, plus the intake-kind derivation."""

    def test_tagged_destinations_edge(self) -> None:
        intake = pc.parse_intake(_REPO, "1", "v4.0.0.b1", '["edge"]', "10:1")
        self.assertEqual(intake.kind, "tagged")
        self.assertEqual(intake.destinations, ("edge",))
        self.assertEqual(intake.primary_channel, "edge")

    def test_tagged_destinations_testing_edge(self) -> None:
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        self.assertEqual(intake.destinations, ("testing", "edge"))
        self.assertEqual(intake.primary_channel, "testing")

    def test_tagged_destinations_testing(self) -> None:
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing"]', "10:1")
        self.assertEqual(intake.destinations, ("testing",))

    def test_tagged_destinations_stable_testing_edge(self) -> None:
        intake = pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing","edge"]', "10:1")
        self.assertEqual(intake.destinations, ("stable", "testing", "edge"))
        self.assertEqual(intake.primary_channel, "stable")

    def test_tagged_destinations_stable_testing(self) -> None:
        intake = pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing"]', "10:1")
        self.assertEqual(intake.destinations, ("stable", "testing"))

    def test_nightly_destinations(self) -> None:
        intake = pc.parse_intake(_REPO, "", "", '["nightly"]', "10:1")
        self.assertEqual(intake.kind, "nightly")
        self.assertEqual(intake.destinations, ("nightly",))
        self.assertEqual(intake.primary_channel, "nightly")

    # --- hostile destinations rows ---

    def test_destinations_empty_string_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", "", "10:1")

    def test_destinations_empty_array_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", "[]", "10:1")

    def test_destinations_not_json_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", "not json", "10:1")

    def test_destinations_object_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", "{}", "10:1")

    def test_destinations_duplicate_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","stable"]', "10:1")

    def test_destinations_unknown_channel_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["devel"]', "10:1")

    def test_destinations_nightly_mixed_with_edge_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "", "", '["nightly","edge"]', "10:1")

    def test_destinations_case_sensitive_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["Stable"]', "10:1")

    def test_destinations_non_string_element_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", "[1]", "10:1")

    def test_destinations_oversized_array_rejected(self) -> None:
        huge = json.dumps([f"x{i}" for i in range(10_000)])
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", huge, "10:1")

    def test_destinations_too_many_elements_rejected(self) -> None:
        """The ELEMENT cap (_MAX_DESTINATIONS_ELEMENTS), distinct from the TEXT cap
        the previous test actually exercises: a huge element count whose
        serialized text still stays well under _MAX_DESTINATIONS_TEXT, so this
        can only be rejected by the element-count check itself."""
        too_many = json.dumps(["e"] * (pc._MAX_DESTINATIONS_ELEMENTS + 1))
        self.assertLess(len(too_many), pc._MAX_DESTINATIONS_TEXT)
        with self.assertRaises(pc.IntakeError) as ctx:
            pc.parse_intake(_REPO, "1", "v4.0.0", too_many, "10:1")
        self.assertIn("too large", str(ctx.exception))

    def test_destinations_stable_alone_rejected(self) -> None:
        """F2: derive_destinations (release_version.py) never returns ("stable",)
        alone — a final tag always fans to at least testing too. Structurally
        unreachable, so it must abort rather than be silently accepted."""
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable"]', "10:1")

    def test_destinations_stable_edge_skipping_testing_rejected(self) -> None:
        """F2: derive_destinations never skips testing to go straight from stable to
        edge — ("stable","edge") is not in the intake allow-list."""
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","edge"]', "10:1")


class IntakeReleaseIdTests(unittest.TestCase):
    def test_release_id_empty_on_tagged_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "", "v4.0.0", '["stable","testing","edge"]', "10:1")

    def test_release_id_non_numeric_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "abc", "v4.0.0", '["stable","testing","edge"]', "10:1")

    def test_release_id_plus_sign_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "+7", "v4.0.0", '["stable","testing","edge"]', "10:1")

    def test_release_id_leading_space_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, " 7", "v4.0.0", '["stable","testing","edge"]', "10:1")

    def test_release_id_decimal_point_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "7.0", "v4.0.0", '["stable","testing","edge"]', "10:1")

    def test_release_id_negative_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "-7", "v4.0.0", '["stable","testing","edge"]', "10:1")

    def test_release_id_non_empty_on_nightly_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "7", "", '["nightly"]', "10:1")


class IntakeReleaseTagTests(unittest.TestCase):
    def test_release_tag_empty_on_tagged_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "", '["stable","testing","edge"]', "10:1")

    def test_release_tag_missing_v_prefix_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "4.0.0", '["stable","testing","edge"]', "10:1")

    def test_release_tag_missing_patch_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0", '["stable","testing","edge"]', "10:1")

    def test_release_tag_bad_stage_letter_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0.x1", '["stable","testing","edge"]', "10:1")

    def test_release_tag_non_empty_on_nightly_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "", "v4.0.0", '["nightly"]', "10:1")


class IntakeSourceRunIdTests(unittest.TestCase):
    def test_source_run_id_empty_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing","edge"]', "")

    def test_source_run_id_non_numeric_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing","edge"]', "abc")

    def test_source_run_id_missing_colon_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing","edge"]', "1")

    def test_source_run_id_missing_attempt_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing","edge"]', "1:")

    def test_source_run_id_missing_run_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing","edge"]', ":1")

    def test_source_run_id_extra_colon_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing","edge"]', "1:1:1")

    def test_source_run_id_negative_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(_REPO, "1", "v4.0.0", '["stable","testing","edge"]', "-1:1")


class IntakeSourceRepositoryTests(unittest.TestCase):
    def test_source_repository_empty_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake("", "1", "v4.0.0", '["stable","testing","edge"]', "10:1")

    def test_source_repository_wrong_repo_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(
                "someone-else/pfBlockerNG",
                "1",
                "v4.0.0",
                '["stable","testing","edge"]',
                "10:1",
            )

    def test_source_repository_case_mismatch_rejected(self) -> None:
        with self.assertRaises(pc.IntakeError):
            pc.parse_intake(
                "pfblockerng/pfblockerng",
                "1",
                "v4.0.0",
                '["stable","testing","edge"]',
                "10:1",
            )


# --------------------------------------------------------------------------- #
# verify_asset
# --------------------------------------------------------------------------- #


@_requires_engine
class AssetVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_path = Path(self._tmp.name)
        self.work_dir = self.tmp_path / "work"

    def _intake(
        self,
        *,
        channel: str,
        destinations: str,
        release_id: str = "1",
        release_tag: str | None = None,
    ) -> pc.Intake:
        if channel == "nightly":
            return pc.parse_intake(_REPO, "", "", destinations, "10:1")
        tag = release_tag or _TAG_FOR_CHANNEL[channel]
        return pc.parse_intake(_REPO, release_id, tag, destinations, "10:1")

    def test_verify_canonical_stable_asset(self) -> None:
        record = _record(channel="stable")
        intake = self._intake(channel="stable", destinations='["stable","testing","edge"]')
        path, digest = _wrap_canonical_pkg(self.tmp_path, record)
        declared = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}-CE-2.8.pkg"
        asset = pc.verify_asset(
            _ENGINE,
            path,
            declared,
            intake=intake,
            expected_sha256=digest,
            work_dir=self.work_dir,
        )
        self.assertEqual(asset.asset_class, "canonical")
        self.assertEqual(asset.record["channel"], "stable")
        self.assertTrue(asset.work_path.is_file())

    def test_verify_canonical_testing_asset(self) -> None:
        record = _record(channel="testing")
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        path, digest = _wrap_canonical_pkg(self.tmp_path, record)
        declared = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}-CE-2.8.pkg"
        asset = pc.verify_asset(
            _ENGINE,
            path,
            declared,
            intake=intake,
            expected_sha256=digest,
            work_dir=self.work_dir,
        )
        self.assertEqual(asset.record["channel"], "testing")

    def test_verify_canonical_edge_asset(self) -> None:
        record = _record(channel="edge")
        intake = self._intake(channel="edge", destinations='["edge"]')
        path, digest = _wrap_canonical_pkg(self.tmp_path, record)
        declared = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}-CE-2.8.pkg"
        asset = pc.verify_asset(
            _ENGINE,
            path,
            declared,
            intake=intake,
            expected_sha256=digest,
            work_dir=self.work_dir,
        )
        self.assertEqual(asset.record["channel"], "edge")

    def test_verify_canonical_nightly_asset(self) -> None:
        record = _record(channel="nightly")
        intake = self._intake(channel="nightly", destinations='["nightly"]')
        path, digest = _wrap_canonical_pkg(self.tmp_path, record)
        declared = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}.pkg"
        asset = pc.verify_asset(
            _ENGINE,
            path,
            declared,
            intake=intake,
            expected_sha256=digest,
            work_dir=self.work_dir,
        )
        self.assertEqual(asset.record["channel"], "nightly")

    def test_verify_dependency_asset_tagged_real_release_asset_shape(self) -> None:
        """F1: release.yml renames a tagged run's dependency .pkg with the SAME
        -<Variant>-<pfsense_version> suffix it applies to the canonical package
        (RENAMED_DEP in the "Build the .pkg via build-leg.sh" step) — this is the
        real asset shape, not a fixture-convenient bare name."""
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        path, digest = _wrap_dependency_pkg(self.tmp_path)
        asset = pc.verify_asset(
            _ENGINE,
            path,
            "py311-charset-normalizer-3.4.0-CE-2.8.pkg",
            intake=intake,
            expected_sha256=digest,
            work_dir=self.work_dir,
        )
        self.assertEqual(asset.asset_class, "dependency")
        self.assertIsNone(asset.record)
        self.assertEqual(asset.canonical_name, "py311-charset-normalizer-3.4.0.pkg")
        # issue #2468: the -<Variant>-<pfsense_version> suffix this asset carries is
        # exposed for the publisher's own per-suffix routing, not just parsed and discarded.
        self.assertEqual(asset.release_suffix, ("CE", "2.8"))

    def test_verify_dependency_asset_nightly_bare_name(self) -> None:
        intake = self._intake(channel="nightly", destinations='["nightly"]')
        path, digest = _wrap_dependency_pkg(self.tmp_path)
        asset = pc.verify_asset(
            _ENGINE,
            path,
            "py311-charset-normalizer-3.4.0.pkg",
            intake=intake,
            expected_sha256=digest,
            work_dir=self.work_dir,
        )
        self.assertEqual(asset.asset_class, "dependency")
        self.assertIsNone(asset.record)
        # issue #2468: a Nightly dependency artifact carries no per-row suffix.
        self.assertIsNone(asset.release_suffix)

    def test_dependency_tagged_bare_name_without_suffix_rejected(self) -> None:
        """A tagged dependency asset that is missing its -<Variant>-<pfsense_version>
        Release-asset suffix (the pre-fix bug: this used to be REJECTED even for the
        real, correctly-suffixed shape; now a bare name on the tagged path is the one
        that must be rejected)."""
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        path, digest = _wrap_dependency_pkg(self.tmp_path)
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                path,
                "py311-charset-normalizer-3.4.0.pkg",
                intake=intake,
                expected_sha256=digest,
                work_dir=self.work_dir,
            )

    def test_dependency_tagged_malformed_suffix_rejected(self) -> None:
        """issue #2468 promotes the -<Variant>-<pfsense_version> suffix from a cosmetic
        label into the routing key that decides which varver a dependency lands in, so
        every malformed shape must be rejected here rather than routed somewhere by
        accident: an empty version ('-CE-'), a bare version with no variant, and an
        empty variant. (A well-formed suffix naming a row this run never built is a
        routing rejection instead — publish_release's own target fan-in.)"""
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        path, digest = _wrap_dependency_pkg(self.tmp_path)
        for malformed in (
            "py311-charset-normalizer-3.4.0-CE-.pkg",
            "py311-charset-normalizer-3.4.0-2.8.pkg",
            "py311-charset-normalizer-3.4.0--2.8.pkg",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(pc.AssetVerificationError) as ctx:
                pc.verify_asset(
                    _ENGINE,
                    path,
                    malformed,
                    intake=intake,
                    expected_sha256=digest,
                    work_dir=self.work_dir,
                )
            self.assertIn("Release-asset suffix", str(ctx.exception))

    # --- hostile asset name rows ---

    def test_asset_name_with_parent_traversal_rejected(self) -> None:
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                self.tmp_path / "whatever",
                "../evil.pkg",
                intake=intake,
                expected_sha256="0" * 64,
                work_dir=self.work_dir,
            )

    def test_asset_name_absolute_path_rejected(self) -> None:
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                self.tmp_path / "whatever",
                "/etc/evil.pkg",
                intake=intake,
                expected_sha256="0" * 64,
                work_dir=self.work_dir,
            )

    def test_asset_name_with_nul_rejected(self) -> None:
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                self.tmp_path / "whatever",
                "evil\x00.pkg",
                intake=intake,
                expected_sha256="0" * 64,
                work_dir=self.work_dir,
            )

    def test_asset_name_with_newline_rejected(self) -> None:
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                self.tmp_path / "whatever",
                "evil\n.pkg",
                intake=intake,
                expected_sha256="0" * 64,
                work_dir=self.work_dir,
            )

    def test_asset_canonical_form_mismatch_rejected(self) -> None:
        record = _record(channel="testing")
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        path, digest = _wrap_canonical_pkg(self.tmp_path, record)
        wrong_declared = "pfSense-pkg-pfBlockerNG-9.9.9-CE-2.8.pkg"
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                path,
                wrong_declared,
                intake=intake,
                expected_sha256=digest,
                work_dir=self.work_dir,
            )

    # --- hostile record/asset divergence rows ---

    def test_checksum_mismatch_rejected(self) -> None:
        record = _record(channel="testing")
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        path, _digest = _wrap_canonical_pkg(self.tmp_path, record)
        declared = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}-CE-2.8.pkg"
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                path,
                declared,
                intake=intake,
                expected_sha256="f" * 64,
                work_dir=self.work_dir,
            )

    def test_canonical_package_without_provenance_rejected(self) -> None:
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        pfb_pkg = _ENGINE.pfb_pkg
        common = {
            "name": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
            "origin": "net/pfSense-pkg-pfBlockerNG",
            "version": "4.0.1.b1",
            "abi": "FreeBSD:15:*",
            "arch": "freebsd:15:*",
            "prefix": "/usr/local",
        }
        compact = json.dumps(common, separators=(",", ":")).encode()
        path = self.tmp_path / "unannotated.pkg"
        _write_tar_pkg(path, [("+COMPACT_MANIFEST", compact, 0o644, 0)])
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        declared = "pfSense-pkg-pfBlockerNG-4.0.1.b1-CE-2.8.pkg"
        with self.assertRaises(pc.AssetVerificationError) as ctx:
            pc.verify_asset(
                _ENGINE,
                path,
                declared,
                intake=intake,
                expected_sha256=digest,
                work_dir=self.work_dir,
            )
        self.assertIn("provenance", str(ctx.exception))

    def test_release_tag_disagrees_with_record_source_tag_rejected(self) -> None:
        record = _record(channel="testing", source_tag="v4.0.1.b1")
        # intake carries a DIFFERENT (but shape-valid) tag than the record's own source_tag.
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b2", '["testing","edge"]', "10:1")
        path, digest = _wrap_canonical_pkg(self.tmp_path, record)
        declared = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}-CE-2.8.pkg"
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                path,
                declared,
                intake=intake,
                expected_sha256=digest,
                work_dir=self.work_dir,
            )

    def test_destination_not_servable_by_record_channel_rejected(self) -> None:
        """Axis 13 in isolation: intake.release_tag is set to the SAME value the edge
        record was built for, so axis 5 (source_tag == release_tag) passes cleanly —
        only the channel/primary-destination mismatch (axis 13) can reject this."""
        record = _record(channel="edge")
        self.assertEqual(record["source_tag"], _TAG_FOR_CHANNEL["edge"])
        intake = pc.parse_intake(_REPO, "1", record["source_tag"], '["testing","edge"]', "10:1")
        path, digest = _wrap_canonical_pkg(self.tmp_path, record)
        declared = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}-CE-2.8.pkg"
        with self.assertRaises(pc.AssetVerificationError) as ctx:
            pc.verify_asset(
                _ENGINE,
                path,
                declared,
                intake=intake,
                expected_sha256=digest,
                work_dir=self.work_dir,
            )
        self.assertIn("channel", str(ctx.exception))

    def test_route_composition_violation_propagates_from_engine(self) -> None:
        """Axis 8 (record.route == channel/varver) is validate_build_record's own
        'route composition' check (brief: do not restate it) — this proves the
        rejection PROPAGATES through verify_asset rather than being silently accepted."""
        record = _record(channel="testing", row=_matrix_row(pfsense_version="2.9"))
        record["route"] = "testing/ce-2.8"  # wrong: matrix_row says 2.9
        pfb_pkg = _ENGINE.pfb_pkg
        record["build_input_digest"] = pfb_pkg.build_input_digest(record)
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        path, digest = _wrap_canonical_pkg(self.tmp_path, record)
        declared = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}-CE-2.9.pkg"
        with self.assertRaises(pc.AssetVerificationError) as ctx:
            pc.verify_asset(
                _ENGINE,
                path,
                declared,
                intake=intake,
                expected_sha256=digest,
                work_dir=self.work_dir,
            )
        self.assertIn("route", str(ctx.exception))

    def test_dependency_name_mismatch_rejected(self) -> None:
        """Correctly Release-asset-suffixed, but the version segment lies about the
        manifest's real version — the real hostile shape, not a bare-name typo."""
        intake = self._intake(channel="testing", destinations='["testing","edge"]')
        path, digest = _wrap_dependency_pkg(self.tmp_path, name="py311-charset-normalizer", version="3.4.0")
        with self.assertRaises(pc.AssetVerificationError):
            pc.verify_asset(
                _ENGINE,
                path,
                "py311-charset-normalizer-9.9.9-CE-2.8.pkg",
                intake=intake,
                expected_sha256=digest,
                work_dir=self.work_dir,
            )


# --------------------------------------------------------------------------- #
# verify_run
# --------------------------------------------------------------------------- #


@_requires_engine
class RunVerificationTests(unittest.TestCase):
    def test_verify_run_single_build_row_success(self) -> None:
        record = _record(channel="testing")
        asset = _fabricated_asset(record, manifest={"name": "pfSense-pkg-pfBlockerNG", "abi": "FreeBSD:15:*"})
        route_matrix = [_matrix_row()]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        result = pc.verify_run(_ENGINE, intake, [asset], route_matrix)
        self.assertEqual(len(result.canonical_assets), 1)
        self.assertEqual(len(result.build_route_rows), 1)

    def test_verify_run_with_route_only_row_and_matching_dependency(self) -> None:
        record = _record(channel="testing")
        canonical = _fabricated_asset(
            record,
            manifest={"name": "pfSense-pkg-pfBlockerNG", "abi": "FreeBSD:15:*"},
            declared_name="canonical.pkg",
        )
        dep_manifest = {
            "name": "py311-charset-normalizer",
            "version": "3.4.0",
            "abi": "FreeBSD:14:*",
        }
        dependency = _fabricated_asset(
            None,
            asset_class="dependency",
            manifest=dep_manifest,
            declared_name="dep.pkg",
        )
        route_matrix = [
            _matrix_row(),
            _matrix_row(
                pfsense_version="2.7",
                freebsd_major="14",
                freebsd_version="14.0-RELEASE",
                role="route-only",
            ),
        ]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        result = pc.verify_run(_ENGINE, intake, [canonical, dependency], route_matrix)
        self.assertEqual(len(result.route_only_rows), 1)
        self.assertEqual(len(result.dependency_assets), 1)

    def test_verify_run_multi_varver_with_dependency_matching_build_row(self) -> None:
        row_a = _matrix_row()
        row_b = _matrix_row(pfsense_version="2.9")
        asset_a = _fabricated_asset(_record(channel="testing", row=row_a), declared_name="a.pkg")
        asset_b = _fabricated_asset(_record(channel="testing", row=row_b), declared_name="b.pkg")
        dep_manifest = {
            "name": "py311-charset-normalizer",
            "version": "3.4.0",
            "abi": "FreeBSD:15:*",
        }
        dependency = _fabricated_asset(
            None,
            asset_class="dependency",
            manifest=dep_manifest,
            declared_name="dep.pkg",
        )
        route_matrix = [row_a, row_b]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        result = pc.verify_run(_ENGINE, intake, [asset_a, asset_b, dependency], route_matrix)
        self.assertEqual(len(result.canonical_assets), 2)
        self.assertEqual(len(result.dependency_assets), 1)

    # --- hostile whole-run rows ---

    def test_matrix_row_absent_from_route_matrix_rejected(self) -> None:
        record = _record(channel="testing", row=_matrix_row(pfsense_version="2.8"))
        asset = _fabricated_asset(record)
        route_matrix = [_matrix_row(pfsense_version="2.9")]  # no row for 2.8
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError):
            pc.verify_run(_ENGINE, intake, [asset], route_matrix)

    def test_duplicate_asset_for_same_route_row_rejected(self) -> None:
        record = _record(channel="testing")
        asset_a = _fabricated_asset(record, declared_name="a.pkg")
        asset_b = _fabricated_asset(record, declared_name="b.pkg")
        route_matrix = [_matrix_row()]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError):
            pc.verify_run(_ENGINE, intake, [asset_a, asset_b], route_matrix)

    def test_route_build_row_with_no_asset_rejected(self) -> None:
        record = _record(channel="testing", row=_matrix_row(pfsense_version="2.8"))
        asset = _fabricated_asset(record)
        route_matrix = [
            _matrix_row(pfsense_version="2.8"),
            _matrix_row(pfsense_version="2.9"),
        ]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError):
            pc.verify_run(_ENGINE, intake, [asset], route_matrix)

    def test_assets_disagree_on_source_sha_rejected(self) -> None:
        row_a = _matrix_row()
        row_b = _matrix_row(pfsense_version="2.9")
        asset_a = _fabricated_asset(
            _record(channel="testing", row=row_a, source_sha="a" * 40),
            declared_name="a.pkg",
        )
        asset_b = _fabricated_asset(
            _record(channel="testing", row=row_b, source_sha="c" * 40),
            declared_name="b.pkg",
        )
        route_matrix = [row_a, row_b]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError):
            pc.verify_run(_ENGINE, intake, [asset_a, asset_b], route_matrix)

    def test_assets_disagree_on_canonical_package_version_rejected(self) -> None:
        row_a = _matrix_row()
        row_b = _matrix_row(pfsense_version="2.9")
        asset_a = _fabricated_asset(
            _record(channel="testing", row=row_a, canonical_package_version="4.0.1.b1"),
            declared_name="a.pkg",
        )
        asset_b = _fabricated_asset(
            _record(channel="testing", row=row_b, canonical_package_version="4.0.1.b2"),
            declared_name="b.pkg",
        )
        route_matrix = [row_a, row_b]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError):
            pc.verify_run(_ENGINE, intake, [asset_a, asset_b], route_matrix)

    def test_assets_disagree_on_release_line_rejected(self) -> None:
        row_a = _matrix_row()
        row_b = _matrix_row(pfsense_version="2.9")
        asset_a = _fabricated_asset(
            _record(channel="testing", row=row_a, release_line="release/4.0"),
            declared_name="a.pkg",
        )
        asset_b = _fabricated_asset(
            _record(channel="testing", row=row_b, release_line="release/3.9"),
            declared_name="b.pkg",
        )
        route_matrix = [row_a, row_b]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError):
            pc.verify_run(_ENGINE, intake, [asset_a, asset_b], route_matrix)

    def test_dependency_with_unmatched_abi_rejected(self) -> None:
        record = _record(channel="testing")
        canonical = _fabricated_asset(record, declared_name="canonical.pkg")
        dep_manifest = {
            "name": "py311-charset-normalizer",
            "version": "3.4.0",
            "abi": "FreeBSD:99:*",
        }
        dependency = _fabricated_asset(
            None,
            asset_class="dependency",
            manifest=dep_manifest,
            declared_name="dep.pkg",
        )
        route_matrix = [_matrix_row()]  # only freebsd_major "15"
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError):
            pc.verify_run(_ENGINE, intake, [canonical, dependency], route_matrix)

    # --- _normalize_route_matrix branches (F4) ---

    def test_route_matrix_row_not_a_mapping_rejected(self) -> None:
        record = _record(channel="testing")
        asset = _fabricated_asset(record)
        route_matrix = ["not-a-mapping"]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError) as ctx:
            pc.verify_run(_ENGINE, intake, [asset], route_matrix)
        self.assertIn("must be an object", str(ctx.exception))

    def test_route_matrix_invalid_role_rejected(self) -> None:
        record = _record(channel="testing")
        asset = _fabricated_asset(record)
        route_matrix = [_matrix_row(role="frozen")]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError) as ctx:
            pc.verify_run(_ENGINE, intake, [asset], route_matrix)
        self.assertIn("invalid role", str(ctx.exception))

    def test_route_matrix_duplicate_version_identity_rejected(self) -> None:
        record = _record(channel="testing")
        asset = _fabricated_asset(record)
        route_matrix = [_matrix_row(), _matrix_row()]
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError) as ctx:
            pc.verify_run(_ENGINE, intake, [asset], route_matrix)
        self.assertIn("duplicate version identity", str(ctx.exception))

    def test_route_matrix_empty_rejected(self) -> None:
        record = _record(channel="testing")
        asset = _fabricated_asset(record)
        intake = pc.parse_intake(_REPO, "1", "v4.0.1.b1", '["testing","edge"]', "10:1")
        with self.assertRaises(pc.RunVerificationError) as ctx:
            pc.verify_run(_ENGINE, intake, [asset], [])
        self.assertIn("must not be empty", str(ctx.exception))


# --------------------------------------------------------------------------- #
# Engine-symbol allowlist and the canonical-record narrowing accessor.
# --------------------------------------------------------------------------- #


class EngineSymbolAllowlistTests(unittest.TestCase):
    """Every engine symbol this module dereferences must be in the allowlist.

    _verify_dependency_asset reads pfb_pkg._VARIANT / _PF_VERSION, which are private
    engine names. Left off _REQUIRED_PFB_PKG_ATTRS, an engine that renamed either one
    would load cleanly and then die on an uncaught AttributeError at the first
    dependency asset, instead of failing fast and by name at load_engine().
    """

    def _module_missing(self, *absent: str) -> ModuleType:
        stub = ModuleType("pfb_pkg_stub")
        for name in pc._REQUIRED_PFB_PKG_ATTRS:
            if name not in absent:
                setattr(stub, name, object())
        return stub

    def test_missing_variant_pattern_is_named_by_load(self) -> None:
        with self.assertRaises(pc.EngineError) as ctx:
            pc._require_attrs(self._module_missing("_VARIANT"), pc._REQUIRED_PFB_PKG_ATTRS, "pfb_pkg")
        self.assertIn("_VARIANT", str(ctx.exception))

    def test_missing_pf_version_pattern_is_named_by_load(self) -> None:
        with self.assertRaises(pc.EngineError) as ctx:
            pc._require_attrs(
                self._module_missing("_PF_VERSION"),
                pc._REQUIRED_PFB_PKG_ATTRS,
                "pfb_pkg",
            )
        self.assertIn("_PF_VERSION", str(ctx.exception))

    @_requires_engine
    def test_real_engine_carries_every_allowlisted_symbol(self) -> None:
        pc._require_attrs(_ENGINE.pfb_pkg, pc._REQUIRED_PFB_PKG_ATTRS, "pfb_pkg")
        pc._require_attrs(
            _ENGINE.build_repo_portable,
            pc._REQUIRED_BUILD_REPO_PORTABLE_ATTRS,
            "build-repo-portable",
        )


class CanonicalRecordAccessorTests(unittest.TestCase):
    """_canonical_record turns the canonical/record pairing into a named error."""

    def test_canonical_asset_without_record_rejected(self) -> None:
        asset = _fabricated_asset(None, asset_class="canonical", declared_name="recordless.pkg")
        with self.assertRaises(pc.RunVerificationError) as ctx:
            pc._canonical_record(asset)
        self.assertIn("expected a canonical asset with a record", str(ctx.exception))

    def test_dependency_asset_rejected(self) -> None:
        asset = _fabricated_asset(None, asset_class="dependency", declared_name="dep.pkg")
        with self.assertRaises(pc.RunVerificationError):
            pc._canonical_record(asset)


if __name__ == "__main__":
    unittest.main()
