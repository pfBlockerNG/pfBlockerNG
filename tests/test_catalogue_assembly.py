"""Tests for scripts/catalogue_assembly.py — issue #2146 R1 ("the tree IS the
state"): regenerate one (channel, varver) catalogue directly from the ``.pkg``
files already sitting under ``site_root/channel/varver``, plus a
per-(channel, varver) retention prune and the multi-destination byte/checksum/
provenance identity post-condition. No intake parsing, no ledger, no git, no
network, no scratch tree, no backup/rollback — this pins the collapsed module
against the pfBlockerNG source-repo engine loaded from PFB_SRC (see
tests/_srcrepo.py). Fixture .pkg archives are minimal, pure-Python zstd-tar
files carrying only +COMPACT_MANIFEST (mirrors
tests/test_publish_catalogues.py's _wrap_dependency_pkg style, simplified
further) — the pool/dependency packages regenerate_catalogue/prune_retained
handle never need the full canonical-package validation path (that only fires
for a manifest carrying a pfb_build_record annotation, which these fixtures
omit; see build-repo-portable.py's _validate_annotated_project_pkg /
_canonical_build_record).

Coverage dropped from the retired Plan-based suite, and why (issue #2146 R1
brief): the mechanism each guarded no longer exists.
  - Plan/CatalogueTarget structural rows (empty plan, duplicate catalogue key,
    missing pool/dependency path, directory-instead-of-file pool entry): a
    Plan aggregating multiple targets, and an explicit list of arbitrary
    source paths per target, no longer exist. One regenerate_catalogue() call
    always targets exactly one (channel, varver), and its pool is DISCOVERED
    by globbing that catalogue directory, not supplied as a path list — a
    "missing pool path" or "duplicate target in the plan" can no longer occur
    structurally.
  - DestinationTupleTests (the five-tuple destinations fan-out): that was
    Plan-level routing of one asset to several (channel, varver) targets in a
    single call. publish_catalogues.py's own _VALID_TAGGED_DESTINATIONS +
    test_publish_catalogues.py already cover the closed five-tuple set at the
    Intake layer, untouched by this change.
  - StagingProtectionTests (same-named files from different source dirs;
    forcing a .pkg suffix on a non-.pkg-named source): _stage's pool now
    always comes from globbing ONE directory for "*.pkg", so two different
    source directories can no longer both contribute to one pool, and every
    pool member already carries a .pkg suffix by construction of the glob.
  - SourceIndexResolutionTests (_build_source_index realpath-aliasing dedup):
    _build_source_index built its map from Plan.targets, which is gone;
    verify_multi_destination_identity now takes a caller-supplied
    source_index directly, so alias resolution is the caller's concern.
  - AtomicityTests / PublishRecoveryTests / the backup-litter and
    stale-backup-clobber halves of the old SteadyStateReplaceTests: all
    exercised the backup/rollback machinery this change deletes outright (the
    git commit of site_root is the transaction boundary now, per the design
    doc landed alongside this change) — nothing here replaces them because
    there is no longer a rollback to test. The surviving, still-meaningful
    halves of SteadyStateReplaceTests (replace leaves a clean directory, other
    catalogues untouched) live on below, adapted to the new call shape.
"""

from __future__ import annotations

import hashlib
import io
import itertools
import json
import shutil
import sys
import tarfile
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalogue_assembly as ca
import publish_catalogues as pc
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


# --------------------------------------------------------------------------- #
# Fixture builders — minimal pure-Python zstd-tar .pkg archives (no binary
# fixtures vendored). Only +COMPACT_MANIFEST is written.
# --------------------------------------------------------------------------- #

_pkg_counter = itertools.count()


def _write_tar_pkg(path: Path, data: bytes) -> None:
    pfb_pkg = _ENGINE.pfb_pkg
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        info = tarfile.TarInfo(name="+COMPACT_MANIFEST")
        info.size = len(data)
        info.mtime = 0
        tf.addfile(info, io.BytesIO(data))
    path.write_bytes(pfb_pkg.zstd_compress(raw.getvalue(), pfb_pkg.PkgError, "zstd unavailable"))


def _make_pkg(
    directory: Path,
    *,
    name: str,
    version: str,
    abi: str = "FreeBSD:15:*",
    origin: str | None = None,
    local_name: str | None = None,
) -> Path:
    """A minimal, valid .pkg: zstd-tar carrying only +COMPACT_MANIFEST."""
    manifest = {
        "name": name,
        "version": version,
        "abi": abi,
        "origin": origin or f"net/{name}",
    }
    path = directory / (local_name or f"pkg-{next(_pkg_counter)}.pkg")
    _write_tar_pkg(path, json.dumps(manifest, separators=(",", ":")).encode())
    return path


def _canonical_pkg(directory: Path, *, version: str, abi: str = "FreeBSD:15:*", **kw: str | None) -> Path:
    return _make_pkg(
        directory,
        name=_ENGINE.pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        version=version,
        abi=abi,
        **kw,
    )


def _dep_pkg(
    directory: Path,
    *,
    name: str = "py311-charset-normalizer",
    version: str = "3.4.0",
    abi: str = "FreeBSD:15:*",
    **kw: str | None,
) -> Path:
    return _make_pkg(directory, name=name, version=version, abi=abi, **kw)


def _zero_byte_file(directory: Path, name: str = "zero.pkg") -> Path:
    path = directory / name
    path.write_bytes(b"")
    return path


def _not_zstd_file(directory: Path, name: str = "garbage.pkg") -> Path:
    path = directory / name
    path.write_bytes(b"not a zstd archive at all, just plain garbage bytes")
    return path


def _build_record(*, channel: str = "testing", release_line: str | None = None) -> dict:
    """A genuine, digest-bound build record — mirrors tests/test_publish_catalogues.py's
    _matrix_row()/_record() (build_input_digest always engine-computed, never
    hand-typed). Only the "testing" shape is needed here; this is not a general
    replacement for that module's fixture builder."""
    pfb_pkg = _ENGINE.pfb_pkg
    row = {
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
    tag = {"stable": "v4.0.0", "testing": "v4.0.1.b1", "edge": "v4.0.0.b1"}[channel]
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
        "source_sha": "a" * 40,
        "canonical_package_version": info.pkg_version,
        "native_recipe_identity": native,
        "emitted_identity": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "matrix_row": row,
        "freebsd_ports_sha": "b" * 64,
        "route": f"{channel}/{cast(str, row['variant']).lower()}-2.8",
        "source_date_epoch": 0,
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    return record


def _annotated_pkg(directory: Path, *, record: dict, local_name: str | None = None) -> Path:
    """A minimal .pkg carrying a genuine, load_build_record-parseable pfb_build_record
    annotation. Consumed directly by verify_multi_destination_identity in these
    tests, never by build_repo/validate_project_pkg, so +COMPACT_MANIFEST alone is
    enough (see _make_pkg's docstring for why the fuller archive is unnecessary)."""
    pfb_pkg = _ENGINE.pfb_pkg
    manifest = {
        "name": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "version": record["canonical_package_version"],
        "abi": f"FreeBSD:{record['matrix_row']['freebsd_major']}:*",
        "origin": "net/pfSense-pkg-pfBlockerNG",
        "annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: json.dumps(record, separators=(",", ":"), sort_keys=True)},
    }
    path = directory / (local_name or f"pkg-{next(_pkg_counter)}.pkg")
    _write_tar_pkg(path, json.dumps(manifest, separators=(",", ":")).encode())
    return path


def _drop(catalogue_dir: Path, *sources: Path) -> None:
    """Copy each of ``sources`` into ``catalogue_dir`` under its own basename —
    exactly what the release job does before calling regenerate_catalogue()."""
    catalogue_dir.mkdir(parents=True, exist_ok=True)
    for source in sources:
        shutil.copy2(source, catalogue_dir / source.name)


def _seed_canonical(tmp: Path, catalogue_dir: Path, versions: list[str], *, abi: str = "FreeBSD:15:*") -> None:
    """Drop canonically-named .pkg fixtures for each of ``versions`` into
    ``catalogue_dir`` — shared by RetentionTests and ContainmentAwarePruningTests
    below. ``tmp`` is the scratch dir the source fixture files get written into
    before ``_drop`` copies them under their canonical on-disk name."""
    for v in versions:
        _drop(
            catalogue_dir,
            _canonical_pkg(tmp, version=v, abi=abi, local_name=f"pfSense-pkg-pfBlockerNG-{v}.pkg"),
        )


def _pkg_names(catalogue_dir: Path) -> list[str]:
    """The catalogue's own emitted package names, excluding the catalog descriptor
    archives (data.pkg/packagesite.pkg) so a test can compare against a plain
    canonical/dependency filename set."""
    if not catalogue_dir.is_dir():
        return []
    return sorted(
        p.name for p in catalogue_dir.glob("*.pkg") if p.name not in _ENGINE.build_repo_portable._CATALOG_PKG_FILES
    )


class _TempDirTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="cat-asm-test-")
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)


# --------------------------------------------------------------------------- #
# Hostile channel rows.
# --------------------------------------------------------------------------- #


class ChannelValidationTests(_TempDirTestCase):
    @_requires_engine
    def test_channel_empty_rejected(self) -> None:
        self._assert_channel_rejected("")

    @_requires_engine
    def test_channel_release_rejected(self) -> None:
        self._assert_channel_rejected("release")

    @_requires_engine
    def test_channel_devel_rejected(self) -> None:
        self._assert_channel_rejected("devel")

    @_requires_engine
    def test_channel_uppercase_rejected(self) -> None:
        self._assert_channel_rejected("Stable")

    @_requires_engine
    def test_channel_path_traversal_rejected(self) -> None:
        self._assert_channel_rejected("nightly/../etc")

    @_requires_engine
    def test_channel_dot_rejected(self) -> None:
        self._assert_channel_rejected(".")

    @_requires_engine
    def test_channel_dotdot_rejected(self) -> None:
        self._assert_channel_rejected("..")

    def _assert_channel_rejected(self, channel: str) -> None:
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.regenerate_catalogue(self.tmp / "out", channel, "ce-2.8", engine=_ENGINE)
        self.assertIn("unknown channel", str(ctx.exception))


# --------------------------------------------------------------------------- #
# Hostile varver rows.
# --------------------------------------------------------------------------- #


class VarverValidationTests(_TempDirTestCase):
    @_requires_engine
    def test_varver_empty_rejected(self) -> None:
        self._assert_varver_rejected("", "must be non-empty")

    @_requires_engine
    def test_varver_extra_segment_rejected(self) -> None:
        # Message-specific: a multi-segment varver must be rejected by THIS
        # module's own single_segment=True guard, not merely happen to raise
        # for some other reason (e.g. the resulting path not existing) —
        # single_segment=False would let "ce-2.8/extra" through this check
        # and still raise downstream on directory-existence, silently
        # papering over a dropped guard.
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.regenerate_catalogue(self.tmp / "out", "stable", "ce-2.8/extra", engine=_ENGINE)
        self.assertIn("invalid varver", str(ctx.exception))
        self.assertIn("ONE segment", str(ctx.exception))

    @_requires_engine
    def test_varver_traversal_prefix_rejected(self) -> None:
        self._assert_varver_rejected("../ce-2.8", "ONE segment")

    @_requires_engine
    def test_varver_leading_slash_rejected(self) -> None:
        self._assert_varver_rejected("/ce-2.8", "ONE segment")

    @_requires_engine
    def test_varver_meta_rejected(self) -> None:
        self._assert_varver_rejected("meta", "collides with pkg(8) catalog plumbing")

    @_requires_engine
    def test_varver_data_pkg_rejected(self) -> None:
        self._assert_varver_rejected("data.pkg", "collides with pkg(8) catalog plumbing")

    @_requires_engine
    def test_varver_packagesite_pkg_rejected(self) -> None:
        self._assert_varver_rejected("packagesite.pkg", "collides with pkg(8) catalog plumbing")

    @_requires_engine
    def test_varver_leading_hyphen_rejected(self) -> None:
        self._assert_varver_rejected("-2.8", "must be non-empty")

    @_requires_engine
    def test_varver_trailing_hyphen_rejected(self) -> None:
        self._assert_varver_rejected("ce-", "must be non-empty")

    @_requires_engine
    def test_varver_nul_byte_rejected(self) -> None:
        self._assert_varver_rejected("ce\x002.8", "must be non-empty")

    @_requires_engine
    def test_varver_newline_rejected(self) -> None:
        self._assert_varver_rejected("ce\n2.8", "must be non-empty")

    @_requires_engine
    def test_varver_too_long_rejected(self) -> None:
        # Message-specific: a bare assertRaises here passes even if
        # _MAX_VARVER_LENGTH were widened past 300, because a 300-char varver
        # still raises CatalogueAssemblyError downstream — from _catalogue_dir's
        # "catalogue directory does not exist" check, not from THIS length
        # guard — so a widened cap would go unnoticed. Pinning the guard's own
        # message text is what makes this test fail if the cap stops firing for
        # a 300-char varver specifically.
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.regenerate_catalogue(self.tmp / "out", "stable", "a" * 300, engine=_ENGINE)
        self.assertIn("exceeds", str(ctx.exception))
        self.assertIn("255 characters", str(ctx.exception))

    def _assert_varver_rejected(self, varver: str, expected_message: str) -> None:
        """A bare assertRaises here is vacuous for a varver whose value happens to
        make site_root/channel/varver a non-existent path anyway (_catalogue_dir's
        own "does not exist" check raises the SAME exception type) — pass
        ``expected_message`` pins the SPECIFIC guard this row means to exercise and is
        mandatory for that reason: an omitted one silently degrades the row to the
        vacuous form."""
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.regenerate_catalogue(self.tmp / "out", "stable", varver, engine=_ENGINE)
        self.assertIn("invalid varver", str(ctx.exception))
        self.assertIn(expected_message, str(ctx.exception))


# --------------------------------------------------------------------------- #
# Catalogue-directory existence + empty-pool rows.
# --------------------------------------------------------------------------- #


class PathExistenceTests(_TempDirTestCase):
    @_requires_engine
    def test_catalogue_dir_missing_rejected(self) -> None:
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.regenerate_catalogue(self.tmp / "out", "stable", "ce-2.8", engine=_ENGINE)
        self.assertIn("does not exist", str(ctx.exception))

    @_requires_engine
    def test_site_root_is_a_file_rejected(self) -> None:
        out = self.tmp / "out"
        out.write_bytes(b"not a directory")
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertIn("does not exist", str(ctx.exception))

    @_requires_engine
    def test_empty_pool_rejected(self) -> None:
        out = self.tmp / "out"
        (out / "stable" / "ce-2.8").mkdir(parents=True)
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertIn("empty pool", str(ctx.exception))

    @_requires_engine
    def test_prune_catalogue_dir_missing_rejected(self) -> None:
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.prune_retained(self.tmp / "out", "stable", "ce-2.8", engine=_ENGINE)
        self.assertIn("does not exist", str(ctx.exception))


# --------------------------------------------------------------------------- #
# Hostile pool content — these are the engine's own checks (build_repo /
# _emit_catalog_from_paths / _check_collisions), propagated unwrapped.
# --------------------------------------------------------------------------- #


class PoolContentHostileTests(_TempDirTestCase):
    @_requires_engine
    def test_zero_byte_file_rejected(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        _drop(catalogue_dir, _zero_byte_file(self.tmp))
        with self.assertRaises(_ENGINE.pfb_pkg.PkgError):
            ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)

    @_requires_engine
    def test_non_zstd_file_rejected(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        _drop(catalogue_dir, _not_zstd_file(self.tmp))
        with self.assertRaises(_ENGINE.pfb_pkg.PkgError):
            ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)

    @_requires_engine
    def test_concrete_abi_rejected(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        pkg = _canonical_pkg(self.tmp, version="4.0.0", abi="FreeBSD:15:amd64")
        _drop(catalogue_dir, pkg)
        with self.assertRaises(_ENGINE.build_repo_portable.BuildRepoError):
            ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)

    @_requires_engine
    def test_mixed_abi_majors_rejected(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        pkg_a = _canonical_pkg(self.tmp, version="4.0.0", abi="FreeBSD:15:*")
        pkg_b = _dep_pkg(self.tmp, name="py311-foo", version="1.0", abi="FreeBSD:16:*")
        _drop(catalogue_dir, pkg_a, pkg_b)
        with self.assertRaises(_ENGINE.build_repo_portable.BuildRepoError):
            ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)

    @_requires_engine
    def test_same_name_version_different_bytes_rejected(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        pkg_a = _canonical_pkg(
            self.tmp,
            version="4.0.0",
            origin="net/pfSense-pkg-pfBlockerNG",
            local_name="a.pkg",
        )
        pkg_b = _canonical_pkg(
            self.tmp,
            version="4.0.0",
            origin="net/pfSense-pkg-pfBlockerNG-DIFFERENT",
            local_name="b.pkg",
        )
        _drop(catalogue_dir, pkg_a, pkg_b)
        with self.assertRaises(_ENGINE.build_repo_portable.BuildRepoError):
            ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)


# --------------------------------------------------------------------------- #
# Basic functional coverage: each channel alone, each varver alone.
# --------------------------------------------------------------------------- #


class BasicRegenerateTests(_TempDirTestCase):
    @_requires_engine
    def test_channel_stable_alone(self) -> None:
        self._assert_single_channel_catalogue("stable")

    @_requires_engine
    def test_channel_testing_alone(self) -> None:
        self._assert_single_channel_catalogue("testing")

    @_requires_engine
    def test_channel_edge_alone(self) -> None:
        self._assert_single_channel_catalogue("edge")

    @_requires_engine
    def test_channel_nightly_alone(self) -> None:
        self._assert_single_channel_catalogue("nightly")

    def _assert_single_channel_catalogue(self, channel: str) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / channel / "ce-2.8"
        pkg = _canonical_pkg(self.tmp, version="4.0.0")
        _drop(catalogue_dir, pkg)
        ca.regenerate_catalogue(out, channel, "ce-2.8", engine=_ENGINE)
        self.assertTrue((catalogue_dir / "pfSense-pkg-pfBlockerNG-4.0.0.pkg").is_file())
        self.assertTrue((catalogue_dir / "meta.conf").is_file())
        self.assertTrue((catalogue_dir / "packagesite.pkg").is_file())
        self.assertTrue((catalogue_dir / "data.pkg").is_file())
        for other in ca._KNOWN_CHANNELS - {channel}:
            self.assertFalse((out / other).exists())

    @_requires_engine
    def test_varver_ce_2_8_alone(self) -> None:
        self._assert_single_varver("ce-2.8")

    @_requires_engine
    def test_varver_plus_26_03_alone(self) -> None:
        self._assert_single_varver("plus-26.03", major="16")

    @_requires_engine
    def test_varver_plus_26_07_alone(self) -> None:
        self._assert_single_varver("plus-26.07", major="16")

    def _assert_single_varver(self, varver: str, *, major: str = "15") -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / varver
        pkg = _canonical_pkg(self.tmp, version="4.0.0", abi=f"FreeBSD:{major}:*")
        _drop(catalogue_dir, pkg)
        ca.regenerate_catalogue(out, "stable", varver, engine=_ENGINE)
        self.assertTrue((catalogue_dir / "pfSense-pkg-pfBlockerNG-4.0.0.pkg").is_file())


# --------------------------------------------------------------------------- #
# Catalogue signing (issue #2675 step 1): sign_key threads straight through to
# build_repo — the wire format itself is test_build_repo_portable.py's own
# concern; these tests only pin that regenerate_catalogue actually reaches it
# and that omitting sign_key stays byte-identical to today.
# --------------------------------------------------------------------------- #


class SigningTests(_TempDirTestCase):
    @_requires_engine
    def test_sign_key_reaches_build_repo_and_verifies(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        pkg = _canonical_pkg(self.tmp, version="4.0.0")
        _drop(catalogue_dir, pkg)
        key = tbrp._gen_key(self.tmp / "repo.key")

        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE, sign_key=key)

        self.assertEqual(
            sorted(tbrp._sig_members(catalogue_dir / "packagesite.pkg")),
            ["packagesite.yaml.pub", "packagesite.yaml.sig"],
        )
        self.assertEqual(
            sorted(tbrp._sig_members(catalogue_dir / "data.pkg")),
            ["data.pub", "data.sig"],
        )
        for archive, member in (
            (catalogue_dir / "packagesite.pkg", "packagesite.yaml"),
            (catalogue_dir / "data.pkg", "data"),
        ):
            sigs = tbrp._sig_members(archive)
            sig = sigs[f"{member}.sig"][len(tbrp._PKGSIGN_ECDSA_HEAD) :]
            pub = sigs[f"{member}.pub"][len(tbrp._PKGSIGN_ECDSA_HEAD) :]
            message = tbrp._pkg_signed_message(tbrp._read_member(archive, member))
            self.assertTrue(
                tbrp._openssl_verify(message, sig, pub, self.tmp),
                f"{member} signature did not verify",
            )

    @_requires_engine
    def test_no_sign_key_leaves_archives_unsigned(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        pkg = _canonical_pkg(self.tmp, version="4.0.0")
        _drop(catalogue_dir, pkg)

        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)

        self.assertEqual(tbrp._sig_members(catalogue_dir / "packagesite.pkg"), {})
        self.assertEqual(tbrp._sig_members(catalogue_dir / "data.pkg"), {})


# --------------------------------------------------------------------------- #
# The _CATALOG_PKG_FILES trap: a second regeneration pass over the SAME
# directory must not swallow the data.pkg/packagesite.pkg the first pass wrote.
# --------------------------------------------------------------------------- #


class RegenerateTwiceTrapTests(_TempDirTestCase):
    @_requires_engine
    def test_regenerate_twice_same_package_set(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        pkg = _canonical_pkg(self.tmp, version="4.0.0")
        _drop(catalogue_dir, pkg)

        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        first_pass = _pkg_names(catalogue_dir)
        self.assertEqual(first_pass, ["pfSense-pkg-pfBlockerNG-4.0.0.pkg"])

        # The trap: regenerate AGAIN over the same directory, which now also
        # contains the data.pkg/packagesite.pkg the first pass just wrote.
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        second_pass = _pkg_names(catalogue_dir)
        self.assertEqual(second_pass, first_pass)

    @_requires_engine
    def test_regenerate_three_times_stable(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "nightly" / "ce-2.8"
        pkg = _canonical_pkg(self.tmp, version="1.0.0")
        _drop(catalogue_dir, pkg)
        for _ in range(3):
            ca.regenerate_catalogue(out, "nightly", "ce-2.8", engine=_ENGINE)
        self.assertEqual(_pkg_names(catalogue_dir), ["pfSense-pkg-pfBlockerNG-1.0.0.pkg"])


# --------------------------------------------------------------------------- #
# Drop a new .pkg in / delete one — the catalogue tracks whatever the
# directory currently holds, nothing more, nothing less.
# --------------------------------------------------------------------------- #


class DirectoryDrivenChangeTests(_TempDirTestCase):
    @_requires_engine
    def test_dropping_new_pkg_gains_it(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        old = _canonical_pkg(self.tmp, version="1.0.0", local_name="old.pkg")
        _drop(catalogue_dir, old)
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertEqual(_pkg_names(catalogue_dir), ["pfSense-pkg-pfBlockerNG-1.0.0.pkg"])

        new = _dep_pkg(self.tmp, name="py311-charset-normalizer", version="3.4.0")
        _drop(catalogue_dir, new)
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertEqual(
            _pkg_names(catalogue_dir),
            sorted(
                [
                    "pfSense-pkg-pfBlockerNG-1.0.0.pkg",
                    "py311-charset-normalizer-3.4.0.pkg",
                ]
            ),
        )

    @_requires_engine
    def test_deleting_pkg_loses_it(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        dep = _dep_pkg(self.tmp, name="py311-charset-normalizer", version="3.4.0")
        canonical = _canonical_pkg(self.tmp, version="1.0.0")
        _drop(catalogue_dir, dep, canonical)
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertEqual(
            _pkg_names(catalogue_dir),
            sorted(
                [
                    "pfSense-pkg-pfBlockerNG-1.0.0.pkg",
                    "py311-charset-normalizer-3.4.0.pkg",
                ]
            ),
        )

        (catalogue_dir / "py311-charset-normalizer-3.4.0.pkg").unlink()
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertEqual(_pkg_names(catalogue_dir), ["pfSense-pkg-pfBlockerNG-1.0.0.pkg"])


# --------------------------------------------------------------------------- #
# Replace-in-place: the old SteadyStateReplaceTests halves that survive the
# removal of the backup/rollback machinery (no stale-backup/no-litter checks —
# there is no backup to leave litter).
# --------------------------------------------------------------------------- #


class ReplaceInPlaceTests(_TempDirTestCase):
    @_requires_engine
    def test_replace_existing_catalogue_clean(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        old_pkg = _canonical_pkg(self.tmp, version="1.0.0", local_name="old.pkg")
        _drop(catalogue_dir, old_pkg)
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertTrue((catalogue_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg").is_file())

        (catalogue_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg").unlink()
        new_pkg = _canonical_pkg(self.tmp, version="2.0.0", local_name="new.pkg")
        _drop(catalogue_dir, new_pkg)
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)

        self.assertFalse((catalogue_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg").exists())
        self.assertTrue((catalogue_dir / "pfSense-pkg-pfBlockerNG-2.0.0.pkg").is_file())
        # No nesting: the varver directory must not contain a copy of itself.
        self.assertFalse((catalogue_dir / "ce-2.8").exists())
        self.assertFalse((catalogue_dir / "stable").exists())

    @_requires_engine
    def test_replace_leaves_other_catalogues_untouched(self) -> None:
        out = self.tmp / "out"
        stable_dir = out / "stable" / "ce-2.8"
        testing_dir = out / "testing" / "ce-2.8"
        _drop(
            stable_dir,
            _canonical_pkg(self.tmp, version="1.0.0", local_name="stable.pkg"),
        )
        _drop(
            testing_dir,
            _canonical_pkg(self.tmp, version="1.0.0", local_name="testing.pkg"),
        )
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        ca.regenerate_catalogue(out, "testing", "ce-2.8", engine=_ENGINE)
        testing_before = {
            p.relative_to(testing_dir): p.read_bytes() for p in sorted(testing_dir.rglob("*")) if p.is_file()
        }

        (stable_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg").unlink()
        _drop(
            stable_dir,
            _canonical_pkg(self.tmp, version="2.0.0", local_name="stable2.pkg"),
        )
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)

        testing_after = {
            p.relative_to(testing_dir): p.read_bytes() for p in sorted(testing_dir.rglob("*")) if p.is_file()
        }
        self.assertEqual(testing_before, testing_after)
        self.assertTrue((stable_dir / "pfSense-pkg-pfBlockerNG-2.0.0.pkg").is_file())


# --------------------------------------------------------------------------- #
# Retention: below/at/above keep, keep=1, two varvers pruning independently,
# dependency packages never counted.
# --------------------------------------------------------------------------- #


class RetentionTests(_TempDirTestCase):
    def _seed(self, catalogue_dir: Path, versions: list[str]) -> None:
        # Canonically-named on disk already — a real catalogue directory only ever
        # holds build_repo's own canonical <name>-<version>.pkg output; prune_retained
        # never renames anything, it only deletes whole files.
        _seed_canonical(self.tmp, catalogue_dir, versions)

    @_requires_engine
    def test_below_keep_all_survive(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        self._seed(catalogue_dir, ["1.0.0", "2.0.0"])
        evicted = ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertEqual(evicted, ())
        self.assertEqual(len(_pkg_names(catalogue_dir)), 2)

    @_requires_engine
    def test_exactly_at_keep_all_survive(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP)]
        self._seed(catalogue_dir, versions)
        evicted = ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertEqual(evicted, ())
        self.assertEqual(len(_pkg_names(catalogue_dir)), ca.DEFAULT_RETENTION_KEEP)

    @_requires_engine
    def test_above_keep_oldest_evicted(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        self._seed(catalogue_dir, versions)
        evicted = ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertEqual(len(evicted), 1)
        self.assertEqual(evicted[0].name, "pfSense-pkg-pfBlockerNG-1.0.0.pkg")
        self.assertFalse(evicted[0].exists())
        remaining = _pkg_names(catalogue_dir)
        self.assertEqual(len(remaining), ca.DEFAULT_RETENTION_KEEP)
        self.assertNotIn("pfSense-pkg-pfBlockerNG-1.0.0.pkg", remaining)

    @_requires_engine
    def test_keep_one(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        self._seed(catalogue_dir, ["1.0.0", "2.0.0", "3.0.0"])
        evicted = ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE, keep_count_for=lambda c, v: 1)
        self.assertEqual(len(evicted), 2)
        self.assertEqual(_pkg_names(catalogue_dir), ["pfSense-pkg-pfBlockerNG-3.0.0.pkg"])

    @_requires_engine
    def test_two_varvers_prune_independently(self) -> None:
        out = self.tmp / "out"
        dir_a = out / "stable" / "ce-2.8"
        dir_b = out / "stable" / "plus-26.03"
        self._seed(dir_a, ["1.0.0", "2.0.0", "3.0.0"])
        for v in ["1.0.0", "2.0.0"]:
            _drop(
                dir_b,
                _canonical_pkg(self.tmp, version=v, abi="FreeBSD:16:*", local_name=f"b{v}.pkg"),
            )

        def keep_for(channel: str, varver: str) -> int:
            return {"ce-2.8": 1, "plus-26.03": 5}[varver]

        evicted_a = ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE, keep_count_for=keep_for)
        evicted_b = ca.prune_retained(out, "stable", "plus-26.03", engine=_ENGINE, keep_count_for=keep_for)
        self.assertEqual(len(evicted_a), 2)
        self.assertEqual(evicted_b, ())
        self.assertEqual(_pkg_names(dir_a), ["pfSense-pkg-pfBlockerNG-3.0.0.pkg"])
        self.assertEqual(len(_pkg_names(dir_b)), 2)

    @_requires_engine
    def test_dependency_pkg_never_counted_or_touched(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        self._seed(catalogue_dir, versions)
        dep = _dep_pkg(
            self.tmp,
            name="py311-charset-normalizer",
            version="3.4.0",
            local_name="py311-charset-normalizer-3.4.0.pkg",
        )
        _drop(catalogue_dir, dep)

        evicted = ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertEqual(len(evicted), 1)
        self.assertNotIn("py311-charset-normalizer", str(evicted[0]))
        self.assertIn("py311-charset-normalizer-3.4.0.pkg", _pkg_names(catalogue_dir))
        canonical_remaining = [n for n in _pkg_names(catalogue_dir) if n.startswith("pfSense-pkg")]
        self.assertEqual(len(canonical_remaining), ca.DEFAULT_RETENTION_KEEP)

    @_requires_engine
    def test_invalid_keep_count_rejected(self) -> None:
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        self._seed(catalogue_dir, ["1.0.0"])
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE, keep_count_for=lambda c, v: 0)
        self.assertIn("positive integer", str(ctx.exception))

    @_requires_engine
    def test_non_int_keep_count_rejected(self) -> None:
        # type(keep) is not int -- a bool or float keep must be rejected the same as
        # a plain out-of-range int (`type(...) is not int`, not `isinstance`, on
        # purpose: bool IS an int subclass and must not sneak through as keep=True).
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        self._seed(catalogue_dir, ["1.0.0"])
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE, keep_count_for=lambda c, v: 5.0)
        self.assertIn("positive integer", str(ctx.exception))
        with self.assertRaises(ca.CatalogueAssemblyError):
            ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE, keep_count_for=lambda c, v: True)

    @_requires_engine
    def test_pruned_generation_absent_after_regenerate(self) -> None:
        """Retention runs BEFORE regeneration in the real flow: an evicted
        generation must never reappear once the catalogue is rebuilt."""
        out = self.tmp / "out"
        catalogue_dir = out / "stable" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        self._seed(catalogue_dir, versions)
        ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE)
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        remaining = _pkg_names(catalogue_dir)
        self.assertEqual(len(remaining), ca.DEFAULT_RETENTION_KEEP)
        self.assertNotIn("pfSense-pkg-pfBlockerNG-1.0.0.pkg", remaining)


# --------------------------------------------------------------------------- #
# Containment-aware retention: edge receives the
# union of every tagged stream, so pruning it independently of stable/testing can evict
# a canonical version one of them still serves, silently breaking the strict-containment
# contract (edge superset-of testing superset-of stable). prune_retained must protect any
# generation still present, canonically, in one of `channel`'s slower channels.
# --------------------------------------------------------------------------- #


class ContainmentAwarePruningTests(_TempDirTestCase):
    @_requires_engine
    def test_edge_protects_version_still_retained_by_stable(self) -> None:
        # 6 canonical versions in edge (one beyond keep=5), the oldest ALSO present
        # as a canonical .pkg in stable for the same varver: it must survive the prune.
        out = self.tmp / "out"
        edge_dir = out / "edge" / "ce-2.8"
        stable_dir = out / "stable" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        _seed_canonical(self.tmp, edge_dir, versions)
        _seed_canonical(self.tmp, stable_dir, [versions[0]])

        evicted = ca.prune_retained(out, "edge", "ce-2.8", engine=_ENGINE)

        self.assertEqual(evicted, ())
        self.assertEqual(len(_pkg_names(edge_dir)), len(versions))
        self.assertIn(f"pfSense-pkg-pfBlockerNG-{versions[0]}.pkg", _pkg_names(edge_dir))

    @_requires_engine
    def test_edge_prunes_when_not_protected(self) -> None:
        # Protection is presence-based, not unconditional: with no
        # stable/testing directory at all, edge's oldest-beyond-keep is still evicted.
        out = self.tmp / "out"
        edge_dir = out / "edge" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        _seed_canonical(self.tmp, edge_dir, versions)

        evicted = ca.prune_retained(out, "edge", "ce-2.8", engine=_ENGINE)

        self.assertEqual(len(evicted), 1)
        self.assertEqual(evicted[0].name, f"pfSense-pkg-pfBlockerNG-{versions[0]}.pkg")

    @_requires_engine
    def test_testing_protects_version_retained_by_stable(self) -> None:
        # Testing's only slower channel is stable.
        out = self.tmp / "out"
        testing_dir = out / "testing" / "ce-2.8"
        stable_dir = out / "stable" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        _seed_canonical(self.tmp, testing_dir, versions)
        _seed_canonical(self.tmp, stable_dir, [versions[0]])

        evicted = ca.prune_retained(out, "testing", "ce-2.8", engine=_ENGINE)

        self.assertEqual(evicted, ())
        self.assertEqual(len(_pkg_names(testing_dir)), len(versions))

    @_requires_engine
    def test_edge_protects_via_either_slower_channel(self) -> None:
        # Edge's slower tuple is (stable, testing): two DIFFERENT
        # old-beyond-keep versions, one protected only by stable and one only by
        # testing, must BOTH survive -- proving the check isn't a single-channel lookup.
        out = self.tmp / "out"
        edge_dir = out / "edge" / "ce-2.8"
        stable_dir = out / "stable" / "ce-2.8"
        testing_dir = out / "testing" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 2)]
        _seed_canonical(self.tmp, edge_dir, versions)
        _seed_canonical(self.tmp, stable_dir, [versions[0]])
        _seed_canonical(self.tmp, testing_dir, [versions[1]])

        evicted = ca.prune_retained(out, "edge", "ce-2.8", engine=_ENGINE)

        self.assertEqual(evicted, ())
        self.assertEqual(len(_pkg_names(edge_dir)), len(versions))

    @_requires_engine
    def test_stable_ignores_faster_channel_presence(self) -> None:
        # Stable has no slower channel (_SLOWER_CHANNELS["stable"] ==
        # ()): an old stable version also present in edge (a FASTER channel) does NOT
        # protect the stable copy. Containment only ever flows slower<-faster, never back.
        out = self.tmp / "out"
        stable_dir = out / "stable" / "ce-2.8"
        edge_dir = out / "edge" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        _seed_canonical(self.tmp, stable_dir, versions)
        _seed_canonical(self.tmp, edge_dir, [versions[0]])

        evicted = ca.prune_retained(out, "stable", "ce-2.8", engine=_ENGINE)

        self.assertEqual(len(evicted), 1)
        self.assertEqual(evicted[0].name, f"pfSense-pkg-pfBlockerNG-{versions[0]}.pkg")

    @_requires_engine
    def test_nightly_independent_no_protection(self) -> None:
        # Nightly is untagged and independent (_SLOWER_CHANNELS["nightly"]
        # == ()): a version also present in stable grants no protection.
        out = self.tmp / "out"
        nightly_dir = out / "nightly" / "ce-2.8"
        stable_dir = out / "stable" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        _seed_canonical(self.tmp, nightly_dir, versions)
        _seed_canonical(self.tmp, stable_dir, [versions[0]])

        evicted = ca.prune_retained(out, "nightly", "ce-2.8", engine=_ENGINE)

        self.assertEqual(len(evicted), 1)
        self.assertEqual(evicted[0].name, f"pfSense-pkg-pfBlockerNG-{versions[0]}.pkg")

    @_requires_engine
    def test_missing_slower_channel_directory_no_protection(self) -> None:
        # Neither slower-channel directory exists AT ALL (not merely
        # missing this varver): no error, no protection, normal eviction.
        out = self.tmp / "out"
        edge_dir = out / "edge" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        _seed_canonical(self.tmp, edge_dir, versions)
        self.assertFalse((out / "stable").exists())
        self.assertFalse((out / "testing").exists())

        evicted = ca.prune_retained(out, "edge", "ce-2.8", engine=_ENGINE)

        self.assertEqual(len(evicted), 1)
        self.assertEqual(evicted[0].name, f"pfSense-pkg-pfBlockerNG-{versions[0]}.pkg")

    @_requires_engine
    def test_slower_channel_dependency_and_meta_never_protect(self) -> None:
        # A dependency .pkg in the slower channel whose OWN version
        # string coincidentally matches edge's oldest canonical version must not grant
        # protection (name mismatch), and the slower dir's real catalog descriptor
        # files (data.pkg/packagesite.pkg, from a genuine regenerate_catalogue pass)
        # must never be read as a canonical manifest. A dependency .pkg sitting in the
        # PRUNED (edge) directory itself is untouched either way (mirrors
        # RetentionTests.test_dependency_pkg_never_counted_or_touched).
        out = self.tmp / "out"
        edge_dir = out / "edge" / "ce-2.8"
        stable_dir = out / "stable" / "ce-2.8"
        versions = [f"1.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP + 1)]
        _seed_canonical(self.tmp, edge_dir, versions)
        _drop(
            edge_dir,
            _dep_pkg(self.tmp, name="py311-charset-normalizer", version="3.4.0", local_name="dep-edge.pkg"),
        )

        _seed_canonical(self.tmp, stable_dir, ["9.9.9"])
        _drop(
            stable_dir,
            _dep_pkg(
                self.tmp,
                name="py311-charset-normalizer",
                version=versions[0],
                local_name=f"py311-charset-normalizer-{versions[0]}.pkg",
            ),
        )
        ca.regenerate_catalogue(out, "stable", "ce-2.8", engine=_ENGINE)
        self.assertTrue((stable_dir / "data.pkg").is_file())
        self.assertTrue((stable_dir / "packagesite.pkg").is_file())

        evicted = ca.prune_retained(out, "edge", "ce-2.8", engine=_ENGINE)

        self.assertEqual(len(evicted), 1)
        self.assertEqual(evicted[0].name, f"pfSense-pkg-pfBlockerNG-{versions[0]}.pkg")
        self.assertIn("dep-edge.pkg", _pkg_names(edge_dir))


# --------------------------------------------------------------------------- #
# Containment backfill: prune-only protection cannot create a missing package.
# Faster tagged catalogues must be copied onto from slower ones (byte-identical)
# so edge superset-of testing superset-of stable. Nightly is independent.
# --------------------------------------------------------------------------- #


class ContainmentBackfillTests(_TempDirTestCase):
    @_requires_engine
    def test_copies_missing_canonical_from_slower(self) -> None:
        out = self.tmp / "out"
        testing_dir = out / "testing" / "ce-2.8"
        edge_dir = out / "edge" / "ce-2.8"
        _seed_canonical(self.tmp, testing_dir, ["1.0.0"])
        _seed_canonical(self.tmp, edge_dir, ["2.0.0"])
        slower = testing_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg"

        copied = ca.backfill_from_slower_channels(out, "edge", "ce-2.8", engine=_ENGINE)

        dest = edge_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg"
        self.assertTrue(dest.is_file())
        self.assertEqual(dest.read_bytes(), slower.read_bytes())
        self.assertEqual(list(copied), [slower.resolve()])
        self.assertEqual(copied[slower.resolve()], [("testing", "ce-2.8"), ("edge", "ce-2.8")])

    @_requires_engine
    def test_already_identical_is_noop(self) -> None:
        out = self.tmp / "out"
        testing_dir = out / "testing" / "ce-2.8"
        edge_dir = out / "edge" / "ce-2.8"
        _seed_canonical(self.tmp, testing_dir, ["1.0.0"])
        _drop(edge_dir, testing_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg")

        copied = ca.backfill_from_slower_channels(out, "edge", "ce-2.8", engine=_ENGINE)

        self.assertEqual(copied, {})
        self.assertEqual(_pkg_names(edge_dir), ["pfSense-pkg-pfBlockerNG-1.0.0.pkg"])

    @_requires_engine
    def test_same_name_different_bytes_rejected(self) -> None:
        out = self.tmp / "out"
        testing_dir = out / "testing" / "ce-2.8"
        edge_dir = out / "edge" / "ce-2.8"
        _seed_canonical(self.tmp, testing_dir, ["1.0.0"])
        _drop(
            edge_dir,
            _canonical_pkg(
                self.tmp,
                version="1.0.0",
                origin="net/pfSense-pkg-pfBlockerNG-EVIL",
                local_name="pfSense-pkg-pfBlockerNG-1.0.0.pkg",
            ),
        )

        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.backfill_from_slower_channels(out, "edge", "ce-2.8", engine=_ENGINE)
        self.assertIn("different build", str(ctx.exception))
        self.assertNotEqual(
            (testing_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg").read_bytes(),
            (edge_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg").read_bytes(),
        )

    @_requires_engine
    def test_slower_sources_disagreeing_bytes_rejected(self) -> None:
        out = self.tmp / "out"
        stable_dir = out / "stable" / "ce-2.8"
        testing_dir = out / "testing" / "ce-2.8"
        edge_dir = out / "edge" / "ce-2.8"
        _seed_canonical(self.tmp, stable_dir, ["1.0.0"])
        _drop(
            testing_dir,
            _canonical_pkg(
                self.tmp,
                version="1.0.0",
                origin="net/pfSense-pkg-pfBlockerNG-EVIL",
                local_name="pfSense-pkg-pfBlockerNG-1.0.0.pkg",
            ),
        )
        edge_dir.mkdir(parents=True)

        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.backfill_from_slower_channels(out, "edge", "ce-2.8", engine=_ENGINE)
        self.assertIn("slower channels disagree", str(ctx.exception))
        self.assertEqual(_pkg_names(edge_dir), [])

    @_requires_engine
    def test_dependency_never_copied(self) -> None:
        out = self.tmp / "out"
        testing_dir = out / "testing" / "ce-2.8"
        edge_dir = out / "edge" / "ce-2.8"
        _seed_canonical(self.tmp, testing_dir, ["1.0.0"])
        _drop(
            testing_dir,
            _dep_pkg(
                self.tmp,
                name="py311-charset-normalizer",
                version="3.4.0",
                local_name="py311-charset-normalizer-3.4.0.pkg",
            ),
        )
        edge_dir.mkdir(parents=True)

        copied = ca.backfill_from_slower_channels(out, "edge", "ce-2.8", engine=_ENGINE)

        self.assertIn("pfSense-pkg-pfBlockerNG-1.0.0.pkg", _pkg_names(edge_dir))
        self.assertNotIn("py311-charset-normalizer-3.4.0.pkg", _pkg_names(edge_dir))
        self.assertEqual(len(copied), 1)

    @_requires_engine
    def test_nightly_destination_copies_nothing(self) -> None:
        out = self.tmp / "out"
        testing_dir = out / "testing" / "ce-2.8"
        nightly_dir = out / "nightly" / "ce-2.8"
        _seed_canonical(self.tmp, testing_dir, ["1.0.0"])
        nightly_dir.mkdir(parents=True)

        copied = ca.backfill_from_slower_channels(out, "nightly", "ce-2.8", engine=_ENGINE)

        self.assertEqual(copied, {})
        self.assertEqual(_pkg_names(nightly_dir), [])

    @_requires_engine
    def test_nightly_source_never_copied(self) -> None:
        out = self.tmp / "out"
        nightly_dir = out / "nightly" / "ce-2.8"
        edge_dir = out / "edge" / "ce-2.8"
        _seed_canonical(self.tmp, nightly_dir, ["1.0.0"])
        edge_dir.mkdir(parents=True)

        copied = ca.backfill_from_slower_channels(out, "edge", "ce-2.8", engine=_ENGINE)

        self.assertEqual(copied, {})
        self.assertEqual(_pkg_names(edge_dir), [])

    @_requires_engine
    def test_stable_has_nothing_to_backfill(self) -> None:
        out = self.tmp / "out"
        testing_dir = out / "testing" / "ce-2.8"
        stable_dir = out / "stable" / "ce-2.8"
        _seed_canonical(self.tmp, testing_dir, ["1.0.0"])
        stable_dir.mkdir(parents=True)

        copied = ca.backfill_from_slower_channels(out, "stable", "ce-2.8", engine=_ENGINE)

        self.assertEqual(copied, {})
        self.assertEqual(_pkg_names(stable_dir), [])

    @_requires_engine
    def test_backfill_then_prune_keeps_slower_version_outside_keep_window(self) -> None:
        # Slower still has 1.0.0; faster only has newer keep-window versions.
        # After backfill + prune, 1.0.0 exists on faster (heal + protection).
        out = self.tmp / "out"
        testing_dir = out / "testing" / "ce-2.8"
        edge_dir = out / "edge" / "ce-2.8"
        newer = [f"2.0.{i}" for i in range(ca.DEFAULT_RETENTION_KEEP)]
        _seed_canonical(self.tmp, testing_dir, ["1.0.0"])
        _seed_canonical(self.tmp, edge_dir, newer)
        slower = testing_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg"

        copied = ca.backfill_from_slower_channels(out, "edge", "ce-2.8", engine=_ENGINE)
        evicted = ca.prune_retained(out, "edge", "ce-2.8", engine=_ENGINE)

        dest = edge_dir / "pfSense-pkg-pfBlockerNG-1.0.0.pkg"
        self.assertTrue(dest.is_file())
        self.assertEqual(dest.read_bytes(), slower.read_bytes())
        self.assertEqual(list(copied), [slower.resolve()])
        self.assertEqual(evicted, ())
        self.assertIn("pfSense-pkg-pfBlockerNG-1.0.0.pkg", _pkg_names(edge_dir))


class SlowerChannelsConsistencyTests(unittest.TestCase):
    # Pure constant-shape checks, no engine/fixtures needed.
    def test_keys_match_known_channels(self) -> None:
        self.assertEqual(set(ca._SLOWER_CHANNELS), ca._KNOWN_CHANNELS)

    def test_values_are_subsets_of_known_channels_and_never_self_referential(self) -> None:
        for channel, slower in ca._SLOWER_CHANNELS.items():
            self.assertTrue(set(slower).issubset(ca._KNOWN_CHANNELS))
            self.assertNotIn(channel, slower)


# --------------------------------------------------------------------------- #
# Fan-out / multi-destination byte+checksum+provenance identity.
# --------------------------------------------------------------------------- #


class FanOutIdentityTests(_TempDirTestCase):
    @_requires_engine
    def test_shared_freebsd_major_fanout_identical_bytes(self) -> None:
        # A NO_ARCH asset with wildcard ABI FreeBSD:16:* legitimately lands in BOTH
        # plus-26.03 and plus-26.07 (both FreeBSD major 16) — same physical bytes,
        # dropped into two catalogue directories, regenerated independently.
        shared = _canonical_pkg(self.tmp, version="4.0.0", abi="FreeBSD:16:*")
        out = self.tmp / "out"
        dir_a = out / "stable" / "plus-26.03"
        dir_b = out / "stable" / "plus-26.07"
        _drop(dir_a, shared)
        _drop(dir_b, shared)
        ca.regenerate_catalogue(out, "stable", "plus-26.03", engine=_ENGINE)
        ca.regenerate_catalogue(out, "stable", "plus-26.07", engine=_ENGINE)

        path_a = dir_a / "pfSense-pkg-pfBlockerNG-4.0.0.pkg"
        path_b = dir_b / "pfSense-pkg-pfBlockerNG-4.0.0.pkg"
        self.assertTrue(path_a.is_file())
        self.assertTrue(path_b.is_file())
        data_a, data_b = path_a.read_bytes(), path_b.read_bytes()
        self.assertEqual(data_a, data_b)
        self.assertEqual(hashlib.sha256(data_a).hexdigest(), hashlib.sha256(data_b).hexdigest())

    @_requires_engine
    def test_multi_channel_fanout_identical_bytes_sha_and_record(self) -> None:
        shared = _canonical_pkg(self.tmp, version="4.0.0", abi="FreeBSD:15:*")
        channels = ("stable", "testing", "edge")
        out = self.tmp / "out"
        for channel in channels:
            _drop(out / channel / "ce-2.8", shared)
            ca.regenerate_catalogue(out, channel, "ce-2.8", engine=_ENGINE)

        paths = [out / channel / "ce-2.8" / "pfSense-pkg-pfBlockerNG-4.0.0.pkg" for channel in channels]
        for p in paths:
            self.assertTrue(p.is_file())
        datas = [p.read_bytes() for p in paths]
        shas = [hashlib.sha256(d).hexdigest() for d in datas]
        self.assertTrue(all(d == datas[0] for d in datas))
        self.assertTrue(all(s == shas[0] for s in shas))
        records = [
            _ENGINE.build_repo_portable._canonical_build_record(p, _ENGINE.pfb_pkg.read_compact_manifest(p))
            for p in paths
        ]
        self.assertTrue(all(r == records[0] for r in records))

        # verify_multi_destination_identity agrees — this is the executable
        # post-condition, not only a hand read of the bytes above.
        source_index = {shared.resolve(): [(c, "ce-2.8") for c in channels]}
        ca.verify_multi_destination_identity(_ENGINE, out, source_index)

    @_requires_engine
    def test_multi_destination_divergence_detected(self) -> None:
        """A direct call proving verify_multi_destination_identity is a real,
        load-bearing post-condition — not merely something the happy path implies."""
        source = _canonical_pkg(self.tmp, version="4.0.0")
        divergent = _canonical_pkg(self.tmp, version="4.0.0", origin="net/pfSense-pkg-pfBlockerNG-EVIL")
        out = self.tmp / "out"
        (out / "stable" / "ce-2.8").mkdir(parents=True)
        (out / "testing" / "ce-2.8").mkdir(parents=True)
        canonical_name = "pfSense-pkg-pfBlockerNG-4.0.0.pkg"
        shutil.copy2(source, out / "stable" / "ce-2.8" / canonical_name)
        shutil.copy2(divergent, out / "testing" / "ce-2.8" / canonical_name)
        index = {source.resolve(): [("stable", "ce-2.8"), ("testing", "ce-2.8")]}
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.verify_multi_destination_identity(_ENGINE, out, index)
        self.assertIn("multi-destination identity violation", str(ctx.exception))

    @_requires_engine
    def test_multi_destination_missing_at_destination_detected(self) -> None:
        source = _canonical_pkg(self.tmp, version="4.0.0")
        out = self.tmp / "out"
        (out / "stable" / "ce-2.8").mkdir(parents=True)
        canonical_name = "pfSense-pkg-pfBlockerNG-4.0.0.pkg"
        shutil.copy2(source, out / "stable" / "ce-2.8" / canonical_name)
        # "testing" destination directory never populated.
        index = {source.resolve(): [("stable", "ce-2.8"), ("testing", "ce-2.8")]}
        with self.assertRaises(ca.CatalogueAssemblyError) as ctx:
            ca.verify_multi_destination_identity(_ENGINE, out, index)
        self.assertIn("missing at destination", str(ctx.exception))


class RecordIdentityTests(_TempDirTestCase):
    @_requires_engine
    def test_multi_destination_record_divergence_detected(self) -> None:
        """The "record" axis of verify_multi_destination_identity: two
        destinations with byte-identical files (same source copied twice — the
        data/sha256 axes agree), but the record returned for one is made to
        diverge (injected via mock on top of a GENUINE,
        load_build_record-parseable annotation) — only the record comparison
        can catch it."""
        record = _build_record()
        source = _annotated_pkg(self.tmp, record=record)
        out = self.tmp / "out"
        (out / "stable" / "ce-2.8").mkdir(parents=True)
        (out / "testing" / "ce-2.8").mkdir(parents=True)
        canonical_name = f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}.pkg"
        dest_a = out / "stable" / "ce-2.8" / canonical_name
        dest_b = out / "testing" / "ce-2.8" / canonical_name
        shutil.copy2(source, dest_a)
        shutil.copy2(source, dest_b)
        self.assertEqual(dest_a.read_bytes(), dest_b.read_bytes())  # bytes/sha256 agree

        real_fn = _ENGINE.build_repo_portable._canonical_build_record

        def _fake(path: Path, manifest: Mapping[str, object]) -> dict[str, object] | None:
            real = real_fn(path, manifest)
            if real is not None and Path(path) == dest_b:
                return dict(real, release_line=f"{real['release_line']}-INJECTED")
            return real

        index = {source.resolve(): [("stable", "ce-2.8"), ("testing", "ce-2.8")]}
        with (
            mock.patch.object(
                _ENGINE.build_repo_portable,
                "_canonical_build_record",
                side_effect=_fake,
            ),
            self.assertRaises(ca.CatalogueAssemblyError) as ctx,
        ):
            ca.verify_multi_destination_identity(_ENGINE, out, index)
        self.assertIn("multi-destination identity violation", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
