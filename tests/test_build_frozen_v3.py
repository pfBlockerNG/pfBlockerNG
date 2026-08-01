"""Tests for scripts/build-frozen-v3.py — the frozen pfBlockerNG v3.2 build+validate driver.

Hermetic: no network, no real ports clone, no real .pkg build. Synthetic .pkg fixtures are
built here (mirroring tests/test_build_repo_portable.py's make_pkg() tar+zstd construction,
extended with +MANIFEST/files/scripts/payload — make_pkg() itself only writes
+COMPACT_MANIFEST, which every scenario here needs beyond). git-dependent behaviour
(resolve_tag_commit) runs against small REAL local git repos created in tmp_path (no
network); the build-leg.sh subprocess seam (_invoke_build_leg) and the tag-export step
(resolve_tag_commit/export_tag) are monkeypatched for the full-pipeline tests.

The tool is a hyphen-named CLI script, so it is loaded by path via importlib.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pfb_pkg
import pytest

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "build-frozen-v3.py"
_spec = importlib.util.spec_from_file_location("build_frozen_v3", _TOOL)
assert _spec is not None and _spec.loader is not None
bfv = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bfv
_spec.loader.exec_module(bfv)


# --------------------------------------------------------------------------- #
# Synthetic .pkg + tag-export fixture builders.
# --------------------------------------------------------------------------- #


def _add_member(tf: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    ti = tarfile.TarInfo(name=name)
    ti.size = len(data)
    ti.mode = mode
    ti.uid = ti.gid = 0
    ti.uname, ti.gname = "root", "wheel"
    ti.mtime = 0
    tf.addfile(ti, io.BytesIO(data))


def _write_pkg(
    path: Path,
    *,
    name: str,
    version: str,
    origin: str | None = None,
    abi: str = "FreeBSD:15:*",
    arch: str = "freebsd:15:*",
    deps: dict[str, dict[str, str]] | None = None,
    scripts: dict[str, str] | None = None,
    files: dict[str, bytes] | None = None,
    omit_compact: bool = False,
    omit_manifest: bool = False,
    corrupt_manifest_json: bool = False,
    extra_manifest: dict | None = None,
) -> None:
    """Write a libpkg-shaped .pkg (zstd tar, +COMPACT_MANIFEST + +MANIFEST + payload)."""
    manifest: dict = {
        "name": name,
        "origin": origin if origin is not None else f"net/{name}",
        "version": version,
        "comment": "demo package",
        "maintainer": "dev@example.com",
        "www": "https://example.com",
        "abi": abi,
        "arch": arch,
        "prefix": "/usr/local",
        "flatsize": sum(len(v) for v in (files or {}).values()),
        "licenselogic": "single",
        "desc": "demo",
        "categories": ["net"],
    }
    if deps:
        manifest["deps"] = deps
    if extra_manifest:
        manifest.update(extra_manifest)
    compact_raw = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"

    full = dict(manifest)
    full["files"] = {
        p: {
            "sum": f"1${hashlib.sha256(b).hexdigest()}",
            "uname": "root",
            "gname": "wheel",
            "perm": "0644",
            "fflags": 0,
            "mtime": 0,
        }
        for p, b in (files or {}).items()
    }
    if scripts is not None:
        full["scripts"] = scripts
    full_raw = json.dumps(full, separators=(",", ":")).encode() + b"\n"
    if corrupt_manifest_json:
        full_raw = b"{not json"

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        if not omit_compact:
            _add_member(tf, "+COMPACT_MANIFEST", compact_raw)
        if not omit_manifest:
            _add_member(tf, "+MANIFEST", full_raw)
        for p, b in (files or {}).items():
            _add_member(tf, p, b)
    path.write_bytes(pfb_pkg.zstd_compress(raw.getvalue(), RuntimeError, "zstd unavailable for tests"))


def _write_export(base: Path, files: dict[str, bytes]) -> Path:
    root = base / "export"
    for relpath, data in files.items():
        p = root / relpath.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


DEMO_SCRIPTS = {"install": "#!/bin/sh\necho install\n", "deinstall": "#!/bin/sh\necho deinstall\n"}
ROW_15 = {"freebsd_major": "15", "php_version": "8.3", "py_flavor": "py311"}
ROW_16 = {"freebsd_major": "16", "php_version": "8.5", "py_flavor": "py311"}
STABLE = bfv.FrozenTarget(channel="stable", tag="v1.2.3", commit="c" * 40, portname="demo-pkg", portversion="1.2.3")
DEVEL = bfv.FrozenTarget(channel="devel", tag="v1.3.0", commit="d" * 40, portname="demo-pkg-devel", portversion="1.3.0")


def _deps_for(row: dict) -> dict[str, dict[str, str]]:
    names = bfv._derive_deps(row)
    deps = {n: {"origin": f"lang/{n}", "version": "1.0"} for n in names}
    deps["extra-unrelated-dep"] = {"origin": "net/extra-unrelated-dep", "version": "1.0"}  # extras are tolerated
    return deps


def _demo_payload(portname: str) -> dict[str, bytes]:
    return {
        "/usr/local/pkg/pfblockerng/pfblockerng.inc": b"<?php // demo\n",
        f"/usr/local/share/{portname}/info.xml": b"<xml><version>%%PKGVERSION%%</version></xml>\n",
        "/usr/local/www/pfblockerng/index.php": b"<?php // www demo\n",
    }


def _packaged_payload(portname: str, version: str) -> dict[str, bytes]:
    payload = _demo_payload(portname)
    info_path = f"/usr/local/share/{portname}/info.xml"
    payload[info_path] = payload[info_path].replace(b"%%PKGVERSION%%", version.encode())
    return payload


def _happy_fixture(
    tmp_path: Path,
    target: Any,
    row: dict,
    *,
    version: str | None = None,
    out_dir: Path | None = None,
    **pkg_kwargs: Any,
) -> tuple[Path, Path]:
    version = version or target.portversion
    export_dir = _write_export(tmp_path, _demo_payload(target.portname))
    out_dir = out_dir or tmp_path
    out_dir.mkdir(parents=True, exist_ok=True)
    pkg_path = out_dir / f"{target.portname}-{version}.pkg"
    kwargs = dict(
        name=target.portname,
        version=version,
        abi=f"FreeBSD:{row['freebsd_major']}:*",
        arch=f"freebsd:{row['freebsd_major']}:*",
        deps=_deps_for(row),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(target.portname, version),
    )
    kwargs.update(pkg_kwargs)
    _write_pkg(pkg_path, **kwargs)
    return pkg_path, export_dir


# --------------------------------------------------------------------------- #
# Row 1-2: happy path identity, stable + devel not interchangeable.
# --------------------------------------------------------------------------- #


def test_happy_path_stable_identity(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15)
    record = bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)
    assert record["name"] == "demo-pkg"
    assert record["version"] == "1.2.3"
    assert record["origin"] == "net/demo-pkg"
    assert record["abi"] == "FreeBSD:15:*"
    assert record["arch"] == "freebsd:15:*"
    assert record["payload_file_count"] == 3
    assert set(record["payload_files"]) == {
        "/usr/local/pkg/pfblockerng/pfblockerng.inc",
        "/usr/local/share/demo-pkg/info.xml",
        "/usr/local/www/pfblockerng/index.php",
    }
    assert record["install_script_sha256"] == hashlib.sha256(DEMO_SCRIPTS["install"].encode()).hexdigest()
    assert record["deinstall_script_sha256"] == hashlib.sha256(DEMO_SCRIPTS["deinstall"].encode()).hexdigest()
    assert record["artifact_sha256"] == hashlib.sha256(pkg_path.read_bytes()).hexdigest()


def test_happy_path_devel_identity_not_interchangeable_with_stable(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, DEVEL, ROW_15)
    record = bfv.validate_artifact(pkg_path, export_dir, DEVEL, ROW_15)
    assert record["name"] == "demo-pkg-devel"
    assert record["origin"] == "net/demo-pkg-devel"

    with pytest.raises(bfv.ArtifactValidationError, match="demo-pkg-devel"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


# --------------------------------------------------------------------------- #
# Row 3-5: plan_artifacts cross-product — never hardcoded to 2.
# --------------------------------------------------------------------------- #


def test_plan_two_row_matrix_both_targets_yields_four_artifacts() -> None:
    rows = [ROW_15, ROW_16]
    plan = bfv.plan_artifacts(rows, target_filter=None, major_filter=None)
    assert len(plan) == 4
    assert {(t.channel, r["freebsd_major"]) for t, r in plan} == {
        ("stable", "15"),
        ("stable", "16"),
        ("devel", "15"),
        ("devel", "16"),
    }


def test_plan_three_row_matrix_yields_six_artifacts() -> None:
    rows = [ROW_15, ROW_16, {"freebsd_major": "17", "php_version": "8.5", "py_flavor": "py312"}]
    plan = bfv.plan_artifacts(rows, target_filter=None, major_filter=None)
    assert len(plan) == 6


def test_plan_one_row_matrix_yields_two_artifacts() -> None:
    plan = bfv.plan_artifacts([ROW_15], target_filter=None, major_filter=None)
    assert len(plan) == 2
    assert {t.channel for t, _ in plan} == {"stable", "devel"}


def test_plan_respects_target_and_major_filters() -> None:
    plan = bfv.plan_artifacts([ROW_15, ROW_16], target_filter="stable", major_filter="16")
    assert len(plan) == 1
    assert plan[0][0].channel == "stable"
    assert plan[0][1]["freebsd_major"] == "16"


# --------------------------------------------------------------------------- #
# Row 6: abi/arch wildcard assertion.
# --------------------------------------------------------------------------- #


def test_wildcard_abi_accepted_concrete_abi_rejected(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15)
    bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)  # FreeBSD:15:* — accepted

    pkg_path2, export_dir2 = _happy_fixture(tmp_path, STABLE, ROW_15, version="1.2.3_9", abi="FreeBSD:15:amd64")
    with pytest.raises(bfv.ArtifactValidationError, match="abi"):
        bfv.validate_artifact(pkg_path2, export_dir2, STABLE, {**ROW_15})


# --------------------------------------------------------------------------- #
# Row 7: php/py dependency derivation.
# --------------------------------------------------------------------------- #


def test_dependency_derivation_matches_row_wrong_flavor_rejected(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15)
    bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)  # php83 present — accepted

    wrong_deps = _deps_for(ROW_16)  # php85, not php83
    pkg_path2, export_dir2 = _happy_fixture(tmp_path, STABLE, ROW_15, version="1.2.3_8", deps=wrong_deps)
    with pytest.raises(bfv.ArtifactValidationError, match="php83"):
        bfv.validate_artifact(pkg_path2, export_dir2, STABLE, ROW_15)


def test_derive_deps_shape() -> None:
    assert bfv._derive_deps(ROW_15) == {"php83", "php83-intl", "python311", "py311-sqlite3", "py311-maxminddb"}
    assert bfv._derive_deps(ROW_16) == {"php85", "php85-intl", "python311", "py311-sqlite3", "py311-maxminddb"}


# --------------------------------------------------------------------------- #
# Row 12-13: tag resolution against a real (tiny, local, no-network) git repo.
# --------------------------------------------------------------------------- #


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


@pytest.fixture
def tiny_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "test@example.com", cwd=repo)
    _git("config", "user.name", "Test", cwd=repo)
    (repo / "usr").mkdir()
    (repo / "usr" / "marker").write_text("hi\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "init", cwd=repo)
    commit = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()
    _git("tag", "v9.9.9", cwd=repo)
    return repo, commit


def test_resolve_tag_commit_happy_path(tiny_repo: tuple[Path, str]) -> None:
    repo, commit = tiny_repo
    assert bfv.resolve_tag_commit(repo, "v9.9.9", commit) == commit


def test_resolve_tag_commit_missing_tag_rejected(tiny_repo: tuple[Path, str]) -> None:
    repo, commit = tiny_repo
    with pytest.raises(bfv.TagResolutionError, match="not-a-real-tag"):
        bfv.resolve_tag_commit(repo, "not-a-real-tag", commit)


def test_resolve_tag_commit_unexpected_commit_rejected_naming_both(tiny_repo: tuple[Path, str]) -> None:
    repo, commit = tiny_repo
    bogus = "f" * 40
    with pytest.raises(bfv.TagResolutionError) as exc_info:
        bfv.resolve_tag_commit(repo, "v9.9.9", bogus)
    assert commit in str(exc_info.value)
    assert bogus in str(exc_info.value)


def test_export_tag_is_clean_and_matches_tree(tiny_repo: tuple[Path, str]) -> None:
    repo, commit = tiny_repo
    dest = repo.parent / "export-dest"
    dest.mkdir()
    bfv.export_tag(repo, commit, dest)
    assert (dest / "usr" / "marker").read_text() == "hi\n"


# --------------------------------------------------------------------------- #
# Row 14-15: name/version identity rejection (PORTREVISION/epoch accepted).
# --------------------------------------------------------------------------- #


def test_wrong_package_name_rejected(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, name="wrong-name", version="1.2.3")
    with pytest.raises(bfv.ArtifactValidationError, match="name"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


@pytest.mark.parametrize("version", ["1.2.4", "1.2.2", "1.2"])
def test_wrong_version_rejected(tmp_path: Path, version: str) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, version=version)
    with pytest.raises(bfv.ArtifactValidationError, match="version"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


@pytest.mark.parametrize("version", ["1.2.3_2", "1.2.3_3", "1.2.3,1"])
def test_portrevision_and_epoch_suffix_accepted(tmp_path: Path, version: str) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, version=version)
    record = bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)
    assert record["version"] == version


# --------------------------------------------------------------------------- #
# Row 16: malformed abi shapes — all rejected; nothing staged outside --out.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad_abi",
    ["FreeBSD:15:..", "FreeBSD:15:/etc", "FreeBSD:15:am d64", "FreeBSD:16:*", "not-an-abi-at-all"],
)
def test_malformed_abi_rejected(tmp_path: Path, bad_abi: str) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, abi=bad_abi)
    with pytest.raises(bfv.ArtifactValidationError, match="abi"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_rejected_artifact_stages_nothing_outside_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, abi="FreeBSD:15:amd64")
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    def fake_invoke(argv: list[str], *, cwd: Path) -> str:
        return str(pkg_path)

    monkeypatch.setattr(bfv, "_invoke_build_leg", fake_invoke)
    with pytest.raises(bfv.ArtifactValidationError):
        bfv.build_and_stage_one(
            target=STABLE,
            row=ROW_15,
            repo=tmp_path,
            export_dir=export_dir,
            build_leg_sh=tmp_path / "build-leg.sh",
            out_dir=out_dir,
            ports_dir=None,
        )
    assert list(out_dir.rglob("*.pkg")) == []


# --------------------------------------------------------------------------- #
# Row 17, 28: filename vs manifest identity; cross-channel rejection.
# --------------------------------------------------------------------------- #


def test_filename_disagreeing_with_manifest_rejected(tmp_path: Path) -> None:
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / "totally-different-filename-9.9.9.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        abi="FreeBSD:15:*",
        arch="freebsd:15:*",
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
    )
    with pytest.raises(bfv.ArtifactValidationError, match="filename"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_stable_artifact_presented_as_devel_rejected(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15)
    with pytest.raises(bfv.ArtifactValidationError):
        bfv.validate_artifact(pkg_path, export_dir, DEVEL, ROW_15)


# --------------------------------------------------------------------------- #
# Row 18-19: determinism — identical bytes pass, differing bytes fail loudly.
# --------------------------------------------------------------------------- #


def test_determinism_check_identical_bytes_passes(tmp_path: Path) -> None:
    pkg_a, _ = _happy_fixture(tmp_path, STABLE, ROW_15, out_dir=tmp_path)
    pkg_b = tmp_path / "copy.pkg"
    pkg_b.write_bytes(pkg_a.read_bytes())
    bfv.check_determinism(pkg_a, pkg_b)  # no raise


def test_determinism_check_different_bytes_fails_naming_both_digests(tmp_path: Path) -> None:
    pkg_a, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, out_dir=tmp_path / "a")
    pkg_b, _ = _happy_fixture(tmp_path, STABLE, ROW_15, version="1.2.3_9", out_dir=tmp_path / "b")
    sha_a = hashlib.sha256(pkg_a.read_bytes()).hexdigest()
    sha_b = hashlib.sha256(pkg_b.read_bytes()).hexdigest()
    assert sha_a != sha_b
    with pytest.raises(bfv.DeterminismError) as exc_info:
        bfv.check_determinism(pkg_a, pkg_b)
    assert sha_a in str(exc_info.value)
    assert sha_b in str(exc_info.value)


# --------------------------------------------------------------------------- #
# Row 20-23: hostile archive shapes.
# --------------------------------------------------------------------------- #


def test_truncated_pkg_rejected_cleanly(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15)
    truncated = tmp_path / "demo-pkg-1.2.3.pkg"
    raw = pkg_path.read_bytes()
    truncated.write_bytes(raw[: len(raw) // 2])
    with pytest.raises(bfv.ArtifactValidationError, match="unreadable|corrupt"):
        bfv.validate_artifact(truncated, export_dir, STABLE, ROW_15)


def test_malformed_manifest_json_rejected(tmp_path: Path) -> None:
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
        corrupt_manifest_json=True,
    )
    with pytest.raises(bfv.ArtifactValidationError, match="MANIFEST"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_missing_compact_manifest_rejected(tmp_path: Path) -> None:
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
        omit_compact=True,
    )
    with pytest.raises(bfv.ArtifactValidationError, match="COMPACT_MANIFEST"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


@pytest.mark.parametrize("missing_key", ["install", "deinstall"])
def test_missing_lifecycle_script_rejected(tmp_path: Path, missing_key: str) -> None:
    scripts = dict(DEMO_SCRIPTS)
    del scripts[missing_key]
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, scripts=scripts)
    with pytest.raises(bfv.ArtifactValidationError, match="scripts"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_empty_lifecycle_script_rejected(tmp_path: Path) -> None:
    scripts = {"install": "", "deinstall": "echo bye\n"}
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, scripts=scripts)
    with pytest.raises(bfv.ArtifactValidationError, match="scripts"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


# --------------------------------------------------------------------------- #
# Row 24-27: payload/export byte parity + the info.xml allowlist vacuity guard.
# --------------------------------------------------------------------------- #


def test_extra_payload_file_not_in_export_rejected(tmp_path: Path) -> None:
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    files = _packaged_payload(STABLE.portname, STABLE.portversion)
    files["/usr/local/pkg/pfblockerng/extra_stray_file.php"] = b"<?php // not in export\n"
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=files,
    )
    with pytest.raises(bfv.ArtifactValidationError, match="extra_stray_file"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_modified_payload_file_rejected_naming_it(tmp_path: Path) -> None:
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    files = _packaged_payload(STABLE.portname, STABLE.portversion)
    files["/usr/local/www/pfblockerng/index.php"] = b"<?php // TAMPERED\n"
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=files,
    )
    with pytest.raises(bfv.ArtifactValidationError, match="index.php"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_info_xml_modified_beyond_pkgversion_substitution_rejected(tmp_path: Path) -> None:
    """Vacuity guard: the info.xml allowlist covers ONLY the %%PKGVERSION%% swap."""
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    files = _packaged_payload(STABLE.portname, STABLE.portversion)
    info_path = f"/usr/local/share/{STABLE.portname}/info.xml"
    files[info_path] = files[info_path].replace(b"</xml>", b"<!-- injected -->\n</xml>")
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=files,
    )
    with pytest.raises(bfv.ArtifactValidationError, match="info.xml"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_info_xml_unsubstituted_pkgversion_token_rejected(tmp_path: Path) -> None:
    """Substitution didn't run: the packaged copy still literally says %%PKGVERSION%%."""
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    files = _demo_payload(STABLE.portname)  # packaged == export, unsubstituted
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=files,
    )
    with pytest.raises(bfv.ArtifactValidationError, match="info.xml"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


# --------------------------------------------------------------------------- #
# Row 29-33: matrix validation.
# --------------------------------------------------------------------------- #


def test_matrix_not_a_list_rejected() -> None:
    with pytest.raises(bfv.MatrixError, match="array"):
        bfv.validate_matrix({"not": "a list"})


def test_matrix_empty_rejected() -> None:
    with pytest.raises(bfv.MatrixError, match="empty"):
        bfv.validate_matrix([])


@pytest.mark.parametrize("missing", ["freebsd_major", "php_version", "py_flavor"])
def test_matrix_row_missing_required_field_rejected(missing: str) -> None:
    row = dict(ROW_15)
    del row[missing]
    with pytest.raises(bfv.MatrixError, match=missing):
        bfv.validate_matrix([row])


@pytest.mark.parametrize("bad_major", ["fifteen", "-1", "0", "15.0", ""])
def test_matrix_row_bad_freebsd_major_rejected(bad_major: str) -> None:
    row = {**ROW_15, "freebsd_major": bad_major}
    with pytest.raises(bfv.MatrixError, match="freebsd_major"):
        bfv.validate_matrix([row])


def test_matrix_duplicate_freebsd_major_rejected() -> None:
    with pytest.raises(bfv.MatrixError, match="duplicate"):
        bfv.validate_matrix([ROW_15, {**ROW_15, "php_version": "8.9"}])


def test_matrix_unexpected_role_rejected() -> None:
    with pytest.raises(bfv.MatrixError, match="role"):
        bfv.validate_matrix([{**ROW_15, "role": "route-only"}])


def test_matrix_role_build_is_accepted() -> None:
    rows = bfv.validate_matrix([{**ROW_15, "role": "build"}])
    assert len(rows) == 1


# --------------------------------------------------------------------------- #
# Row 34: matrix command process failure surfaces stderr / rejects garbage stdout.
# --------------------------------------------------------------------------- #


def test_matrix_command_nonzero_exit_surfaces_stderr(tmp_path: Path) -> None:
    with pytest.raises(bfv.MatrixError, match="boom"):
        bfv.run_matrix_cmd(["sh", "-c", "echo boom 1>&2; exit 3"], cwd=tmp_path)


def test_matrix_command_garbage_stdout_rejected(tmp_path: Path) -> None:
    with pytest.raises(bfv.MatrixError, match="JSON"):
        bfv.run_matrix_cmd(["echo", "not-json"], cwd=tmp_path)


def test_matrix_command_happy_path(tmp_path: Path) -> None:
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))
    obj = bfv.run_matrix_cmd(["cat", str(matrix_file)], cwd=tmp_path)
    assert bfv.validate_matrix(obj) == [ROW_15]


# --------------------------------------------------------------------------- #
# Row 35: crafted manifest values are DATA, never interpreted — no shell/path escape.
# --------------------------------------------------------------------------- #


def test_crafted_package_name_shell_injection_is_inert(tmp_path: Path) -> None:
    marker_dir = tmp_path / "marker"
    marker_dir.mkdir()
    hostile_name = f"$(touch {marker_dir}/PWNED_NAME)"
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / "hostile-name.pkg"
    _write_pkg(
        pkg_path,
        name=hostile_name,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
    )
    with pytest.raises(bfv.ArtifactValidationError):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)
    assert not (marker_dir / "PWNED_NAME").exists()


def test_crafted_version_with_newline_is_rejected(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, version="1.2.3\nEVIL")
    with pytest.raises(bfv.ArtifactValidationError, match="version"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_crafted_abi_with_semicolon_is_rejected(tmp_path: Path) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, STABLE, ROW_15, abi="FreeBSD:15:*; rm -rf /")
    with pytest.raises(bfv.ArtifactValidationError, match="abi"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_safe_segment_rejects_path_traversal_and_whitespace() -> None:
    for bad in ["../etc/passwd", "a/b", "a b", "", ".."]:
        with pytest.raises(bfv.ArtifactValidationError):
            bfv._safe_segment(bad, "test value")
    assert bfv._safe_segment("3.2.15_2", "test value") == "3.2.15_2"


# --------------------------------------------------------------------------- #
# Full-pipeline integration: matrix -> plan -> build (stubbed) -> validate ->
# stage -> determinism -> report. Row 8 (report shape), 9 (determinism, at the
# orchestration level), 10 (--verify-only, no build seam), 11 (staging layout).
# --------------------------------------------------------------------------- #


def _fake_build_leg(targets_by_channel: dict[str, Any]) -> Any:
    """Stand-in for build-leg.sh: mirrors whatever --local-src holds into a synthetic .pkg.
    Deterministic given identical inputs (no timestamps, no randomness) — repeated calls with
    the same export tree + target + row produce byte-identical archives.
    """

    def fake(argv: list[str], *, cwd: Path) -> str:
        opts: dict[str, str] = {}
        i = 0
        while i < len(argv):
            tok = argv[i]
            if tok == "--no-arch":
                i += 1
                continue
            if tok.startswith("--"):
                opts[tok[2:]] = argv[i + 1]
                i += 2
            else:
                i += 1
        target = targets_by_channel[opts["channel"]]
        major = opts["abi"].split(":")[1]
        row = {"freebsd_major": major, "php_version": opts["php"], "py_flavor": opts["py-flavor"]}
        export_dir = Path(opts["local-src"])
        out_dir = Path(opts["out-dir"])
        out_dir.mkdir(parents=True, exist_ok=True)

        payload = {}
        for f in sorted(export_dir.rglob("*")):
            if f.is_file():
                payload["/" + f.relative_to(export_dir).as_posix()] = f.read_bytes()
        info_path = f"/usr/local/share/{target.portname}/info.xml"
        if info_path in payload:
            payload[info_path] = payload[info_path].replace(b"%%PKGVERSION%%", target.portversion.encode())

        pkg_path = out_dir / f"{target.portname}-{target.portversion}.pkg"
        _write_pkg(
            pkg_path,
            name=target.portname,
            version=target.portversion,
            abi=f"FreeBSD:{major}:*",
            arch=f"freebsd:{major}:*",
            deps=_deps_for(row),
            scripts=DEMO_SCRIPTS,
            files=payload,
        )
        return str(pkg_path)

    return fake


def _stub_git(monkeypatch: pytest.MonkeyPatch, export_dir_by_commit: dict[str, Path]) -> None:
    def fake_resolve(repo: Path, tag: str, expected_commit: str) -> str:
        return expected_commit

    def fake_export(repo: Path, commit: str, dest: Path) -> None:
        import shutil

        shutil.copytree(export_dir_by_commit[commit], dest, dirs_exist_ok=True)

    monkeypatch.setattr(bfv, "resolve_tag_commit", fake_resolve)
    monkeypatch.setattr(bfv, "export_tag", fake_export)


def test_full_pipeline_two_targets_two_rows_report_and_determinism(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export_stable = _write_export(tmp_path / "src_stable", _demo_payload(STABLE.portname))
    export_devel = _write_export(tmp_path / "src_devel", _demo_payload(DEVEL.portname))
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE, DEVEL))
    _stub_git(monkeypatch, {STABLE.commit: export_stable, DEVEL.commit: export_devel})
    monkeypatch.setattr(bfv, "_invoke_build_leg", _fake_build_leg({"stable": STABLE, "devel": DEVEL}))

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15, ROW_16]))
    out_dir = tmp_path / "stage"

    rc = bfv.main(["--out", str(out_dir), "--matrix-cmd", f"cat {matrix_file}", "--repo", str(tmp_path)])
    assert rc == 0

    staged = sorted(out_dir.glob("fbsd*/*.pkg"))
    assert [p.relative_to(out_dir).as_posix() for p in staged] == [
        "fbsd15/demo-pkg-1.2.3.pkg",
        "fbsd15/demo-pkg-devel-1.3.0.pkg",
        "fbsd16/demo-pkg-1.2.3.pkg",
        "fbsd16/demo-pkg-devel-1.3.0.pkg",
    ]

    report = json.loads((out_dir / "frozen-v3-report.json").read_text())
    assert report["ports_ref"] == bfv.FROZEN_PORTS_REF
    assert len(report["artifacts"]) == 4
    for artifact in report["artifacts"]:
        assert artifact["channel"] in ("stable", "devel")
        assert artifact["artifact_sha256"]
        assert artifact["payload_file_count"] == 3
        assert list(artifact["payload_files"]) == sorted(artifact["payload_files"])  # sorted inventory

    # Deterministic report bytes: rerun into a fresh --out, compare byte-for-byte
    # modulo the staged_path prefix (a different --out root).
    out_dir_2 = tmp_path / "stage2"
    rc2 = bfv.main(["--out", str(out_dir_2), "--matrix-cmd", f"cat {matrix_file}", "--repo", str(tmp_path)])
    assert rc2 == 0
    report2 = json.loads((out_dir_2 / "frozen-v3-report.json").read_text())
    for a, b in zip(
        sorted(report["artifacts"], key=lambda x: x["staged_path"]),
        sorted(report2["artifacts"], key=lambda x: x["staged_path"]),
    ):
        assert a["artifact_sha256"] == b["artifact_sha256"]
        assert a["payload_files"] == b["payload_files"]


def test_verify_only_validates_staged_dir_without_invoking_build_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    _stub_git(monkeypatch, {STABLE.commit: export_dir})

    def boom(argv: list[str], *, cwd: Path) -> str:
        raise AssertionError("build seam must not be invoked in --verify-only mode")

    monkeypatch.setattr(bfv, "_invoke_build_leg", boom)

    stage_dir = tmp_path / "stage"
    (stage_dir / "fbsd15").mkdir(parents=True)
    pkg_path = stage_dir / "fbsd15" / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
    )

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))

    rc = bfv.main(
        [
            "--out",
            str(stage_dir),
            "--verify-only",
            str(stage_dir),
            "--matrix-cmd",
            f"cat {matrix_file}",
            "--repo",
            str(tmp_path),
        ]
    )
    assert rc == 0
    report = json.loads((stage_dir / "frozen-v3-report.json").read_text())
    assert len(report["artifacts"]) == 1


def test_staging_layout_no_extra_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    _stub_git(monkeypatch, {STABLE.commit: export_dir})
    monkeypatch.setattr(bfv, "_invoke_build_leg", _fake_build_leg({"stable": STABLE}))

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))
    out_dir = tmp_path / "stage"
    rc = bfv.main(
        [
            "--out",
            str(out_dir),
            "--matrix-cmd",
            f"cat {matrix_file}",
            "--repo",
            str(tmp_path),
            "--no-deterministic-check",
        ]
    )
    assert rc == 0
    all_pkgs = list(out_dir.glob("fbsd*/*.pkg"))
    assert len(all_pkgs) == 1


def test_nothing_to_build_when_filters_exclude_every_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))
    rc = bfv.main(
        ["--out", str(tmp_path / "out"), "--matrix-cmd", f"cat {matrix_file}", "--repo", str(tmp_path), "--major", "99"]
    )
    assert rc == 1


# --------------------------------------------------------------------------- #
# Production constants pinned — a regression here silently rebuilds the wrong bits.
# --------------------------------------------------------------------------- #


def test_frozen_constants_match_probed_facts() -> None:
    assert bfv.FROZEN_PORTS_REF == "d30af128f456396a1cc961a10fdf23ad61bdfd58"
    by_channel = {t.channel: t for t in bfv.FROZEN_TARGETS}
    assert by_channel["stable"] == bfv.FrozenTarget(
        channel="stable",
        tag="v3.2.15",
        commit="0846aa7c090f96e62b5322d7dea70e80b1f31b63",
        portname="pfSense-pkg-pfBlockerNG",
        portversion="3.2.15",
    )
    assert by_channel["devel"] == bfv.FrozenTarget(
        channel="devel",
        tag="v3.2.16",
        commit="0676cd1c7ed79d49a0644070151c4fffa39ea409",
        portname="pfSense-pkg-pfBlockerNG-devel",
        portversion="3.2.16",
    )
