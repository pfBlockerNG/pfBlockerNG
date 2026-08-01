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
    compact_overrides: dict | None = None,
    link_members: tuple[tuple[str, str, int], ...] = (),
    duplicate_manifest: bool = False,
    manifest_file_overrides: dict[str, object] | None = None,
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
    compact_manifest = dict(manifest)
    if compact_overrides:
        compact_manifest.update(compact_overrides)
    compact_raw = json.dumps(compact_manifest, separators=(",", ":")).encode() + b"\n"

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
    if manifest_file_overrides:
        full["files"].update(manifest_file_overrides)
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
        if duplicate_manifest:
            # libarchive/libpkg reads the FIRST member of a duplicated name, Python's
            # tarfile the LAST — so a second +MANIFEST is a validator/consumer split.
            _add_member(tf, "+MANIFEST", full_raw)
        for p, b in (files or {}).items():
            _add_member(tf, p, b)
        for link_name, link_target, link_type in link_members:
            ti = tarfile.TarInfo(name=link_name)
            ti.type = link_type  # type: ignore[assignment]
            ti.linkname = link_target
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname, ti.gname = "root", "wheel"
            ti.mtime = 0
            tf.addfile(ti)
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


def _tar_bytes_with(member: tarfile.TarInfo, payload: bytes = b"pwned\n") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        member.size = len(payload)
        tf.addfile(member, io.BytesIO(payload))
    return buf.getvalue()


def _stub_git_archive(monkeypatch: pytest.MonkeyPatch, tar_bytes: bytes) -> None:
    monkeypatch.setattr(
        bfv.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(args=a, returncode=0, stdout=tar_bytes, stderr=b""),
    )


def test_export_tag_rejects_escaping_member_as_clean_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A tag export whose member would land outside the export dir is a clean refusal.

    Intent: the frozen build is a supply-chain step, so an escaping member is reported as
    the module's own named error — never a raw tarfile traceback — and nothing is written
    outside the destination.
    """
    _stub_git_archive(monkeypatch, _tar_bytes_with(tarfile.TarInfo("../escaped")))
    dest = tmp_path / "export-dest"
    dest.mkdir()

    with pytest.raises(bfv.TagResolutionError, match="unsafe member"):
        bfv.export_tag(tmp_path / "repo", "0" * 40, dest)

    assert not (tmp_path / "escaped").exists(), "wrote outside the export dir"
    assert sorted(p.name for p in dest.iterdir()) == [], "extracted despite the escape"


def test_export_tag_keeps_an_absolute_member_inside_the_export_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An absolute member name is contained, not honoured as an absolute write.

    Intent: pins the PEP 706 `data` filter's containment guarantee, so a future change of
    extraction strategy cannot silently regain the ability to write to `/`.
    """
    _stub_git_archive(monkeypatch, _tar_bytes_with(tarfile.TarInfo("/tmp/escaped")))
    dest = tmp_path / "export-dest"
    dest.mkdir()

    bfv.export_tag(tmp_path / "repo", "0" * 40, dest)

    assert (dest / "tmp" / "escaped").read_bytes() == b"pwned\n"


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


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("version", {"version": "4.9.9"}),
        ("abi", {"abi": "FreeBSD:15:amd64"}),
        ("arch", {"arch": "freebsd:15:amd64"}),
        ("name", {"name": "pfSense-pkg-somethingelse"}),
        ("origin", {"origin": "net/somethingelse"}),
    ],
)
def test_compact_manifest_disagreeing_with_full_manifest_rejected(tmp_path: Path, label: str, overrides: dict) -> None:
    """The two manifests must agree on identity, because consumers read different ones.

    Intent: identity validation here reads +MANIFEST, but the catalog generator reads
    +COMPACT_MANIFEST. A package whose two documents disagree would be validated as one
    identity and published as another, so the divergence itself is the defect.
    """
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
        compact_overrides=overrides,
    )
    with pytest.raises(bfv.ArtifactValidationError, match="COMPACT_MANIFEST disagrees"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


@pytest.mark.parametrize(
    ("label", "link_type"),
    [("symlink", tarfile.SYMTYPE), ("hardlink", tarfile.LNKTYPE)],
)
def test_non_regular_payload_member_rejected(tmp_path: Path, label: str, link_type: int) -> None:
    """A link member smuggled into the payload is rejected, not silently ignored.

    Intent: payload parity compares regular files against the tag export, so a member
    that is not a regular file would never enter the comparison at all — it must be
    refused outright rather than travelling in the artifact unexamined.
    """
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
        link_members=(("/usr/local/pkg/pfblockerng/backdoor.inc", "../../../../etc/passwd", link_type),),
    )
    with pytest.raises(bfv.ArtifactValidationError, match="not a regular file"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


def test_duplicate_member_name_rejected(tmp_path: Path) -> None:
    """A duplicated archive member is refused rather than resolved by reader order.

    Intent: libpkg takes the first member of a duplicated name and Python's tarfile the
    last, so tolerating duplicates lets the validator and the installer read different
    documents from the same artifact.
    """
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
        duplicate_manifest=True,
    )
    with pytest.raises(bfv.ArtifactValidationError, match="duplicate archive member"):
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)


@pytest.mark.parametrize("row", [ROW_15, ROW_16])
def test_build_leg_argv_pins_the_frozen_ports_ref_and_forces_no_arch(tmp_path: Path, row: dict) -> None:
    """The two arguments the frozen build cannot lose are pinned by an assertion.

    Intent: dropping --no-arch yields a concrete-ABI package that leaves aarch64
    unserved, and dropping the pinned ports ref builds the frozen payload against a
    moving ports tree — the exact drift this tool exists to prevent.
    """
    argv = bfv._build_leg_argv(
        tmp_path / "build-leg.sh",
        target=STABLE,
        row=row,
        local_src=tmp_path / "src",
        out_dir=tmp_path / "out",
        ports_dir=None,
    )

    assert "--no-arch" in argv, f"--no-arch missing from {argv!r}"
    assert "--ports-ref" in argv, f"--ports-ref missing from {argv!r}"
    assert argv[argv.index("--ports-ref") + 1] == bfv.FROZEN_PORTS_REF


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


# Issue #2020: every +MANIFEST files[].sum must match packaged member bytes.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("target", "row"), [(STABLE, ROW_15), (DEVEL, ROW_15)])
def test_issue_2020_manifest_checksum_accepts_stable_and_devel(tmp_path: Path, target: Any, row: dict) -> None:
    pkg_path, export_dir = _happy_fixture(tmp_path, target, row)
    record = bfv.validate_artifact(pkg_path, export_dir, target, row)
    assert record["payload_file_count"] == 3


@pytest.mark.parametrize(
    "member_name",
    [
        "/usr/local/pkg/pfblockerng/pfblockerng.inc",
        "/usr/local/share/demo-pkg/info.xml",
        "/usr/local/www/pfblockerng/index.php",
    ],
)
def test_issue_2020_manifest_checksum_mismatch_rejected_for_each_member(tmp_path: Path, member_name: str) -> None:
    files = _packaged_payload(STABLE.portname, STABLE.portversion)
    expected = f"1${hashlib.sha256(files[member_name]).hexdigest()}"
    wrong = "1$" + "0" * 64
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=files,
        manifest_file_overrides={member_name: {"sum": wrong}},
    )

    with pytest.raises(bfv.ArtifactValidationError) as exc_info:
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)
    message = str(exc_info.value)
    assert member_name in message
    assert expected in message
    assert wrong in message


def test_issue_2020_info_xml_export_checksum_rejected(tmp_path: Path) -> None:
    files = _packaged_payload(STABLE.portname, STABLE.portversion)
    info_path = f"/usr/local/share/{STABLE.portname}/info.xml"
    export_sum = f"1${hashlib.sha256(_demo_payload(STABLE.portname)[info_path]).hexdigest()}"
    packaged_sum = f"1${hashlib.sha256(files[info_path]).hexdigest()}"
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=files,
        manifest_file_overrides={info_path: {"sum": export_sum}},
    )

    with pytest.raises(bfv.ArtifactValidationError) as exc_info:
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)
    message = str(exc_info.value)
    assert info_path in message
    assert packaged_sum in message
    assert export_sum in message


@pytest.mark.parametrize(
    ("label", "entry"),
    [
        ("wrong_digest", {"sum": "1$" + "0" * 64}),
        ("missing_sum", {}),
        ("wrong_prefix", {"sum": "2$" + "0" * 64}),
        ("string_entry", "not-an-object"),
        ("list_entry", []),
        ("null_entry", None),
    ],
)
def test_issue_2020_malformed_manifest_file_entry_rejected(tmp_path: Path, label: str, entry: object) -> None:
    del label
    member_name = "/usr/local/pkg/pfblockerng/pfblockerng.inc"
    export_dir = _write_export(tmp_path, _demo_payload(STABLE.portname))
    pkg_path = tmp_path / f"{STABLE.portname}-{STABLE.portversion}.pkg"
    _write_pkg(
        pkg_path,
        name=STABLE.portname,
        version=STABLE.portversion,
        deps=_deps_for(ROW_15),
        scripts=DEMO_SCRIPTS,
        files=_packaged_payload(STABLE.portname, STABLE.portversion),
        manifest_file_overrides={member_name: entry},
    )

    with pytest.raises(bfv.ArtifactValidationError) as exc_info:
        bfv.validate_artifact(pkg_path, export_dir, STABLE, ROW_15)
    assert member_name in str(exc_info.value)


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
        # The recorded checksum must be the STAGED bytes' — that is the file a later
        # publication step uploads, so hashing anything else makes the report unverifiable.
        staged_bytes = (out_dir / artifact["staged_path"]).read_bytes()
        assert artifact["artifact_sha256"] == hashlib.sha256(staged_bytes).hexdigest()
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


def test_determinism_failure_leaves_no_staged_artifact_behind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A row that fails the determinism re-build must not leave a publish candidate.

    Intent: staging is what makes an artifact eligible for the later publication step, so
    a row whose second build disagreed must disappear from the staging root entirely —
    otherwise a subsequent --verify-only would bless bytes this run rejected.
    """
    export_stable = _write_export(tmp_path / "src_stable", _demo_payload(STABLE.portname))
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    _stub_git(monkeypatch, {STABLE.commit: export_stable})

    inner = _fake_build_leg({"stable": STABLE})
    calls = {"n": 0}

    def flaky(argv: list[str], *, cwd: Path) -> str:
        produced = inner(argv, cwd=cwd)
        calls["n"] += 1
        if calls["n"] == 2:  # the determinism re-build disagrees by one byte
            Path(produced).write_bytes(Path(produced).read_bytes() + b"\0")
        return produced

    monkeypatch.setattr(bfv, "_invoke_build_leg", flaky)
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))
    out_dir = tmp_path / "stage"

    rc = bfv.main(["--out", str(out_dir), "--matrix-cmd", f"cat {matrix_file}", "--repo", str(tmp_path)])

    assert rc != 0, "a non-deterministic build must not exit 0"
    assert sorted(out_dir.glob("fbsd*/*.pkg")) == [], "staged artifact left behind after a determinism failure"


@pytest.mark.parametrize("field", ["php_version", "py_flavor"])
def test_matrix_row_with_non_string_scalar_rejected_cleanly(field: str) -> None:
    """A non-string matrix scalar is a named MatrixError, not a downstream crash.

    Intent: the hostile-input contract requires malformed matrix input to be rejected in
    the matrix validator, where the offending field can be named.
    """
    row: dict[str, Any] = dict(ROW_15)
    row[field] = 8.3

    with pytest.raises(bfv.MatrixError, match=field):
        bfv.validate_matrix([row])


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


def _stage_valid_artifact(tmp_path: Path, stage: Path, target: Any, row: dict) -> Path:
    """Stage one identity-valid fixture and return its export directory."""
    fixture_root = tmp_path / f"fixture-{target.channel}-{row['freebsd_major']}"
    _, export_dir = _happy_fixture(
        fixture_root,
        target,
        row,
        out_dir=stage / f"fbsd{row['freebsd_major']}",
    )
    return export_dir


def _stub_verify_exports(monkeypatch: pytest.MonkeyPatch, exports: dict[str, Path]) -> None:
    _stub_git(monkeypatch, exports)


def test_issue_2019_filtered_target_accepts_other_frozen_target_but_rejects_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Target-filtered verification accepts the sibling target in the selected major."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE, DEVEL))
    stage = tmp_path / "stage"
    exports = {
        STABLE.commit: _stage_valid_artifact(tmp_path, stage, STABLE, ROW_15),
        DEVEL.commit: _stage_valid_artifact(tmp_path, stage, DEVEL, ROW_15),
    }
    _stub_verify_exports(monkeypatch, exports)

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))
    rc = bfv.main(
        [
            "--out",
            str(stage),
            "--verify-only",
            str(stage),
            "--target",
            "stable",
            "--matrix-cmd",
            f"cat {matrix_file}",
            "--repo",
            str(tmp_path),
        ]
    )
    assert rc == 0, "a legitimate sibling target in the selected major must be ignored"

    _write_pkg(stage / "fbsd15" / "random-extra-1.0.pkg", name="random-extra", version="1.0")
    rc = bfv.main(
        [
            "--out",
            str(stage),
            "--verify-only",
            str(stage),
            "--target",
            "stable",
            "--matrix-cmd",
            f"cat {matrix_file}",
            "--repo",
            str(tmp_path),
        ]
    )
    assert rc == 1, "an unknown selected-major package must be rejected"


def test_issue_2019_major_filter_ignores_unselected_valid_major_pkg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Major-filtered verification ignores valid-layout packages in unselected majors."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    stage = tmp_path / "stage"
    export = _stage_valid_artifact(tmp_path, stage, STABLE, ROW_15)
    _stub_verify_exports(monkeypatch, {STABLE.commit: export})
    (stage / "fbsd16").mkdir(parents=True)
    _write_pkg(stage / "fbsd16" / "random-extra-1.0.pkg", name="random-extra", version="1.0")

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15, ROW_16]))
    rc = bfv.main(
        [
            "--out",
            str(stage),
            "--verify-only",
            str(stage),
            "--major",
            "15",
            "--matrix-cmd",
            f"cat {matrix_file}",
            "--repo",
            str(tmp_path),
        ]
    )
    assert rc == 0


@pytest.mark.parametrize(
    "relative_path",
    [
        "root-extra.pkg",
        "not-fbsd/random-extra.pkg",
        "fbsd15/nested/random-extra.pkg",
    ],
)
def test_issue_2019_invalid_pkg_layout_rejected_recursively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative_path: str
) -> None:
    """Stray scan rejects root, non-fbsd, and deeper package paths under every filter."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    stage = tmp_path / "stage"
    export = _stage_valid_artifact(tmp_path, stage, STABLE, ROW_15)
    _stub_verify_exports(monkeypatch, {STABLE.commit: export})
    stray = stage / relative_path
    stray.parent.mkdir(parents=True, exist_ok=True)
    _write_pkg(stray, name="random-extra", version="1.0")

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))
    rc = bfv.main(
        [
            "--out",
            str(stage),
            "--verify-only",
            str(stage),
            "--target",
            "stable",
            "--major",
            "15",
            "--matrix-cmd",
            f"cat {matrix_file}",
            "--repo",
            str(tmp_path),
        ]
    )
    assert rc == 1


def test_issue_2019_stray_diagnostics_report_relative_paths_for_duplicate_basenames(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No-filter stray diagnostics include both selected relative paths for one basename."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    stage = tmp_path / "stage"
    export = _stage_valid_artifact(tmp_path, stage, STABLE, ROW_15)
    _stage_valid_artifact(tmp_path, stage, STABLE, ROW_16)
    _stub_verify_exports(monkeypatch, {STABLE.commit: export})
    for major in ("15", "16"):
        _write_pkg(stage / f"fbsd{major}" / "same-extra.pkg", name="same-extra", version="1.0")

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15, ROW_16]))
    rc = bfv.main(
        [
            "--out",
            str(stage),
            "--verify-only",
            str(stage),
            "--matrix-cmd",
            f"cat {matrix_file}",
            "--repo",
            str(tmp_path),
        ]
    )
    assert rc == 1
    stderr = capsys.readouterr().err
    assert "fbsd15/same-extra.pkg" in stderr
    assert "fbsd16/same-extra.pkg" in stderr


def test_issue_2019_stable_filename_boundary_does_not_claim_devel_pkg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stable's shorter port name cannot claim the legitimate devel sibling filename."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE, DEVEL))
    stage = tmp_path / "stage"
    stable_export = _stage_valid_artifact(tmp_path, stage, STABLE, ROW_15)
    _stage_valid_artifact(tmp_path, stage, DEVEL, ROW_15)
    _stub_verify_exports(monkeypatch, {STABLE.commit: stable_export, DEVEL.commit: stable_export})
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))

    rc = bfv.main(
        [
            "--out",
            str(stage),
            "--verify-only",
            str(stage),
            "--target",
            "stable",
            "--matrix-cmd",
            f"cat {matrix_file}",
            "--repo",
            str(tmp_path),
        ]
    )
    assert rc == 0, "stable candidate boundary must not claim the devel sibling"


@pytest.mark.parametrize("target_filter", [None, "stable"])
def test_issue_2019_selected_scope_rejects_stale_frozen_target_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_filter: str | None
) -> None:
    """A build rejects extra revisions of a selected frozen target."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    export = _write_export(tmp_path, _demo_payload(STABLE.portname))
    _stub_git(monkeypatch, {STABLE.commit: export})
    monkeypatch.setattr(bfv, "_invoke_build_leg", _fake_build_leg({"stable": STABLE}))
    stage = tmp_path / "stage"
    (stage / "fbsd15").mkdir(parents=True)
    _write_pkg(
        stage / "fbsd15" / f"{STABLE.portname}-{STABLE.portversion}_1.pkg",
        name=STABLE.portname,
        version=f"{STABLE.portversion}_1",
        files=_demo_payload(STABLE.portname),
    )
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))

    assert (
        bfv.main(
            [
                "--out",
                str(stage),
                "--matrix-cmd",
                f"cat {matrix_file}",
                "--repo",
                str(tmp_path),
                "--no-deterministic-check",
            ]
            + (["--target", target_filter] if target_filter is not None else [])
        )
        == 1
    )


def test_issue_2019_build_rejects_symlinked_leg_before_staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Build mode cannot stage through a symlinked FreeBSD leg directory."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    export = _write_export(tmp_path, _demo_payload(STABLE.portname))
    _stub_git(monkeypatch, {STABLE.commit: export})
    monkeypatch.setattr(bfv, "_invoke_build_leg", _fake_build_leg({"stable": STABLE}))
    stage = tmp_path / "stage"
    outside = tmp_path / "outside"
    stage.mkdir()
    outside.mkdir()
    (stage / "fbsd15").symlink_to(outside, target_is_directory=True)
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))

    assert (
        bfv.main(
            [
                "--out",
                str(stage),
                "--matrix-cmd",
                f"cat {matrix_file}",
                "--repo",
                str(tmp_path),
                "--no-deterministic-check",
            ]
        )
        == 1
    )
    assert not (outside / f"{STABLE.portname}-{STABLE.portversion}.pkg").exists()


def test_issue_2019_verify_rejects_packages_hidden_by_symlinked_leg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify mode cannot overlook packages behind a symlinked leg directory."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE,))
    stage = tmp_path / "stage"
    outside = tmp_path / "outside"
    stage.mkdir()
    outside.mkdir()
    (stage / "fbsd15").symlink_to(outside, target_is_directory=True)
    export = _stage_valid_artifact(tmp_path, stage, STABLE, ROW_15)
    _write_pkg(outside / "random-extra-1.0.pkg", name="random-extra", version="1.0")
    _stub_verify_exports(monkeypatch, {STABLE.commit: export})
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15]))

    assert (
        bfv.main(
            [
                "--out",
                str(stage),
                "--verify-only",
                str(stage),
                "--matrix-cmd",
                f"cat {matrix_file}",
                "--repo",
                str(tmp_path),
            ]
        )
        == 1
    )


def test_issue_2019_target_and_major_filters_scope_strays_to_intersection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Combined filters accept sibling/other-major staging but reject selected-scope extras."""
    monkeypatch.setattr(bfv, "FROZEN_TARGETS", (STABLE, DEVEL))
    stage = tmp_path / "stage"
    stable_export = _stage_valid_artifact(tmp_path, stage, STABLE, ROW_15)
    _stage_valid_artifact(tmp_path, stage, DEVEL, ROW_15)
    _stub_verify_exports(monkeypatch, {STABLE.commit: stable_export, DEVEL.commit: stable_export})
    (stage / "fbsd16").mkdir(parents=True)
    _write_pkg(stage / "fbsd16" / "random-extra-1.0.pkg", name="random-extra", version="1.0")

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([ROW_15, ROW_16]))
    args = [
        "--out",
        str(stage),
        "--verify-only",
        str(stage),
        "--target",
        "stable",
        "--major",
        "15",
        "--matrix-cmd",
        f"cat {matrix_file}",
        "--repo",
        str(tmp_path),
    ]
    assert bfv.main(args) == 0

    _write_pkg(stage / "fbsd15" / "random-extra-1.0.pkg", name="random-extra", version="1.0")
    assert bfv.main(args) == 1


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
