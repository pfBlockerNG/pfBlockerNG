#!/usr/bin/env python3
# build-frozen-v3.py — build + identity-validate the FROZEN pfBlockerNG v3.2
# Stable/Devel .pkg artifacts (issue #1676) for every BUILD-matrix row.
#
# The v3.2 sources predate the 2026-06-05 list_scripts/ move: a current-devel
# ports ref cannot build them, and a current source tree cannot be built by
# the frozen ports ref either. So this tool pins BOTH sides — an exact
# FreeBSD-ports commit (FROZEN_PORTS_REF) and, per channel, an exact
# pfBlockerNG source tag/commit (FROZEN_TARGETS) — and treats a mismatch on
# either as a hard error rather than silently drifting.
#
# Per (frozen target x BUILD-matrix row) this:
#   1. exports the pinned source tag with `git archive` into a fresh temp dir
#      (never the working tree — the export is clean BY CONSTRUCTION, not
#      merely by inspection);
#   2. builds one .pkg leg via scripts/build-leg.sh (the shared build path);
#   3. validates the artifact's identity (validate_artifact) — name, origin,
#      version, wildcarded ABI/arch, matrix-derived dependency names, the one
#      reviewed packaging divergence (info.xml's %%PKGVERSION%% substitution),
#      and byte-exact payload parity against the tag export otherwise — and
#      REFUSES to stage anything that fails;
#   4. unless --no-deterministic-check, rebuilds the same row and requires a
#      byte-identical second artifact;
#   5. writes a JSON identity report.
#
# This tool NEVER publishes: no GitHub Release upload, no catalog write, no
# network write of any kind. Publication is a separate, maintainer-gated step.
#
# Python 3.11+, standard library only. See --help for the full CLI.

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pfb_pkg

# --------------------------------------------------------------------------- #
# Frozen identities — constants, not matrix-tracked. Never edit these to
# "catch up" with a later tag; a new frozen build target is a new constant.
# --------------------------------------------------------------------------- #

FROZEN_PORTS_REF = "d30af128f456396a1cc961a10fdf23ad61bdfd58"


@dataclass(frozen=True)
class FrozenTarget:
    channel: str  # "stable" | "devel"
    tag: str
    commit: str
    portname: str
    portversion: str


FROZEN_TARGETS: tuple[FrozenTarget, ...] = (
    FrozenTarget(
        channel="stable",
        tag="v3.2.15",
        commit="0846aa7c090f96e62b5322d7dea70e80b1f31b63",
        portname="pfSense-pkg-pfBlockerNG",
        portversion="3.2.15",
    ),
    FrozenTarget(
        channel="devel",
        tag="v3.2.16",
        commit="0676cd1c7ed79d49a0644070151c4fffa39ea409",
        portname="pfSense-pkg-pfBlockerNG-devel",
        portversion="3.2.16",
    ),
)


class MatrixError(Exception):
    """The BUILD matrix (or the command that produced it) is unusable."""


class TagResolutionError(Exception):
    """A frozen source tag could not be resolved to its expected commit."""


class BuildLegError(Exception):
    """scripts/build-leg.sh failed or violated its stdout contract."""


class ArtifactValidationError(Exception):
    """A built .pkg failed identity validation. Never staged when raised."""


class DeterminismError(Exception):
    """Two builds of the same row produced different artifacts."""


# --------------------------------------------------------------------------- #
# Matrix: read + validate (never infer a default for a missing/bad field).
# --------------------------------------------------------------------------- #

_MAJOR_RE = re.compile(r"^[1-9][0-9]*$")
_REQUIRED_ROW_FIELDS = ("freebsd_major", "php_version", "py_flavor")


def run_matrix_cmd(cmd: list[str], *, cwd: Path) -> object:
    """Run the matrix command (never a shell string) and parse its stdout as JSON."""
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise MatrixError(f"matrix command {cmd!r} failed (exit {proc.returncode}): {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except ValueError as e:
        raise MatrixError(
            f"matrix command {cmd!r} did not print JSON: {e}; "
            f"stdout={proc.stdout[:500]!r} stderr={proc.stderr.strip()!r}"
        ) from None


def validate_matrix(obj: object) -> list[dict]:
    """Reject anything the BUILD-matrix contract does not guarantee — never infer."""
    if not isinstance(obj, list):
        raise MatrixError(f"BUILD matrix must be a JSON array, got {type(obj).__name__}")
    if not obj:
        raise MatrixError("BUILD matrix is empty")
    seen_majors: set[str] = set()
    rows: list[dict] = []
    for i, row in enumerate(obj):
        if not isinstance(row, dict):
            raise MatrixError(f"BUILD matrix row {i} is not an object: {row!r}")
        missing = [k for k in _REQUIRED_ROW_FIELDS if k not in row]
        if missing:
            raise MatrixError(f"BUILD matrix row {i} missing required field(s): {', '.join(missing)}")
        for key in ("php_version", "py_flavor"):
            if not isinstance(row[key], str):
                raise MatrixError(f"BUILD matrix row {i}: {key} must be a string, got {row[key]!r}")
        major = row["freebsd_major"]
        if not isinstance(major, str) or not _MAJOR_RE.fullmatch(major):
            raise MatrixError(f"BUILD matrix row {i}: freebsd_major must be a positive-integer string, got {major!r}")
        if major in seen_majors:
            raise MatrixError(f"BUILD matrix has duplicate freebsd_major {major!r} (--print-build must dedupe)")
        seen_majors.add(major)
        role = row.get("role")
        if role is not None and role != "build":
            raise MatrixError(f"BUILD matrix row {i} (freebsd_major={major}) carries unexpected role {role!r}")
        rows.append(row)
    return rows


def plan_artifacts(
    rows: list[dict], *, target_filter: str | None, major_filter: str | None
) -> list[tuple[FrozenTarget, dict]]:
    targets = [t for t in FROZEN_TARGETS if target_filter is None or t.channel == target_filter]
    rows = [r for r in rows if major_filter is None or r["freebsd_major"] == major_filter]
    return [(t, r) for t in targets for r in rows]


def _derive_deps(row: dict) -> set[str]:
    php_key = "php" + row["php_version"].replace(".", "")
    py_flavor = row["py_flavor"]
    py_num = py_flavor[2:] if py_flavor.startswith("py") else ""
    if not py_num.isdigit():
        raise ArtifactValidationError(f"cannot derive a python dependency name from py_flavor {py_flavor!r}")
    return {php_key, f"{php_key}-intl", f"python{py_num}", f"{py_flavor}-sqlite3", f"{py_flavor}-maxminddb"}


# --------------------------------------------------------------------------- #
# Safe path segments — a name/version/major that becomes a path component is
# validated (no "/", no "..", no whitespace, non-empty) before it is ever
# joined into a filesystem path.
# --------------------------------------------------------------------------- #

_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._,-]*$")


def _safe_segment(value: object, what: str) -> str:
    if not isinstance(value, str) or not _SAFE_SEGMENT_RE.fullmatch(value) or ".." in value:
        raise ArtifactValidationError(f"unsafe path segment for {what}: {value!r}")
    return value


# --------------------------------------------------------------------------- #
# Tag resolution + export — the export is clean by construction: `git archive`
# into a fresh temp dir, never the working tree, so there is no dirty-tree
# state to accidentally ship.
# --------------------------------------------------------------------------- #


def resolve_tag_commit(repo: Path, tag: str, expected_commit: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise TagResolutionError(f"tag {tag!r} not found in {repo}: {proc.stderr.strip()}")
    actual = proc.stdout.strip()
    if actual != expected_commit:
        raise TagResolutionError(f"tag {tag!r} resolves to {actual}, expected {expected_commit}")
    return actual


def export_tag(repo: Path, commit: str, dest: Path) -> None:
    proc = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", commit], capture_output=True, check=False)
    if proc.returncode != 0:
        raise TagResolutionError(f"git archive {commit} failed: {proc.stderr.decode(errors='replace').strip()}")
    with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tf:
        # Mirrors build-pkg-portable.py's _safe_extract: the stdlib 'data' filter (PEP 706,
        # Python 3.11.4+ — the repo's floor is 3.11) rejects absolute paths, parent-dir
        # traversal, and link-based escapes. There is deliberately NO unfiltered fallback:
        # degrading to a bare extractall would silently drop that guard in a supply-chain step.
        try:
            tf.extractall(dest, filter="data")
        except tarfile.FilterError as e:
            raise TagResolutionError(f"unsafe member in the {commit} tag export: {e}") from None


# --------------------------------------------------------------------------- #
# .pkg reading — corruption/malformed archives are a clean ArtifactValidationError,
# never a raw traceback.
# --------------------------------------------------------------------------- #


def _read_pkg(pkg_path: Path) -> tuple[dict, dict[str, bytes]]:
    try:
        tar_bytes = pfb_pkg.zstd_decompress(pkg_path.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
            names = tf.getnames()
            if "+COMPACT_MANIFEST" not in names:
                raise ArtifactValidationError(f"{pkg_path.name}: missing +COMPACT_MANIFEST")
            if "+MANIFEST" not in names:
                raise ArtifactValidationError(f"{pkg_path.name}: missing +MANIFEST")
            # libarchive/libpkg resolves a duplicated member name to the FIRST copy while
            # Python's tarfile resolves it to the LAST, so a duplicate would let this
            # validator and the installer read different bytes from one artifact.
            duplicates = sorted({n for n in names if names.count(n) > 1})
            if duplicates:
                raise ArtifactValidationError(f"{pkg_path.name}: duplicate archive member(s): {', '.join(duplicates)}")
            compact_raw = tf.extractfile("+COMPACT_MANIFEST").read()  # type: ignore[union-attr]
            manifest_raw = tf.extractfile("+MANIFEST").read()  # type: ignore[union-attr]
            payload: dict[str, bytes] = {}
            for member in tf.getmembers():
                if member.name in ("+MANIFEST", "+COMPACT_MANIFEST"):
                    continue
                # Only regular files are comparable against the tag export. A symlink,
                # hardlink, dir or device would skip payload parity entirely, so refuse
                # it rather than let it ride along unexamined.
                if not member.isfile():
                    raise ArtifactValidationError(
                        f"{pkg_path.name}: payload member {member.name!r} is not a regular file "
                        f"(tar type {member.type!r})"
                    )
                extracted = tf.extractfile(member)
                payload[member.name] = extracted.read() if extracted is not None else b""
    except ArtifactValidationError:
        raise
    except Exception as e:
        raise ArtifactValidationError(f"{pkg_path.name}: unreadable/corrupt .pkg ({e.__class__.__name__}: {e})") from e

    try:
        compact_obj = json.loads(compact_raw)
    except ValueError as e:
        raise ArtifactValidationError(f"{pkg_path.name}: +COMPACT_MANIFEST is not valid JSON: {e}") from None
    if not isinstance(compact_obj, dict):
        raise ArtifactValidationError(f"{pkg_path.name}: +COMPACT_MANIFEST is not a JSON object")
    try:
        manifest = json.loads(manifest_raw)
    except ValueError as e:
        raise ArtifactValidationError(f"{pkg_path.name}: +MANIFEST is not valid JSON: {e}") from None
    if not isinstance(manifest, dict):
        raise ArtifactValidationError(f"{pkg_path.name}: +MANIFEST is not a JSON object")
    # Identity is validated below against +MANIFEST, but the catalog generator
    # (build-repo-portable.py, via pfb_pkg.read_compact_manifest) routes on
    # +COMPACT_MANIFEST. Divergence would validate one identity and publish another.
    disagreements = [
        f"{key}: +MANIFEST={manifest.get(key)!r} vs +COMPACT_MANIFEST={compact_obj.get(key)!r}"
        for key in ("name", "origin", "version", "abi", "arch")
        if manifest.get(key) != compact_obj.get(key)
    ]
    if disagreements:
        raise ArtifactValidationError(
            f"{pkg_path.name}: +COMPACT_MANIFEST disagrees with +MANIFEST — {'; '.join(disagreements)}"
        )
    return manifest, payload


# --------------------------------------------------------------------------- #
# Artifact identity validation — pure, directly testable.
# --------------------------------------------------------------------------- #


def validate_artifact(pkg_path: Path, export_dir: Path, target: FrozenTarget, row: dict) -> dict:
    manifest, payload = _read_pkg(pkg_path)

    name = manifest.get("name")
    if name != target.portname:
        raise ArtifactValidationError(
            f"{pkg_path.name}: manifest name {name!r} != expected {target.portname!r} for channel {target.channel!r}"
        )
    expected_origin = f"net/{target.portname}"
    origin = manifest.get("origin")
    if origin != expected_origin:
        raise ArtifactValidationError(f"{pkg_path.name}: manifest origin {origin!r} != expected {expected_origin!r}")

    version = manifest.get("version")
    version_re = re.compile(rf"^{re.escape(target.portversion)}(_[0-9]+)?(,[0-9]+)?$")
    if not isinstance(version, str) or not version_re.fullmatch(version):
        raise ArtifactValidationError(
            f"{pkg_path.name}: manifest version {version!r} does not match PORTVERSION {target.portversion!r} "
            "(+ optional _PORTREVISION/,EPOCH)"
        )
    name = _safe_segment(name, "manifest name")
    version = _safe_segment(version, "manifest version")

    major = row["freebsd_major"]
    expected_abi = f"FreeBSD:{major}:*"
    expected_arch = f"freebsd:{major}:*"
    abi = manifest.get("abi")
    arch = manifest.get("arch")
    if abi != expected_abi:
        raise ArtifactValidationError(f"{pkg_path.name}: manifest abi {abi!r} != expected {expected_abi!r}")
    if arch != expected_arch:
        raise ArtifactValidationError(f"{pkg_path.name}: manifest arch {arch!r} != expected {expected_arch!r}")

    expected_filename = f"{name}-{version}.pkg"
    if pkg_path.name != expected_filename:
        raise ArtifactValidationError(
            f"{pkg_path.name}: filename disagrees with the manifest identity (expected {expected_filename!r})"
        )

    required_deps = _derive_deps(row)
    deps = manifest.get("deps")
    have_deps = set(deps) if isinstance(deps, dict) else set()
    missing_deps = sorted(required_deps - have_deps)
    if missing_deps:
        raise ArtifactValidationError(f"{pkg_path.name}: missing derived dependency name(s): {', '.join(missing_deps)}")

    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict) or not scripts.get("install") or not scripts.get("deinstall"):
        raise ArtifactValidationError(f"{pkg_path.name}: manifest scripts.install/scripts.deinstall missing or empty")
    install_sha = hashlib.sha256(scripts["install"].encode()).hexdigest()
    deinstall_sha = hashlib.sha256(scripts["deinstall"].encode()).hexdigest()

    files_manifest = manifest.get("files")
    if not isinstance(files_manifest, dict) or not files_manifest:
        raise ArtifactValidationError(f"{pkg_path.name}: manifest has no (non-empty) files section")

    payload_names = set(payload)
    manifest_names = set(files_manifest)
    extra = sorted(payload_names - manifest_names)
    if extra:
        raise ArtifactValidationError(
            f"{pkg_path.name}: payload has file(s) not listed in the manifest: {', '.join(extra)}"
        )
    missing_payload = sorted(manifest_names - payload_names)
    if missing_payload:
        raise ArtifactValidationError(
            f"{pkg_path.name}: manifest lists file(s) missing from the payload: {', '.join(missing_payload)}"
        )

    info_xml_path = f"/usr/local/share/{name}/info.xml"
    export_root = export_dir.resolve()
    payload_inventory: dict[str, str] = {}
    for member_name, data in sorted(payload.items()):
        manifest_entry = files_manifest[member_name]
        if not isinstance(manifest_entry, dict):
            raise ArtifactValidationError(f"{pkg_path.name}: manifest file entry {member_name!r} must be an object")
        manifest_sum = manifest_entry.get("sum")
        if not isinstance(manifest_sum, str) or re.fullmatch(r"1\$[0-9a-f]{64}", manifest_sum) is None:
            raise ArtifactValidationError(
                f"{pkg_path.name}: manifest file entry {member_name!r} has malformed sum {manifest_sum!r}"
            )
        payload_sha256 = hashlib.sha256(data).hexdigest()
        expected_sum = f"1${payload_sha256}"
        if manifest_sum != expected_sum:
            raise ArtifactValidationError(
                f"{pkg_path.name}: manifest checksum mismatch for payload file {member_name!r}: "
                f"expected {expected_sum!r}, actual {manifest_sum!r}"
            )
        rel = member_name.lstrip("/")
        export_path = (export_dir / rel).resolve()
        if export_path != export_root and export_root not in export_path.parents:
            raise ArtifactValidationError(f"{pkg_path.name}: payload path escapes the tag export: {member_name!r}")
        if not export_path.is_file():
            raise ArtifactValidationError(
                f"{pkg_path.name}: payload file {member_name!r} not present in the tag export"
            )
        export_bytes = export_path.read_bytes()
        if member_name == info_xml_path:
            # issue #1676: the port's do-install REINPLACE_CMD on %%PKGVERSION%% is the
            # ONE reviewed packaging divergence — allowlisted here and nowhere else.
            expected_bytes = export_bytes.replace(b"%%PKGVERSION%%", version.encode())
            if data != expected_bytes:
                raise ArtifactValidationError(
                    f"{pkg_path.name}: {member_name} diverges from the tag export beyond "
                    "the %%PKGVERSION%% substitution"
                )
        elif data != export_bytes:
            raise ArtifactValidationError(f"{pkg_path.name}: payload file {member_name!r} diverges from the tag export")
        payload_inventory[member_name] = payload_sha256

    artifact_sha256 = hashlib.sha256(pkg_path.read_bytes()).hexdigest()

    return {
        "name": name,
        "version": version,
        "origin": origin,
        "abi": abi,
        "arch": arch,
        "artifact_sha256": artifact_sha256,
        "payload_file_count": len(payload_inventory),
        "payload_files": payload_inventory,
        "install_script_sha256": install_sha,
        "deinstall_script_sha256": deinstall_sha,
    }


def check_determinism(pkg_a: Path, pkg_b: Path) -> None:
    sha_a = hashlib.sha256(pkg_a.read_bytes()).hexdigest()
    sha_b = hashlib.sha256(pkg_b.read_bytes()).hexdigest()
    if sha_a == sha_b:
        return
    detail = []
    try:
        manifest_a, payload_a = _read_pkg(pkg_a)
        manifest_b, payload_b = _read_pkg(pkg_b)
        if manifest_a != manifest_b:
            detail.append("manifest differs")
        inv_a = {k: hashlib.sha256(v).hexdigest() for k, v in payload_a.items()}
        inv_b = {k: hashlib.sha256(v).hexdigest() for k, v in payload_b.items()}
        if inv_a != inv_b:
            detail.append("payload inventory differs")
    except ArtifactValidationError:
        pass
    suffix = f" ({'; '.join(detail)})" if detail else ""
    raise DeterminismError(
        f"non-deterministic build: {pkg_a.name} sha256={sha_a} vs {pkg_b.name} sha256={sha_b}{suffix}"
    )


# --------------------------------------------------------------------------- #
# build-leg.sh invocation — ONE subprocess seam (stubbed by tests).
# --------------------------------------------------------------------------- #


def _build_leg_argv(
    build_leg_sh: Path, *, target: FrozenTarget, row: dict, local_src: Path, out_dir: Path, ports_dir: str | None
) -> list[str]:
    # The concrete "amd64" here is an INERT placeholder (mirrors release.yml's "Compute
    # this leg's LEG/ABI" step): --no-arch wildcards the manifest stamp regardless, so
    # the one .pkg this leg builds serves every arch of this FreeBSD major.
    argv = [
        "sh",
        str(build_leg_sh),
        "--ports-ref",
        FROZEN_PORTS_REF,
        "--channel",
        target.channel,
        "--local-src",
        str(local_src),
        "--abi",
        f"FreeBSD:{row['freebsd_major']}:amd64",
        "--php",
        row["php_version"],
        "--py-flavor",
        row["py_flavor"],
        "--no-arch",
        "--out-dir",
        str(out_dir),
    ]
    if ports_dir:
        argv += ["--ports-dir", ports_dir]
    return argv


def _invoke_build_leg(argv: list[str], *, cwd: Path) -> str:
    """Run build-leg.sh and return its ONE stdout line (the resolved .pkg path).

    The stubbable subprocess seam: tests monkeypatch this function's module
    attribute rather than driving a real ports clone / package build.
    """
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise BuildLegError(f"build-leg.sh failed (exit {proc.returncode}):\n{proc.stderr}")
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if len(lines) != 1:
        raise BuildLegError(f"build-leg.sh stdout contract violated (expected exactly one path line): {proc.stdout!r}")
    return lines[0]


# --------------------------------------------------------------------------- #
# Per-row orchestration: build to scratch, validate, stage ONLY on success.
# --------------------------------------------------------------------------- #


def build_and_stage_one(
    *,
    target: FrozenTarget,
    row: dict,
    repo: Path,
    export_dir: Path,
    build_leg_sh: Path,
    out_dir: Path,
    ports_dir: str | None,
) -> dict:
    major = _safe_segment(row["freebsd_major"], "freebsd_major")
    scratch = Path(tempfile.mkdtemp(prefix="pfb-frozen-scratch-"))
    try:
        argv = _build_leg_argv(
            build_leg_sh, target=target, row=row, local_src=export_dir, out_dir=scratch, ports_dir=ports_dir
        )
        pkg_path = Path(_invoke_build_leg(argv, cwd=repo))
        identity = validate_artifact(pkg_path, export_dir, target, row)  # raises; nothing staged below on failure
        leg_dir = out_dir / f"fbsd{major}"
        leg_dir.mkdir(parents=True, exist_ok=True)
        staged_path = leg_dir / pkg_path.name
        shutil.copy2(pkg_path, staged_path)
        # Re-hash the STAGED file: the report's checksum must describe the bytes a later
        # publication step would upload, not the scratch copy they were taken from.
        identity["artifact_sha256"] = hashlib.sha256(staged_path.read_bytes()).hexdigest()
        identity["staged_path"] = staged_path
        return identity
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _assert_no_stray_pkgs(
    out_dir: Path,
    staged: set[Path],
    *,
    plan: list[tuple[FrozenTarget, dict]],
    target_filter: str | None,
    major_filter: str | None,
) -> None:
    owned_majors = {row["freebsd_major"] for _, row in plan}
    extra: list[str] = []
    for path in sorted(out_dir.rglob("*.pkg")):
        relative = path.relative_to(out_dir)
        layout = relative.parts
        if len(layout) != 2:
            extra.append(relative.as_posix())
            continue
        major_match = re.fullmatch(r"fbsd([1-9][0-9]*)", layout[0])
        if major_match is None:
            extra.append(relative.as_posix())
            continue
        major = major_match.group(1)
        if major_filter is not None and major != major_filter:
            continue
        if major_filter is None and major not in owned_majors:
            extra.append(relative.as_posix())
            continue
        if path in staged:
            continue
        if target_filter is not None and any(
            target.channel != target_filter
            and re.fullmatch(
                rf"{re.escape(target.portname)}-{re.escape(target.portversion)}(?:_[0-9]+)?(?:,[0-9]+)?\.pkg",
                path.name,
            )
            for target in FROZEN_TARGETS
        ):
            continue
        extra.append(relative.as_posix())
    if extra:
        raise ArtifactValidationError(
            f"{out_dir}: unexpected staged file(s) beyond the planned artifacts: {', '.join(extra)}"
        )


def _assert_no_staging_symlinks(out_dir: Path) -> None:
    links = sorted(path.relative_to(out_dir).as_posix() for path in out_dir.rglob("*") if path.is_symlink())
    if links:
        raise ArtifactValidationError(f"{out_dir}: staging symlink(s) are not allowed: {', '.join(links)}")


def build_all(
    plan: list[tuple[FrozenTarget, dict]],
    *,
    repo: Path,
    build_leg_sh: Path,
    out_dir: Path,
    ports_dir: str | None,
    do_determinism: bool,
    target_filter: str | None,
    major_filter: str | None,
) -> dict:
    _assert_no_staging_symlinks(out_dir)
    export_cache: dict[str, Path] = {}
    artifacts: list[dict] = []
    staged: set[Path] = set()
    with contextlib.ExitStack() as stack:
        for target, row in plan:
            if target.commit not in export_cache:
                resolve_tag_commit(repo, target.tag, target.commit)
                export_dir = Path(
                    stack.enter_context(tempfile.TemporaryDirectory(prefix=f"pfb-frozen-export-{target.channel}-"))
                )
                export_tag(repo, target.commit, export_dir)
                export_cache[target.commit] = export_dir
            export_dir = export_cache[target.commit]

            identity = build_and_stage_one(
                target=target,
                row=row,
                repo=repo,
                export_dir=export_dir,
                build_leg_sh=build_leg_sh,
                out_dir=out_dir,
                ports_dir=ports_dir,
            )
            staged_path = identity.pop("staged_path")
            staged.add(staged_path)

            if do_determinism:
                scratch2 = Path(tempfile.mkdtemp(prefix="pfb-frozen-scratch2-"))
                try:
                    argv = _build_leg_argv(
                        build_leg_sh,
                        target=target,
                        row=row,
                        local_src=export_dir,
                        out_dir=scratch2,
                        ports_dir=ports_dir,
                    )
                    pkg2_path = Path(_invoke_build_leg(argv, cwd=repo))
                    try:
                        check_determinism(staged_path, pkg2_path)
                    except DeterminismError:
                        # Staging is what makes an artifact a publication candidate, so a
                        # row that failed its re-build must not survive in the staging root
                        # for a later --verify-only to bless.
                        staged_path.unlink(missing_ok=True)
                        staged.discard(staged_path)
                        raise
                finally:
                    shutil.rmtree(scratch2, ignore_errors=True)

            artifacts.append(
                {
                    "channel": target.channel,
                    "tag": target.tag,
                    "source_commit": target.commit,
                    "ports_ref": FROZEN_PORTS_REF,
                    "matrix_row": row,
                    "staged_path": str(staged_path.relative_to(out_dir)),
                    **identity,
                }
            )
    _assert_no_stray_pkgs(
        out_dir,
        staged,
        plan=plan,
        target_filter=target_filter,
        major_filter=major_filter,
    )
    return {"ports_ref": FROZEN_PORTS_REF, "artifacts": artifacts}


def verify_staged(
    dir_: Path,
    plan: list[tuple[FrozenTarget, dict]],
    *,
    repo: Path,
    target_filter: str | None,
    major_filter: str | None,
) -> dict:
    _assert_no_staging_symlinks(dir_)
    export_cache: dict[str, Path] = {}
    artifacts: list[dict] = []
    staged: set[Path] = set()
    with contextlib.ExitStack() as stack:
        for target, row in plan:
            if target.commit not in export_cache:
                resolve_tag_commit(repo, target.tag, target.commit)
                export_dir = Path(
                    stack.enter_context(tempfile.TemporaryDirectory(prefix=f"pfb-frozen-verify-{target.channel}-"))
                )
                export_tag(repo, target.commit, export_dir)
                export_cache[target.commit] = export_dir
            export_dir = export_cache[target.commit]

            major = _safe_segment(row["freebsd_major"], "freebsd_major")
            leg_dir = dir_ / f"fbsd{major}"
            # Require the char right after "<portname>-" to be a digit (a version), so
            # stable's shorter portname never matches devel's "<portname>-devel-..." file.
            name_re = re.compile(rf"^{re.escape(target.portname)}-\d[^/]*\.pkg$")
            candidates = sorted(p for p in leg_dir.glob("*.pkg") if name_re.match(p.name)) if leg_dir.is_dir() else []
            if len(candidates) != 1:
                raise ArtifactValidationError(
                    f"{leg_dir}: expected exactly one {target.channel} artifact matching "
                    f"{target.portname}-<version>.pkg, found {len(candidates)}: {[c.name for c in candidates]}"
                )
            pkg_path = candidates[0]
            identity = validate_artifact(pkg_path, export_dir, target, row)
            staged.add(pkg_path)
            artifacts.append(
                {
                    "channel": target.channel,
                    "tag": target.tag,
                    "source_commit": target.commit,
                    "ports_ref": FROZEN_PORTS_REF,
                    "matrix_row": row,
                    "staged_path": str(pkg_path.relative_to(dir_)),
                    **identity,
                }
            )
    _assert_no_stray_pkgs(
        dir_,
        staged,
        plan=plan,
        target_filter=target_filter,
        major_filter=major_filter,
    )
    return {"ports_ref": FROZEN_PORTS_REF, "artifacts": artifacts}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _default_repo() -> Path:
    return Path(__file__).resolve().parent.parent


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="build-frozen-v3.py",
        description=(
            "Build and identity-validate the frozen pfBlockerNG v3.2 Stable (v3.2.15) and "
            "Devel (v3.2.16) .pkg artifacts for every BUILD-matrix row. Never publishes anything: "
            "no GitHub Release upload, no catalog write, no network write."
        ),
    )
    p.add_argument(
        "--out",
        required=True,
        type=Path,
        help="staging root. Layout: DIR/fbsd<major>/<pkgname>-<version>.pkg, one leg dir per FreeBSD major.",
    )
    p.add_argument(
        "--report",
        type=Path,
        default=None,
        help="JSON identity report path (default: <out>/frozen-v3-report.json).",
    )
    p.add_argument(
        "--ports-dir",
        default=None,
        help="FreeBSD-ports checkout dir, passed through to build-leg.sh (default: build-leg.sh keys its own).",
    )
    p.add_argument(
        "--matrix-cmd",
        type=shlex.split,
        default=None,
        help="override the BUILD-matrix command, as a single shell-quoted string parsed with shlex "
        "(default: 'scripts/read-version-matrix.sh --print-build'). The test seam.",
    )
    p.add_argument(
        "--repo",
        type=Path,
        default=None,
        help="pfBlockerNG git checkout to export the frozen source tags from (default: this script's own repo root).",
    )
    p.add_argument(
        "--no-deterministic-check",
        action="store_true",
        help="skip the double-build determinism proof (default: build every row twice, require byte-identical output).",
    )
    p.add_argument(
        "--verify-only",
        type=Path,
        default=None,
        metavar="DIR",
        help="validate an already-staged DIR against the BUILD matrix without building anything.",
    )
    p.add_argument(
        "--target",
        choices=sorted({t.channel for t in FROZEN_TARGETS}),
        default=None,
        help="build/verify only this channel (default: both stable and devel).",
    )
    p.add_argument(
        "--major",
        type=int,
        default=None,
        help="build/verify only this FreeBSD major (default: every BUILD-matrix row).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    repo = (args.repo or _default_repo()).resolve()
    build_leg_sh = repo / "scripts" / "build-leg.sh"
    matrix_cmd = args.matrix_cmd or [str(repo / "scripts" / "read-version-matrix.sh"), "--print-build"]
    out_dir = args.out.resolve()
    report_path = (args.report or (out_dir / "frozen-v3-report.json")).resolve()
    major_filter = str(args.major) if args.major is not None else None

    try:
        rows = validate_matrix(run_matrix_cmd(matrix_cmd, cwd=repo))
        plan = plan_artifacts(rows, target_filter=args.target, major_filter=major_filter)
        if not plan:
            raise MatrixError("nothing to do: --target/--major filters excluded every BUILD-matrix row")

        if args.verify_only is not None:
            report = verify_staged(
                args.verify_only.resolve(),
                plan,
                repo=repo,
                target_filter=args.target,
                major_filter=major_filter,
            )
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
            report = build_all(
                plan,
                repo=repo,
                build_leg_sh=build_leg_sh,
                out_dir=out_dir,
                ports_dir=args.ports_dir,
                do_determinism=not args.no_deterministic_check,
                target_filter=args.target,
                major_filter=major_filter,
            )

        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"build-frozen-v3.py: wrote {report_path} ({len(report['artifacts'])} artifact(s))", file=sys.stderr)
        return 0
    except (MatrixError, TagResolutionError, BuildLegError, ArtifactValidationError, DeterminismError) as e:
        print(f"build-frozen-v3.py: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
