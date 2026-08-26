#!/usr/bin/env python3
"""Create and validate the immutable tagged-release publisher handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

try:
    from scripts.pfb_pkg import (
        CANONICAL_EMITTED_IDENTITY,
        PFB_BUILD_RECORD_KEY,
        PkgError,
        inspect_pkg,
        load_build_record,
        read_compact_manifest,
        validate_build_matrix_row,
        validate_dependency_builder,
    )
except ImportError:
    from pfb_pkg import (
        CANONICAL_EMITTED_IDENTITY,
        PFB_BUILD_RECORD_KEY,
        PkgError,
        inspect_pkg,
        load_build_record,
        read_compact_manifest,
        validate_build_matrix_row,
        validate_dependency_builder,
    )

_GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RELEASE_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:\.[abr][1-9][0-9]*)?$")
_FIELDS = {
    "schema",
    "kind",
    "release_tag",
    "source_sha",
    "ci_metadata_sha",
    "ports_sha",
    "source_date_epoch",
    "dependency_builder",
    "route_matrix",
    "dependency_packages",
}
_DEP_BUILD_RECORD_KEY = "pfb_dep_build_record"
_DEP_RECORD_FIELDS = {
    "schema",
    "freebsd_ports_sha",
    "port_origin",
    "port_version",
    "distfile",
    "distfile_sha256",
    "distfile_size",
    "py_flavor",
    "freebsd_major",
    "abi",
    "source_date_epoch",
    "toolchain",
}
_DEP_IDENTITY_FIELDS = (
    "portname",
    "port_version",
    "distfile",
    "distfile_sha256",
    "distfile_size",
    "package_name",
    "package_version",
    "filename",
    "freebsd_ports_sha",
    "source_date_epoch",
    "toolchain",
    "abi",
    "freebsd_major",
    "py_flavor",
)
_DEP_COMPACT_MANIFEST_FIELDS = {
    "name",
    "origin",
    "version",
    "comment",
    "maintainer",
    "www",
    "abi",
    "arch",
    "prefix",
    "flatsize",
    "licenselogic",
    "licenses",
    "desc",
    "categories",
    "deps",
    "annotations",
}
_DEP_FULL_MANIFEST_FIELDS = _DEP_COMPACT_MANIFEST_FIELDS | {"files"}
_ORIGIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*/[A-Za-z0-9][A-Za-z0-9+_.-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class HandoffError(ValueError):
    """The tagged release handoff is absent, malformed, or inconsistent."""


def _git_sha(value: object, name: str) -> str:
    if not isinstance(value, str) or not _GIT_SHA_RE.fullmatch(value):
        raise HandoffError(f"{name} must be lowercase 40- or 64-character hex")
    return value


def _ports_sha(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise HandoffError("ports_sha must be lowercase 40-character hex")
    return value


def _route_matrix(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise HandoffError("route_matrix must be a non-empty JSON array")
    normalized: list[dict[str, object]] = []
    try:
        for raw_row in value:
            if not isinstance(raw_row, Mapping):
                raise HandoffError("route_matrix rows must be JSON objects")
            route_row = dict(raw_row)
            ci = route_row.pop("ci", None)
            if ci is not None and type(ci) is not bool:
                raise HandoffError("route_matrix row ci must be boolean")
            role = route_row.get("role")
            if role == "route-only":
                del route_row["role"]
            row = validate_build_matrix_row(route_row)
            if role == "route-only":
                row["role"] = role
            if ci is not None:
                row["ci"] = ci
            normalized.append(row)
    except PkgError as exc:
        raise HandoffError(str(exc)) from exc
    return normalized


def _dependency_packages(
    value: object,
    rows: Sequence[Mapping[str, object]],
    *,
    ports_sha: str,
    source_date_epoch: int,
    dependency_builder: Mapping[str, str],
) -> dict[str, dict[str, dict[str, object]]]:
    if not isinstance(value, Mapping):
        raise HandoffError("dependency_packages must be an object")
    required: dict[str, tuple[Mapping[str, object], list[str]]] = {}
    for index, row in enumerate(rows):
        origins = row.get("extra_pkgs")
        if not isinstance(origins, list):
            raise HandoffError(f"route_matrix row {index} extra_pkgs must be an array")
        suffix = f"-{row['variant']}-{row['pfsense_version']}.pkg"
        if origins:
            if suffix in required:
                raise HandoffError(f"route_matrix has duplicate dependency asset suffix {suffix}")
            for origin in origins:
                if not isinstance(origin, str) or not _ORIGIN_RE.fullmatch(origin):
                    raise HandoffError(f"route_matrix row {index} extra_pkgs contains a malformed origin")
            required[suffix] = (row, origins)
    if set(value) != set(required):
        raise HandoffError("dependency_packages must exactly match ROUTE dependency asset suffixes")

    normalized: dict[str, dict[str, dict[str, object]]] = {}
    for suffix, (row, origins) in required.items():
        identities = value[suffix]
        if not isinstance(identities, Mapping) or set(identities) != set(origins):
            raise HandoffError(f"dependency_packages[{suffix!r}] must exactly match ROUTE extra_pkgs origins")
        normalized[suffix] = {}
        for origin in origins:
            identity = identities[origin]
            label = f"dependency_packages[{suffix!r}][{origin!r}]"
            if not isinstance(identity, Mapping) or set(identity) != set(_DEP_IDENTITY_FIELDS):
                raise HandoffError(f"{label} exact fields required")
            portname = identity["portname"]
            port_version = identity["port_version"]
            distfile = identity["distfile"]
            distfile_sha256 = identity["distfile_sha256"]
            distfile_size = identity["distfile_size"]
            if not isinstance(portname, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]*", portname):
                raise HandoffError(f"{label}.portname is malformed")
            if not isinstance(port_version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]*", port_version):
                raise HandoffError(f"{label}.port_version is malformed")
            if (
                not isinstance(distfile, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*\.tar\.gz", distfile)
                or port_version not in distfile
            ):
                raise HandoffError(f"{label}.distfile is malformed")
            if not isinstance(distfile_sha256, str) or not _SHA256_RE.fullmatch(distfile_sha256):
                raise HandoffError(f"{label}.distfile_sha256 is malformed")
            if type(distfile_size) is not int or distfile_size <= 0:
                raise HandoffError(f"{label}.distfile_size is malformed")

            package_name = f"{row['py_flavor']}-{portname}"
            expected = {
                "package_name": package_name,
                "package_version": port_version,
                "filename": f"{package_name}-{port_version}{suffix}",
                "freebsd_ports_sha": ports_sha,
                "source_date_epoch": source_date_epoch,
                "toolchain": dependency_builder,
                "abi": f"FreeBSD:{row['freebsd_major']}:*",
                "freebsd_major": row["freebsd_major"],
                "py_flavor": row["py_flavor"],
            }
            for field, expected_value in expected.items():
                if identity[field] != expected_value:
                    raise HandoffError(f"{label}.{field} does not match tagged release handoff")
            normalized[suffix][origin] = dict(identity)
    return normalized


def build_handoff(
    *,
    release_tag: str,
    source_sha: str,
    ci_metadata_sha: str,
    ports_sha: str,
    route_matrix: object,
    dependency_packages: object,
    source_date_epoch: int,
    dependency_builder: object,
) -> dict[str, object]:
    """Build the canonical handoff attached to a draft tagged release."""
    if not isinstance(release_tag, str) or not _RELEASE_TAG_RE.fullmatch(release_tag):
        raise HandoffError("release_tag is malformed")
    source_sha = _git_sha(source_sha, "source_sha")
    ci_metadata_sha = _git_sha(ci_metadata_sha, "ci_metadata_sha")
    ports_sha = _ports_sha(ports_sha)
    rows = _route_matrix(route_matrix)
    if type(source_date_epoch) is not int or source_date_epoch < 0:
        raise HandoffError("source_date_epoch must be a non-negative integer")
    try:
        normalized_dependency_builder = validate_dependency_builder(dependency_builder)
    except PkgError as exc:
        raise HandoffError(str(exc)) from exc
    normalized_dependency_packages = _dependency_packages(
        dependency_packages,
        rows,
        ports_sha=ports_sha,
        source_date_epoch=source_date_epoch,
        dependency_builder=normalized_dependency_builder,
    )
    return {
        "schema": 1,
        "kind": "tagged-release-handoff",
        "release_tag": release_tag,
        "source_sha": source_sha,
        "ci_metadata_sha": ci_metadata_sha,
        "ports_sha": ports_sha,
        "source_date_epoch": source_date_epoch,
        "dependency_builder": normalized_dependency_builder,
        "route_matrix": rows,
        "dependency_packages": normalized_dependency_packages,
    }


def load_handoff(
    path: str | Path,
    *,
    expected_release_tag: str,
    expected_source_sha: str,
) -> dict[str, object]:
    """Load a handoff and bind it to the selected Release tag and source commit."""
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise HandoffError(f"cannot read tagged release handoff {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise HandoffError(f"tagged release handoff is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise HandoffError("tagged release handoff must be a JSON object")
    if set(raw) != _FIELDS:
        raise HandoffError("tagged release handoff has unexpected fields")
    if type(raw["schema"]) is not int or raw["schema"] != 1 or raw["kind"] != "tagged-release-handoff":
        raise HandoffError("tagged release handoff schema or kind is unsupported")

    validated = build_handoff(
        release_tag=raw["release_tag"],
        source_sha=raw["source_sha"],
        ci_metadata_sha=raw["ci_metadata_sha"],
        ports_sha=raw["ports_sha"],
        route_matrix=raw["route_matrix"],
        dependency_packages=raw["dependency_packages"],
        source_date_epoch=raw["source_date_epoch"],
        dependency_builder=raw["dependency_builder"],
    )
    if validated["release_tag"] != expected_release_tag:
        raise HandoffError("release_tag does not match the selected Release")
    if validated["source_sha"] != _git_sha(expected_source_sha, "expected source_sha"):
        raise HandoffError("source_sha does not match the selected Release tag")
    return validated


def validate_build_records(handoff: Mapping[str, object], records: Sequence[Mapping[str, object]]) -> None:
    """Require every canonical package record to carry the handoff identities."""
    if not records:
        raise HandoffError("tagged release has no canonical build records")
    expected = {
        "source_tag": handoff.get("release_tag"),
        "source_sha": handoff.get("source_sha"),
        "freebsd_ports_sha": handoff.get("ports_sha"),
        "source_date_epoch": handoff.get("source_date_epoch"),
        "dependency_builder": handoff.get("dependency_builder"),
    }
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise HandoffError(f"build record {index} must be an object")
        for name, value in expected.items():
            if record.get(name) != value:
                raise HandoffError(f"build record {index} {name} does not match tagged release handoff")


def _dependency_requirements(
    handoff: Mapping[str, object],
) -> tuple[
    dict[tuple[str, str], tuple[Mapping[str, object], Mapping[str, object]]],
    dict[str, Mapping[str, object]],
]:
    rows = handoff.get("route_matrix")
    dependency_packages = handoff.get("dependency_packages")
    if not isinstance(rows, list) or not isinstance(dependency_packages, Mapping):
        raise HandoffError("tagged release handoff dependency requirements are malformed")
    requirements: dict[tuple[str, str], tuple[Mapping[str, object], Mapping[str, object]]] = {}
    rows_by_suffix: dict[str, Mapping[str, object]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise HandoffError(f"route_matrix row {index} must be an object")
        values = {field: row.get(field) for field in ("variant", "pfsense_version", "freebsd_major", "py_flavor")}
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise HandoffError(f"route_matrix row {index} dependency identity is malformed")
        suffix = f"-{values['variant']}-{values['pfsense_version']}.pkg"
        if suffix in rows_by_suffix:
            raise HandoffError(f"route_matrix has duplicate dependency asset suffix {suffix}")
        rows_by_suffix[suffix] = row
        origins = row.get("extra_pkgs")
        if not isinstance(origins, list):
            raise HandoffError(f"route_matrix row {index} extra_pkgs must be an array")
        identities = dependency_packages.get(suffix, {})
        if not isinstance(identities, Mapping):
            raise HandoffError(f"dependency_packages[{suffix!r}] is malformed")
        for origin in origins:
            if not isinstance(origin, str) or not _ORIGIN_RE.fullmatch(origin):
                raise HandoffError(f"route_matrix row {index} extra_pkgs contains a malformed origin")
            identity = identities.get(origin)
            if not isinstance(identity, Mapping):
                raise HandoffError(f"dependency_packages[{suffix!r}][{origin!r}] is missing")
            key = (suffix, origin)
            if key in requirements:
                raise HandoffError(f"route_matrix has duplicate dependency requirement {origin}{suffix}")
            requirements[key] = (row, identity)
    return requirements, rows_by_suffix


def _dependency_record(package: Path, manifest: Mapping[str, object]) -> dict[str, object]:
    annotations = manifest.get("annotations")
    if not isinstance(annotations, Mapping):
        raise HandoffError(f"{package.name}: dependency package annotations are missing")
    annotation = annotations.get(_DEP_BUILD_RECORD_KEY)
    if not isinstance(annotation, str):
        raise HandoffError(f"{package.name}: dependency package build record annotation is missing")
    if set(annotations) != {_DEP_BUILD_RECORD_KEY}:
        raise HandoffError(f"{package.name}: dependency package exact annotation keys required")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        record = json.loads(annotation, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HandoffError(f"{package.name}: dependency package build record is malformed: {exc}") from None
    if not isinstance(record, dict) or set(record) != _DEP_RECORD_FIELDS:
        raise HandoffError(f"{package.name}: dependency package build record exact fields required")
    if record["schema"] != 1 or type(record["schema"]) is not int:
        raise HandoffError(f"{package.name}: dependency package build record schema is malformed")
    for field in ("port_origin", "port_version", "distfile", "py_flavor", "freebsd_major", "abi"):
        if not isinstance(record[field], str) or not record[field]:
            raise HandoffError(f"{package.name}: dependency package build record {field} is malformed")
    if not _ORIGIN_RE.fullmatch(record["port_origin"]):
        raise HandoffError(f"{package.name}: dependency package build record port_origin is malformed")
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*\.tar\.gz", record["distfile"])
        or record["port_version"] not in record["distfile"]
    ):
        raise HandoffError(f"{package.name}: dependency package build record distfile identity is malformed")
    if not isinstance(record["distfile_sha256"], str) or not _SHA256_RE.fullmatch(record["distfile_sha256"]):
        raise HandoffError(f"{package.name}: dependency package build record distfile_sha256 is malformed")
    if type(record["distfile_size"]) is not int or record["distfile_size"] <= 0:
        raise HandoffError(f"{package.name}: dependency package build record distfile_size is malformed")
    if type(record["source_date_epoch"]) is not int or record["source_date_epoch"] < 0:
        raise HandoffError(f"{package.name}: dependency package build record source_date_epoch is malformed")
    try:
        record["toolchain"] = validate_dependency_builder(record["toolchain"])
    except PkgError as exc:
        raise HandoffError(f"{package.name}: dependency package build record toolchain: {exc}") from exc
    expected_annotation = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if annotation != expected_annotation:
        raise HandoffError(f"{package.name}: dependency package build record is not canonical JSON")
    return record


def _validate_dependency_package(
    package: Path,
    compact: Mapping[str, object],
    record: Mapping[str, object],
    row: Mapping[str, object],
    identity: Mapping[str, object],
) -> None:
    evidence = inspect_pkg(package)
    manifest = evidence["manifest"]
    payload = evidence["payload"]
    member_info = evidence["member_info"]
    if not isinstance(manifest, dict) or not isinstance(payload, dict) or not isinstance(member_info, dict):
        raise HandoffError(f"{package.name}: dependency package inspection evidence is malformed")
    if set(compact) != _DEP_COMPACT_MANIFEST_FIELDS:
        raise HandoffError(
            f"{package.name}: dependency package compact/full manifest exact compact fields required; "
            f"got {sorted(compact)}"
        )
    if set(manifest) != _DEP_FULL_MANIFEST_FIELDS:
        raise HandoffError(
            f"{package.name}: dependency package compact/full manifest exact full fields required; "
            f"got {sorted(manifest)}"
        )
    compact_from_full = {key: value for key, value in manifest.items() if key != "files"}
    if compact != compact_from_full:
        raise HandoffError(f"{package.name}: dependency package compact/full manifest mismatch")
    expected = {
        "freebsd_ports_sha": identity["freebsd_ports_sha"],
        "source_date_epoch": identity["source_date_epoch"],
        "toolchain": identity["toolchain"],
        "freebsd_major": identity["freebsd_major"],
        "py_flavor": identity["py_flavor"],
        "abi": identity["abi"],
        "port_version": identity["port_version"],
        "distfile": identity["distfile"],
        "distfile_sha256": identity["distfile_sha256"],
        "distfile_size": identity["distfile_size"],
    }
    for field, value in expected.items():
        if record[field] != value:
            raise HandoffError(f"{package.name}: dependency package build record {field} does not match route handoff")
    name = compact.get("name")
    version = compact.get("version")
    if name != identity["package_name"]:
        raise HandoffError(f"{package.name}: dependency package name does not match route handoff")
    if version != identity["package_version"] or version != record["port_version"]:
        raise HandoffError(f"{package.name}: dependency package version does not match route handoff")
    if package.name != identity["filename"]:
        raise HandoffError(f"{package.name}: dependency package filename must be {identity['filename']}")
    if compact.get("origin") != record["port_origin"]:
        raise HandoffError(f"{package.name}: dependency package origin does not match build record port_origin")
    if compact.get("abi") != identity["abi"] or compact.get("arch") != f"freebsd:{row['freebsd_major']}:*":
        raise HandoffError(f"{package.name}: dependency package manifest ABI/arch does not match route")
    py_digits = str(identity["py_flavor"])[2:]
    dependency_name = f"python{py_digits}"
    dependencies = compact.get("deps")
    dependency = dependencies.get(dependency_name) if isinstance(dependencies, Mapping) else None
    if (
        not isinstance(dependencies, Mapping)
        or set(dependencies) != {dependency_name}
        or not isinstance(dependency, Mapping)
        or set(dependency) != {"origin", "version"}
        or dependency["origin"] != f"lang/{dependency_name}"
        or not isinstance(dependency["version"], str)
        or not dependency["version"]
    ):
        raise HandoffError(f"{package.name}: dependency package runtime dependencies are malformed")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or set(files) != set(payload):
        raise HandoffError(f"{package.name}: dependency package payload inventory differs from manifest")
    for path, entry in files.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(entry, dict):
            raise HandoffError(f"{package.name}: dependency package manifest file entry is malformed")
        data = payload[path]
        checksum = entry.get("sum")
        if (
            not isinstance(data, bytes)
            or not isinstance(checksum, str)
            or not re.fullmatch(r"1\$[0-9a-f]{64}", checksum)
        ):
            raise HandoffError(f"{package.name}: dependency package checksum for {path} is malformed")
        if checksum[2:] != hashlib.sha256(data).hexdigest():
            raise HandoffError(f"{package.name}: dependency package checksum mismatch for {path}")
        member = member_info[path]
        required_fields = {"sum", "uname", "gname", "perm", "fflags", "mtime"}
        if not required_fields.issubset(entry) or set(entry) - required_fields - {"size"}:
            raise HandoffError(f"{package.name}: dependency package manifest metadata for {path} is malformed")
        perm = entry["perm"]
        mtime = entry["mtime"]
        size = entry.get("size")
        if (
            entry["uname"] != "root"
            or entry["gname"] != "wheel"
            or entry["fflags"] != 0
            or not isinstance(perm, str)
            or not re.fullmatch(r"0[0-7]{3}", perm)
            or type(mtime) is not int
            or ("size" in entry and type(size) is not int)
        ):
            raise HandoffError(f"{package.name}: dependency package manifest metadata for {path} is malformed")
        mode = int(perm, 8)
        expected_mode = 0o555 if path.startswith("/usr/local/bin/") else 0o644
        if (
            member.uid != 0
            or member.gid != 0
            or member.uname != "root"
            or member.gname != "wheel"
            or member.mode != mode
            or mode != expected_mode
            or int(member.mtime) != mtime
            or mtime != identity["source_date_epoch"]
            or member.size != len(data)
            or ("size" in entry and size != len(data))
        ):
            raise HandoffError(
                f"{package.name}: dependency package manifest metadata for {path} does not match handoff"
            )


def validate_packages(handoff: Mapping[str, object], packages: Sequence[str | Path]) -> None:
    """Validate canonical and required dependency package outputs against the handoff."""
    records: list[Mapping[str, object]] = []
    requirements, rows_by_suffix = _dependency_requirements(handoff)
    seen_dependencies: set[tuple[str, str]] = set()
    seen_canonical: set[str] = set()
    try:
        for raw_package in packages:
            package = Path(raw_package)
            manifest = read_compact_manifest(package)
            if manifest.get("name") == CANONICAL_EMITTED_IDENTITY:
                suffixes = [suffix for suffix in rows_by_suffix if package.name.endswith(suffix)]
                if len(suffixes) != 1:
                    raise HandoffError(f"{package.name}: canonical package filename does not match one route row")
                suffix = suffixes[0]
                annotations = manifest.get("annotations")
                if not isinstance(annotations, Mapping):
                    raise HandoffError(f"{package.name}: package annotations are missing")
                annotation = annotations.get(PFB_BUILD_RECORD_KEY)
                if not isinstance(annotation, str):
                    raise HandoffError(f"{package.name}: package build record annotation is missing")
                record = load_build_record(annotation)
                row = rows_by_suffix[suffix]
                record_row = record["matrix_row"]
                expected_filename = (
                    f"{CANONICAL_EMITTED_IDENTITY}-{record['canonical_package_version']}"
                    f"-{row['variant']}-{row['pfsense_version']}.pkg"
                )
                if package.name != expected_filename:
                    raise HandoffError(f"{package.name}: canonical package filename must be {expected_filename}")
                if (
                    not isinstance(record_row, Mapping)
                    or record_row.get("variant") != row["variant"]
                    or record_row.get("pfsense_version") != row["pfsense_version"]
                ):
                    raise HandoffError(f"{package.name}: canonical package matrix row does not match route handoff")
                if suffix in seen_canonical:
                    raise HandoffError(f"{package.name}: duplicate canonical package for route row {suffix}")
                seen_canonical.add(suffix)
                records.append(record)
                continue
            suffixes = [suffix for suffix in rows_by_suffix if package.name.endswith(suffix)]
            if len(suffixes) != 1:
                raise HandoffError(f"{package.name}: dependency package filename does not match one route row")
            suffix = suffixes[0]
            record = _dependency_record(package, manifest)
            origin = str(record["port_origin"])
            key = (suffix, origin)
            requirement = requirements.get(key)
            if requirement is None:
                raise HandoffError(f"{package.name}: unrequested dependency package {origin}")
            row, identity = requirement
            _validate_dependency_package(package, manifest, record, row, identity)
            if key in seen_dependencies:
                raise HandoffError(f"{package.name}: duplicate dependency package {origin}{suffix}")
            seen_dependencies.add(key)
    except PkgError as exc:
        raise HandoffError(str(exc)) from exc
    missing = sorted(set(requirements) - seen_dependencies)
    if missing:
        raise HandoffError(f"missing dependency assets: {missing}")
    validate_build_records(handoff, records)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-metadata-sha", required=True)
    parser.add_argument("--ports-sha", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--dependency-builder", required=True, type=Path)
    parser.add_argument("--route-matrix", required=True, type=Path)
    parser.add_argument("--dependency-packages", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def _parse_validation_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate tagged handoff package outputs")
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("packages", nargs="+", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if arguments[:1] == ["validate-packages"]:
            args = _parse_validation_args(arguments[1:])
            handoff = load_handoff(
                args.handoff,
                expected_release_tag=args.release_tag,
                expected_source_sha=args.source_sha,
            )
            validate_packages(handoff, args.packages)
        else:
            args = _parse_args(arguments)
            route_matrix = json.loads(args.route_matrix.read_text(encoding="utf-8"))
            dependency_builder = json.loads(args.dependency_builder.read_text(encoding="utf-8"))
            dependency_packages = json.loads(args.dependency_packages.read_text(encoding="utf-8"))
            handoff = build_handoff(
                release_tag=args.release_tag,
                source_sha=args.source_sha,
                ci_metadata_sha=args.ci_metadata_sha,
                ports_sha=args.ports_sha,
                route_matrix=route_matrix,
                dependency_packages=dependency_packages,
                source_date_epoch=args.source_date_epoch,
                dependency_builder=dependency_builder,
            )
            args.output.write_text(
                json.dumps(handoff, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
    except (OSError, json.JSONDecodeError, HandoffError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
