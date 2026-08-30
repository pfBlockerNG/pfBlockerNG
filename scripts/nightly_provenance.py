"""Verified build records and publisher handoffs for stateless Nightly runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Mapping, Sequence

try:
    from scripts.pfb_pkg import (
        PkgError,
        build_input_digest,
        validate_build_matrix_row,
        validate_build_record,
        validate_dependency_builder,
    )
    from scripts.release_version import combined_nightly_input_digest, validate_nightly_version
except ImportError:  # script directory is also a direct import root
    from pfb_pkg import (
        PkgError,
        build_input_digest,
        validate_build_matrix_row,
        validate_build_record,
        validate_dependency_builder,
    )
    from release_version import combined_nightly_input_digest, validate_nightly_version


class ProvenanceError(ValueError):
    """Nightly build provenance or handoff is invalid."""


_ARTIFACT_FIELDS = {"abi", "name", "sha256"}
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ABI = re.compile(r"^FreeBSD:[0-9]+:(?:[A-Za-z0-9._+-]+|\*)$")
# Dependency .pkg filename (issue #2146 S1): printable-ASCII segment charset
# (excludes '/', '\\', control bytes incl. newline) ending in the literal
# ".pkg" suffix; ".." is rejected separately below (the charset alone would
# allow it mid-string, e.g. "a..pkg").
_DEP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\.pkg$")


def _exact_fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    keys = set(value)
    if keys != expected:
        raise ProvenanceError(
            f"{label} exact fields required (missing={sorted(expected - keys)}, unknown={sorted(keys - expected)})"
        )


def _validate_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ProvenanceError(f"{label} must be lowercase 40- or 64-character hex")
    return value


def _validate_ports_sha(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ProvenanceError("ports_sha must be lowercase 40-character hex")
    return value


def _validate_artifacts(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ProvenanceError("artifacts must be a non-empty list")
    artifacts: list[dict[str, str]] = []
    seen_abis: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ProvenanceError("artifact must be an object")
        _exact_fields(item, _ARTIFACT_FIELDS, "artifact")
        abi, name, digest = item["abi"], item["name"], item["sha256"]
        if not isinstance(abi, str) or not _ABI.fullmatch(abi):
            raise ProvenanceError("artifact.abi is malformed")
        if abi in seen_abis:
            raise ProvenanceError("artifact ABI entries must be unique")
        seen_abis.add(abi)
        if not isinstance(name, str) or not name or not name.isascii():
            raise ProvenanceError("artifact.name must be non-empty ASCII")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ProvenanceError("artifact.sha256 must be lowercase 64-character hex")
        artifacts.append({"abi": abi, "name": name, "sha256": digest})
    return sorted(artifacts, key=lambda item: item["abi"])


def _validate_dep_artifacts(value: object, *, leg_abi: str, canonical_name: str) -> list[dict[str, str]]:
    """Validate one BUILD leg's extra_pkgs dependency .pkgs (issue #2146 S1).

    Unlike _validate_artifacts (the canonical per-leg artifact, unique ABI
    ACROSS the whole handoff), a leg may ship zero or more dependency
    packages, all sharing that SAME leg's own wildcard ABI -- uniqueness here
    is per (abi, name) WITHIN this one leg only, never across the handoff (a
    different leg/major may legitimately carry a dep .pkg of the same name).
    Dep names come from build output filenames, so they are untrusted input:
    reject path separators, "..", control bytes, and anything not ending in
    the literal ".pkg" suffix.
    """
    if not isinstance(value, list):
        raise ProvenanceError("dep_artifacts must be a list")
    artifacts: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ProvenanceError("dep_artifacts entry must be an object")
        _exact_fields(item, _ARTIFACT_FIELDS, "dep_artifacts entry")
        abi, name, digest = item["abi"], item["name"], item["sha256"]
        if abi != leg_abi:
            raise ProvenanceError("dep_artifacts entry abi must match the leg's wildcard ABI")
        if not isinstance(name, str) or ".." in name or not _DEP_NAME.fullmatch(name):
            raise ProvenanceError("dep_artifacts entry name is unsafe or malformed")
        if name == canonical_name:
            raise ProvenanceError("dep_artifacts entry name must not equal the canonical artifact name")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ProvenanceError("dep_artifacts entry sha256 must be lowercase 64-character hex")
        key = (abi, name)
        if key in seen:
            raise ProvenanceError("dep_artifacts entries must be unique per (abi, name) within a leg")
        seen.add(key)
        artifacts.append({"abi": abi, "name": name, "sha256": digest})
    return sorted(artifacts, key=lambda item: item["name"])


def make_build_record(
    *,
    pkg_version: str,
    source_sha: str,
    ports_sha: str,
    matrix_row: Mapping[str, object],
    source_date_epoch: int,
    dependency_builder: Mapping[str, object],
) -> dict[str, object]:
    """Create one digest-bound portable-builder record for a Nightly leg."""
    try:
        validate_nightly_version(pkg_version, source_sha=source_sha)
        _validate_ports_sha(ports_sha)
        row = validate_build_matrix_row(dict(matrix_row))
    except (PkgError, TypeError, ValueError) as exc:
        raise ProvenanceError(str(exc)) from exc
    if type(source_date_epoch) is not int or source_date_epoch < 0:
        raise ProvenanceError("source_date_epoch must be a non-negative integer")
    major_minor = ".".join(str(row["pfsense_version"]).split(".")[:2])
    record: dict[str, object] = {
        "schema": 1,
        "channel": "nightly",
        "release_line": "nightly",
        "classification": "nightly",
        "source_tag": None,
        "source_sha": source_sha,
        "canonical_package_version": pkg_version,
        "native_recipe_identity": "pfSense-pkg-pfBlockerNG-nightly",
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": row,
        "freebsd_ports_sha": ports_sha,
        "route": f"nightly/{str(row['variant']).lower()}-{major_minor}",
        "source_date_epoch": source_date_epoch,
        "dependency_builder": validate_dependency_builder(dict(dependency_builder)),
        "build_input_digest": "",
    }
    record["build_input_digest"] = build_input_digest(record)
    try:
        return validate_build_record(record)
    except (PkgError, TypeError, ValueError) as exc:
        raise ProvenanceError(str(exc)) from exc


def build_handoff(
    *,
    pkg_version: str,
    build_rows: Sequence[Mapping[str, object]],
    route_rows: Sequence[Mapping[str, object]],
    results: Sequence[Mapping[str, object]],
    source_sha: str,
    ports_sha: str,
    tools_sha: str,
    matrix_sha: str,
    matrix_digest: str,
    dependency_builder: Mapping[str, object],
    source_date_epoch: int,
    run_id: str,
    source_ref: str = "",
    ports_repo: str = "",
    ports_ref: str = "",
) -> dict[str, object]:
    """Validate every matrix/build result and return publisher input."""
    try:
        validate_nightly_version(pkg_version, source_sha=source_sha)
        _validate_ports_sha(ports_sha)
    except ValueError as exc:
        raise ProvenanceError(str(exc)) from exc
    if not _SHA.fullmatch(tools_sha):
        raise ProvenanceError("handoff tools_sha is malformed")
    if not _SHA.fullmatch(matrix_sha):
        raise ProvenanceError("handoff matrix_sha is malformed")
    if not _DIGEST.fullmatch(matrix_digest):
        raise ProvenanceError("handoff matrix_digest is malformed")
    if type(source_date_epoch) is not int or source_date_epoch < 0:
        raise ProvenanceError("handoff source_date_epoch must be a non-negative integer")
    normalized_dependency_builder = validate_dependency_builder(dict(dependency_builder))
    handoff_inputs = json.dumps(
        {
            "matrix_digest": matrix_digest,
            "source_date_epoch": source_date_epoch,
            "dependency_builder": normalized_dependency_builder,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    input_digest = combined_nightly_input_digest(
        source_sha,
        ports_sha,
        hashlib.sha256(handoff_inputs).hexdigest(),
    )
    if not build_rows or not route_rows:
        raise ProvenanceError("BUILD and ROUTE matrices must not be empty")

    normalized_build_rows = [validate_build_matrix_row(dict(row)) for row in build_rows]
    normalized_route_rows: list[dict[str, object]] = []
    for raw_row in route_rows:
        route_row = dict(raw_row)
        role = route_row.get("role")
        ci = route_row.pop("ci", None)
        if ci is not None and type(ci) is not bool:
            raise ProvenanceError("ROUTE matrix ci must be boolean")
        if role == "route-only":
            del route_row["role"]
        normalized = validate_build_matrix_row(route_row)
        if role is not None:
            normalized["role"] = role
        if ci is not None:
            normalized["ci"] = ci
        normalized_route_rows.append(normalized)
    # issue #2926: build identity is the exact runtime tuple (freebsd_major,
    # php_version, py_flavor) — the same key the pfBlockerNG/pkg Nightly
    # consumer uses. Identical tuples are one build target; same-major rows
    # with a differing php/py stay separate. Duplicate EXACT tuples reject.
    expected_rows = {
        (str(row["freebsd_major"]), str(row["php_version"]), str(row["py_flavor"])): row
        for row in normalized_build_rows
    }
    if len(expected_rows) != len(normalized_build_rows):
        raise ProvenanceError("BUILD matrix contains duplicate build tuples")
    if len(results) != len(expected_rows):
        raise ProvenanceError("BUILD result count does not match BUILD matrix")

    builds: list[dict[str, object]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for result in results:
        if not isinstance(result, dict):
            raise ProvenanceError("BUILD result must be an object")
        if set(result) != {"matrix_row", "record", "artifact", "dep_artifacts"}:
            raise ProvenanceError("BUILD result has unexpected fields")
        row = validate_build_matrix_row(dict(result["matrix_row"]))
        key = (str(row["freebsd_major"]), str(row["php_version"]), str(row["py_flavor"]))
        if key in seen_keys or expected_rows.get(key) != row:
            raise ProvenanceError("BUILD result row is missing, duplicated, or changed")
        record = validate_build_record(result["record"], abi=f"FreeBSD:{row['freebsd_major']}:amd64")
        if record["matrix_row"] != row:
            raise ProvenanceError("build record matrix row does not match BUILD result")
        if (
            record["canonical_package_version"] != pkg_version
            or record["source_sha"] != source_sha
            or record["freebsd_ports_sha"] != ports_sha
            or record["dependency_builder"] != normalized_dependency_builder
            or record["source_date_epoch"] != source_date_epoch
        ):
            raise ProvenanceError("BUILD result provenance does not match Nightly snapshot")
        artifact = _validate_artifacts([result["artifact"]])[0]
        if artifact["name"] != f"pfSense-pkg-pfBlockerNG-{pkg_version}.pkg":
            raise ProvenanceError("BUILD artifact name does not match Nightly snapshot")
        dep_artifacts = _validate_dep_artifacts(
            result["dep_artifacts"],
            leg_abi=f"FreeBSD:{key[0]}:*",
            canonical_name=artifact["name"],
        )
        # issue #2405: empty extra_pkgs still requires dep_artifacts == []
        expected_deps = len(row.get("extra_pkgs") or [])
        if len(dep_artifacts) != expected_deps:
            raise ProvenanceError(
                f"dep_artifacts count must match extra_pkgs (got {len(dep_artifacts)}, expected {expected_deps})"
            )
        seen_keys.add(key)
        builds.append({"matrix_row": row, "record": record, "artifact": artifact, "dep_artifacts": dep_artifacts})
    if seen_keys != set(expected_rows):
        raise ProvenanceError("BUILD results do not cover every BUILD matrix row")

    route_keys: set[tuple[object, object]] = set()
    for row in normalized_route_rows:
        key = (row["variant"], row["pfsense_version"])
        if key in route_keys:
            raise ProvenanceError("ROUTE matrix contains duplicate version identity")
        route_keys.add(key)

    return {
        "schema": 1,
        "kind": "nightly-handoff",
        "run_id": run_id,
        "source_ref": source_ref,
        "ports_repo": ports_repo,
        "ports_ref": ports_ref,
        "pkg_version": pkg_version,
        "input_digest": input_digest,
        "source_sha": source_sha,
        "ports_sha": ports_sha,
        "tools_sha": tools_sha,
        "matrix_sha": matrix_sha,
        "matrix_digest": matrix_digest,
        "source_date_epoch": source_date_epoch,
        "dependency_builder": normalized_dependency_builder,
        "build_matrix": normalized_build_rows,
        "route_matrix": normalized_route_rows,
        "builds": sorted(
            builds,
            key=lambda item: (
                str(item["matrix_row"]["freebsd_major"]),
                str(item["matrix_row"]["php_version"]),
                str(item["matrix_row"]["py_flavor"]),
            ),
        ),
    }


def _read_json(path: Path, *, default: object | None = None) -> object:
    if not path.exists():
        if default is not None:
            return default
        raise ProvenanceError(f"missing JSON file: {path}")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ProvenanceError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"invalid JSON file {path}: {exc}") from exc


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _command_record(args: argparse.Namespace) -> int:
    row_raw = _read_json(Path(args.matrix_row))
    if not isinstance(row_raw, dict):
        raise ProvenanceError("matrix row JSON is malformed")
    record = make_build_record(
        pkg_version=args.pkg_version,
        source_sha=args.source_sha,
        ports_sha=args.ports_sha,
        matrix_row=row_raw,
        source_date_epoch=args.source_date_epoch,
        dependency_builder=_read_json(Path(args.dependency_builder)),
    )
    _write_json(Path(args.output), record)
    return 0


def _command_handoff(args: argparse.Namespace) -> int:
    build_rows = _read_json(Path(args.build_matrix))
    route_rows = _read_json(Path(args.route_matrix))
    if not isinstance(build_rows, list) or not isinstance(route_rows, list):
        raise ProvenanceError("matrix JSON must be arrays")
    result_dir = Path(args.results_dir)
    result_values: list[Mapping[str, object]] = []
    for result_path in sorted(result_dir.glob("*/result.json")):
        result = _read_json(result_path)
        if not isinstance(result, dict):
            raise ProvenanceError(f"malformed BUILD result: {result_path}")
        result_values.append(result)
    handoff = build_handoff(
        pkg_version=args.pkg_version,
        build_rows=build_rows,
        route_rows=route_rows,
        results=result_values,
        source_sha=args.source_sha,
        ports_sha=args.ports_sha,
        tools_sha=args.tools_sha,
        matrix_sha=args.matrix_sha,
        matrix_digest=args.matrix_digest,
        dependency_builder=_read_json(Path(args.dependency_builder)),
        source_date_epoch=args.source_date_epoch,
        run_id=args.run_id,
        source_ref=args.source_ref,
        ports_repo=args.ports_repo,
        ports_ref=args.ports_ref,
    )
    _write_json(Path(args.output), handoff)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--pkg-version", required=True)
    record_parser.add_argument("--source-sha", required=True)
    record_parser.add_argument("--ports-sha", required=True)
    record_parser.add_argument("--matrix-row", required=True)
    record_parser.add_argument("--source-date-epoch", required=True, type=int)
    record_parser.add_argument("--dependency-builder", required=True)
    record_parser.add_argument("--output", required=True)
    record_parser.set_defaults(handler=_command_record)
    handoff_parser = subparsers.add_parser("handoff")
    handoff_parser.add_argument("--pkg-version", required=True)
    handoff_parser.add_argument("--build-matrix", required=True)
    handoff_parser.add_argument("--route-matrix", required=True)
    handoff_parser.add_argument("--results-dir", required=True)
    handoff_parser.add_argument("--source-sha", required=True)
    handoff_parser.add_argument("--ports-sha", required=True)
    handoff_parser.add_argument("--tools-sha", required=True)
    handoff_parser.add_argument("--matrix-sha", required=True)
    handoff_parser.add_argument("--matrix-digest", required=True)
    handoff_parser.add_argument("--dependency-builder", required=True)
    handoff_parser.add_argument("--source-date-epoch", required=True, type=int)
    handoff_parser.add_argument("--run-id", required=True)
    handoff_parser.add_argument("--source-ref", default="")
    handoff_parser.add_argument("--ports-repo", default="")
    handoff_parser.add_argument("--ports-ref", default="")
    handoff_parser.add_argument("--output", required=True)
    handoff_parser.set_defaults(handler=_command_handoff)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, PkgError, ProvenanceError, TypeError, ValueError) as exc:
        print(f"nightly provenance: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
