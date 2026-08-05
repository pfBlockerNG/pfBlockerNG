"""Durable allocation and verified handoff state for branch-independent Nightly."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, replace
from datetime import date
from pathlib import Path
from typing import Mapping, Sequence

try:
    from scripts.pfb_pkg import PkgError, build_input_digest, validate_build_matrix_row, validate_build_record
    from scripts.release_version import (
        NightlyAllocation,
        allocate_nightly,
        combined_nightly_input_digest,
        validate_nightly_allocation,
    )
except ImportError:  # script directory is also a direct import root
    from pfb_pkg import PkgError, build_input_digest, validate_build_matrix_row, validate_build_record
    from release_version import (
        NightlyAllocation,
        allocate_nightly,
        combined_nightly_input_digest,
        validate_nightly_allocation,
    )


class ProvenanceError(ValueError):
    """Durable Nightly state or completion is invalid."""


_STATE_FIELDS = {"schema", "generation", "records"}
_RECORD_FIELDS = {"allocation", "artifacts", "run_id"}
_ALLOCATION_FIELDS = {
    "outcome",
    "portversion",
    "portrevision",
    "pkg_version",
    "source_sha",
    "ports_sha",
    "input_digest",
}
_ARTIFACT_FIELDS = {"abi", "name", "sha256"}
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ABI = re.compile(r"^FreeBSD:[0-9]+:(?:[A-Za-z0-9._+-]+|\*)$")


@dataclass(frozen=True)
class Candidate:
    allocation: NightlyAllocation
    generation: int


def empty_state() -> dict[str, object]:
    """Return an empty, versioned provenance state."""
    return {"schema": 1, "generation": 0, "records": []}


def replace_allocation(allocation: NightlyAllocation, **changes: object) -> NightlyAllocation:
    """Return a test- and tooling-friendly changed allocation."""
    return replace(allocation, **changes)


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


def _validate_allocation(value: object) -> NightlyAllocation:
    if not isinstance(value, dict):
        raise ProvenanceError("record allocation must be an object")
    _exact_fields(value, _ALLOCATION_FIELDS, "allocation")
    try:
        allocation = NightlyAllocation(**value)
    except (TypeError, ValueError) as exc:
        raise ProvenanceError(f"invalid allocation: {exc}") from exc
    try:
        validate_nightly_allocation(allocation)
    except (TypeError, ValueError) as exc:
        raise ProvenanceError(f"invalid allocation: {exc}") from exc
    if allocation.outcome != "build":
        raise ProvenanceError("durable records may contain only build allocations")
    return allocation


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


def validate_state(state: object) -> dict[str, object]:
    """Validate and normalize durable state without changing its values."""
    if not isinstance(state, dict):
        raise ProvenanceError("state must be an object")
    _exact_fields(state, _STATE_FIELDS, "state")
    if state["schema"] != 1:
        raise ProvenanceError("state schema must be 1")
    generation = state["generation"]
    if type(generation) is not int or generation < 0:
        raise ProvenanceError("state generation must be a non-negative integer")
    records = state["records"]
    if not isinstance(records, list) or generation != len(records):
        raise ProvenanceError("state generation must equal record count")

    normalized_records: list[dict[str, object]] = []
    identities: set[tuple[str, str, str]] = set()
    versions: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ProvenanceError("state record must be an object")
        _exact_fields(record, _RECORD_FIELDS, "record")
        allocation = _validate_allocation(record["allocation"])
        artifacts = _validate_artifacts(record["artifacts"])
        run_id = record["run_id"]
        if not isinstance(run_id, str) or not run_id or len(run_id) > 128 or not run_id.isascii():
            raise ProvenanceError("record.run_id must be non-empty ASCII of at most 128 characters")
        identity = (allocation.source_sha, allocation.ports_sha, allocation.input_digest)
        if identity in identities:
            raise ProvenanceError("duplicate Nightly input identity")
        if allocation.pkg_version in versions:
            raise ProvenanceError("Nightly version collision")
        identities.add(identity)
        versions.add(allocation.pkg_version)
        normalized_records.append({"allocation": asdict(allocation), "artifacts": artifacts, "run_id": run_id})
    return {"schema": 1, "generation": generation, "records": normalized_records}


def _allocations(state: Mapping[str, object]) -> tuple[NightlyAllocation, ...]:
    records = state["records"]
    assert isinstance(records, list)
    return tuple(_validate_allocation(record["allocation"]) for record in records if isinstance(record, dict))


def allocate_candidate(
    state: Mapping[str, object],
    *,
    build_date: date,
    source_sha: str,
    ports_sha: str,
    matrix_digest: str,
) -> Candidate:
    """Allocate from durable state, returning an unchanged candidate for a no-op."""
    normalized = validate_state(dict(state))
    if not isinstance(matrix_digest, str) or not _DIGEST.fullmatch(matrix_digest):
        raise ProvenanceError("matrix_digest must be lowercase 64-character hex")
    try:
        input_digest = combined_nightly_input_digest(source_sha, ports_sha, matrix_digest)
        allocation = allocate_nightly(
            build_date,
            _validate_sha(source_sha, "source_sha"),
            _validate_sha(ports_sha, "ports_sha"),
            input_digest,
            _allocations(normalized),
        )
    except (TypeError, ValueError) as exc:
        raise ProvenanceError(str(exc)) from exc
    return Candidate(allocation=allocation, generation=int(normalized["generation"]))


def _artifact_signature(artifacts: Sequence[Mapping[str, str]]) -> tuple[tuple[str, str, str], ...]:
    return tuple(sorted((item["abi"], item["name"], item["sha256"]) for item in artifacts))


def complete(
    state: Mapping[str, object],
    candidate: Candidate,
    artifacts: Sequence[Mapping[str, str]],
    *,
    run_id: str,
    expected_input_digest: str | None = None,
) -> dict[str, object]:
    """Append one verified build, or replay an identical completion idempotently."""
    normalized = validate_state(dict(state))
    if not isinstance(candidate, Candidate):
        raise TypeError("candidate must be Candidate")
    try:
        validate_nightly_allocation(candidate.allocation)
    except (TypeError, ValueError) as exc:
        raise ProvenanceError(f"invalid candidate allocation: {exc}") from exc
    if expected_input_digest is not None:
        if not _DIGEST.fullmatch(expected_input_digest):
            raise ProvenanceError("expected input digest is malformed")
        if candidate.allocation.input_digest != expected_input_digest:
            raise ProvenanceError("completion input digest does not match verified handoff")
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128 or not run_id.isascii():
        raise ProvenanceError("run_id must be non-empty ASCII of at most 128 characters")
    allocation = candidate.allocation
    normalized_artifacts = _validate_artifacts(list(artifacts)) if artifacts else []

    records = normalized["records"]
    assert isinstance(records, list)
    identity = (allocation.source_sha, allocation.ports_sha, allocation.input_digest)
    for record in records:
        assert isinstance(record, dict)
        existing = _validate_allocation(record["allocation"])
        existing_identity = (existing.source_sha, existing.ports_sha, existing.input_digest)
        if existing_identity == identity:
            existing_artifacts = _validate_artifacts(record["artifacts"])
            if normalized_artifacts and _artifact_signature(existing_artifacts) != _artifact_signature(
                normalized_artifacts
            ):
                raise ProvenanceError("artifact bytes collide for an existing Nightly input")
            return normalized

    if allocation.outcome != "build":
        if normalized_artifacts:
            raise ProvenanceError("unchanged candidate does not match durable artifacts")
        return normalized
    if candidate.generation != normalized["generation"]:
        raise ProvenanceError("stale Nightly completion cannot replace newer state")
    if any(
        isinstance(record, dict)
        and isinstance(record.get("allocation"), dict)
        and record["allocation"].get("pkg_version") == allocation.pkg_version
        for record in records
    ):
        raise ProvenanceError("Nightly version collision for different inputs")
    if not normalized_artifacts:
        raise ProvenanceError("build completion requires artifacts")
    normalized["records"].append(
        {
            "allocation": asdict(allocation),
            "artifacts": normalized_artifacts,
            "run_id": run_id,
        }
    )
    normalized["generation"] = int(normalized["generation"]) + 1
    return validate_state(normalized)


def make_build_record(
    *,
    allocation: NightlyAllocation,
    matrix_row: Mapping[str, object],
    source_date_epoch: int,
) -> dict[str, object]:
    """Create one digest-bound portable-builder record for a Nightly leg."""
    if allocation.outcome != "build":
        raise ProvenanceError("build records require a build allocation")
    try:
        row = validate_build_matrix_row(dict(matrix_row))
    except (PkgError, TypeError, ValueError) as exc:
        raise ProvenanceError(str(exc)) from exc
    if type(source_date_epoch) is not int or source_date_epoch < 0:
        raise ProvenanceError("source_date_epoch must be a non-negative integer")
    version = allocation.pkg_version
    major_minor = ".".join(str(row["pfsense_version"]).split(".")[:2])
    record: dict[str, object] = {
        "schema": 1,
        "channel": "nightly",
        "release_line": "nightly",
        "classification": "nightly",
        "source_tag": None,
        "source_sha": allocation.source_sha,
        "canonical_package_version": version,
        "native_recipe_identity": "pfSense-pkg-pfBlockerNG-nightly",
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": row,
        "freebsd_ports_sha": allocation.ports_sha,
        "route": f"nightly/{str(row['variant']).lower()}-{major_minor}",
        "source_date_epoch": source_date_epoch,
        "build_input_digest": "",
    }
    record["build_input_digest"] = build_input_digest(record)
    try:
        return validate_build_record(record)
    except (PkgError, TypeError, ValueError) as exc:
        raise ProvenanceError(str(exc)) from exc


def build_handoff(
    *,
    candidate: Candidate,
    state: Mapping[str, object],
    build_rows: Sequence[Mapping[str, object]],
    route_rows: Sequence[Mapping[str, object]],
    results: Sequence[Mapping[str, object]],
    source_sha: str,
    ports_sha: str,
    tools_sha: str,
    matrix_sha: str,
    matrix_digest: str,
    run_id: str,
    source_ref: str = "",
    ports_repo: str = "",
    ports_ref: str = "",
) -> dict[str, object]:
    """Validate every matrix/build result and return publisher input."""
    normalized_state = validate_state(dict(state))
    if candidate.generation != normalized_state["generation"]:
        raise ProvenanceError("handoff candidate generation is stale")
    if candidate.allocation.outcome != "build":
        raise ProvenanceError("handoff requires a build allocation")
    if (candidate.allocation.source_sha, candidate.allocation.ports_sha) != (source_sha, ports_sha):
        raise ProvenanceError("handoff source identity does not match allocation")
    if not _SHA.fullmatch(tools_sha):
        raise ProvenanceError("handoff tools_sha is malformed")
    if not _SHA.fullmatch(matrix_sha):
        raise ProvenanceError("handoff matrix_sha is malformed")
    if not _DIGEST.fullmatch(matrix_digest):
        raise ProvenanceError("handoff matrix_digest is malformed")
    expected_input_digest = combined_nightly_input_digest(source_sha, ports_sha, matrix_digest)
    if candidate.allocation.input_digest != expected_input_digest:
        raise ProvenanceError("handoff input digest does not match pinned inputs")
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
    expected_rows = {str(row["freebsd_major"]): row for row in normalized_build_rows}
    if len(expected_rows) != len(normalized_build_rows):
        raise ProvenanceError("BUILD matrix contains duplicate FreeBSD majors")
    if len(results) != len(expected_rows):
        raise ProvenanceError("BUILD result count does not match BUILD matrix")

    builds: list[dict[str, object]] = []
    seen_majors: set[str] = set()
    for result in results:
        if not isinstance(result, dict):
            raise ProvenanceError("BUILD result must be an object")
        if set(result) != {"matrix_row", "record", "artifact"}:
            raise ProvenanceError("BUILD result has unexpected fields")
        row = validate_build_matrix_row(dict(result["matrix_row"]))
        major = str(row["freebsd_major"])
        if major in seen_majors or expected_rows.get(major) != row:
            raise ProvenanceError("BUILD result row is missing, duplicated, or changed")
        record = validate_build_record(result["record"], abi=f"FreeBSD:{major}:amd64")
        if record["matrix_row"] != row:
            raise ProvenanceError("build record matrix row does not match BUILD result")
        if (
            record["canonical_package_version"] != candidate.allocation.pkg_version
            or record["source_sha"] != source_sha
            or record["freebsd_ports_sha"] != ports_sha
        ):
            raise ProvenanceError("BUILD result provenance does not match Nightly allocation")
        artifact = _validate_artifacts([result["artifact"]])[0]
        if artifact["name"] != f"pfSense-pkg-pfBlockerNG-{candidate.allocation.pkg_version}.pkg":
            raise ProvenanceError("BUILD artifact name does not match Nightly allocation")
        seen_majors.add(major)
        builds.append({"matrix_row": row, "record": record, "artifact": artifact})
    if seen_majors != set(expected_rows):
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
        "allocation": asdict(candidate.allocation),
        "source_sha": source_sha,
        "ports_sha": ports_sha,
        "tools_sha": tools_sha,
        "matrix_sha": matrix_sha,
        "matrix_digest": matrix_digest,
        "build_matrix": normalized_build_rows,
        "route_matrix": normalized_route_rows,
        "builds": sorted(builds, key=lambda item: str(item["matrix_row"]["freebsd_major"])),
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


def _parse_date(value: str) -> date:
    try:
        return date(int(value[:4]), int(value[4:6]), int(value[6:]))
    except (ValueError, IndexError) as exc:
        raise ProvenanceError("build date must be YYYYMMDD") from exc


def _command_allocate(args: argparse.Namespace) -> int:
    state = _read_json(Path(args.state), default=empty_state())
    candidate = allocate_candidate(
        state,
        build_date=_parse_date(args.build_date),
        source_sha=args.source_sha,
        ports_sha=args.ports_sha,
        matrix_digest=args.matrix_digest,
    )
    _write_json(Path(args.output), {"allocation": asdict(candidate.allocation), "generation": candidate.generation})
    return 0


def _command_complete(args: argparse.Namespace) -> int:
    state = _read_json(Path(args.state), default=empty_state())
    candidate_raw = _read_json(Path(args.candidate))
    artifacts = _read_json(Path(args.artifacts))
    if not isinstance(candidate_raw, dict) or not isinstance(candidate_raw.get("allocation"), dict):
        raise ProvenanceError("candidate JSON is malformed")
    candidate = Candidate(
        allocation=_validate_allocation(candidate_raw["allocation"]),
        generation=candidate_raw.get("generation", -1),
    )
    if type(candidate.generation) is not int:
        raise ProvenanceError("candidate generation must be an integer")
    result = complete(
        state,
        candidate,
        artifacts if isinstance(artifacts, list) else [],
        run_id=args.run_id,
        expected_input_digest=args.expected_input_digest,
    )
    _write_json(Path(args.output), result)
    return 0


def _command_record(args: argparse.Namespace) -> int:
    allocation_raw = _read_json(Path(args.allocation))
    row_raw = _read_json(Path(args.matrix_row))
    if not isinstance(allocation_raw, dict) or not isinstance(row_raw, dict):
        raise ProvenanceError("allocation or matrix row JSON is malformed")
    allocation = _validate_allocation(allocation_raw)
    record = make_build_record(
        allocation=allocation,
        matrix_row=row_raw,
        source_date_epoch=args.source_date_epoch,
    )
    _write_json(Path(args.output), record)
    return 0


def _command_handoff(args: argparse.Namespace) -> int:
    state = _read_json(Path(args.state))
    allocation_raw = _read_json(Path(args.allocation))
    build_rows = _read_json(Path(args.build_matrix))
    route_rows = _read_json(Path(args.route_matrix))
    if not isinstance(allocation_raw, dict) or not isinstance(allocation_raw.get("allocation"), dict):
        raise ProvenanceError("allocation JSON is malformed")
    if not isinstance(build_rows, list) or not isinstance(route_rows, list):
        raise ProvenanceError("matrix JSON must be arrays")
    candidate = Candidate(
        allocation=_validate_allocation(allocation_raw["allocation"]),
        generation=allocation_raw.get("generation", -1),
    )
    if type(candidate.generation) is not int:
        raise ProvenanceError("allocation generation must be an integer")
    result_dir = Path(args.results_dir)
    result_values: list[Mapping[str, object]] = []
    for result_path in sorted(result_dir.glob("*/result.json")):
        result = _read_json(result_path)
        if not isinstance(result, dict):
            raise ProvenanceError(f"malformed BUILD result: {result_path}")
        result_values.append(result)
    handoff = build_handoff(
        candidate=candidate,
        state=state if isinstance(state, dict) else {},
        build_rows=build_rows,
        route_rows=route_rows,
        results=result_values,
        source_sha=args.source_sha,
        ports_sha=args.ports_sha,
        tools_sha=args.tools_sha,
        matrix_sha=args.matrix_sha,
        matrix_digest=args.matrix_digest,
        run_id=args.run_id,
        source_ref=args.source_ref,
        ports_repo=args.ports_repo,
        ports_ref=args.ports_ref,
    )
    _write_json(Path(args.output), handoff)
    return 0


def _command_validate(args: argparse.Namespace) -> int:
    value = _read_json(Path(args.state))
    validate_state(value)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    allocate_parser = subparsers.add_parser("allocate")
    allocate_parser.add_argument("--state", required=True)
    allocate_parser.add_argument("--output", required=True)
    allocate_parser.add_argument("--build-date", required=True)
    allocate_parser.add_argument("--source-sha", required=True)
    allocate_parser.add_argument("--ports-sha", required=True)
    allocate_parser.add_argument("--matrix-digest", required=True)
    allocate_parser.set_defaults(handler=_command_allocate)
    complete_parser = subparsers.add_parser("complete")
    complete_parser.add_argument("--state", required=True)
    complete_parser.add_argument("--candidate", required=True)
    complete_parser.add_argument("--artifacts", required=True)
    complete_parser.add_argument("--run-id", required=True)
    complete_parser.add_argument("--expected-input-digest")
    complete_parser.add_argument("--output", required=True)
    complete_parser.set_defaults(handler=_command_complete)
    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--allocation", required=True)
    record_parser.add_argument("--matrix-row", required=True)
    record_parser.add_argument("--source-date-epoch", required=True, type=int)
    record_parser.add_argument("--output", required=True)
    record_parser.set_defaults(handler=_command_record)
    handoff_parser = subparsers.add_parser("handoff")
    handoff_parser.add_argument("--state", required=True)
    handoff_parser.add_argument("--allocation", required=True)
    handoff_parser.add_argument("--build-matrix", required=True)
    handoff_parser.add_argument("--route-matrix", required=True)
    handoff_parser.add_argument("--results-dir", required=True)
    handoff_parser.add_argument("--source-sha", required=True)
    handoff_parser.add_argument("--ports-sha", required=True)
    handoff_parser.add_argument("--tools-sha", required=True)
    handoff_parser.add_argument("--matrix-sha", required=True)
    handoff_parser.add_argument("--matrix-digest", required=True)
    handoff_parser.add_argument("--run-id", required=True)
    handoff_parser.add_argument("--source-ref", default="")
    handoff_parser.add_argument("--ports-repo", default="")
    handoff_parser.add_argument("--ports-ref", default="")
    handoff_parser.add_argument("--output", required=True)
    handoff_parser.set_defaults(handler=_command_handoff)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--state", required=True)
    validate_parser.set_defaults(handler=_command_validate)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, PkgError, ProvenanceError, TypeError, ValueError) as exc:
        print(f"nightly provenance: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
