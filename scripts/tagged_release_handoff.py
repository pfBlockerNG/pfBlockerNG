#!/usr/bin/env python3
"""Create and validate the immutable tagged-release publisher handoff."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

_GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RELEASE_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:\.[abr][1-9][0-9]*)?$")
_FIELDS = {
    "schema",
    "kind",
    "release_tag",
    "source_sha",
    "ci_metadata_sha",
    "ports_sha",
    "route_matrix",
}


class HandoffError(ValueError):
    """The tagged release handoff is absent, malformed, or inconsistent."""


class BuildRecordIdentityError(HandoffError):
    """A canonical package record disagrees with one handoff identity."""

    def __init__(self, index: int, field: str) -> None:
        self.field = field
        super().__init__(f"build record {index} {field} does not match tagged release handoff")


def _git_sha(value: object, name: str) -> str:
    if not isinstance(value, str) or not _GIT_SHA_RE.fullmatch(value):
        raise HandoffError(f"{name} must be lowercase 40- or 64-character hex")
    return value


def _route_matrix(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise HandoffError("route_matrix must be a non-empty JSON array")
    if any(not isinstance(row, Mapping) for row in value):
        raise HandoffError("route_matrix rows must be JSON objects")
    try:
        normalized = json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise HandoffError(f"route_matrix is not JSON-serializable: {exc}") from exc
    return normalized


def build_handoff(
    *,
    release_tag: str,
    source_sha: str,
    ci_metadata_sha: str,
    ports_sha: str,
    route_matrix: object,
) -> dict[str, object]:
    """Build the canonical handoff attached to a draft tagged release."""
    if not isinstance(release_tag, str) or not _RELEASE_TAG_RE.fullmatch(release_tag):
        raise HandoffError("release_tag is malformed")
    source_sha = _git_sha(source_sha, "source_sha")
    ci_metadata_sha = _git_sha(ci_metadata_sha, "ci_metadata_sha")
    ports_sha = _git_sha(ports_sha, "ports_sha")
    rows = _route_matrix(route_matrix)
    return {
        "schema": 1,
        "kind": "tagged-release-handoff",
        "release_tag": release_tag,
        "source_sha": source_sha,
        "ci_metadata_sha": ci_metadata_sha,
        "ports_sha": ports_sha,
        "route_matrix": rows,
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
    }
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise HandoffError(f"build record {index} must be an object")
        for name, value in expected.items():
            if record.get(name) != value:
                raise BuildRecordIdentityError(index, name)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-metadata-sha", required=True)
    parser.add_argument("--ports-sha", required=True)
    parser.add_argument("--route-matrix", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        route_matrix = json.loads(args.route_matrix.read_text(encoding="utf-8"))
        handoff = build_handoff(
            release_tag=args.release_tag,
            source_sha=args.source_sha,
            ci_metadata_sha=args.ci_metadata_sha,
            ports_sha=args.ports_sha,
            route_matrix=route_matrix,
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
