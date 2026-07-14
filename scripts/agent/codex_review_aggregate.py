#!/usr/bin/env python3
"""Deterministically merge and verify schema-constrained Codex review results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return value


def prepare(output_dir: Path, result_paths: list[Path]) -> None:
    output_dir.mkdir(parents=True, exist_ok=False)
    seen: set[str] = set()
    merged: list[dict[str, Any]] = []
    per_file: list[dict[str, Any]] = []

    for path in result_paths:
        result = _read_object(path)
        findings = result.get("findings")
        verdicts = result.get("per_file")
        if not isinstance(findings, list) or not isinstance(verdicts, list):
            raise SystemExit(f"{path}: missing schema-constrained review arrays")
        per_file.extend(verdicts)
        for finding in findings:
            if not isinstance(finding, dict):
                raise SystemExit(f"{path}: finding is not an object")
            location = finding.get("location")
            explanation = finding.get("explanation")
            if not isinstance(location, str) or not isinstance(explanation, str):
                raise SystemExit(f"{path}: finding lacks string location/explanation")
            key = f"{location}|{explanation[:80]}"
            if key not in seen:
                seen.add(key)
                merged.append(finding)

    for index, finding in enumerate(merged, start=1):
        (output_dir / f"finding-{index}.json").write_text(json.dumps(finding, sort_keys=True) + "\n")
    (output_dir / "per-file.json").write_text(json.dumps(per_file) + "\n")
    (output_dir / "count").write_text(f"{len(merged)}\n")


def finalize(merged_dir: Path, verdict_dir: Path, output_path: Path) -> None:
    count = int((merged_dir / "count").read_text().strip())
    per_file = json.loads((merged_dir / "per-file.json").read_text())
    confirmed: list[dict[str, Any]] = []
    refuted: list[dict[str, Any]] = []

    for index in range(1, count + 1):
        finding = _read_object(merged_dir / f"finding-{index}.json")
        verdict = _read_object(verdict_dir / f"verdict-{index}.json")
        holds = verdict.get("holds")
        if not isinstance(holds, bool):
            raise SystemExit(f"verdict-{index}: holds must be boolean")
        if holds:
            severity = verdict.get("revised_severity") or finding.get("severity")
            confirmed.append({**finding, "severity": severity, "verified": verdict})
        else:
            refuted.append(
                {
                    "location": finding.get("location"),
                    "explanation": finding.get("explanation"),
                    "evidence": verdict.get("evidence"),
                }
            )

    result = {
        "confirmed": confirmed,
        "refuted": refuted,
        "per_file": per_file,
        "lenses_returned": 3,
    }
    output_path.write_text(json.dumps(result, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("output_dir", type=Path)
    prepare_parser.add_argument("results", nargs="+", type=Path)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("merged_dir", type=Path)
    finalize_parser.add_argument("verdict_dir", type=Path)
    finalize_parser.add_argument("output", type=Path)
    args = parser.parse_args()

    if args.command == "prepare":
        prepare(args.output_dir, args.results)
    else:
        finalize(args.merged_dir, args.verdict_dir, args.output)


if __name__ == "__main__":
    main()
