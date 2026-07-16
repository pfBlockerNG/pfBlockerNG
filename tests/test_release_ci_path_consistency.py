"""Keep release CI fallback exclusions aligned with workflow path filters."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _workflow_paths_from_source(source: str, trigger: str) -> list[str]:
    lines = source.splitlines()
    trigger_line = f"  {trigger}:"
    try:
        start = lines.index(trigger_line)
    except ValueError as exc:
        raise AssertionError(f"workflow trigger {trigger!r} is missing") from exc
    end = next(
        (index for index in range(start + 1, len(lines)) if re.fullmatch(r"  [A-Za-z_][A-Za-z0-9_-]*:", lines[index])),
        len(lines),
    )
    try:
        paths_start = next(index for index in range(start + 1, end) if lines[index] == "    paths-ignore:")
    except StopIteration as exc:
        raise AssertionError(f"{trigger}: missing paths-ignore") from exc
    paths: list[str] = []
    for line in lines[paths_start + 1 : end]:
        if line and not line.startswith("      "):
            break
        if not line:
            continue
        match = re.fullmatch(r"      - '(.+)'", line)
        if match is None:
            raise AssertionError(f"unparsed paths-ignore entry: {line!r}")
        paths.append(match.group(1))
    return paths


def _workflow_paths(trigger: str) -> list[str]:
    source = (ROOT / ".github/workflows/test.yml").read_text()
    return _workflow_paths_from_source(source, trigger)


def _release_gate_paths() -> list[str]:
    source = (ROOT / "scripts/release-ci-gate.sh").read_text()
    return re.findall(r"':\(top,exclude,(?:glob|literal)\)([^']+)'", source)


def test_release_fallback_exclusions_match_both_workflow_triggers() -> None:
    push = _workflow_paths("push")
    pull_request = _workflow_paths("pull_request")
    release_gate = _release_gate_paths()

    assert push, "push paths-ignore must not be empty"
    assert pull_request, "pull_request paths-ignore must not be empty"
    assert release_gate, "release fallback exclusions must not be empty"
    assert pull_request == push, f"pull_request paths-ignore differs from push: {pull_request!r} != {push!r}"
    assert release_gate == push, f"release fallback exclusions differ from workflow: {release_gate!r} != {push!r}"


def test_workflow_parser_does_not_cross_trigger_boundaries() -> None:
    source = """\
on:
  push:
    branches:
      - devel
  pull_request:
    paths-ignore:
      - '**/*.md'
"""

    with pytest.raises(AssertionError, match="push: missing paths-ignore"):
        _workflow_paths_from_source(source, "push")


def test_workflow_parser_rejects_unparsed_path_entries() -> None:
    source = """\
on:
  push:
    paths-ignore:
      - "**/*.md"
"""

    with pytest.raises(AssertionError, match="unparsed paths-ignore entry"):
        _workflow_paths_from_source(source, "push")
