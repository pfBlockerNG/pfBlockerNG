"""Keep release CI fallback exclusions aligned with workflow path filters."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _workflow_paths(trigger: str) -> list[str]:
    lines = (ROOT / ".github/workflows/test.yml").read_text().splitlines()
    trigger_line = f"  {trigger}:"
    start = lines.index(trigger_line)
    paths_start = next(index for index in range(start + 1, len(lines)) if lines[index] == "    paths-ignore:")
    paths: list[str] = []
    for line in lines[paths_start + 1 :]:
        if line and not line.startswith("      "):
            break
        match = re.match(r"      - '(.+)'$", line)
        if match:
            paths.append(match.group(1))
    return paths


def _release_gate_paths() -> list[str]:
    source = (ROOT / "scripts/release-ci-gate.sh").read_text()
    return re.findall(r"':\(top,exclude,(?:glob|literal)\)([^']+)'", source)


def test_release_fallback_exclusions_match_both_workflow_triggers() -> None:
    push = _workflow_paths("push")
    pull_request = _workflow_paths("pull_request")
    release_gate = _release_gate_paths()

    assert pull_request == push, f"pull_request paths-ignore differs from push: {pull_request!r} != {push!r}"
    assert release_gate == push, f"release fallback exclusions differ from workflow: {release_gate!r} != {push!r}"
