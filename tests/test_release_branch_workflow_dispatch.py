"""The release branch must be able to produce an exact-head CI check."""

from pathlib import Path


def test_tests_workflow_has_manual_dispatch() -> None:
    workflow = (Path(__file__).parents[1] / ".github/workflows/test.yml").read_text()
    lines = workflow.splitlines()
    start = lines.index("on:") + 1
    triggers = []
    for line in lines[start:]:
        if line and not line[0].isspace():
            break
        triggers.append(line)

    assert "  workflow_dispatch:" in triggers
