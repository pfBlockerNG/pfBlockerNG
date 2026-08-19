"""The release branch must be able to produce an exact-head CI check."""

from pathlib import Path


def test_tests_workflow_has_manual_dispatch() -> None:
    workflow = (Path(__file__).parents[1] / ".github/workflows/test.yml").read_text()
    triggers = workflow.split("\non:\n", 1)[1].split("\njobs:\n", 1)[0]

    assert "\n  workflow_dispatch:\n" in triggers
