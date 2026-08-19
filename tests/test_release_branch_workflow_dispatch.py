"""The release branch must be able to produce an exact-head CI check."""

from pathlib import Path

import yaml


def test_tests_workflow_has_manual_dispatch() -> None:
    source = (Path(__file__).parents[1] / ".github/workflows/test.yml").read_text()
    workflow = yaml.load(source, Loader=yaml.BaseLoader)
    assert isinstance(workflow, dict)

    triggers = workflow.get("on")
    assert isinstance(triggers, dict)
    assert "workflow_dispatch" in triggers
