"""Failure-run marker parsing distinguishes legacy and corrupt issue bodies."""

from __future__ import annotations

import json
import re
import subprocess

import pytest

from tests.test_workflow_issue_dedup_contract import WORKFLOWS
from tests.test_workflow_issue_recovery_order import _recovery_script


@pytest.mark.parametrize("workflow", ["nightly-failure-alert.yml", "top1m-healthcheck.yml"])
@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("<!-- failure-run: 101:2 -->", "101 2"),
        ("legacy body", "legacy"),
        (None, "legacy"),
        ("<!-- failure-run: x:y -->", "malformed"),
        ("<!-- failure-run: 99:1 --><!-- failure-run: 101:1 -->", "malformed"),
    ],
)
def test_failure_run_marker_parser(body: str | None, expected: str, workflow: str) -> None:
    script = _recovery_script(WORKFLOWS / workflow)
    query = re.search(r"--jq '(.+?)'\)", script, re.DOTALL)

    assert query is not None
    result = subprocess.run(
        ["jq", "-r", query.group(1)],
        input=json.dumps({"body": body}),
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == expected
