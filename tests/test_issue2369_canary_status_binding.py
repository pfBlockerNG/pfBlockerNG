from typing import Any

import pytest

from tests.test_issue2369_canary_status import ROWS, _workflow_gate
from tests.test_issue2369_skip_gate_coverage import _checker_report, _shell_commands

EXACT_GUARD = ("&&", ":;", "canary_status=$?;", "[", "$canary_status", "-eq", "1", "]", "||")


def _canary_report(row: Any) -> str:
    if not row.node:
        return "tests/fixtures/skip-allowlist-canary.xml"
    return "/tmp/widget-js-canary.xml" if row.suite == "widget-js" else "/tmp/webassets-node-canary.xml"


@pytest.mark.parametrize("row", ROWS, ids=lambda row: row.suite)
def test_each_workflow_exact_status_guard_belongs_to_its_canary(row: Any) -> None:
    report = _canary_report(row)
    commands = [argv for argv in _shell_commands(_workflow_gate(row)) if _checker_report(argv, row.suite) == report]
    assert len(commands) == 1, f"{row.suite}: expected one checker for {report}"
    checker = commands[0]
    report_index = checker.index(report)
    guard = checker[report_index + 1 : report_index + 1 + len(EXACT_GUARD)]
    assert guard == EXACT_GUARD, f"{row.suite}: exact status guard must follow its canary checker"
