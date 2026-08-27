import re
import runpy
from pathlib import Path
from typing import Any

import pytest
import yaml

_HELPERS = runpy.run_path(str(Path(__file__).with_name("test_issue2369_skip_gate_coverage.py")))
ROWS = _HELPERS["ROWS"]
_step = _HELPERS["_step"]

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github/workflows"
CHECKER = r"python3 scripts/check_skip_allowlist\.py --suite {suite} --allowlist tests/skip-allowlist\.txt "
EXACT_STATUS = r"&& :;\s*canary_status=\$\?;\s*\[ \"\$canary_status\" -eq 1 \] \|\|"


def _workflow_gate(row: Any) -> str:
    workflow = yaml.safe_load((WORKFLOW_DIR / row.workflow).read_text(encoding="utf-8"))
    if row.same_step:
        step = _step(workflow, row)
    else:
        step = next(item for item in workflow["jobs"][row.job]["steps"] if item.get("name") == "Skip allowlist")
    assert step is not None
    return str(step["run"])


@pytest.mark.parametrize("row", ROWS, ids=lambda row: row.suite)
def test_each_workflow_canary_requires_checker_exit_one(row: Any) -> None:
    pattern = CHECKER.format(suite=re.escape(row.suite)) + r"\S+\s+" + EXACT_STATUS
    assert re.search(pattern, _workflow_gate(row)), f"{row.suite}: canary must reject checker exit 0 or 2"


@pytest.mark.parametrize("suite", ("pytest", "phpunit", "shellspec"))
def test_each_local_canary_requires_checker_exit_one(suite: str) -> None:
    script = (ROOT / "scripts/agent/run-gates.sh").read_text(encoding="utf-8")
    pattern = CHECKER.format(suite=suite) + r"tests/fixtures/skip-allowlist-canary\.xml " + EXACT_STATUS
    assert re.search(pattern, script), f"local {suite}: canary must reject checker exit 0 or 2"
