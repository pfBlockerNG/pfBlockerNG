"""Issue #3489 -- a run testing a caller-named ref must not write the caches trusted runs restore.

``smoke-single.yml`` (job ``smoke``) and ``ui-tests.yml`` (job ``ui``) check out
``inputs.checkout_ref``: the code under test can come from a ref the caller names.
Anything such a run saves into the Actions cache (the pfSense/civm image dirs via
``actions/cache/save``, uv's download cache via ``astral-sh/setup-uv``) is then
restored by later runs of the default ref, so the named ref could poison them.
Restores stay unguarded: a custom-ref run still READS the cache.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"

# (workflow, job) -> number of actions/cache/save steps. The counts are a vacuity guard:
# a renamed or removed save step must fail here rather than leave nothing to check.
SAVE_STEP_COUNTS = {("smoke-single.yml", "smoke"): 2, ("ui-tests.yml", "ui"): 1}
JOBS = pytest.mark.parametrize(("workflow", "job"), list(SAVE_STEP_COUNTS), ids=lambda v: str(v))

UNTRUSTED_REF_CLAUSE = "inputs.checkout_ref == ''"


def _steps(workflow: str, job: str, uses_prefix: str) -> list[dict[str, Any]]:
    """The job's steps whose ``uses`` starts with ``uses_prefix``, after proving the job
    really does check out the caller-named ref (else this guard has nothing to protect)."""
    workflow_doc = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = workflow_doc["jobs"][job]["steps"]
    checkouts = [s["with"]["ref"] for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert checkouts == ["${{ inputs.checkout_ref }}"], f"{workflow}:{job} checkout refs: {checkouts}"
    return [s for s in steps if str(s.get("uses", "")).startswith(uses_prefix)]


@JOBS
def test_cache_save_steps_are_skipped_for_a_caller_named_ref(workflow: str, job: str) -> None:
    saves = _steps(workflow, job, "actions/cache/save@")

    assert len(saves) == SAVE_STEP_COUNTS[(workflow, job)], f"{workflow}:{job} save steps: {[s['name'] for s in saves]}"
    for step in saves:
        condition = str(step.get("if", "")).strip()
        assert condition.endswith(f"&& {UNTRUSTED_REF_CLAUSE}"), f"{step['name']!r} if: {condition!r}"
        assert "||" not in condition, f"{step['name']!r} if: {condition!r} must AND the clause, never OR it"


@JOBS
def test_uv_cache_is_not_saved_for_a_caller_named_ref(workflow: str, job: str) -> None:
    setup_uv = _steps(workflow, job, "astral-sh/setup-uv@")

    assert len(setup_uv) == 1, f"{workflow}:{job} setup-uv steps: {[s['name'] for s in setup_uv]}"
    assert setup_uv[0]["with"].get("save-cache") == f"${{{{ {UNTRUSTED_REF_CLAUSE} }}}}"


@JOBS
def test_no_combined_restore_and_save_cache_step(workflow: str, job: str) -> None:
    """``actions/cache@`` saves implicitly in its post step, bypassing the guarded save steps."""
    assert [s.get("name", s["uses"]) for s in _steps(workflow, job, "actions/cache@")] == []
