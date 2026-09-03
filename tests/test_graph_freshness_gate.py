"""Issue #3139: the PR-scoped `graph-freshness` job proves graphify-out/graph.json equals a
rebuild of the PR tree, and cannot fall out of the merge gate unnoticed.

The job's verdict rides shell wiring no unit test executes (`set -eu`, `&& :; status=$?`,
exit propagation), so it carries testing.md's red canary in the SAME `run:` block ahead of
the real check: a copy of the tree with one added function must be reported stale first.
Every assertion below fails when its wiring is removed; the vacuity tests at the end plant
each removal and require exactly that failure.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from tests._workflow_steps import extract_after, extract_before, extract_job

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/test.yml"
JOB = "graph-freshness"
CHECK = "sh scripts/agent/check-graph-fresh.sh"
REAL_CHECK = f"{CHECK} ."
INSTALL = "sh scripts/agent/ensure-graphify.sh ."
SETUP_UV = "astral-sh/setup-uv@v10.0.1"
CANARY_SOURCE = "src/usr/local/pkg/pfblockerng/pfblockerng.inc"
PR_ONLY = "github.event_name == 'pull_request'"
HEAD_SHA = "${{ github.event.pull_request.head.sha }}"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job(text: str) -> dict:
    jobs = yaml.safe_load(text)["jobs"]
    assert JOB in jobs, f"test.yml has no `{JOB}` job"
    return jobs[JOB]


def _step_markers(job: dict) -> list[str]:
    """One marker per step, in order: its `uses:` action or its `run:` body."""
    markers: list[str] = []
    for step in job["steps"]:
        marker = step.get("uses") or step.get("run")
        assert marker, f"{JOB}: a step has neither uses: nor run:"
        markers.append(marker)
    return markers


def _index_of(markers: list[str], needle: str) -> int:
    hits = [index for index, marker in enumerate(markers) if needle in marker]
    assert len(hits) == 1, f"{JOB}: expected exactly one step carrying {needle!r}, found {len(hits)}"
    return hits[0]


def _enforce_body(job: dict) -> str:
    bodies = [step["run"] for step in job["steps"] if CHECK in step.get("run", "")]
    assert len(bodies) == 1, f"{JOB}: the canary and the real check must share ONE run: block, found {len(bodies)}"
    return bodies[0]


def assert_job_is_pr_scoped(text: str) -> None:
    job = _job(text)
    assert job.get("if") == PR_ONLY, f"{JOB} must be PR-only like coverage-pairing, got if: {job.get('if')!r}"
    assert yaml.safe_load(text)["jobs"]["coverage-pairing"]["if"] == job["if"]


def assert_job_checks_out_the_pr_head(text: str) -> None:
    # The graph is a function of the committed tree. The default pull_request
    # checkout is refs/pull/N/merge, whose tree the PR never rebuilt against.
    checkouts = [step for step in _job(text)["steps"] if "actions/checkout@" in step.get("uses", "")]
    assert len(checkouts) == 1, f"{JOB}: expected exactly one checkout step, found {len(checkouts)}"
    assert checkouts[0].get("with", {}).get("ref") == HEAD_SHA, (
        f"{JOB}: checkout must pin ref to the PR head, got {checkouts[0].get('with')!r}"
    )


def assert_graphify_installed_before_the_check(text: str) -> None:
    markers = _step_markers(_job(text))
    checkout = _index_of(markers, "actions/checkout@")
    setup_uv = _index_of(markers, SETUP_UV)
    install = _index_of(markers, INSTALL)
    check = _index_of(markers, CHECK)
    assert checkout < setup_uv < install < check, (
        f"{JOB}: steps must run checkout, then uv, then the shared installer (it applies the "
        f".inc patch), then the check; got checkout={checkout} uv={setup_uv} install={install} check={check}"
    )


def assert_red_canary_precedes_the_real_check(text: str) -> None:
    body = _enforce_body(_job(text))
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    assert lines[0] == "set -eu", (
        f"{JOB}: the block must open with `set -eu` so both checks share its options, got {lines[0]!r}"
    )
    assert lines[-1] == REAL_CHECK, f"{JOB}: the real check must be the block's last command, got {lines[-1]!r}"
    canary = extract_before(body, REAL_CHECK)
    assert CHECK in canary, f"{JOB}: no canary check runs before the real check"
    mutation = extract_before(canary, CHECK)
    assert f'>> "$canary/{CANARY_SOURCE}"' in mutation, (
        f"{JOB}: the canary must append to a COPY of {CANARY_SOURCE} before its check runs"
    )
    assert "function pfb_graph_freshness_canary()" in mutation, (
        f"{JOB}: the canary must add a symbol -- a comment-only edit leaves the graph unchanged"
    )
    verdict = extract_after(canary, CHECK)
    assert re.search(r'\[ "\$canary_status" -eq 1 \] \|\|', verdict), (
        f"{JOB}: the canary must require exit 1, got:\n{verdict}"
    )
    assert "exit 1" in verdict, f"{JOB}: a canary that is not reported stale must fail the job"


def assert_all_tests_passed_needs_the_job(text: str) -> None:
    fan_in = yaml.safe_load(text)["jobs"]["all-tests-passed"]
    assert JOB in fan_in["needs"], f"all-tests-passed does not need {JOB}"
    result_check = extract_job(text, "all-tests-passed")
    verdict = extract_after(result_check, f"needs.{JOB}.result")
    case_arm = extract_before(verdict, "esac")
    assert "success|skipped) ;;" in case_arm, f"a skipped (push) run must fold in as a pass; got:\n{case_arm}"
    assert "exit 1" in case_arm, f"a failed or cancelled {JOB} must fail the merge gate; got:\n{case_arm}"


def test_graph_freshness_job_is_pr_scoped_like_coverage_pairing() -> None:
    assert_job_is_pr_scoped(_workflow_text())


def test_graphify_is_installed_through_the_shared_installer_before_the_check() -> None:
    assert_graphify_installed_before_the_check(_workflow_text())


def test_graph_freshness_job_checks_out_the_pr_head_not_the_merge_ref() -> None:
    assert_job_checks_out_the_pr_head(_workflow_text())


def test_red_canary_runs_first_in_the_same_block_and_requires_exit_1() -> None:
    assert_red_canary_precedes_the_real_check(_workflow_text())


def test_all_tests_passed_needs_the_job_and_fails_when_it_fails() -> None:
    assert_all_tests_passed_needs_the_job(_workflow_text())


def _without_job(text: str) -> str:
    """test.yml with the whole `graph-freshness:` job block removed."""
    block = extract_job(text, JOB)
    return text.replace(f"  {JOB}:\n{block}", "", 1)


def _in_job(job: str, old: str, new: str) -> Callable[[str], str]:
    """A mutation confined to one job block: the same shell text recurs in sibling
    jobs (the skip-allowlist canary uses the identical `-eq 1 ||` guard), so a
    file-global first-match replacement would plant the removal elsewhere."""

    def mutate(text: str) -> str:
        block = extract_job(text, job)
        assert old in block, f"{job}: planted removal target {old!r} is absent -- the guard would be vacuous"
        return text.replace(block, block.replace(old, new, 1), 1)

    return mutate


@pytest.mark.parametrize(
    ("mutate", "check", "expected"),
    [
        (_without_job, assert_job_is_pr_scoped, "has no `graph-freshness` job"),
        (_in_job(JOB, f"    if: {PR_ONLY}\n", ""), assert_job_is_pr_scoped, "PR-only"),
        (
            _in_job(JOB, f"          ref: {HEAD_SHA}\n", ""),
            assert_job_checks_out_the_pr_head,
            "pin ref to the PR head",
        ),
        (
            _in_job(JOB, f"run: {INSTALL}", "run: echo installer dropped"),
            assert_graphify_installed_before_the_check,
            "exactly one step",
        ),
        (
            _in_job(JOB, '[ "$canary_status" -eq 1 ] ||', '[ "$canary_status" -eq 0 ] ||'),
            assert_red_canary_precedes_the_real_check,
            "require exit 1",
        ),
        (
            _in_job(JOB, "function pfb_graph_freshness_canary()", "// pfb_graph_freshness_canary"),
            assert_red_canary_precedes_the_real_check,
            "add a symbol",
        ),
        (_in_job("all-tests-passed", f", {JOB}", ""), assert_all_tests_passed_needs_the_job, f"does not need {JOB}"),
    ],
    ids=[
        "job-deleted",
        "job-unconditional",
        "checkout-merge-ref",
        "installer-dropped",
        "canary-accepts-fresh",
        "canary-comment-only",
        "fan-in-drops-job",
    ],
)
def test_each_wiring_removal_is_caught(
    mutate: Callable[[str], str], check: Callable[[str], None], expected: str
) -> None:
    mutated = mutate(_workflow_text())
    assert mutated != _workflow_text(), "the planted removal changed nothing -- the guard would be vacuous"
    with pytest.raises(AssertionError, match=re.escape(expected)):
        check(mutated)
