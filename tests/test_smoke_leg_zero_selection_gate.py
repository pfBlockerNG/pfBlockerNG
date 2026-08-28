"""Pin issue #1767: a whole-leg zero-selection must fail the release gate.

scripts/run-smoke.sh (~:274-291) maps pytest exit 5 ("no tests collected") to 0
PER SHARD whenever shard_total > 1 (issue #855's legitimate empty-partition
tolerance). The release qualification added by #1662 runs full smoke at 3
shards per leg, so a pathological whole-leg zero-selection (marker typo,
collection bug, path-filter regression) would report every shard "empty,
success" and the fail-closed `all-smoke-passed` aggregate would pass a leg
that executed nothing.

The fix is a LEG-level assertion, layered on top of (never replacing) the
per-shard tolerance:
  - scripts/run-smoke.sh's sharded branch now also records the shard's outcome
    ('empty' | 'selected') to $PFB_DIAG_DIR/shard-selection-status (pinned by
    tests/shell/run_smoke_spec.sh -- the shellspec suite for this script).
  - smoke-single.yml uploads that one-word file as a tiny per-shard artifact.
  - smoke.yml's all-smoke-passed job downloads every shard's marker and fails
    a multi-shard leg unless AT LEAST ONE of its shards says 'selected' -- a
    caller-set pytest_filter (a deliberately selective run, mirroring
    ui-tests.yml's PR #1766 exemption) exempts the whole check.

This file lifts the real `run:` bodies out of the workflow YAML (the repo's
established technique -- see tests/test_ui_release_gate_wiring.py) and
executes them under sh with a fabricated CI_MATRIX + downloaded-artifact tree,
so the truth table below runs the ACTUAL gate logic, not a re-description of it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SMOKE_WORKFLOW = ROOT / ".github/workflows/smoke.yml"
SMOKE_SINGLE_WORKFLOW = ROOT / ".github/workflows/smoke-single.yml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$")
_STEP_HEADER_RE = re.compile(r"^      - ")


def _jobs_section_lines(workflow_text: str) -> list[str]:
    lines = workflow_text.splitlines()
    start = lines.index("jobs:") + 1
    return lines[start:]


def _split_into_jobs(lines: list[str]) -> dict[str, list[str]]:
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    buffer: list[str] = []
    for line in lines:
        match = _JOB_HEADER_RE.match(line)
        if match is not None:
            if current is not None:
                jobs[current] = buffer
            current = match.group(1)
            buffer = []
        elif current is not None:
            buffer.append(line)
    if current is not None:
        jobs[current] = buffer
    return jobs


def _split_into_steps(job_lines: list[str]) -> list[list[str]]:
    steps: list[list[str]] = []
    for line in job_lines:
        if _STEP_HEADER_RE.match(line):
            steps.append([])
        if steps:
            steps[-1].append(line)
    return steps


def _jobs(workflow: Path) -> dict[str, list[str]]:
    return _split_into_jobs(_jobs_section_lines(workflow.read_text(encoding="utf-8")))


def _step_run_script(step_lines: list[str]) -> str:
    """Verbatim `run: |` body of a single step, dedented (the repo's established
    lift-verbatim-and-run-under-sh technique)."""
    text = "\n".join(step_lines)
    marker = "run: |\n"
    idx = text.index(marker) + len(marker)
    return textwrap.dedent(text[idx:])


# --------------------------------------------------------------------------- #
# Structural: smoke-single.yml uploads the per-shard marker
# --------------------------------------------------------------------------- #


def _shard_status_upload_step() -> list[str]:
    jobs = _jobs(SMOKE_SINGLE_WORKFLOW)
    steps = _split_into_steps(jobs["smoke"])
    target = [s for s in steps if any("shard-selection-status" in line for line in s)]
    assert len(target) == 1, "expected exactly one step referencing shard-selection-status"
    return target[0]


def test_smoke_single_uploads_shard_selection_status_marker() -> None:
    step_text = "\n".join(_shard_status_upload_step())
    assert "uses: actions/upload-artifact@" in step_text, step_text
    assert re.search(r"if:\s*always\(\)", step_text), f"upload must run unconditionally, got:\n{step_text}"
    name_line = next(line for line in _shard_status_upload_step() if line.strip().startswith("name:"))
    assert "inputs.image_name" in name_line and "inputs.pfsense_version" in name_line and "inputs.shard" in name_line, (
        f"marker artifact name must be keyed on image_name/pfsense_version/shard, got: {name_line}"
    )
    path_line = next(line for line in _shard_status_upload_step() if line.strip().startswith("path:"))
    assert "smoke-diag/shard-selection-status" in path_line, path_line
    assert "if-no-files-found: ignore" in step_text, (
        f"a single-shard leg (or a shard that never reaches the sharded branch) writes no marker -- "
        f"the upload must tolerate that, got:\n{step_text}"
    )


# --------------------------------------------------------------------------- #
# Structural: all-smoke-passed downloads the per-shard markers
# --------------------------------------------------------------------------- #


def _download_markers_step() -> list[str]:
    jobs = _jobs(SMOKE_WORKFLOW)
    steps = _split_into_steps(jobs["all-smoke-passed"])
    target = [s for s in steps if any("actions/download-artifact" in line for line in s)]
    assert len(target) == 1, "expected exactly one download-artifact step in all-smoke-passed"
    return target[0]


def test_all_smoke_passed_downloads_shard_status_markers() -> None:
    step_text = "\n".join(_download_markers_step())
    assert "pattern: smoke-shard-status-*" in step_text, step_text
    assert "continue-on-error: true" in step_text, (
        f"a run with no multi-shard leg uploads no marker at all -- the pattern then matches nothing, "
        f"which must not hard-fail the job, got:\n{step_text}"
    )


# --------------------------------------------------------------------------- #
# The leg-level assert script: lifted verbatim, run under sh, truth table
# --------------------------------------------------------------------------- #


def _assert_script() -> str:
    jobs = _jobs(SMOKE_WORKFLOW)
    steps = _split_into_steps(jobs["all-smoke-passed"])
    target = [s for s in steps if any("Assert every smoke leg passed" in line for line in s)]
    assert len(target) == 1, "expected exactly one 'Assert every smoke leg passed' step"
    return _step_run_script(target[0])


def _write_shard_status(tmp_path: Path, image_name: str, pfsense_version: str, shard: str, content: str | None) -> None:
    """content=None -> the artifact/marker is simply absent (simulates a shard that
    genuinely selected tests -- no marker uploaded -- OR a download failure)."""
    if content is None:
        return
    d = tmp_path / "shard-status" / f"smoke-shard-status-{image_name}-{pfsense_version}-s{shard}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "shard-selection-status").write_text(content)


def _run_assert(
    tmp_path: Path,
    *,
    smoke_result: str,
    leg_count: str,
    ci_matrix: list[dict[str, str]],
    pytest_filter: str,
) -> subprocess.CompletedProcess[str]:
    script = _assert_script()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SMOKE_RESULT": smoke_result,
        "LEG_COUNT": leg_count,
        "CI_MATRIX": json.dumps(ci_matrix),
        "PYTEST_FILTER": pytest_filter,
    }
    return subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


def _three_shard_ce_matrix() -> list[dict[str, str]]:
    return [
        {"image_name": "pfsense-ce", "pfsense_version": "2.8", "shard": str(i), "shard_total": "3"} for i in range(3)
    ]


# ── Required coverage row 1: every shard of a full-scope 3-shard leg is empty ─ #


def test_leg_fails_when_every_shard_of_a_full_scope_leg_is_empty(tmp_path: Path) -> None:
    for i in range(3):
        _write_shard_status(tmp_path, "pfsense-ce", "2.8", str(i), "empty")
    completed = _run_assert(
        tmp_path, smoke_result="success", leg_count="3", ci_matrix=_three_shard_ce_matrix(), pytest_filter=""
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert "pfsense-ce-2.8" in (completed.stdout + completed.stderr)


def _two_leg_ce_plus_matrix() -> list[dict[str, str]]:
    """A representative MULTI-leg shape (>=2 ci:true amd64 legs, 3 shards each) -- unlike
    every other row in this file, which only ever builds a single-leg matrix. The gate is
    cardinality-agnostic and groups on image_name|pfsense_version, so the real
    --print-ci row count does not belong in this fixture. Plus listed first:
    that ordering is what makes the mutation probe below (grouping collapsed
    to one bucket) demonstrate a false PASS rather than an accidental correct
    result -- see that test's docstring."""
    legs = [("pfsense-plus", "26.03"), ("pfsense-ce", "2.8")]
    return [
        {"image_name": image_name, "pfsense_version": pfsense_version, "shard": str(i), "shard_total": "3"}
        for image_name, pfsense_version in legs
        for i in range(3)
    ]


# ── Required coverage row 1b: two production legs, only ONE fully empty ────── #


def test_leg_fails_when_only_one_of_two_production_legs_is_fully_empty(tmp_path: Path) -> None:
    """Pins the grouping key (`.image_name + "|" + .pfsense_version`) against the
    REAL two-leg production shape, not just the single-leg matrix every other
    case here uses. The reviewer hand-verified the two-leg case correct but it
    was unpinned -- nothing stops a future edit from grouping wrongly (e.g.
    collapsing every leg into one bucket) and only failing when EVERY leg is
    empty, letting a healthy leg mask a genuinely empty one. Asserts the gate
    fails AND that the error names only the bad leg -- that second half pins
    the per-leg grouping itself, not just a blanket any-empty-anywhere check."""
    _write_shard_status(tmp_path, "pfsense-plus", "26.03", "0", "selected")
    _write_shard_status(tmp_path, "pfsense-plus", "26.03", "1", "empty")
    _write_shard_status(tmp_path, "pfsense-plus", "26.03", "2", "empty")
    for i in range(3):
        _write_shard_status(tmp_path, "pfsense-ce", "2.8", str(i), "empty")
    completed = _run_assert(
        tmp_path, smoke_result="success", leg_count="6", ci_matrix=_two_leg_ce_plus_matrix(), pytest_filter=""
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr
    output = completed.stdout + completed.stderr
    assert "pfsense-ce-2.8" in output, output
    assert "pfsense-plus-26.03" not in output, output


# ── Required coverage row 2: #855's legitimate single-empty-shard, pinned ───── #


def test_leg_passes_when_one_shard_is_empty_and_others_selected(tmp_path: Path) -> None:
    _write_shard_status(tmp_path, "pfsense-ce", "2.8", "0", "empty")
    _write_shard_status(tmp_path, "pfsense-ce", "2.8", "1", "selected")
    _write_shard_status(tmp_path, "pfsense-ce", "2.8", "2", "empty")
    completed = _run_assert(
        tmp_path, smoke_result="success", leg_count="3", ci_matrix=_three_shard_ce_matrix(), pytest_filter=""
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


# ── Required coverage row 3: a selective (filtered) run stays tolerated ─────── #


def test_selective_invocation_with_every_shard_empty_is_tolerated(tmp_path: Path) -> None:
    for i in range(3):
        _write_shard_status(tmp_path, "pfsense-ce", "2.8", str(i), "empty")
    completed = _run_assert(
        tmp_path,
        smoke_result="success",
        leg_count="3",
        ci_matrix=_three_shard_ce_matrix(),
        pytest_filter="test_something_specific",
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


# ── Required coverage row 4: a missing/unreadable marker fails CLOSED ───────── #


def test_all_markers_missing_fails_closed(tmp_path: Path) -> None:
    """No shard-status/ directory at all (e.g. the download step's continue-on-error
    swallowed a genuine outage) must not be silently read as 'nothing to check' --
    a full-scope multi-shard leg with zero PROOF of a real selection stays a failure."""
    completed = _run_assert(
        tmp_path, smoke_result="success", leg_count="3", ci_matrix=_three_shard_ce_matrix(), pytest_filter=""
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_one_missing_marker_among_otherwise_empty_shards_fails_closed(tmp_path: Path) -> None:
    _write_shard_status(tmp_path, "pfsense-ce", "2.8", "0", None)  # missing
    _write_shard_status(tmp_path, "pfsense-ce", "2.8", "1", "empty")
    _write_shard_status(tmp_path, "pfsense-ce", "2.8", "2", "empty")
    completed = _run_assert(
        tmp_path, smoke_result="success", leg_count="3", ci_matrix=_three_shard_ce_matrix(), pytest_filter=""
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr


# ── Single-shard legs are untouched by this check (already handled by the raw
#    exit-5 propagation -- SMOKE_RESULT would already be 'failure' there) ──── #


def test_single_shard_legs_are_not_touched_by_the_new_check(tmp_path: Path) -> None:
    matrix = [{"image_name": "pfsense-ce", "pfsense_version": "2.8", "shard": "0", "shard_total": "1"}]
    completed = _run_assert(tmp_path, smoke_result="success", leg_count="1", ci_matrix=matrix, pytest_filter="")
    assert completed.returncode == 0, completed.stdout + completed.stderr


# ── Pre-existing arms must stay untouched (never weaken an existing assertion) ── #


@pytest.mark.parametrize("smoke_result", ["failure", "skipped", "cancelled", "garbage"])
def test_pre_existing_non_success_arms_still_fail(tmp_path: Path, smoke_result: str) -> None:
    completed = _run_assert(
        tmp_path, smoke_result=smoke_result, leg_count="3", ci_matrix=_three_shard_ce_matrix(), pytest_filter=""
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_pre_existing_zero_leg_count_still_fails(tmp_path: Path) -> None:
    completed = _run_assert(tmp_path, smoke_result="success", leg_count="0", ci_matrix=[], pytest_filter="")
    assert completed.returncode != 0, completed.stdout + completed.stderr
