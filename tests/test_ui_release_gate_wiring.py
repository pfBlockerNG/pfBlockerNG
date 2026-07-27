"""Pin the reusable-workflow half of issue #1662: ui-tests.yml + smoke.yml must be able to
consume prebuilt exact-release .pkg artifacts (via a `pkg_artifact_prefix` input) instead of
always building their own, ui-tests.yml gets a fail-closed `all-ui-passed` AND gate (mirroring
smoke.yml's `all-smoke-passed`), and the ui tier's pytest-exit-5 mapper stops silently passing
a full, unfiltered run that selected zero tests.

release.yml itself (part 2 -- wiring the prefix in from a real release build) is a LATER
change by someone else; this file only pins the reusable-workflow side.
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UI_WORKFLOW = ROOT / ".github/workflows/ui-tests.yml"
SMOKE_WORKFLOW = ROOT / ".github/workflows/smoke.yml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$")
_STEP_HEADER_RE = re.compile(r"^      - ")


def _jobs_section_lines(workflow_text: str) -> list[str]:
    lines = workflow_text.splitlines()
    start = lines.index("jobs:") + 1
    return lines[start:]


def _split_into_jobs(lines: list[str]) -> dict[str, list[str]]:
    """Group the (already `jobs:`-relative) lines under each top-level job name."""
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


def _trigger_blocks(workflow: Path) -> tuple[str, str]:
    """Return (workflow_call inputs block, workflow_dispatch inputs block) as raw text,
    each spanning from its own `inputs:` header to the next top-level (2-space) key."""
    text = workflow.read_text(encoding="utf-8")
    # Leading "\n" so the trigger split below (which requires a preceding
    # newline) also matches the FIRST trigger key, not just later ones.
    on_section = "\n" + text.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]

    def _block(trigger: str) -> str:
        after = on_section.split(f"\n  {trigger}:\n", 1)[1]
        # Ends at the next 2-space-indented key (another trigger, or the section end).
        m = re.search(r"\n  [A-Za-z]", after)
        return after[: m.start()] if m else after

    return _block("workflow_call"), _block("workflow_dispatch")


def _step_run_script(step_lines: list[str]) -> str:
    """Verbatim `run: |` body of a single step, dedented (test_release_dry_run_gate.py's
    lift-verbatim-and-run-under-sh technique)."""
    text = "\n".join(step_lines)
    marker = "run: |\n"
    idx = text.index(marker) + len(marker)
    return textwrap.dedent(text[idx:])


# --------------------------------------------------------------------------- #
# pkg_artifact_prefix input: both trigger blocks, both workflows, default ''
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("workflow", [UI_WORKFLOW, SMOKE_WORKFLOW])
def test_pkg_artifact_prefix_declared_in_both_trigger_blocks(workflow: Path) -> None:
    call_block, dispatch_block = _trigger_blocks(workflow)
    for name, block in (("workflow_call", call_block), ("workflow_dispatch", dispatch_block)):
        assert "pkg_artifact_prefix:" in block, f"{workflow.name}: {name} is missing pkg_artifact_prefix"
        # the input's own sub-block (description/required/type/default) ends well
        # within a generous slice; scan that for the default line.
        sub = block.split("pkg_artifact_prefix:\n", 1)[1][:400]
        assert re.search(r"^\s*default:\s*\"\"\s*$", sub, re.MULTILINE), (
            f"{workflow.name}: {name}'s pkg_artifact_prefix must default to '' -- block was:\n{sub}"
        )


# --------------------------------------------------------------------------- #
# build-pkg gates on the prefix being empty
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("workflow", [UI_WORKFLOW, SMOKE_WORKFLOW])
def test_build_pkg_job_skips_when_prefix_supplied(workflow: Path) -> None:
    jobs = _jobs(workflow)
    assert "build-pkg" in jobs, f"{workflow.name}: no build-pkg job"
    job_text = "\n".join(jobs["build-pkg"])
    if_line = next((line for line in jobs["build-pkg"] if line.strip().startswith("if:")), None)
    assert if_line is not None, f"{workflow.name}: build-pkg has no if: condition\n{job_text}"
    assert "inputs.pkg_artifact_prefix == ''" in if_line, (
        f"{workflow.name}: build-pkg's if: must gate on inputs.pkg_artifact_prefix == '', got: {if_line}"
    )


# --------------------------------------------------------------------------- #
# ui download-name / smoke pkg_artifact expressions thread the prefix
# --------------------------------------------------------------------------- #


def test_ui_download_step_uses_the_prefix_when_set() -> None:
    jobs = _jobs(UI_WORKFLOW)
    steps = _split_into_steps(jobs["ui"])
    target = [s for s in steps if any("Download the built pfBlockerNG package" in line for line in s)]
    assert len(target) == 1, "ui job must have exactly one 'Download the built pfBlockerNG package' step"
    step_text = "\n".join(target[0])
    assert (
        "format('{0}-{1}-{2}-{3}', inputs.pkg_artifact_prefix, matrix.variant, matrix.version, matrix.arch)"
        in step_text
    ), f"ui download step must build the prefixed artifact name from prefix/variant/version/arch, got:\n{step_text}"
    assert "inputs.pkg_artifact_prefix != ''" in step_text
    assert "format('pfBlockerNG-pkg-{0}', matrix.version)" in step_text, (
        "the blank-prefix fallback must stay byte-identical to the pre-#1662 literal name"
    )


def test_smoke_job_threads_the_prefix_into_pkg_artifact() -> None:
    jobs = _jobs(SMOKE_WORKFLOW)
    job_text = "\n".join(jobs["smoke"])
    assert "pkg_artifact:" in job_text
    pkg_artifact_line = next(line for line in jobs["smoke"] if "pkg_artifact:" in line and "with" not in line)
    assert "inputs.pkg_artifact_prefix != ''" in pkg_artifact_line, (
        f"smoke job's pkg_artifact: must branch on inputs.pkg_artifact_prefix, got: {pkg_artifact_line}"
    )
    assert "inputs.pkg_artifact_prefix" in pkg_artifact_line and "matrix.pfsense_version" in pkg_artifact_line
    assert "format('pfBlockerNG-pkg-{0}-{1}', matrix.image_name, matrix.pfsense_version)" in pkg_artifact_line, (
        "the blank-prefix fallback must stay byte-identical to the pre-#1662 literal name"
    )


# --------------------------------------------------------------------------- #
# ui job if-condition: !cancelled() + prepare success, tolerates skipped build-pkg
# --------------------------------------------------------------------------- #


def test_ui_job_if_condition_shape() -> None:
    jobs = _jobs(UI_WORKFLOW)
    job_text = "\n".join(jobs["ui"])
    # The if: may be a folded multi-line block (`if: >-`); grab up to the `runs-on:` line.
    if_block = job_text.split("if:", 1)[1].split("\n    runs-on:", 1)[0]
    assert "!cancelled()" in if_block
    assert "needs.prepare.result == 'success'" in if_block
    assert "needs.prepare.outputs.run == 'true'" in if_block
    assert "inputs.pkg_artifact_prefix != ''" in if_block
    assert "needs.build-pkg.result == 'success'" in if_block


# --------------------------------------------------------------------------- #
# all-ui-passed: exists, needs [prepare, ui], if always()
# --------------------------------------------------------------------------- #


def test_all_ui_passed_job_exists_and_is_wired() -> None:
    jobs = _jobs(UI_WORKFLOW)
    assert "all-ui-passed" in jobs, "ui-tests.yml must gain a terminal all-ui-passed AND gate"
    job_lines = jobs["all-ui-passed"]
    job_text = "\n".join(job_lines)
    needs_line = next(line for line in job_lines if line.strip().startswith("needs:"))
    assert "prepare" in needs_line and "ui" in needs_line, f"all-ui-passed must need [prepare, ui], got: {needs_line}"
    if_line = next(line for line in job_lines if line.strip().startswith("if:"))
    assert "always()" in if_line, f"all-ui-passed must run unconditionally (if: always()), got: {if_line}"
    assert "runs-on:" in job_text


# --------------------------------------------------------------------------- #
# all-ui-passed run script: lifted verbatim, executed under sh, truth table
# --------------------------------------------------------------------------- #


def _all_ui_passed_script() -> str:
    jobs = _jobs(UI_WORKFLOW)
    steps = _split_into_steps(jobs["all-ui-passed"])
    assert len(steps) == 1, "expected exactly one step in all-ui-passed"
    return _step_run_script(steps[0])


def _run_all_ui_passed(run_gate: str, leg_count: str, ui_result: str) -> subprocess.CompletedProcess[str]:
    script = _all_ui_passed_script()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "RUN_GATE": run_gate,
        "LEG_COUNT": leg_count,
        "UI_RESULT": ui_result,
    }
    return subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("leg_count", ["0", "", "5"])
@pytest.mark.parametrize("ui_result", ["success", "failure", "skipped", "cancelled", "garbage"])
def test_all_ui_passed_run_gate_declined_always_passes(leg_count: str, ui_result: str) -> None:
    """run != 'true' (the nightly no-commit guard skipped the whole run) is a PASS
    regardless of leg_count/ui_result -- nothing was supposed to run."""
    completed = _run_all_ui_passed(run_gate="false", leg_count=leg_count, ui_result=ui_result)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_all_ui_passed_zero_legs_with_run_true_fails() -> None:
    completed = _run_all_ui_passed(run_gate="true", leg_count="0", ui_result="success")
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_all_ui_passed_empty_leg_count_with_run_true_fails() -> None:
    completed = _run_all_ui_passed(run_gate="true", leg_count="", ui_result="success")
    assert completed.returncode != 0, completed.stdout + completed.stderr


@pytest.mark.parametrize(
    ("ui_result", "expect_pass"),
    [
        ("success", True),
        ("failure", False),
        ("skipped", False),
        ("cancelled", False),
        ("garbage", False),
    ],
)
def test_all_ui_passed_result_case(ui_result: str, expect_pass: bool) -> None:
    completed = _run_all_ui_passed(run_gate="true", leg_count="5", ui_result=ui_result)
    if expect_pass:
        assert completed.returncode == 0, completed.stdout + completed.stderr
    else:
        assert completed.returncode != 0, completed.stdout + completed.stderr


# --------------------------------------------------------------------------- #
# exit-5 mapper: lifted verbatim, run-smoke.sh stubbed, truth table
# --------------------------------------------------------------------------- #


def _exit5_mapper_script() -> str:
    jobs = _jobs(UI_WORKFLOW)
    steps = _split_into_steps(jobs["ui"])
    target = [s for s in steps if any("sh scripts/run-smoke.sh" in line for line in s)]
    assert len(target) == 1, "expected exactly one step invoking scripts/run-smoke.sh"
    return _step_run_script(target[0])


def _run_exit5_mapper(
    tmp_path: Path, run_smoke_rc: int, pytest_filter: str, scope: str
) -> subprocess.CompletedProcess[str]:
    script = _exit5_mapper_script()
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir(exist_ok=True)
    run_smoke = scripts_dir / "run-smoke.sh"
    run_smoke.write_text(f"#!/bin/sh\nexit {run_smoke_rc}\n")
    run_smoke.chmod(0o755)
    select_box = scripts_dir / "select-box.sh"
    select_box.write_text("#!/bin/sh\necho stub-run-id\n")
    select_box.chmod(0o755)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTEST_FILTER": pytest_filter,
        "SCOPE": scope,
        "MARKER": "ui_render",
    }
    return subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


def test_exit5_full_scope_no_filter_stays_a_failure(tmp_path: Path) -> None:
    completed = _run_exit5_mapper(tmp_path, run_smoke_rc=5, pytest_filter="", scope="full")
    assert completed.returncode == 5, completed.stdout + completed.stderr


def test_exit5_with_a_pytest_filter_is_benign(tmp_path: Path) -> None:
    completed = _run_exit5_mapper(tmp_path, run_smoke_rc=5, pytest_filter="test_foo", scope="full")
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_exit5_impacted_scope_is_benign(tmp_path: Path) -> None:
    completed = _run_exit5_mapper(tmp_path, run_smoke_rc=5, pytest_filter="", scope="impacted")
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_exit5_impacted_scope_with_filter_is_also_benign(tmp_path: Path) -> None:
    completed = _run_exit5_mapper(tmp_path, run_smoke_rc=5, pytest_filter="test_foo", scope="impacted")
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_non_five_failure_rc_stays_unmapped(tmp_path: Path) -> None:
    completed = _run_exit5_mapper(tmp_path, run_smoke_rc=1, pytest_filter="", scope="full")
    assert completed.returncode == 1, completed.stdout + completed.stderr


def test_success_rc_stays_zero(tmp_path: Path) -> None:
    completed = _run_exit5_mapper(tmp_path, run_smoke_rc=0, pytest_filter="", scope="full")
    assert completed.returncode == 0, completed.stdout + completed.stderr
