"""Pin issue #1662 end to end. Part 1 (reusable-workflow side): ui-tests.yml + smoke.yml
must be able to consume prebuilt exact-release .pkg artifacts (via a `pkg_artifact_prefix`
input) instead of always building their own, ui-tests.yml gets a fail-closed `all-ui-passed`
AND gate (mirroring smoke.yml's `all-smoke-passed`) -- including the prepare-crash fail-closed
fix -- and the ui tier's pytest-exit-5 mapper stops silently passing a full, unfiltered run
that selected zero tests.

Part 2 (release.yml side): build-pkgs-portable matrix-ifies over the read-matrix release_matrix
-- one row per build-role Variant/version -- and uploads one EXACT-named artifact per
row (`pfBlockerNG-relpkg-<Variant>-<pfsense_version>`); attach-pkgs merges them by pattern;
ui-suite/smoke-suite are re-enabled, consume those exact artifacts, and gate
tag-release (issue #1855: the tag, and therefore everything after it, waits on
every live leg).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

from tests._workflow_steps import extract_after, extract_between

ROOT = Path(__file__).resolve().parents[1]
UI_WORKFLOW = ROOT / ".github/workflows/ui-tests.yml"
SMOKE_WORKFLOW = ROOT / ".github/workflows/smoke.yml"
SMOKE_SINGLE_WORKFLOW = ROOT / ".github/workflows/smoke-single.yml"
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
PUBLISHED_WORKFLOW = ROOT / ".github/workflows/release-published.yml"

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


def _step(job_lines: list[str], needle: str) -> list[str]:
    matches = [s for s in _split_into_steps(job_lines) if any(needle in line for line in s)]
    assert len(matches) == 1, f"expected exactly one step containing {needle!r}, got {len(matches)}"
    return matches[0]


def _trigger_blocks(workflow: Path) -> tuple[str, str]:
    """Return (workflow_call inputs block, workflow_dispatch inputs block) as raw text,
    each spanning from its own `inputs:` header to the next top-level (2-space) key."""
    text = workflow.read_text(encoding="utf-8")
    # Leading "\n" so the trigger marker below (which requires a preceding
    # newline) also matches the FIRST trigger key, not just later ones.
    on_section = "\n" + extract_between(text, "\non:\n", "\npermissions:\n")

    def _block(trigger: str) -> str:
        after = extract_after(on_section, f"\n  {trigger}:\n")
        # Ends at the next 2-space-indented key (another trigger, or the section end).
        m = re.search(r"\n  [A-Za-z]", after)
        return after[: m.start()] if m else after

    return _block("workflow_call"), _block("workflow_dispatch")


def _input_block(trigger_block: str, name: str) -> str:
    """The `name:` input's OWN sub-block, bounded at the next input key at the same
    (6-space) indentation. A fixed-length suffix window instead reaches into a sibling
    input, so an input that loses its own `default:` can pass on its neighbour's."""
    body = extract_after(trigger_block, f"{name}:\n")
    sibling = re.search(r"\n      [A-Za-z]", body)
    return body[: sibling.start()] if sibling else body


_JOB_KEY_RE = re.compile(r"^    [A-Za-z_-]+:")


def _job_if_block(job_lines: list[str]) -> str:
    """The whole job-level `if:` value, including a folded multi-line (`if: >-`) form.

    A single-line `next(... startswith("if:"))` silently reads only the first line of a
    folded condition, so a gate spread over several lines would look absent.
    """
    collected: list[str] = []
    for line in job_lines:
        if collected:
            if _JOB_KEY_RE.match(line):
                break
            collected.append(line)
        elif line.startswith("    if:"):
            collected.append(line)
    assert collected, f"job carries no job-level if:\n{chr(10).join(job_lines)}"
    return "\n".join(collected)


def _step_run_script(step_lines: list[str]) -> str:
    """Verbatim `run: |` body of a single step, dedented (test_release_dry_run_gate.py's
    lift-verbatim-and-run-under-sh technique)."""
    text = "\n".join(step_lines)
    marker = "run: |\n"
    idx = text.index(marker) + len(marker)
    raw = text[idx:].splitlines()
    first = next((line for line in raw if line.strip()), "")
    base = len(first) - len(first.lstrip())
    end = len(raw)
    for i, line in enumerate(raw):
        if line.strip() and len(line) - len(line.lstrip()) < base:
            end = i
            break
    return textwrap.dedent("\n".join(raw[:end])) + "\n"


# --------------------------------------------------------------------------- #
# pkg_artifact_prefix input: both trigger blocks, both workflows, default ''
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("workflow", [UI_WORKFLOW, SMOKE_WORKFLOW])
def test_pkg_artifact_prefix_declared_in_both_trigger_blocks(workflow: Path) -> None:
    call_block, dispatch_block = _trigger_blocks(workflow)
    for name, block in (("workflow_call", call_block), ("workflow_dispatch", dispatch_block)):
        assert "pkg_artifact_prefix:" in block, f"{workflow.name}: {name} is missing pkg_artifact_prefix"
        sub = _input_block(block, "pkg_artifact_prefix")
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
    assert "format('{0}-{1}-{2}', inputs.pkg_artifact_prefix, matrix.variant, matrix.version)" in step_text, (
        f"ui download step must build the prefixed artifact name from prefix/row identity, got:\n{step_text}"
    )
    assert "inputs.pkg_artifact_prefix != ''" in step_text
    assert "format('pfBlockerNG-pkg-{0}-{1}', matrix.variant, matrix.version)" in step_text, (
        "the blank-prefix fallback must carry the row identity"
    )


def test_smoke_job_threads_the_prefix_into_pkg_artifact() -> None:
    jobs = _jobs(SMOKE_WORKFLOW)
    job_text = "\n".join(jobs["smoke"])
    assert "pkg_artifact:" in job_text
    pkg_artifact_line = next(line for line in jobs["smoke"] if "pkg_artifact:" in line and "with" not in line)
    assert "inputs.pkg_artifact_prefix != ''" in pkg_artifact_line, (
        f"smoke job's pkg_artifact: must branch on inputs.pkg_artifact_prefix, got: {pkg_artifact_line}"
    )
    assert (
        "format('{0}-{1}-{2}', inputs.pkg_artifact_prefix, matrix.variant, matrix.pfsense_version)" in pkg_artifact_line
    ), f"the prefix-set branch must key on Variant/version, got: {pkg_artifact_line}"
    assert "format('pfBlockerNG-pkg-{0}-{1}', matrix.variant, matrix.pfsense_version)" in pkg_artifact_line, (
        f"the blank-prefix fallback must match build-pkg's own row artifact_name, got: {pkg_artifact_line}"
    )


# --------------------------------------------------------------------------- #
# ui job if-condition: !cancelled() + prepare success, tolerates skipped build-pkg
# --------------------------------------------------------------------------- #


def test_ui_job_if_condition_shape() -> None:
    jobs = _jobs(UI_WORKFLOW)
    job_text = "\n".join(jobs["ui"])
    # The if: may be a folded multi-line block (`if: >-`); grab up to the `runs-on:` line.
    if_block = extract_between(job_text, "if:", "\n    runs-on:")
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


def _run_all_ui_passed(
    run_gate: str, leg_count: str, ui_result: str, prepare_result: str = "success"
) -> subprocess.CompletedProcess[str]:
    script = _all_ui_passed_script()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "RUN_GATE": run_gate,
        "LEG_COUNT": leg_count,
        "UI_RESULT": ui_result,
        # Existing rows below don't pass this explicitly -- they all mean a
        # genuinely-succeeded prepare job, so the default carries that.
        "PREPARE_RESULT": prepare_result,
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


# --------------------------------------------------------------------------- #
# prepare-crash fail-closed FINDING (issue #1662): a prepare job that did NOT
# genuinely succeed must fail the gate even though a crash leaves RUN_GATE
# empty -- the old RUN_GATE-first check read that as "scheduled idle, pass".
# Checked BEFORE the RUN_GATE branch, so it wins regardless of RUN_GATE.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("prepare_result", ["failure", "cancelled", "skipped"])
def test_all_ui_passed_prepare_not_success_fails_closed_even_with_empty_run_gate(prepare_result: str) -> None:
    completed = _run_all_ui_passed(run_gate="", leg_count="", ui_result="skipped", prepare_result=prepare_result)
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_all_ui_passed_prepare_success_with_run_gate_false_still_passes() -> None:
    """A genuinely-succeeded prepare that legitimately declined the run (nightly
    no-commit guard) stays a pass -- the fix must not touch this existing case."""
    completed = _run_all_ui_passed(run_gate="false", leg_count="", ui_result="skipped", prepare_result="success")
    assert completed.returncode == 0, completed.stdout + completed.stderr


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


def test_ui_run_block_writes_and_checks_the_same_junit_report() -> None:
    script = _exit5_mapper_script()
    assert "--junitxml=/tmp/ui-junit.xml" in script
    assert script.count("scripts/check_skip_allowlist.py --suite ui --allowlist tests/skip-allowlist.txt") == 2
    assert "tests/fixtures/skip-allowlist-canary.xml" in script
    assert script.index("tests/fixtures/skip-allowlist-canary.xml") < script.index("--junitxml=/tmp/ui-junit.xml")


def _run_exit5_mapper(
    tmp_path: Path, run_smoke_rc: int, pytest_filter: str, scope: str
) -> subprocess.CompletedProcess[str]:
    script = _exit5_mapper_script()
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir(exist_ok=True)
    run_smoke = scripts_dir / "run-smoke.sh"
    run_smoke.write_text(
        "#!/bin/sh\n"
        'for arg do case "$arg" in --junitxml=*) report=${arg#*=} ;; esac; done\n'
        'printf "<testsuites/>\\n" > "$report"\n'
        f"exit {run_smoke_rc}\n"
    )
    run_smoke.chmod(0o755)
    select_box = scripts_dir / "select-box.sh"
    select_box.write_text("#!/bin/sh\necho stub-run-id\n")
    select_box.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python3 = bin_dir / "python3"
    python3.write_text(
        "#!/bin/sh\n"
        'case "$*" in *skip-allowlist-canary.xml*) exit 1 ;; esac\n'
        "for report do :; done\n"
        '[ -s "$report" ] || exit 2\n'
    )
    python3.chmod(0o755)
    env = {
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "PYTEST_FILTER": pytest_filter,
        "SCOPE": scope,
        "MARKER": "ui_render",
        # The runner always provides GITHUB_WORKSPACE; the step's run body
        # derives its image/screenshot paths from it under set -eu (issue #2231).
        "GITHUB_WORKSPACE": str(tmp_path),
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


# =========================================================================== #
# release.yml (part 2): per-leg artifacts, live-gate wiring, publish gating
# =========================================================================== #


# --------------------------------------------------------------------------- #
# build-pkgs-portable: matrix-ified over read-matrix's build_matrix
# --------------------------------------------------------------------------- #


def test_build_pkgs_portable_matrixes_over_read_matrix_release_matrix() -> None:
    jobs = _jobs(RELEASE_WORKFLOW)
    assert "build-pkgs-portable" in jobs
    job_text = "\n".join(jobs["build-pkgs-portable"])
    assert "strategy:" in job_text, "build-pkgs-portable must gain a strategy.matrix"
    assert "fail-fast: false" in job_text
    assert "fromJson(needs.read-matrix.outputs.release_matrix)" in job_text, (
        f"build-pkgs-portable must matrix over read-matrix's release_matrix output, got:\n{job_text}"
    )


def test_build_pkgs_portable_per_row_upload_name_is_the_exact_contract() -> None:
    """Release artifact names carry the exact Variant/version row identity."""
    jobs = _jobs(RELEASE_WORKFLOW)
    steps = _split_into_steps(jobs["build-pkgs-portable"])
    upload_steps = [s for s in steps if any("uses: actions/upload-artifact" in line for line in s)]
    # issue #1806 B1: TWO upload steps now -- the branch .pkg (this test) and,
    # gated on this major's extra_pkgs being non-empty, its dep .pkg as a
    # SEPARATE artifact (see test_build_pkgs_portable_dep_pkg_upload_name_is_the_exact_contract).
    assert len(upload_steps) == 2, (
        f"expected exactly two upload-artifact steps in build-pkgs-portable, got {len(upload_steps)}"
    )
    pkg_step = next(s for s in upload_steps if any("pfBlockerNG-relpkg-${{ matrix.variant }}" in line for line in s))
    name_line = next(line for line in pkg_step if line.strip().startswith("name:"))
    assert "pfBlockerNG-relpkg-${{ matrix.variant }}-${{ matrix.pfsense_version }}" in name_line, (
        f"per-row upload name must carry Variant/version, got: {name_line}"
    )


def test_build_pkgs_portable_dep_pkg_upload_name_is_the_exact_contract() -> None:
    """issue #1806 B1: the dep-pkg artifact name mirrors the branch pkg's own
    per-major contract, with a 'deppkgs' segment inserted -- smoke.yml's/
    ui-tests.yml's pkg_artifact_prefix == 'pfBlockerNG-relpkg' download steps
    compose this exact literal. Gated (never an empty artifact when a major's
    extra_pkgs is empty)."""
    jobs = _jobs(RELEASE_WORKFLOW)
    steps = _split_into_steps(jobs["build-pkgs-portable"])
    upload_steps = [s for s in steps if any("uses: actions/upload-artifact" in line for line in s)]
    dep_step = next(s for s in upload_steps if any("deppkgs" in line for line in s))
    name_line = next(line for line in dep_step if line.strip().startswith("name:"))
    assert "pfBlockerNG-relpkg-deppkgs-${{ matrix.variant }}-${{ matrix.pfsense_version }}" in name_line, (
        f"dep-pkg upload name must carry Variant/version, got: {name_line}"
    )
    if_line = next((line for line in dep_step if line.strip().startswith("if:")), "")
    assert "HAS_DEP_PKGS" in if_line, f"dep-pkg upload must be gated (never an empty artifact), got: {if_line!r}"


def test_build_pkgs_portable_leg_step_carries_row_identity_and_abi() -> None:
    """The leg-naming job carries the exact Variant/version identity and ABI."""
    job_text = "\n".join(_jobs(RELEASE_WORKFLOW)["build-pkgs-portable"])
    assert "matrix.freebsd_major" in job_text
    assert "matrix.variant" in job_text
    assert "matrix.pfsense_version" in job_text
    assert "matrix.arch" not in job_text


def test_release_dependency_builder_receives_structured_reproducibility_inputs() -> None:
    workflow = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    build_steps = workflow["jobs"]["build-pkgs-portable"]["steps"]
    setup = next(step for step in build_steps if step.get("name") == "Set up the pinned dependency-package toolchain")
    sync = next(step for step in build_steps if step.get("name") == "Sync the locked dependency-package toolchain")
    record = next(step for step in build_steps if step.get("name") == "Write the destination-bound build record")
    build = next(step for step in build_steps if step.get("name") == "Build the .pkg via build-leg.sh")
    read_matrix_steps = workflow["jobs"]["read-matrix"]["steps"]
    pins = next(
        step for step in read_matrix_steps if step.get("name") == "Pin ci-metadata, ROUTE, and Ports identities"
    )
    pinned_builder = next(
        step for step in read_matrix_steps if step.get("name") == "Check out pinned dependency-builder source"
    )
    handoffs = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("name") == "Create tagged release handoff"
    ]

    assert setup["with"] == {"version": "0.12.6", "activate-environment": True}
    assert sync["run"] == "uv sync --locked --only-group dep-pkg-build"
    assert pinned_builder["uses"] == "actions/checkout@v6"
    assert pinned_builder["with"]["ref"] == (
        "${{ github.event.inputs.source == 'release/3.3' && github.workflow_sha || "
        "steps.destinations.outputs.source_sha }}"
    )
    assert pinned_builder["with"]["path"] == "pinned-builder"
    assert "scripts/" in pinned_builder["with"]["sparse-checkout"]
    assert "uv.lock" in pinned_builder["with"]["sparse-checkout"]
    assert 'python3 "$PINNED_BUILDER/scripts/build-dep-pkg-portable.py" --print-toolchain' in pins["run"]
    assert "python3 scripts/build-dep-pkg-portable.py --print-toolchain" not in pins["run"]
    assert "--print-port-identity" in pins["run"]
    assert "dependency_packages=${DEPENDENCY_PACKAGES}" in pins["run"]
    assert pins["env"]["INPUT_SOURCE"] == "${{ github.event.inputs.source }}"
    assert pins["env"]["SOURCE_SHA"] == "${{ steps.destinations.outputs.source_sha }}"
    assert "map(.extra_pkgs = [])" in pins["run"]
    assert {"CREATED", "DEPENDENCY_BUILDER", "EXTRA_PKGS"} <= record["env"].keys()
    assert '"source_date_epoch": int(os.environ["CREATED"])' in record["run"]
    assert 'if row["extra_pkgs"]:' in record["run"]
    assert 'record["dependency_builder"] = json.loads(os.environ["DEPENDENCY_BUILDER"])' in record["run"]
    assert 'record["build_input_digest"] = build_input_digest(record)' in record["run"]
    assert '--ports-sha "$PORTS_SHA"' in build["run"]
    assert '--source-date-epoch "$CREATED"' in build["run"]
    assert '"$DEP_PYTHON" scripts/build-dep-pkg-portable.py' in build["run"]
    assert "python3 scripts/build-dep-pkg-portable.py \\" not in build["run"]
    assert len(handoffs) == 1
    assert "DEPENDENCY_BUILDER" in handoffs[0]["env"]
    assert '--source-date-epoch "$(git show -s --format=%ct "$SOURCE_SHA")"' in handoffs[0]["run"]
    assert '--dependency-builder "$DEPENDENCY_BUILDER_FILE"' in handoffs[0]["run"]
    assert "DEPENDENCY_PACKAGES" in handoffs[0]["env"]
    assert '--dependency-packages "$DEPENDENCY_PACKAGES_FILE"' in handoffs[0]["run"]
    assert setup["if"] == "github.event.inputs.source != 'release/3.3'"
    assert sync["if"] == "github.event.inputs.source != 'release/3.3'"


# --------------------------------------------------------------------------- #
# attach-pkgs: merges every per-leg artifact by pattern
# --------------------------------------------------------------------------- #


_ARTIFACT_ACTION_RE = re.compile(r"uses:\s+actions/(?P<kind>upload|download)-artifact@v(?P<major>\d+)")


def test_attach_pkgs_downloads_every_leg_by_pattern_with_merge() -> None:
    jobs = _jobs(RELEASE_WORKFLOW)
    steps = _split_into_steps(jobs["attach-pkgs"])
    target = [s for s in steps if any("Download .pkg artifacts" in line for line in s)]
    assert len(target) == 1, "expected exactly one 'Download .pkg artifacts' step in attach-pkgs"
    step_text = "\n".join(target[0])
    assert "pattern: pfBlockerNG-relpkg-*" in step_text, step_text
    assert "merge-multiple: true" in step_text, step_text
    assert "continue-on-error:" not in step_text, (
        "attach-pkgs download must not continue-on-error (issue #2385):\n" + step_text
    )


def test_release_yml_upload_and_download_artifact_majors_match() -> None:
    """issue #2385: a download-artifact major behind upload-artifact misses the
    .pkg artifacts and used to publish a Release with none attached."""
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    uploads = [m.group("major") for m in _ARTIFACT_ACTION_RE.finditer(text) if m.group("kind") == "upload"]
    downloads = [m.group("major") for m in _ARTIFACT_ACTION_RE.finditer(text) if m.group("kind") == "download"]
    assert uploads, "release.yml must use actions/upload-artifact"
    assert downloads, "release.yml must use actions/download-artifact"
    assert len(set(uploads)) == 1, f"upload-artifact majors {sorted(set(uploads))} must be uniform"
    assert len(set(downloads)) == 1, f"download-artifact majors {sorted(set(downloads))} must be uniform"
    assert uploads[0] == downloads[0], (
        f"upload-artifact major {uploads[0]} must equal download-artifact major {downloads[0]}"
    )


def test_attach_pkgs_executes_tagged_handoff_package_validation(tmp_path: Path) -> None:
    script = _step_run_script(_step(_jobs(RELEASE_WORKFLOW)["attach-pkgs"], "Validate tagged handoff"))
    tag = "v4.0.0.b1"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    package = pkg_dir / "main.pkg"
    package.touch()
    handoff_source = tmp_path / "handoff-source.json"
    handoff_source.write_text("{}\n", encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "gh").write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = --dir ]; then shift; out=$1; fi\n'
        "  shift\n"
        "done\n"
        'mkdir -p "$out"\n'
        'cp "$HANDOFF_SOURCE" "$out/pfblockerng-release-handoff.json"\n',
        encoding="utf-8",
    )
    (fake_bin / "python3").write_text(
        '#!/bin/sh\nprintf \'%s\\0\' "$@" > "$VALIDATOR_LOG"\nexit "${VALIDATOR_EXIT:-0}"\n',
        encoding="utf-8",
    )
    for executable in (fake_bin / "gh", fake_bin / "python3"):
        executable.chmod(0o755)
    validator_log = tmp_path / "validator-argv"
    env = os.environ | {
        "GH_TOKEN": "test-token",
        "TAG": tag,
        "SOURCE_SHA": "a" * 40,
        "HANDOFF_SOURCE": str(handoff_source),
        "VALIDATOR_LOG": str(validator_log),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }

    completed = subprocess.run(["dash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert validator_log.read_bytes().split(b"\0")[:-1] == [
        b"scripts/tagged_release_handoff.py",
        b"validate-packages",
        b"--handoff",
        b"provenance/pfblockerng-release-handoff.json",
        b"--release-tag",
        tag.encode(),
        b"--source-sha",
        b"a" * 40,
        b"pkgs/main.pkg",
    ]

    env["VALIDATOR_EXIT"] = "7"
    failed = subprocess.run(["dash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert failed.returncode == 7, failed.stdout + failed.stderr


def test_attach_pkgs_empty_pkgs_fails_the_step(tmp_path: Path) -> None:
    """issue #2385: empty pkgs/ (download miss) must fail attach, not exit 0."""
    script = _step_run_script(_step(_jobs(RELEASE_WORKFLOW)["attach-pkgs"], "Append .pkg files"))
    empty_branch = re.search(r'if \[ -z "\$PKGS" \]; then(?P<body>.*?)\n\s*fi', script, re.DOTALL)
    assert empty_branch is not None, script
    assert "exit 0" not in empty_branch.group("body"), empty_branch.group("body")
    assert re.search(r'find pkgs -type f -name "\*\.pkg"', script), script

    (tmp_path / "pkgs").mkdir()
    (tmp_path / "pkgs" / "empty.pkg").mkdir()
    completed = subprocess.run(
        ["dash", "-c", script],
        cwd=tmp_path,
        env=os.environ | {"GH_TOKEN": "test-token", "TAG": "v4.0.0.a1"},
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_attach_pkgs_upload_step_runs_under_posix_sh(tmp_path: Path) -> None:
    script = _step_run_script(_step(_jobs(RELEASE_WORKFLOW)["attach-pkgs"], "Append .pkg files"))
    assert "read -r -d" not in script
    pkg_dir = tmp_path / "pkgs" / "CE row;safe"
    pkg_dir.mkdir(parents=True)
    packages = [pkg_dir / "first package.pkg", pkg_dir / "second.pkg"]
    for package in packages:
        package.touch()

    fake_bin = tmp_path / "fake bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    fake_gh.write_text('#!/bin/sh\nprintf \'%s\\0\' "$@" >> "$UPLOAD_LOG"\n', encoding="utf-8")
    fake_gh.chmod(0o755)
    upload_log = tmp_path / "uploads"
    env = os.environ | {
        "GH_TOKEN": "test-token",
        "TAG": "v4.0.0.a1",
        "UPLOAD_LOG": str(upload_log),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }

    completed = subprocess.run(
        ["dash", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    args = upload_log.read_bytes().split(b"\0")[:-1]
    calls = {tuple(args[offset : offset + 5]) for offset in range(0, len(args), 5)}
    assert calls == {
        (b"release", b"upload", b"v4.0.0.a1", os.fsencode(package.relative_to(tmp_path)), b"--clobber")
        for package in packages
    }

    fake_gh.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    failed = subprocess.run(["dash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert failed.returncode != 0, failed.stdout + failed.stderr


# --------------------------------------------------------------------------- #
# ui-suite / smoke-suite: re-enabled, gated on build-pkgs-portable, exact prefix
# --------------------------------------------------------------------------- #


def test_ui_suite_is_no_longer_hard_disabled() -> None:
    jobs = _jobs(RELEASE_WORKFLOW)
    job_lines = jobs["ui-suite"]
    if_line = next((line for line in job_lines if line.strip().startswith("if:")), None)
    assert if_line is not None, "ui-suite must carry an if: condition gating it on the upstream jobs"
    assert if_line.strip() != "if: false", f"ui-suite must no longer be hard-disabled, got: {if_line}"


@pytest.mark.parametrize("job_name", ["ui-suite", "smoke-suite"])
def test_suite_job_if_condition_shape(job_name: str) -> None:
    jobs = _jobs(RELEASE_WORKFLOW)
    assert job_name in jobs, f"release.yml must have a {job_name} job"
    job_lines = jobs[job_name]
    if_line = next((line for line in job_lines if line.strip().startswith("if:")), None)
    assert if_line is not None, f"{job_name} must carry an if: condition"
    assert "!cancelled()" in if_line
    assert "needs.build-pkgs-portable.result == 'success'" in if_line


@pytest.mark.parametrize("job_name", ["ui-suite", "smoke-suite"])
def test_suite_job_needs_build_pkgs_portable(job_name: str) -> None:
    jobs = _jobs(RELEASE_WORKFLOW)
    needs_line = next(line for line in jobs[job_name] if line.strip().startswith("needs:"))
    assert "build-pkgs-portable" in needs_line, f"{job_name} must need build-pkgs-portable, got: {needs_line}"


@pytest.mark.parametrize("job_name", ["ui-suite", "smoke-suite"])
def test_suite_job_carries_the_exact_pkg_artifact_prefix(job_name: str) -> None:
    jobs = _jobs(RELEASE_WORKFLOW)
    job_text = "\n".join(jobs[job_name])
    assert "pkg_artifact_prefix: pfBlockerNG-relpkg" in job_text, (
        f"{job_name} must pass the literal pkg_artifact_prefix: pfBlockerNG-relpkg, got:\n{job_text}"
    )
    assert "secrets: inherit" in job_text


@pytest.mark.parametrize("job_name", ["ui-suite", "smoke-suite"])
def test_suite_job_pins_scope_full(job_name: str) -> None:
    """A silent `scope: full` -> `scope: impacted` regression would quietly
    narrow release qualification to a selective run -- where the ui job's
    exit-5 mapper (see test_exit5_impacted_scope_is_benign above) treats a
    zero-selected-tests run as a PASS instead of a failure. Pinning scope
    here is what makes that exit-5 tolerance safe."""
    jobs = _jobs(RELEASE_WORKFLOW)
    job_text = "\n".join(jobs[job_name])
    assert "scope: full" in job_text, f"{job_name} must pin scope: full, got:\n{job_text}"


def test_ui_suite_pins_tier_all() -> None:
    """A silently-dropped `tier: all` would narrow the release-gating UI
    fan-out to a subset of CI legs -- same silent-scope-narrowing risk
    scope: full guards against above."""
    jobs = _jobs(RELEASE_WORKFLOW)
    job_text = "\n".join(jobs["ui-suite"])
    assert "tier: all" in job_text, f"ui-suite must pin tier: all, got:\n{job_text}"


@pytest.mark.parametrize("job_name", ["ui-suite", "smoke-suite"])
def test_suite_jobs_carry_no_dry_run_reference(job_name: str) -> None:
    """ADR-14 D1 / dry-run parity: these run in BOTH modes, so they must reference
    dry_run nowhere in their job body (they are deliberately kept OUT of the
    MUTATION_JOBS set in test_release_dry_run_gate.py)."""
    jobs = _jobs(RELEASE_WORKFLOW)
    job_text = "\n".join(jobs[job_name])
    assert "dry_run" not in job_text, f"{job_name} must carry NO dry_run reference, got:\n{job_text}"


# --------------------------------------------------------------------------- #
# tag-release: the single suite AND-gate seam; everything after inherits it
#
# issue #1855 moved verification BEFORE tagging, so the live-suite AND-gate now
# hangs off `tag-release` -- the first irreversible-on-GitHub job. The draft, its
# assets and the draft healthcheck stay gated transitively (release needs
# tag-release, attach-pkgs needs release, draft-healthcheck needs attach-pkgs);
# tests/test_release_tag_after_verify.py walks that whole graph.
# --------------------------------------------------------------------------- #


def test_tag_release_needs_both_suites() -> None:
    jobs = _jobs(RELEASE_WORKFLOW)
    assert "tag-release" in jobs, "release.yml must have a tag-release job"
    needs_line = next(line for line in jobs["tag-release"] if line.strip().startswith("needs:"))
    assert "ui-suite" in needs_line and "smoke-suite" in needs_line, f"got: {needs_line}"


def test_tag_release_if_gates_on_every_upstream_result_and_retains_dry_run_false() -> None:
    """The `if:` string is the WHOLE gate — `needs:` edges gate nothing here.

    Because `tag-release` opens with a status function, GitHub drops the implicit
    `success()` and runs the job whatever its `needs:` produced; every term that
    actually holds the tag back lives in this one string. Dropping the build term is the
    incident class this work exists to close: for an alpha/beta there is no suite gate
    to fall back on, so a failed build would push the tag anyway. The prepare and
    read-matrix terms carry the same weight — the pinned SHA and the `run_suites`
    decision are only trustworthy if the jobs that produced them succeeded.
    """
    jobs = _jobs(RELEASE_WORKFLOW)
    if_block = _job_if_block(jobs["tag-release"])
    for term in (
        "needs.prepare-release.result == 'success'",
        "needs.read-matrix.result == 'success'",
        "needs.build-pkgs-portable.result == 'success'",
        "needs.ui-suite.result == 'success'",
        "needs.smoke-suite.result == 'success'",
        "dry_run == 'false'",
    ):
        assert term in if_block, f"tag-release's gate lost `{term}`: {if_block}"


def test_draft_healthcheck_retains_the_dry_run_false_gate() -> None:
    jobs = _jobs(RELEASE_WORKFLOW)
    if_line = next(line for line in jobs["draft-healthcheck"] if line.strip().startswith("if:"))
    assert "dry_run == 'false'" in if_line, if_line


# --------------------------------------------------------------------------- #
# issue #1859: the suites test the code they ship
#
# The package under test comes from the pinned release SHA; without an explicit
# ref the suites checked out the CALLER's dispatch ref, so a commit landing
# during a ~hour-long live fan-out meant the release was verified by test code
# that is not in the release. A blank checkout_ref keeps every non-release
# caller inheriting its own ref, exactly as before.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("workflow", [UI_WORKFLOW, SMOKE_WORKFLOW, SMOKE_SINGLE_WORKFLOW])
def test_checkout_ref_input_declared_in_both_trigger_blocks(workflow: Path) -> None:
    call_block, dispatch_block = _trigger_blocks(workflow)
    for name, block in (("workflow_call", call_block), ("workflow_dispatch", dispatch_block)):
        assert "checkout_ref:" in block, f"{workflow.name}: {name} is missing checkout_ref"
        sub = _input_block(block, "checkout_ref")
        assert re.search(r"^\s*default:\s*\"\"\s*$", sub, re.MULTILINE), (
            f"{workflow.name}: {name}'s checkout_ref must default to '' -- block was:\n{sub}"
        )


def test_smoke_threads_the_checkout_ref_down_to_the_leg() -> None:
    """smoke.yml runs no tests itself; the leg that does is smoke-single.yml."""
    job_text = "\n".join(_jobs(SMOKE_WORKFLOW)["smoke"])
    assert "checkout_ref: ${{ inputs.checkout_ref }}" in job_text, job_text


@pytest.mark.parametrize(
    ("workflow", "job"),
    [(UI_WORKFLOW, "ui"), (SMOKE_SINGLE_WORKFLOW, "smoke")],
)
def test_the_test_running_job_checks_out_the_requested_ref(workflow: Path, job: str) -> None:
    checkout = _step(_jobs(workflow)[job], "uses: actions/checkout")
    step_text = "\n".join(checkout)
    assert "ref: ${{ inputs.checkout_ref }}" in step_text, (
        f"{workflow.name}:{job} must honour checkout_ref, got:\n{step_text}"
    )


@pytest.mark.parametrize("job_name", ["ui-suite", "smoke-suite"])
def test_release_suites_verify_the_pinned_commit(job_name: str) -> None:
    job_text = "\n".join(_jobs(RELEASE_WORKFLOW)[job_name])
    assert "checkout_ref: ${{ needs.prepare-release.outputs.sha }}" in job_text, job_text


# --------------------------------------------------------------------------- #
# issue #1855 Part 2: only a RELEASED-status row may veto a release
#
# `release_gate: true` (release.yml only) makes resolve-legs.sh stamp every leg
# with release_blocking; a demoted leg still RUNS and still REPORTS, it just
# cannot fail the suite call. The predicate itself lives in ONE place --
# scripts/resolve-legs.sh, pinned by tests/shell/resolve_legs_spec.sh.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("workflow", [UI_WORKFLOW, SMOKE_WORKFLOW])
def test_release_gate_input_declared_in_both_trigger_blocks(workflow: Path) -> None:
    call_block, dispatch_block = _trigger_blocks(workflow)
    for name, block in (("workflow_call", call_block), ("workflow_dispatch", dispatch_block)):
        assert "release_gate:" in block, f"{workflow.name}: {name} is missing release_gate"
        sub = _input_block(block, "release_gate")
        assert re.search(r"^\s*default:\s*false\s*$", sub, re.MULTILINE), (
            f"{workflow.name}: {name}'s release_gate must default to false -- block was:\n{sub}"
        )


@pytest.mark.parametrize("workflow", [UI_WORKFLOW, SMOKE_WORKFLOW])
def test_prepare_threads_release_gate_into_resolve_legs(workflow: Path) -> None:
    job_text = "\n".join(_jobs(workflow)["prepare"])
    assert "RELEASE_GATE_INPUT: ${{ inputs.release_gate }}" in job_text, (
        f"{workflow.name}: prepare must thread release_gate into resolve-legs.sh, got:\n{job_text}"
    )


def test_ui_prepare_projects_release_blocking_onto_every_matrix_entry() -> None:
    job_text = "\n".join(_jobs(UI_WORKFLOW)["prepare"])
    assert "release_blocking" in job_text, (
        "ui-tests.yml's (tier x leg) matrix projection must carry release_blocking through"
    )


def test_ui_leg_is_non_blocking_when_its_row_is_demoted() -> None:
    """A demoted UI leg runs, reports red, and does NOT fail the suite call."""
    job_lines = _jobs(UI_WORKFLOW)["ui"]
    coe = next((line for line in job_lines if line.strip().startswith("continue-on-error:")), None)
    assert coe is not None, "the ui job must carry a continue-on-error demotion switch"
    assert "matrix.release_blocking == 'false'" in coe, coe


def test_smoke_leg_threads_nonblocking_into_smoke_single() -> None:
    """smoke.yml's fan-out is a reusable-workflow CALL, and GitHub forbids
    continue-on-error on a `uses:` job -- so the demotion rides into smoke-single.yml
    as an input and is applied on ITS job instead."""
    job_text = "\n".join(_jobs(SMOKE_WORKFLOW)["smoke"])
    assert "nonblocking: ${{ matrix.release_blocking == 'false' }}" in job_text, job_text


def test_smoke_single_demotes_a_nonblocking_leg() -> None:
    jobs = _jobs(SMOKE_SINGLE_WORKFLOW)
    job_lines = jobs["smoke"]
    coe = next((line for line in job_lines if line.strip().startswith("continue-on-error:")), None)
    assert coe is not None, "smoke-single.yml's smoke job must carry the demotion switch"
    assert "inputs.nonblocking" in coe, coe
    call_block, _dispatch = _trigger_blocks(SMOKE_SINGLE_WORKFLOW)
    assert "nonblocking:" in call_block, "smoke-single.yml must declare the nonblocking input"


def test_all_smoke_passed_zero_selection_check_skips_demoted_legs() -> None:
    """The #1767 whole-leg zero-selection assert must not resurrect the veto: a demoted
    leg that died before uploading its marker would otherwise fail the AND gate."""
    job_text = "\n".join(_jobs(SMOKE_WORKFLOW)["all-smoke-passed"])
    assert 'release_blocking != "false"' in job_text, job_text


@pytest.mark.parametrize("job_name", ["ui-suite", "smoke-suite"])
def test_release_suites_turn_the_released_status_gate_on(job_name: str) -> None:
    job_text = "\n".join(_jobs(RELEASE_WORKFLOW)[job_name])
    assert "release_gate: true" in job_text, f"{job_name} must ask for the released-status gate, got:\n{job_text}"


# --------------------------------------------------------------------------- #
# Cross-contract consistency: release-side naming == part-1 consumer-side naming
#
# issue #2143: the release-side artifact name is a DIRECT
# `pfBlockerNG-relpkg-${{ matrix.variant }}-${{ matrix.pfsense_version }}` template. This test
# LIFTS the leg-naming step's `run:` body straight out of release.yml and
# executes it under sh for every DISTINCT freebsd_major in the real build
# matrix, comparing the emitted ABI + LEG shape and the release/ui/smoke
# artifact names against the consumer-side format(...) templates parsed out
# of the real ui-tests.yml / smoke.yml text.
# --------------------------------------------------------------------------- #


def _leg_step() -> list[str]:
    jobs = _jobs(RELEASE_WORKFLOW)
    steps = _split_into_steps(jobs["build-pkgs-portable"])
    target = [s for s in steps if any("Compute this leg's LEG/ABI" in line for line in s)]
    assert len(target) == 1, 'expected exactly one "Compute this leg\'s LEG/ABI" step'
    return target[0]


def _run_leg_step(tmp_path: Path, row: dict[str, str]) -> dict[str, str]:
    """Execute the REAL leg-naming step's `run:` body (lifted verbatim) under sh,
    with a real $GITHUB_OUTPUT file, and return the parsed step outputs."""
    script = _step_run_script(_leg_step())
    output_file = tmp_path / f"github_output_{row['variant']}_{row['version']}"
    output_file.write_text("")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "MAJOR": row["freebsd_major"],
        "VARIANT": row["variant"],
        "PFSENSE_VERSION": row["version"],
        "GITHUB_OUTPUT": str(output_file),
    }
    completed = subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        env=env,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    outputs: dict[str, str] = {}
    for line in output_file.read_text().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            outputs[key] = value
    return outputs


def _extract_first_format_call(text: str) -> tuple[str, list[str]]:
    """Parse the FIRST `format('tmpl', arg, arg, ...)` GH-expression call out of
    `text` (balanced-paren scan -- ui-tests.yml's download name: line has a SECOND
    format(...) call in its blank-prefix fallback branch, so a naive regex greedy
    match would swallow both). Returns (template, [arg-expr, ...])."""
    start = text.index("format(") + len("format(")
    depth = 1
    i = start
    while depth > 0:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
        i += 1
    inner = text[start : i - 1]
    m = re.match(r"'([^']*)'\s*,\s*(.*)$", inner, re.DOTALL)
    assert m is not None, f"cannot parse format(...) call args: {inner!r}"
    template = m.group(1)
    args = [a.strip() for a in m.group(2).split(",")]
    return template, args


def _resolve_matrix_arg(expr: str, row: dict[str, str]) -> str:
    """Resolve one GH-expression argument -- as parsed out of the real
    ui-tests.yml/smoke.yml text -- to the string it evaluates to for `row`."""
    if expr == "inputs.pkg_artifact_prefix":
        return "pfBlockerNG-relpkg"
    if expr == "matrix.freebsd_major":
        return row["freebsd_major"]
    if expr == "matrix.variant":
        return row["variant"]
    if expr in ("matrix.version", "matrix.pfsense_version"):
        return row["version"]
    raise AssertionError(f"unrecognised matrix arg expression in a consumer-side format(...) call: {expr!r}")


def _consumer_side_names(row: dict[str, str]) -> tuple[str, str]:
    """(ui-tests.yml download name, smoke.yml pkg_artifact prefix-set branch) for
    `row`, computed from the format(...) templates parsed out of the REAL workflow
    text -- never a hardcoded literal."""
    ui_jobs = _jobs(UI_WORKFLOW)
    ui_steps = _split_into_steps(ui_jobs["ui"])
    dl_step = next(s for s in ui_steps if any("Download the built pfBlockerNG package" in line for line in s))
    ui_name_line = next(line for line in dl_step if line.strip().startswith("name:"))
    ui_template, ui_args = _extract_first_format_call(ui_name_line)
    ui_name = ui_template.format(*(_resolve_matrix_arg(a, row) for a in ui_args))

    smoke_jobs = _jobs(SMOKE_WORKFLOW)
    pkg_artifact_line = next(line for line in smoke_jobs["smoke"] if "pkg_artifact:" in line and "with" not in line)
    smoke_template, smoke_args = _extract_first_format_call(pkg_artifact_line)
    smoke_name = smoke_template.format(*(_resolve_matrix_arg(a, row) for a in smoke_args))

    return ui_name, smoke_name


def _cross_contract_rows() -> list[dict[str, str]] | None:
    """Real per-version CI rows, read via read-version-matrix.sh --print-ci
    (reads the already-fetched origin/ci-metadata ref, no network
    needed once it's present). Returns None when the ref is unreachable in this
    environment (a graceful skip contract) -- callers must skip, never fabricate
    rows."""
    try:
        proc = subprocess.run(  # noqa: S603
            ["sh", "scripts/read-version-matrix.sh", "--print-ci"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        matrix = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(matrix, list) or not matrix:
        return None
    return [
        {
            "freebsd_major": str(entry["freebsd_major"]),
            "variant": str(entry["variant"]),
            "version": str(entry["pfsense_version"]),
        }
        for entry in matrix
    ]


def test_release_side_artifact_name_matches_both_consumer_sides(tmp_path: Path) -> None:
    """For every real release row, execute
    the REAL leg-naming step (a sanity check that it still runs + emits a usable
    ABI/LEG) and assert the LITERAL release-side artifact name
    (pfBlockerNG-relpkg-<Variant>-<version>) equals BOTH ui-tests.yml's download name AND
    smoke.yml's pkg_artifact prefix-set branch -- computed from the real
    format(...) templates in those files."""
    rows = _cross_contract_rows()
    if rows is None:
        pytest.skip("ci-metadata matrix not available in this environment -- skipping real-matrix rows")
        # Editors that know pytest.skip() is NoReturn flag this `return` as unreachable.
        # It is not removable: mypy does NOT narrow through the skip, so without it `rows`
        # stays `list[...] | None` at the loop below and `mypy tests/` fails with
        # union-attr. Keep it until the gate's analyser learns the NoReturn.
        return

    failures: list[str] = []
    for row in rows:
        outputs = _run_leg_step(tmp_path, row)
        assert outputs.get("abi") == f"FreeBSD:{row['freebsd_major']}:amd64", (
            f"row {row}: leg step emitted an unexpected abi: {outputs!r}"
        )
        release_side_name = f"pfBlockerNG-relpkg-{row['variant']}-{row['version']}"
        ui_name, smoke_name = _consumer_side_names(row)
        if not (release_side_name == ui_name == smoke_name):
            failures.append(f"row {row}: release={release_side_name!r} ui={ui_name!r} smoke={smoke_name!r}")
    assert not failures, "producer/consumer artifact-name mismatch:\n" + "\n".join(failures)


def test_release_channel_metadata_and_edge_following_do_not_start_a_second_release() -> None:
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    published = PUBLISHED_WORKFLOW.read_text(encoding="utf-8")
    assert "pfBlockerNG-Release-Channel" in release, release
    assert "pfBlockerNG-Release-Channel" in published, published
    assert "workflow_dispatch" not in published, published
    assert "release.yml" not in published, published
    assert "build-pkg" not in published, published


def test_tagged_release_recipe_never_mutates_the_nightly_port() -> None:
    published = PUBLISHED_WORKFLOW.read_text(encoding="utf-8")
    sync = extract_between(published, "\n  sync-ports-fork:\n", "\n  publish-pkg:\n")
    assert "pfSense-pkg-pfBlockerNG-nightly" not in sync, sync
    assert 'PORT_PATHS="net/pfSense-pkg-pfBlockerNG-devel net/pfSense-pkg-pfBlockerNG-nightly"' not in published


def test_smoke_single_nightly_fixture_uses_utc_timestamp_and_source_sha() -> None:
    text = SMOKE_SINGLE_WORKFLOW.read_text(encoding="utf-8")
    nightly = extract_between(text, "- name: Build a nightly .pkg", "\n      # ADR-24")
    assert 'SOURCE_SHA="$(git rev-parse HEAD)"' in nightly, nightly
    assert 'NIGHTLY_VERSION="$(sh scripts/nightly-pkgversion.sh "$SOURCE_SHA")"' in nightly, nightly
    assert '--annotate   "commit=${SOURCE_SHA}"' in nightly, nightly
    assert "github.sha" not in nightly, nightly
    assert "NIGHTLY_COUNT" not in nightly, nightly
    assert "20260606" not in nightly, nightly


# --------------------------------------------------------------------------- #
# draft-healthcheck: EXPECTED_PKGS floor (issue #1662 I1)
# --------------------------------------------------------------------------- #


def _healthcheck_script() -> str:
    jobs = _jobs(RELEASE_WORKFLOW)
    steps = _split_into_steps(jobs["draft-healthcheck"])
    target = [s for s in steps if any("Health-check the draft release is complete" in line for line in s)]
    assert len(target) == 1, "expected exactly one 'Health-check the draft release is complete' step"
    script = _step_run_script(target[0])
    # This step (uniquely among the ones lifted in this file) inlines
    # `${{ github.repository }}` directly in its run: body instead of routing it
    # through the step's env: block, so GH Actions would normally template it away
    # before the shell ever runs. Substitute a fixed value -- the gh stub below
    # never inspects REPO, so this has no bearing on the logic under test.
    return script.replace("${{ github.repository }}", "owner/repo")


def _run_healthcheck(
    tmp_path: Path,
    build_matrix: str,
    assets_json: str,
    *,
    is_draft: bool = True,
    source: str = "release/4.0",
    handoff_count: int = 1,
) -> subprocess.CompletedProcess[str]:
    script = _healthcheck_script()
    assets = json.loads(assets_json)
    assets.extend({"name": "pfblockerng-release-handoff.json"} for _ in range(handoff_count))
    assets_json = json.dumps(assets, separators=(",", ":"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh_stub = bin_dir / "gh"
    response = f'{{"isDraft":{str(is_draft).lower()},"name":"Test Release","body":"body text","assets":{assets_json}}}'
    gh_stub.write_text(f"#!/bin/sh\necho '{response}'\n")
    gh_stub.chmod(0o755)
    env = {
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "GH_TOKEN": "stub-token",
        "TAG": "v0.0.0-test",
        "BUILD_MATRIX": build_matrix,
        "PORTVERSION": "4.0.0",
        "SOURCE": source,
    }
    return subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        env=env,
        capture_output=True,
        text=True,
    )


def test_healthcheck_empty_build_matrix_fails_closed(tmp_path: Path) -> None:
    """Issue #1662 I1: an empty build matrix (EXPECTED_PKGS=0) must fail the
    healthcheck, not sail through because PKG_COUNT (also 0 -- no .pkg assets on
    the draft) happens to equal EXPECTED_PKGS."""
    completed = _run_healthcheck(
        tmp_path,
        build_matrix="[]",
        assets_json='[{"name":"pfBlockerNG-src.tar.gz"}]',
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_healthcheck_rejects_published_stale_release(tmp_path: Path) -> None:
    completed = _run_healthcheck(
        tmp_path,
        build_matrix='[{"variant":"CE","pfsense_version":"2.8"}]',
        assets_json='[{"name":"pfBlockerNG-src.tar.gz"},{"name":"pfSense-pkg-pfBlockerNG-4.0.0-CE-2.8.pkg"}]',
        is_draft=False,
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("handoff_count", [0, 2])
def test_healthcheck_requires_exactly_one_tagged_handoff(tmp_path: Path, handoff_count: int) -> None:
    completed = _run_healthcheck(
        tmp_path,
        build_matrix='[{"variant":"CE","pfsense_version":"2.8"}]',
        assets_json='[{"name":"pfBlockerNG-src.tar.gz"},{"name":"pfSense-pkg-pfBlockerNG-4.0.0-CE-2.8.pkg"}]',
        handoff_count=handoff_count,
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_healthcheck_nonempty_matrix_with_matching_pkgs_still_passes(tmp_path: Path) -> None:
    """The new floor must not disturb the healthy path: a non-empty matrix whose
    .pkg count matches the draft's still passes."""
    completed = _run_healthcheck(
        tmp_path,
        build_matrix='[{"variant":"CE","pfsense_version":"2.8"}]',
        assets_json='[{"name":"pfBlockerNG-src.tar.gz"},{"name":"pfSense-pkg-pfBlockerNG-4.0.0-CE-2.8.pkg"}]',
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_healthcheck_rejects_wrong_main_asset_when_pkg_count_matches(tmp_path: Path) -> None:
    completed = _run_healthcheck(
        tmp_path,
        build_matrix='[{"variant":"CE","pfsense_version":"2.8"}]',
        assets_json='[{"name":"pfBlockerNG-src.tar.gz"},{"name":"pfSense-pkg-pfBlockerNG-4.0.0-Plus-2.8.pkg"}]',
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_healthcheck_counts_extra_pkgs_dep_assets_too(tmp_path: Path) -> None:
    """issue #1806 B1 (delta review finding): attach-pkgs's pfBlockerNG-relpkg-*
    sweep ALSO attaches each row's dep .pkg artifact
    (pfBlockerNG-relpkg-deppkgs-<Variant>-<version>) -- a deliberate release asset, not
    a leak. EXPECTED_PKGS must count those too, or a release with any major's
    extra_pkgs non-empty (CE today) fails this healthcheck and gets stuck as a
    draft even though every expected asset IS present (dry-run CI never
    exercises attach/publish, so no workflow run catches this pre-merge).

    Two build-matrix rows: major 15 with one extra_pkgs entry, major 16 with
    none. Draft carries exactly 2 branch .pkgs + 1 dep .pkg (the CE dep) + the
    source archive -- a fully complete, correct draft. Must pass.
    """
    completed = _run_healthcheck(
        tmp_path,
        build_matrix=(
            '[{"variant":"CE","pfsense_version":"2.8","extra_pkgs":["textproc/py-charset-normalizer"]},'
            '{"variant":"Plus","pfsense_version":"26.03","extra_pkgs":[]}]'
        ),
        assets_json=(
            '[{"name":"pfBlockerNG-src.tar.gz"},'
            '{"name":"pfSense-pkg-pfBlockerNG-4.0.0-CE-2.8.pkg"},'
            '{"name":"pfSense-pkg-pfBlockerNG-4.0.0-Plus-26.03.pkg"},'
            '{"name":"py311-charset-normalizer-3.4.4-CE-2.8.pkg"}]'
        ),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_healthcheck_release_33_ignores_matrix_extra_packages(tmp_path: Path) -> None:
    completed = _run_healthcheck(
        tmp_path,
        build_matrix=(
            '[{"variant":"CE","pfsense_version":"2.8","extra_pkgs":["textproc/py-charset-normalizer"]},'
            '{"variant":"Plus","pfsense_version":"26.03","extra_pkgs":[]}]'
        ),
        assets_json=(
            '[{"name":"pfBlockerNG-src.tar.gz"},'
            '{"name":"pfSense-pkg-pfBlockerNG-4.0.0-CE-2.8.pkg"},'
            '{"name":"pfSense-pkg-pfBlockerNG-4.0.0-Plus-26.03.pkg"}]'
        ),
        source="release/3.3",
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_healthcheck_receives_the_release_source_binding() -> None:
    step = "\n".join(_step(_jobs(RELEASE_WORKFLOW)["draft-healthcheck"], "Health-check the draft release"))
    assert "SOURCE:       ${{ needs.release.outputs.source }}" in step
