"""Pin fail-closed `dry_run` handling for draft-workflow mutation jobs."""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

from tests._workflow_steps import extract_between

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"

# Current jobs that create or mutate draft-workflow artifacts. Published-release
# effects are not among them: `release-published.yml` has no dispatch dry-run mode.
MUTATION_JOBS = {
    "prepare-release",
    "tag-release",
    "release",
    "attach-pkgs",
    "draft-healthcheck",
}

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$")
# Any string-compared fail-open shape: dry_run != 'true' / != "true", regardless
# of which context reads it (github.event.inputs / steps.*.outputs / needs.*.outputs).
_FAIL_OPEN_RE = re.compile(r"dry_run\s*!=\s*['\"]true['\"]")
# A step starts at a `- ` list item at step indent (6 spaces inside a job body).
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


def _dry_run_expressions(job_lines: list[str]) -> list[str]:
    """Every live (non-comment) line in a job body that reads `dry_run`.

    Covers every consumption form named in issue #1661: `github.event.inputs.dry_run`,
    `inputs.dry_run`, `steps.*.outputs.dry_run`, and `needs.release.outputs.dry_run`
    -- whichever forms the line actually uses, not a fixed list of contexts. Deliberately
    does NOT require the `${{ }}` wrapper: a job/step-level `if:` value is itself an
    expression and is commonly written bare (e.g. `if: needs.release.outputs.dry_run
    != 'true'`), so requiring `${{` would silently miss exactly the gates this test
    exists to check.
    """
    return [line.strip() for line in job_lines if "dry_run" in line and not line.strip().startswith("#")]


def _split_into_steps(job_lines: list[str]) -> list[list[str]]:
    """Group a job body into its steps, so a per-step assertion is bounded by the step
    itself rather than by a line count that rots as comments are added around it."""
    steps: list[list[str]] = []
    for line in job_lines:
        if _STEP_HEADER_RE.match(line):
            steps.append([])
        if steps:
            steps[-1].append(line)
    return steps


def _parsed_jobs() -> dict[str, list[str]]:
    return _split_into_jobs(_jobs_section_lines(WORKFLOW.read_text(encoding="utf-8")))


def test_mutation_jobs_exist_in_the_workflow() -> None:
    # Sanity check on the fixture itself: if a job in MUTATION_JOBS gets renamed
    # or removed, fail here with a clear message rather than a confusing
    # false-negative in the gate assertions below.
    jobs = _parsed_jobs()
    missing = MUTATION_JOBS - jobs.keys()
    assert not missing, f"expected job(s) not found in release.yml: {missing}"


# Jobs that are safe to run unmodified in dry-run mode: never skipped by mode, never
# gate a step on `dry_run == 'false'`. Some are dry-run-AWARE (they read dry_run to
# pick which git ref to check out) without being dry-run-GATED -- that distinction is
# what the assertion below checks, not textual absence of the string "dry_run".
DRY_RUN_SAFE_JOBS = frozenset(
    {
        "read-matrix",  # reads the build matrix from repo state; no external effect
        # issue #1855: both of these now check out prepare-release's PINNED SHA (the tag
        # does not exist yet at build time), falling back to the dispatch ref in dry-run --
        # a needs-output value pick, no dry_run reference at all, still unconditional.
        "resolve-stamp",
        "build-pkgs-portable",
        "ui-suite",  # runs the browser UI test suite against a built artifact
        "smoke-suite",  # runs the live-VM smoke suite against a built artifact
    }
)

# A job-level `if:` sits at 4-space indent directly under the job key (2-space indent);
# a step-level `if:` sits deeper, inside a step body. Distinguishing the two is exactly
# what tells a mode-aware-but-unconditional job (safe) apart from a mode-gated one (not).
_JOB_LEVEL_IF_DRY_RUN_RE = re.compile(r"^ {4}if:.*dry_run")
_STEP_IF_FALSE_RE = re.compile(r"if:.*dry_run\s*==\s*'false'")


def _job_level_if_references_dry_run(job_lines: list[str]) -> bool:
    """True if the JOB ITSELF can be skipped based on dry_run (unsafe for DRY_RUN_SAFE_JOBS)."""
    return any(_JOB_LEVEL_IF_DRY_RUN_RE.match(line) for line in job_lines)


def _has_step_level_false_gate(job_lines: list[str]) -> bool:
    """True if any STEP inside the job is gated on `if: ... dry_run == 'false' ...`.

    A `ref: ${{ dry_run == 'false' && tag || github.ref }}` line is a mode-aware value
    pick, not a gate -- it does not start with `if:`, so it is deliberately not matched.
    """
    return any(_STEP_IF_FALSE_RE.search(line) for step in _split_into_steps(job_lines) for line in step)


def test_every_job_is_classified_for_dry_run() -> None:
    """Every top-level job must be in exactly one of MUTATION_JOBS / DRY_RUN_SAFE_JOBS.

    Closes the other half of the #1661 gap: a brand-new job that mutates something but
    was never added to MUTATION_JOBS (or a safe job that quietly becomes mode-gated) is
    invisible to every other test in this file, since they all iterate MUTATION_JOBS
    rather than scanning the workflow's actual job list. This test is the one that scans
    the job list itself.
    """
    jobs = _parsed_jobs()
    all_jobs = set(jobs.keys())
    classified = MUTATION_JOBS | DRY_RUN_SAFE_JOBS

    unclassified = all_jobs - classified
    assert not unclassified, (
        f"job(s) not classified into MUTATION_JOBS or DRY_RUN_SAFE_JOBS -- add each to "
        f"whichever set matches (with a WHY comment for a safe job): {unclassified}"
    )
    stale = classified - all_jobs
    assert not stale, f"classified job(s) no longer exist in release.yml: {stale}"

    mode_gated_safe_jobs = {
        job
        for job in DRY_RUN_SAFE_JOBS
        if _job_level_if_references_dry_run(jobs[job]) or _has_step_level_false_gate(jobs[job])
    }
    assert not mode_gated_safe_jobs, (
        f"job(s) classified dry-run-safe but can be skipped or step-gated by dry_run -- "
        f"reclassify as a mutation job: {mode_gated_safe_jobs}"
    )

    unpinned_mutation_jobs = {
        job
        for job in MUTATION_JOBS
        if not any(_POSITIVE_FALSE_RE.search(line) for line in _dry_run_expressions(jobs[job]))
    }
    assert not unpinned_mutation_jobs, (
        f"mutation job(s) not gated on an explicit dry_run == 'false': {unpinned_mutation_jobs}"
    )


def test_no_fail_open_dry_run_gate_anywhere() -> None:
    """No job or step condition may use the fail-open `dry_run != 'true'` shape.

    This is a whole-file scan, not limited to MUTATION_JOBS, so a brand-new
    job/step added later that reintroduces the fail-open shape is caught too.
    """
    jobs = _parsed_jobs()
    offenders = [
        f"{job}: {expr}"
        for job, lines in jobs.items()
        for expr in _dry_run_expressions(lines)
        if _FAIL_OPEN_RE.search(expr)
    ]
    assert not offenders, f"fail-open 'dry_run != true' shape found (must be 'dry_run == false'): {offenders}"


def test_every_mutation_job_gates_on_dry_run() -> None:
    """Every listed mutation job must reference `dry_run` somewhere in its body."""
    jobs = _parsed_jobs()
    gated_jobs = {job for job, lines in jobs.items() if _dry_run_expressions(lines)}
    missing = MUTATION_JOBS - gated_jobs
    assert not missing, f"mutation job(s) with no dry_run reference at all: {missing}"


# Shared by test_every_mutation_job_gates_on_an_explicit_false and
# test_every_job_is_classified_for_dry_run -- both pin the same "positive == 'false'"
# literal, so it lives once here rather than being redefined per test.
_POSITIVE_FALSE_RE = re.compile(r"dry_run\s*==\s*'false'")


def test_every_mutation_job_gates_on_an_explicit_false() -> None:
    """Each mutation job must carry a positive `dry_run == 'false'` comparison.

    Merely mentioning dry_run is not enough: a polarity flip to `== 'true'` would make
    every DRY RUN publish -- the mirror of the bug this file exists for -- while still
    referencing dry_run, so the previous test cannot see it.
    """
    jobs = _parsed_jobs()
    unpinned = {
        job
        for job in MUTATION_JOBS
        if not any(_POSITIVE_FALSE_RE.search(line) for line in _dry_run_expressions(jobs[job]))
    }
    assert not unpinned, f"mutation job(s) not gated on an explicit == 'false': {unpinned}"


def test_the_release_draft_step_is_gated_on_an_explicit_false() -> None:
    """The draft-creation step sits inside the `release` job, which carries other
    dry_run references, so a per-job check cannot tell that THIS step lost its gate."""
    steps = _split_into_steps(_parsed_jobs()["release"])
    draft = [step for step in steps if any("softprops/action-gh-release" in line for line in step)]
    assert draft, "the release job no longer creates a draft via softprops/action-gh-release"
    assert re.search(r"dry_run\s*==\s*'false'", "\n".join(draft[0])), (
        "the draft-creation step must be gated on an explicit dry_run == 'false'"
    )


def test_dry_run_input_is_declared_boolean() -> None:
    """The dispatch form itself must only offer two values, not free-form text."""
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    dispatch = extract_between(workflow_text, "\non:\n", "\npermissions:\n")
    dry_run_block = extract_between(dispatch, "      dry_run:\n", "\n\n")
    assert re.search(r"^        type:\s*boolean\s*$", dry_run_block, re.MULTILINE), (
        f"dry_run input must declare `type: boolean`; block was:\n{dry_run_block}"
    )


def test_dry_run_input_defaults_to_the_safe_value() -> None:
    """An omitted input must default to a dry run.

    The default carries as much of the fail-closed contract as the type does: flip it to
    false and a dispatch that simply omits the input publishes for real.
    """
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    dispatch = extract_between(workflow_text, "\non:\n", "\npermissions:\n")
    dry_run_block = extract_between(dispatch, "      dry_run:\n", "\n\n")
    assert re.search(r"^        default:\s*(true|'true'|\"true\")\s*$", dry_run_block, re.MULTILINE), (
        f"dry_run input must default to true (a dry run); block was:\n{dry_run_block}"
    )


def test_metadata_step_rejects_non_boolean_dry_run() -> None:
    """The `release` job's metadata step must hard-reject anything but true/false.

    Must run BEFORE the step writes to $GITHUB_OUTPUT, so a bad dispatch value
    never reaches a downstream job/output at all.
    """
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    meta_step = extract_between(workflow_text, "id: meta\n", "\n      - name:")

    guard_match = re.search(r'case "\$DRY_RUN" in\n(.*?)\n[ \t]*esac', meta_step, re.DOTALL)
    assert guard_match is not None, (
        f"metadata step must validate $DRY_RUN with a case/esac guard; step was:\n{meta_step}"
    )
    guard = guard_match.group(1)
    assert "::error::" in guard, f"guard must emit ::error:: on rejection, got:\n{guard}"
    assert "exit 1" in guard, f"guard must exit non-zero on rejection, got:\n{guard}"
    output_marker = meta_step.index('>> "$GITHUB_OUTPUT"')
    guard_pos = meta_step.index(guard_match.group(0))
    assert guard_pos < output_marker, "the dry_run guard must run BEFORE any $GITHUB_OUTPUT write"


# The pre-tag guard blocks case variants before mutation; the metadata guard
# protects downstream outputs. Both shipped guards must execute -- kept only as a
# sanity floor for discovery below, not as the enumeration mechanism.
GUARD_VARS = ("INPUT_DRY", "DRY_RUN")

_CASE_LINE_RE = re.compile(r'^([ \t]*)case "\$([A-Za-z_][A-Za-z0-9_]*)" in[ \t]*$')
_TRUE_FALSE_ARM_RE = re.compile(r"^[ \t]*true\|false\)")

# Two known blind spots in the shape match above, both accepted: (1) a braced
# case subject, `case "${VAR}" in`, is invisible to _CASE_LINE_RE (only the
# bare `$VAR` form is matched); (2) a guard born with an already-widened first
# arm, e.g. `TRUE|true|false)`, is invisible to _TRUE_FALSE_ARM_RE (anchored on
# `true|false)` starting the arm). Accepted because there is no live instance
# of either shape in this workflow, the shop's shell style sticks to bare
# `$VAR` + a plain `true|false)` first arm, and the GUARD_VARS floor below
# still catches a shape-blind miss on either KNOWN guard -- it only misses a
# brand-new guard written from the start in one of these two shapes.


def _discover_guard_blocks(workflow_text: str) -> list[tuple[str, str]]:
    """Find every dry-run boolean guard by SHAPE, not by a fixed var-name list.

    A guard is any `case "$VAR" in` block whose first arm is exactly `true|false)`
    -- that structural shape is what makes it a dry-run guard, regardless of what
    VAR is called, so a third, differently-named guard added later is discovered
    automatically instead of silently skipped. An optional `VAR="..."` assignment
    line immediately above the case line is folded in (carries default-fallback
    logic, e.g. `DRY_RUN="${INPUT_DRY:-true}"`), matching what the guard actually
    executes in the workflow.
    """
    lines = workflow_text.splitlines()
    blocks: list[tuple[str, str]] = []
    for idx, line in enumerate(lines):
        header = _CASE_LINE_RE.match(line)
        if header is None:
            continue
        indent, var = header.group(1), header.group(2)
        if idx + 1 >= len(lines) or not _TRUE_FALSE_ARM_RE.match(lines[idx + 1]):
            continue  # not a boolean dry-run guard shape (e.g. the $BODY case blocks)
        esac_idx = next(
            (j for j in range(idx + 1, len(lines)) if re.match(rf"^{re.escape(indent)}esac[ \t]*$", lines[j])),
            None,
        )
        assert esac_idx is not None, f"unterminated case block for ${var} starting at line {idx + 1}"
        block_lines = lines[idx : esac_idx + 1]
        if idx > 0 and re.match(rf'^[ \t]*{re.escape(var)}="[^"\n]*"$', lines[idx - 1]):
            block_lines = [lines[idx - 1], *block_lines]
        blocks.append((var, "\n".join(block_lines)))
    return blocks


def _guard_scripts() -> list[str]:
    """Every guard, lifted from the workflow verbatim, discovered structurally."""
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    blocks = _discover_guard_blocks(workflow_text)
    discovered_vars = {var for var, _ in blocks}
    assert len(blocks) >= len(GUARD_VARS), (
        f"expected at least {len(GUARD_VARS)} dry-run guard(s) (one per {GUARD_VARS}), found {len(blocks)}"
    )
    assert set(GUARD_VARS) <= discovered_vars, (
        f"expected known guards {GUARD_VARS} among discovered vars {discovered_vars}"
    )
    return [textwrap.dedent(script) for _, script in blocks]


def _run_guard(value: str) -> list[tuple[int, str]]:
    """Execute EVERY dry_run guard under sh, returning each (exit status, resolved value).

    Only `INPUT_DRY` is supplied -- whatever a guard derives from it comes from the
    workflow's own text.
    """
    results = []
    for script in _guard_scripts():
        body = f'INPUT_DRY="$1"\n{script}\nprintf %s "${{DRY_RUN-$INPUT_DRY}}"\n'
        completed = subprocess.run(  # noqa: S603
            ["sh", "-c", body, "sh", value],
            env={"PATH": os.environ.get("PATH", "")},
            capture_output=True,
            text=True,
        )
        results.append((completed.returncode, completed.stdout))
    return results


def test_pre_tag_guard_is_the_first_prepare_release_step() -> None:
    """Case-variant false must be rejected before any release mutation."""
    steps = _split_into_steps(_parsed_jobs()["prepare-release"])
    assert steps, "prepare-release must contain the pre-tag dry_run guard"
    first_step = "\n".join(steps[0])
    assert 'case "$INPUT_DRY" in' in first_step, (
        f"prepare-release must validate $INPUT_DRY in its first step; first step was:\n{first_step}"
    )


@pytest.mark.parametrize("value", ["true", "false"])
def test_the_guard_accepts_exactly_the_safe_values(value: str) -> None:
    """Executed, not pattern-matched: these must survive the real guard."""
    outcomes = _run_guard(value)
    assert all(rc == 0 for rc, _ in outcomes), f"all guards must accept {value!r}; actual outcomes were {outcomes!r}"


def test_an_omitted_value_resolves_to_a_dry_run() -> None:
    """An omitted value must RESOLVE to "true", not merely survive a guard.

    Checking exit status alone cannot see this: the guards accept both "true" and
    "false", so a default flipped to false would pass every acceptance check while
    turning an omitted input into a real publish. Assert the value each guard actually
    produces. The pre-tag guard has no default and rejects a raw empty string, which is
    equally safe -- it simply never runs for an omitted value, since its job-level
    expression requires 'false'.
    """
    outcomes = _run_guard("")
    resolved = [value for rc, value in outcomes if rc == 0]
    assert resolved, "no guard accepted an omitted value; at least the metadata guard must"
    assert all(value == "true" for value in resolved), f"an omitted dry_run must resolve to a dry run, got {outcomes!r}"


@pytest.mark.parametrize("value", ["TRUE", "True", "FALSE", "False", "tru", "yes", "1", "0", " false"])
def test_the_guard_rejects_case_variants_and_malformed_values(value: str) -> None:
    """Issue #1661 asks that case variants and malformed values be PINNED, not merely
    handled. Running the guard is the only way to catch a regression that widens it --
    an assertion on the guard's source text passes happily against `TRUE|true|false)`.
    """
    outcomes = _run_guard(value)
    assert all(rc != 0 for rc, _ in outcomes), f"all guards must reject {value!r}; actual outcomes were {outcomes!r}"
