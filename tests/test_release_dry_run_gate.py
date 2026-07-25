"""release.yml's `dry_run` must fail CLOSED (issue #1661).

`dry_run` gates every mutating step of the release pipeline (tag creation, the
GitHub Release, .pkg attachment, publish, the pkg-repo dispatch, and the
FreeBSD-ports bump). The workflow used to gate every one of those with the
fail-OPEN shape `dry_run != 'true'`: anything that is not the exact string
"true" -- "TRUE", "True", "tru", "yes", "1", an empty string via a bad
dispatch -- published for real. This module parses the live workflow (never a
copy) and enforces the fail-CLOSED shape everywhere `dry_run` is read, plus
that the input itself is declared as a two-value boolean and that the
`release` job's metadata step rejects anything else loudly before emitting
any output.

The job/step enumeration is built from the parsed YAML *structure* (job
headers), never from hardcoded line numbers, so it keeps working as the file
is edited and a mutation job that quietly loses its dry_run gate — or a new
one added without picking it up — is caught rather than silently unguarded.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"

# Jobs that perform a real-world mutation gated by dry_run (issue #1661 evidence
# table): prepare-release creates+pushes the tag; release creates the GitHub
# Release; attach-pkgs/publish-release/repo-publish/sync-ports-fork publish,
# flip the release live, poke the pkg repo, and push the ports-fork bump.
MUTATION_JOBS = {
    "prepare-release",
    "release",
    "attach-pkgs",
    "publish-release",
    "repo-publish",
    "sync-ports-fork",
}

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$")
# Any string-compared fail-open shape: dry_run != 'true' / != "true", regardless
# of which context reads it (github.event.inputs / steps.*.outputs / needs.*.outputs).
_FAIL_OPEN_RE = re.compile(r"dry_run\s*!=\s*['\"]true['\"]")


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


def _parsed_jobs() -> dict[str, list[str]]:
    return _split_into_jobs(_jobs_section_lines(WORKFLOW.read_text(encoding="utf-8")))


def test_mutation_jobs_exist_in_the_workflow() -> None:
    # Sanity check on the fixture itself: if a job in MUTATION_JOBS gets renamed
    # or removed, fail here with a clear message rather than a confusing
    # false-negative in the gate assertions below.
    jobs = _parsed_jobs()
    missing = MUTATION_JOBS - jobs.keys()
    assert not missing, f"expected job(s) not found in release.yml: {missing}"


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
    """Every publish-mutating job must reference `dry_run` somewhere in its body.

    Built from the parsed job bodies (never a hardcoded line number), so a
    mutation job whose gate is deleted outright -- or a newly added mutation
    job that forgets to reference dry_run at all -- fails here.
    """
    jobs = _parsed_jobs()
    gated_jobs = {job for job, lines in jobs.items() if _dry_run_expressions(lines)}
    missing = MUTATION_JOBS - gated_jobs
    assert not missing, f"mutation job(s) with no dry_run reference at all: {missing}"


def test_dry_run_input_is_declared_boolean() -> None:
    """The dispatch form itself must only offer two values, not free-form text."""
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    dispatch = workflow_text.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
    dry_run_block = dispatch.split("      dry_run:\n", 1)[1].split("\n\n", 1)[0]
    assert re.search(r"^        type:\s*boolean\s*$", dry_run_block, re.MULTILINE), (
        f"dry_run input must declare `type: boolean`; block was:\n{dry_run_block}"
    )


def test_metadata_step_rejects_non_boolean_dry_run() -> None:
    """The `release` job's metadata step must hard-reject anything but true/false.

    Must run BEFORE the step writes to $GITHUB_OUTPUT, so a bad dispatch value
    never reaches a downstream job/output at all.
    """
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    meta_step = workflow_text.split("id: meta\n", 1)[1].split("\n      - name:", 1)[0]

    guard_match = re.search(r'case "\$DRY_RUN" in\n(.*?)\n[ \t]*esac', meta_step, re.DOTALL)
    assert guard_match is not None, (
        f"metadata step must validate $DRY_RUN with a case/esac guard; step was:\n{meta_step}"
    )
    guard = guard_match.group(1)
    assert re.search(r"true\|false\)\s*;;", guard), f"guard must accept only true/false, got:\n{guard}"
    assert "::error::" in guard, f"guard must emit ::error:: on rejection, got:\n{guard}"
    assert "exit 1" in guard, f"guard must exit non-zero on rejection, got:\n{guard}"

    output_marker = meta_step.index('>> "$GITHUB_OUTPUT"')
    guard_pos = meta_step.index(guard_match.group(0))
    assert guard_pos < output_marker, "the dry_run guard must run BEFORE any $GITHUB_OUTPUT write"
