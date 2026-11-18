"""GitHub Actions jobs that create commits activate repository hooks first.

Issue #3045: git.md requires every Actions workflow that commits code to run
``scripts/setup-hooks.sh`` after checkout. HSTS/PSL/TLD refresh already do;
the remaining writers must pair hook activation with the commit step.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
_COMMIT = re.compile(r"\bgit(?:\s+-C\s+\S+)?\s+commit\b")
_HOOKS = re.compile(r"scripts/setup-hooks\.sh|core\.hooksPath")


def _active_script(step: dict[str, Any]) -> str:
    """A step's ``run`` body with whole-line comments blanked.

    A documented ``git commit`` or ``setup-hooks.sh`` is prose; only real
    invocations are judged.
    """
    script = step.get("run", "")
    if not isinstance(script, str) or not script:
        return ""
    return "\n".join("" if line.lstrip().startswith("#") else line for line in script.splitlines())


def _writer_jobs(text: str) -> list[tuple[str, list[dict[str, Any]]]]:
    workflow = yaml.safe_load(text)
    writers: list[tuple[str, list[dict[str, Any]]]] = []
    for job_name, job in workflow.get("jobs", {}).items():
        steps = job.get("steps", [])
        if any(_COMMIT.search(_active_script(step)) for step in steps):
            writers.append((job_name, steps))
    return writers


def _offenders(name: str, text: str) -> tuple[list[str], list[str]]:
    """(offending job descriptions, inspected job labels) for one workflow."""
    offenders: list[str] = []
    inspected: list[str] = []
    for job, steps in _writer_jobs(text):
        inspected.append(f"{name}:{job}")
        hook_indexes = [index for index, step in enumerate(steps) if _HOOKS.search(_active_script(step))]
        writer_indexes = [index for index, step in enumerate(steps) if _COMMIT.search(_active_script(step))]
        if not hook_indexes:
            offenders.append(f"{name}: job `{job}` commits without activating repository hooks")
            continue
        if min(hook_indexes) >= min(writer_indexes):
            offenders.append(f"{name}: job `{job}` activates hooks after writing a commit")
    return offenders, inspected


def test_git_commit_writer_jobs_activate_hooks_before_committing() -> None:
    """Every job that can create a commit activates .githooks first.

    Given a job whose steps include ``git commit``,
    when the inventory runs,
    then ``scripts/setup-hooks.sh`` (or ``core.hooksPath``) appears in an
    earlier step of that same job.
    """
    offenders: list[str] = []
    inspected: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        job_offenders, job_inspected = _offenders(path.name, path.read_text(encoding="utf-8"))
        offenders.extend(job_offenders)
        inspected.extend(job_inspected)
    assert inspected, "no Git-commit writer jobs discovered"
    assert not offenders, "\n".join(offenders)


def test_guard_flags_a_writer_without_hooks() -> None:
    """The guard's own red path: a commit job with no hook activation."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: |\n"
        "          git add tests/smoke/module-durations.txt\n"
        "          git commit -m 'refresh'\n",
    )
    assert inspected == ["synthetic.yml:refresh"]
    assert offenders == ["synthetic.yml: job `refresh` commits without activating repository hooks"]


def test_guard_flags_hooks_activated_after_the_commit() -> None:
    """Ordering matters: hooks after ``git commit`` are too late."""
    offenders, _inspected = _offenders(
        "synthetic.yml",
        "jobs:\n  refresh:\n    steps:\n      - run: git commit -m 'x'\n      - run: sh scripts/setup-hooks.sh\n",
    )
    assert offenders == ["synthetic.yml: job `refresh` activates hooks after writing a commit"]


def test_guard_passes_hooks_before_the_commit() -> None:
    """The fixed shape: activate hooks, then commit."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        "      - run: |\n"
        "          git add tests/smoke/module-durations.txt\n"
        "          git commit -m 'refresh'\n",
    )
    assert inspected == ["synthetic.yml:refresh"]
    assert offenders == []


def test_guard_sees_git_c_commit_and_helper_checkout_hook_path() -> None:
    """``git -C`` commits and a helper-checkout setup-hooks path still count."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        '      - run: sh "${GITHUB_WORKSPACE}/pfblockerng-src/scripts/setup-hooks.sh"\n'
        '      - run: git -C "$WT" commit -m activate\n',
    )
    assert inspected == ["synthetic.yml:refresh"]
    assert offenders == []


def test_guard_ignores_a_git_commit_that_is_only_a_comment() -> None:
    """A documented ``git commit`` is prose; only real invocations are judged."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  react:\n"
        "    steps:\n"
        "      - run: |\n"
        "          # No git commit on channel branches appears in this job.\n"
        "          echo ok\n",
    )
    assert inspected == []
    assert offenders == []


def test_guard_ignores_a_hook_activation_that_is_only_a_comment() -> None:
    """A commented ``setup-hooks.sh`` does not pair a writer."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: |\n"
        "          # sh scripts/setup-hooks.sh\n"
        "          git commit -m 'x'\n",
    )
    assert inspected == ["synthetic.yml:refresh"]
    assert offenders == ["synthetic.yml: job `refresh` commits without activating repository hooks"]
