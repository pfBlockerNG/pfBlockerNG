"""A delayed success must not close a tracker updated by a newer failure."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from tests._workflow_steps import extract_after

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _recovery_script(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    tail = extract_after(source, "      - name: Close the recovered tracking issue\n")
    step = re.split(r"\n(?:      - name:|  [a-z][a-z0-9_-]*:)", tail, maxsplit=1)[0]
    return "\n".join(line[10:] for line in extract_after(step, "        run: |\n").splitlines())


def _run_recovery(
    path: Path,
    tmp_path: Path,
    *,
    title: str,
    failure_run: str,
    run_number: str,
    run_attempt: str,
) -> list[str]:
    log = tmp_path / "gh.log"
    fake_gh = tmp_path / "gh"
    fake_gh.write_text(
        """#!/bin/sh
case "$*" in
  "issue list "*) printf '%s\n' "$GH_OPEN" ;;
  "issue view "*) printf '%s\n' "$GH_FAILURE_RUN" ;;
  "issue close "*) printf 'close %s\n' "$3" >> "$GH_LOG" ;;
esac
""",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    env = os.environ | {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "GH_FAILURE_RUN": failure_run,
        "GH_LOG": str(log),
        "GH_OPEN": json.dumps([{"number": 42, "title": title, "state": "OPEN"}]),
        "REPO": "owner/repo",
        "WF_NAME": "Smoke",
        "BRANCH": "devel",
        "RUN_URL": "https://example.invalid/run",
        "RUN_NUMBER": run_number,
        "RUN_ATTEMPT": run_attempt,
    }
    subprocess.run(
        ["bash", "-c", _recovery_script(path)],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


@pytest.mark.parametrize(
    ("workflow", "title"),
    [
        ("nightly-failure-alert.yml", "[nightly-red] Smoke failing on devel"),
        ("top1m-healthcheck.yml", "[top1m-healthcheck] provider URL unhealthy"),
    ],
)
@pytest.mark.parametrize(
    ("failure_run", "run_number", "run_attempt", "expected"),
    [
        ("101 1", "100", "1", []),
        ("100 1", "100", "2", ["close 42"]),
        ("100 2", "101", "1", ["close 42"]),
        ("", "100", "1", ["close 42"]),
    ],
)
def test_recovery_closes_only_when_not_older_than_the_recorded_failure(
    tmp_path: Path,
    workflow: str,
    title: str,
    failure_run: str,
    run_number: str,
    run_attempt: str,
    expected: list[str],
) -> None:
    assert (
        _run_recovery(
            WORKFLOWS / workflow,
            tmp_path,
            title=title,
            failure_run=failure_run,
            run_number=run_number,
            run_attempt=run_attempt,
        )
        == expected
    )


@pytest.mark.parametrize("workflow", ["nightly-failure-alert.yml", "top1m-healthcheck.yml"])
def test_failure_issue_body_records_the_run_order(workflow: str) -> None:
    source = (WORKFLOWS / workflow).read_text(encoding="utf-8")

    assert "<!-- failure-run: %s:%s -->" in source
    assert "RUN_NUMBER:" in source
    assert "RUN_ATTEMPT:" in source
