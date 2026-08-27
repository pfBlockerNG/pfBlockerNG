"""Preserve safe deduplication around issue creation (issue #1735)."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from tests._workflow_steps import extract_after

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
_LABEL = re.compile(r'--label "([^"]+)"')


def _commands(source: str) -> list[str]:
    commands: list[str] = []
    command = ""
    for line in source.splitlines():
        stripped = line.strip()
        command = f"{command} {stripped}".strip()
        if stripped.endswith("\\"):
            command = command[:-1].rstrip()
        else:
            commands.append(command)
            command = ""
    return commands


def _issue_creation_steps(path: Path) -> list[str]:
    return [step for step in path.read_text(encoding="utf-8").split("\n      - name:") if "gh issue create " in step]


def _script(step: str) -> str:
    return "\n".join(line[10:] for line in extract_after(step, "        run: |\n").splitlines())


def _run_script(
    path: Path,
    step_name: str,
    tmp_path: Path,
    *,
    opened: str,
    closed: str = "[]",
    extra_env: dict[str, str] | None = None,
) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tail = extract_after(source, f"      - name: {step_name}\n")
    step = re.split(r"\n(?:      - name:|  [a-z][a-z0-9_-]*:)", tail, maxsplit=1)[0]
    script = _script(step).replace("${{ steps.report.outputs.body_file }}", str(tmp_path / "body.md"))
    log = tmp_path / "gh.log"
    fake_gh = tmp_path / "gh"
    fake_gh.write_text(
        """#!/bin/sh
case "$*" in
  "issue list "*"--state closed"*) printf '%s\\n' "$GH_CLOSED" ;;
  "issue list "*) printf '%s\\n' "$GH_OPEN" ;;
  "issue edit "*) printf 'edit %s\\n' "$3" >> "$GH_LOG" ;;
  "issue create "*) printf 'create\\n' >> "$GH_LOG" ;;
  "issue close "*) printf 'close %s\\n' "$3" >> "$GH_LOG" ;;
  "issue reopen "*) printf 'reopen %s\\n' "$3" >> "$GH_LOG" ;;
esac
""",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    env = os.environ | {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "GH_CLOSED": closed,
        "GH_LOG": str(log),
        "GH_OPEN": opened,
        "REPO": "owner/repo",
    }
    env.update(extra_env or {})
    subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, check=True, capture_output=True, text=True)
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_issue_creation_steps_keep_exact_open_deduplication() -> None:
    steps = [
        step
        for path in sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")))
        for step in _issue_creation_steps(path)
    ]
    assert steps, "found no issue-creation steps"

    for step in steps:
        commands = _commands(step)
        code = "\n".join(line for line in _script(step).splitlines() if not line.lstrip().startswith("#"))
        creates = [command for command in commands if command.startswith("gh issue create ")]
        dedups = [
            command for command in commands if "gh issue list " in command and "--json number,title,state" in command
        ]
        assert len(dedups) == len(creates), f"expected one dedup lookup per issue create: {step}"
        assert "set -euo pipefail" in code, f"issue dedup must fail closed on lookup errors: {step}"
        assert code.count("select(.title == $t)") == len(creates), f"issue dedup must use exact titles: {step}"

        for create, dedup in zip(creates, dedups, strict=True):
            assert "--state open" in dedup, f"issue dedup must query open issues only: {dedup}"
            assert "--limit 500" in dedup, f"issue dedup must lift the default page limit: {dedup}"
            assert _LABEL.findall(dedup) == _LABEL.findall(create), (
                f"dedup and create labels differ: dedup={dedup!r}, create={create!r}"
            )


@pytest.mark.parametrize(
    ("opened", "expected"),
    [
        ('[{"number":42,"title":"[nightly-red] Smoke failing on devel","state":"OPEN"}]', ["edit 42"]),
        ("[]", ["create"]),
        ('[{"number":42,"title":"different","state":"OPEN"}]', ["create"]),
    ],
)
def test_nightly_open_match_updates_and_closed_only_creates(tmp_path: Path, opened: str, expected: list[str]) -> None:
    assert (
        _run_script(
            WORKFLOWS / "nightly-failure-alert.yml",
            "Open or update the tracking issue",
            tmp_path,
            opened=opened,
            extra_env={
                "WF_NAME": "Smoke",
                "RUN_URL": "https://example.invalid/run",
                "HEAD_SHA": "deadbeef",
                "BRANCH": "devel",
                "DRILL": "",
            },
        )
        == expected
    )


@pytest.mark.parametrize(
    ("opened", "expected"),
    [
        ('[{"number":42,"title":"[top1m-healthcheck] provider URL unhealthy","state":"OPEN"}]', ["edit 42"]),
        ("[]", ["create"]),
        ('[{"number":42,"title":"different","state":"OPEN"}]', ["create"]),
    ],
)
def test_top1m_open_match_updates_and_closed_only_creates(tmp_path: Path, opened: str, expected: list[str]) -> None:
    assert (
        _run_script(
            WORKFLOWS / "top1m-healthcheck.yml",
            "Open or update the tracking issue",
            tmp_path,
            opened=opened,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("workflow", "opened", "expected"),
    [
        (
            "nightly-failure-alert.yml",
            '[{"number":42,"title":"[nightly-red] Smoke failing on devel","state":"OPEN"}]',
            ["close 42"],
        ),
        ("nightly-failure-alert.yml", '[{"number":42,"title":"different","state":"OPEN"}]', []),
        (
            "top1m-healthcheck.yml",
            '[{"number":42,"title":"[top1m-healthcheck] provider URL unhealthy","state":"OPEN"}]',
            ["close 42"],
        ),
        ("top1m-healthcheck.yml", '[{"number":42,"title":"different","state":"OPEN"}]', []),
    ],
)
def test_success_closes_only_the_matching_open_tracker(
    tmp_path: Path, workflow: str, opened: str, expected: list[str]
) -> None:
    assert (
        _run_script(
            WORKFLOWS / workflow,
            "Close the recovered tracking issue",
            tmp_path,
            opened=opened,
            extra_env={"WF_NAME": "Smoke", "BRANCH": "devel", "RUN_URL": "https://example.invalid/run"},
        )
        == expected
    )


@pytest.mark.parametrize("workflow", ["nightly-failure-alert.yml", "top1m-healthcheck.yml"])
def test_success_without_an_open_tracker_is_a_no_op(tmp_path: Path, workflow: str) -> None:
    assert (
        _run_script(
            WORKFLOWS / workflow,
            "Close the recovered tracking issue",
            tmp_path,
            opened="[]",
            extra_env={"WF_NAME": "Smoke", "BRANCH": "devel", "RUN_URL": "https://example.invalid/run"},
        )
        == []
    )


def test_recovery_runs_only_for_successful_matching_pipeline_events() -> None:
    nightly = (WORKFLOWS / "nightly-failure-alert.yml").read_text(encoding="utf-8")
    top1m = (WORKFLOWS / "top1m-healthcheck.yml").read_text(encoding="utf-8")

    nightly_success = "\n".join(
        (
            "github.event.workflow_run.event == 'schedule' &&",
            "       github.event.workflow_run.conclusion == 'success'",
        )
    )
    assert nightly_success in nightly
    assert "if: success()" in top1m


def test_failure_and_recovery_reconciliation_are_serialized() -> None:
    nightly = (WORKFLOWS / "nightly-failure-alert.yml").read_text(encoding="utf-8")
    top1m = (WORKFLOWS / "top1m-healthcheck.yml").read_text(encoding="utf-8")

    assert nightly.count("group: nightly-red-") == 2
    assert top1m.count("group: top1m-provider-alert") == 2
