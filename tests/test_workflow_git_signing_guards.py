"""Runtime guards cannot let a Git writer outlive its signing setup."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
_SIGNING_STEP = "Configure pfblockerng-bot signing"
_COMMIT = re.compile(r"\bgit(?:\s+-C\s+\S+)?\s+commit\b")
_ANNOTATED_TAG = re.compile(r"\bgit\s+tag\s+-a\b")


def test_writer_steps_match_their_signing_step_runtime_guards() -> None:
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in workflow.get("jobs", {}).items():
            steps: list[dict[str, Any]] = job.get("steps", [])
            writers = [
                step
                for step in steps
                if _COMMIT.search(step.get("run", "")) or _ANNOTATED_TAG.search(step.get("run", ""))
            ]
            if not writers:
                continue
            setup = next(step for step in steps if step.get("name") == _SIGNING_STEP)
            for writer in writers:
                assert writer.get("if") == setup.get("if"), (
                    f"{path.name}:{job_name} signing and writer if guards differ"
                )
                assert writer.get("continue-on-error") == setup.get("continue-on-error"), (
                    f"{path.name}:{job_name} signing and writer failure semantics differ"
                )
