"""GitHub Actions jobs that write Git objects use the project bot's SSH key."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
_SIGNING_STEP = "Configure pfblockerng-bot signing"
_SIGNING_SECRET = "${{ secrets.PFB_BOT_SIGNING_KEY }}"
_COMMIT = re.compile(r"\bgit(?:\s+-C\s+\S+)?\s+commit\b")
_ANNOTATED_TAG = re.compile(r"\bgit\s+tag\s+-a\b")
_REQUIRED_CONFIG = (
    'git config user.name "pfblockerng-bot"',
    'git config user.email "293667935+pfblockerng-bot@users.noreply.github.com"',
    "git config gpg.format ssh",
    'git config user.signingkey "$RUNNER_TEMP/pfb-bot-signing-key"',
    "git config commit.gpgsign true",
)


def _writer_jobs() -> list[tuple[str, str, list[dict[str, Any]], bool]]:
    writers: list[tuple[str, str, list[dict[str, Any]], bool]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in workflow.get("jobs", {}).items():
            steps = job.get("steps", [])
            scripts = [step.get("run", "") for step in steps]
            writes_commit = any(_COMMIT.search(script) for script in scripts)
            writes_annotated_tag = any(_ANNOTATED_TAG.search(script) for script in scripts)
            if writes_commit or writes_annotated_tag:
                writers.append((path.name, job_name, steps, writes_annotated_tag))
    return writers


def test_git_object_writer_jobs_configure_pfblockerng_bot_ssh_signing() -> None:
    writers = _writer_jobs()
    assert writers, "no Git-object writer jobs discovered"

    for workflow, job, steps, writes_annotated_tag in writers:
        setup_index = next(
            (index for index, step in enumerate(steps) if step.get("name") == _SIGNING_STEP),
            None,
        )
        assert setup_index is not None, f"{workflow}:{job} lacks {_SIGNING_STEP!r}"

        writer_indexes = [
            index
            for index, step in enumerate(steps)
            if _COMMIT.search(step.get("run", "")) or _ANNOTATED_TAG.search(step.get("run", ""))
        ]
        assert setup_index < min(writer_indexes), f"{workflow}:{job} configures signing after writing a Git object"

        setup = steps[setup_index]
        assert setup.get("env", {}).get("PFB_BOT_SIGNING_KEY") == _SIGNING_SECRET, (
            f"{workflow}:{job} does not consume the org signing-key secret"
        )
        script = setup.get("run", "")
        assert '[ -n "${PFB_BOT_SIGNING_KEY:-}" ]' in script, f"{workflow}:{job} accepts an empty signing key"
        assert 'install -m 600 /dev/null "$RUNNER_TEMP/pfb-bot-signing-key"' in script
        assert 'printf \'%s\\n\' "$PFB_BOT_SIGNING_KEY" > "$RUNNER_TEMP/pfb-bot-signing-key"' in script
        for command in _REQUIRED_CONFIG:
            assert command in script, f"{workflow}:{job} lacks {command!r}"
        if writes_annotated_tag:
            assert "git config tag.gpgSign true" in script, f"{workflow}:{job} does not sign annotated tags"


def test_workflows_never_configure_the_generic_actions_commit_identity() -> None:
    generic_identity = re.compile(r"git config user\.(?:name|email).*github-actions(?:\[bot\])?", re.IGNORECASE)
    offenders = [
        path.name
        for path in sorted(WORKFLOWS.glob("*.yml"))
        if generic_identity.search(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"generic Actions commit identity remains in: {', '.join(offenders)}"
