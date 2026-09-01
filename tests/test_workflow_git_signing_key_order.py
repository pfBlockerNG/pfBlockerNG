"""Bot signing keys are written only after the mode-600 file exists."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
_SIGNING_STEP = "Configure pfblockerng-bot signing"
_INSTALL = 'install -m 600 /dev/null "$RUNNER_TEMP/pfb-bot-signing-key"'
_WRITE = 'printf \'%s\\n\' "$PFB_BOT_SIGNING_KEY" > "$RUNNER_TEMP/pfb-bot-signing-key"'


def test_signing_steps_create_the_protected_key_file_before_writing_it() -> None:
    setups: list[tuple[str, str, str]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        document: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in document.get("jobs", {}).items():
            for step in job.get("steps", []):
                if step.get("name") == _SIGNING_STEP:
                    setups.append((path.name, job_name, step.get("run", "")))

    assert setups, "no bot-signing steps discovered"
    for workflow_name, job, script in setups:
        assert script.index(_INSTALL) < script.index(_WRITE), (
            f"{workflow_name}:{job} must create the mode-600 key file before writing the secret"
        )
