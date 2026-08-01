"""Issue-opening workflows deduplicate against open issues only (issue #1735)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


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


def test_issue_openers_never_reopen_closed_issues() -> None:
    creators: list[str] = []
    offenders: list[str] = []
    for path in sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml"))):
        source = path.read_text(encoding="utf-8")
        commands = _commands(source)
        creation_steps = [step for step in source.split("\n      - name:") if "gh issue create " in step]
        if not creation_steps:
            continue
        creators.append(path.name)
        offenders.extend(f"{path.name}: {command}" for command in commands if command.startswith("gh issue reopen "))
        for step in creation_steps:
            step = re.split(r"\n  [a-z][a-z0-9_-]*:", step, maxsplit=1)[0]
            dedup_commands = [
                command
                for command in _commands(step)
                if "gh issue list " in command and "--json number,title,state" in command
            ]
            assert len(dedup_commands) == 1, (
                f"{path.name}: expected one exact-state dedup lookup per issue create; found {dedup_commands}"
            )
            assert "--state open" in dedup_commands[0], (
                f"{path.name}: issue dedup must query open issues only: {dedup_commands[0]}"
            )

    assert creators, "found no issue-opening workflows"
    assert not offenders, "issue-opening workflows must never reopen closed issues:\n" + "\n".join(offenders)
