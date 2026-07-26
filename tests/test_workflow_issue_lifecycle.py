"""Issue-opening workflows deduplicate against open issues only (issue #1735)."""

from __future__ import annotations

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
        commands = _commands(path.read_text(encoding="utf-8"))
        create_count = sum(command.startswith("gh issue create ") for command in commands)
        if not create_count:
            continue
        creators.append(path.name)
        offenders.extend(f"{path.name}: {command}" for command in commands if command.startswith("gh issue reopen "))
        dedup_commands = [
            command for command in commands if "gh issue list " in command and "--json number,title,state" in command
        ]
        assert len(dedup_commands) == create_count, (
            f"{path.name}: expected one exact-state dedup lookup per issue create; "
            f"found {len(dedup_commands)} for {create_count} create command(s)"
        )
        assert all("--state open" in command for command in dedup_commands), (
            f"{path.name}: issue dedup must query open issues only: {dedup_commands}"
        )

    assert creators, "found no issue-opening workflows"
    assert not offenders, "issue-opening workflows must never reopen closed issues:\n" + "\n".join(offenders)
