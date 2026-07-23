"""Ticket creators must set descriptive labels and native issue types together."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_automated_issue_creators_set_label_and_type() -> None:
    commands = []
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if "gh issue create" not in line:
                continue
            command = "\n".join(lines[index : index + 10])
            commands.append(f"{path.name}:{index + 1}")
            assert "--label" in command, f"{commands[-1]} creates an unlabelled issue"
            assert "--type" in command, f"{commands[-1]} creates an untyped issue"

    assert commands, "no automated issue creators were inspected"


def test_bug_form_sets_label_and_type() -> None:
    form = _read(".github/ISSUE_TEMPLATE/bug_report.yml")
    assert '\nlabels: ["bug"]\n' in form
    assert "\ntype: bug\n" in form


def test_human_ticket_procedures_require_both_metadata_axes() -> None:
    policy = _read(".agents/policy/issues.md")
    for issue_type in ("Bug", "Feature", "Task"):
        assert f"| `{issue_type}` |" in policy

    assert "`gh issue create --label bug --type Bug`" in _read(".agents/skills/qa/SKILL.md")

    tracker = _read(".agents/skills/setup-matt-pocock-skills/issue-tracker-github.md")
    assert "--label" in tracker
    assert "--type" in tracker

    wayfinder = _read(".agents/skills/wayfinder/SKILL.md")
    assert "native issue type `Task`" in wayfinder
