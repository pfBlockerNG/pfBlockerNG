"""Ticket creators must set descriptive labels and native issue types together."""

import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _continued_command(lines: list[str], start: int) -> str:
    command = [lines[start]]
    while command[-1].rstrip().endswith("\\"):
        command.append(lines[start + len(command)])
    return "\n".join(command)


def _option_values(command: str, option: str) -> list[str]:
    tokens = shlex.split(command.replace("\\\n", " "))
    return [tokens[index + 1] for index, token in enumerate(tokens[:-1]) if token == option]


def test_automated_issue_creators_set_label_and_type() -> None:
    expected = {
        "nightly-failure-alert.yml": [("nightly-red,bug", "Bug")],
        "top1m-healthcheck.yml": [("top1m-provider,bug", "Bug")],
        "version-tracker.yml": [
            ("version-tracker,enhancement", "Task"),
            ("version-tracker,enhancement", "Task"),
        ],
    }
    commands: dict[str, list[str]] = {}
    workflows = ROOT / ".github/workflows"
    for path in workflows.iterdir():
        if path.suffix not in {".yml", ".yaml"}:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if "gh issue create" not in line:
                continue
            command = _continued_command(lines, index)
            commands.setdefault(path.name, []).append(command)

    assert commands.keys() == expected.keys()
    for filename, expected_commands in expected.items():
        assert len(commands[filename]) == len(expected_commands)
        for command, (label, issue_type) in zip(commands[filename], expected_commands, strict=True):
            assert _option_values(command, "--label") == [label]
            assert _option_values(command, "--type") == [issue_type]


def test_issue_forms_set_label_and_type_and_disable_blank_issues() -> None:
    forms = {
        "bug_report.yml": ('labels: ["bug"]', "type: bug"),
        "feature_request.yml": ('labels: ["enhancement"]', "type: feature"),
        "task_request.yml": ('labels: ["enhancement"]', "type: task"),
    }
    template_dir = ROOT / ".github/ISSUE_TEMPLATE"
    form_files = {
        path.name for path in template_dir.iterdir() if path.suffix in {".yml", ".yaml"} and path.name != "config.yml"
    }
    assert form_files == forms.keys()
    for filename, (label, issue_type) in forms.items():
        form = _read(f".github/ISSUE_TEMPLATE/{filename}")
        assert f"\n{label}\n" in form
        assert f"\n{issue_type}\n" in form

    config = _read(".github/ISSUE_TEMPLATE/config.yml")
    assert "blank_issues_enabled: false" in config


def test_human_ticket_procedures_require_both_metadata_axes() -> None:
    policy = _read(".agents/policy/issues.md")
    for issue_type in ("Bug", "Feature", "Task"):
        assert f"| `{issue_type}` |" in policy
    assert "`gh issue create --label bug --type Bug`" in policy

    qa = _read(".agents/skills/qa/SKILL.md")
    assert "`gh issue create --label bug --type Bug`" in qa

    tracker = _read(".agents/skills/setup-matt-pocock-skills/issue-tracker-github.md")
    assert '--label "<label>" --type "<type>"' in tracker
    assert "gh issue create --label wayfinder:map --type Task" in tracker

    wayfinder = _read(".agents/skills/wayfinder/SKILL.md")
    assert "`wayfinder:<type>` label" in wayfinder
    assert "native issue type `Task`" in wayfinder

    workflow = _read(".agents/policy/workflow.md")
    assert "`wayfinder:map` and typed `Task`" in workflow
    assert "descriptive label(s)" in workflow
    assert "native type defined by `issues.md`" in workflow

    refactor = _read(".agents/skills/request-refactor-plan/SKILL.md")
    assert "`gh issue create --label architecture --type Task`" in refactor

    security = _read(".agents/skills/caveman-compress/SECURITY.md")
    assert "label `security` and native type `Bug`" in security
