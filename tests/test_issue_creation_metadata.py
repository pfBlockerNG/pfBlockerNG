"""Ticket creators use native issue types; labels add only orthogonal metadata."""

import re
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


def test_automated_issue_creators_set_type_and_only_additive_labels() -> None:
    expected = {
        "nightly-failure-alert.yml": [("nightly-red", "Bug")],
        "top1m-healthcheck.yml": [("top1m-provider", "Bug")],
        # version-tracker.yml creates NO issues anymore — the matrix auto-PR is
        # the sole notification surface (issue #1823)
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


def test_issue_forms_declare_native_type_and_disable_blank_issues() -> None:
    # The bug form carries no label: its category rides solely on the native
    # issue type (a81fc030 dropped the redundant `bug` label).
    forms = {
        "bug_report.yml": ("type: bug",),
        "feature_request.yml": ("type: feature",),
        "task_request.yml": ("type: task",),
    }
    template_dir = ROOT / ".github/ISSUE_TEMPLATE"
    form_files = {
        path.name for path in template_dir.iterdir() if path.suffix in {".yml", ".yaml"} and path.name != "config.yml"
    }
    assert form_files == forms.keys()
    for filename, expected_lines in forms.items():
        form = _read(f".github/ISSUE_TEMPLATE/{filename}")
        for expected in expected_lines:
            assert f"\n{expected}\n" in form
        assert not re.search(r"""(?m)^\s*["']?labels["']?\s*:""", form)

    config = _read(".github/ISSUE_TEMPLATE/config.yml")
    assert "blank_issues_enabled: false" in config


def test_human_ticket_procedures_make_labels_optional() -> None:
    policy = _read(".agents/policy/issues.md")
    for issue_type in ("Bug", "Feature", "Task"):
        assert f"| `{issue_type}` |" in policy
    assert "Labels are optional" in policy
    assert "`gh issue create --type Bug`" in policy

    workflow = _read(".agents/policy/workflow.md")
    assert "`wayfinder:map` and typed `Task`" in workflow
    assert "optional additive labels" in workflow
    assert "native type defined by `issues.md`" in workflow
