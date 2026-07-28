"""Ticket creators use native issue types; labels add only orthogonal metadata."""

import json
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

    qa = _read(".agents/skills/qa/SKILL.md")
    assert "`gh issue create --type Bug`" in qa

    tracker = _read("plugins/mattpocock-skills/codex/skills/setup-matt-pocock-skills/issue-tracker-github.md")
    assert '--type "<type>"' in tracker
    assert "`--label` is optional" in tracker
    assert "gh issue create --label wayfinder:map --type Task" in tracker

    wayfinder = _read("plugins/mattpocock-skills/codex/skills/wayfinder/SKILL.md")
    assert "`wayfinder:<type>` label" in wayfinder
    assert "native issue type `Task`" in wayfinder

    workflow = _read(".agents/policy/workflow.md")
    assert "`wayfinder:map` and typed `Task`" in workflow
    assert "optional additive labels" in workflow
    assert "native type defined by `issues.md`" in workflow

    refactor = _read(".agents/skills/request-refactor-plan/SKILL.md")
    assert "`gh issue create --label architecture --type Task`" in refactor

    security = _read(".agents/skills/caveman-compress/SECURITY.md")
    assert "label `security` and native type `Bug`" in security


def test_mattpocock_plugin_packages_promoted_skills_once() -> None:
    plugin = ROOT / "plugins/mattpocock-skills"
    claude = json.loads((plugin / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
    codex = json.loads((plugin / "codex/.codex-plugin/plugin.json").read_text(encoding="utf-8"))
    marketplace = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text(encoding="utf-8"))
    claude_marketplace = json.loads((plugin / ".claude-plugin/marketplace.json").read_text(encoding="utf-8"))
    locked = set(json.loads((ROOT / "skills-lock.json").read_text(encoding="utf-8"))["skills"])

    claude_skills = {Path(skill).name for skill in claude["skills"]}
    codex_skills = {path.name for path in (plugin / "codex/skills").iterdir() if path.is_dir()}
    promoted = {
        "ask-matt",
        "code-review",
        "codebase-design",
        "diagnosing-bugs",
        "domain-modeling",
        "grill-me",
        "grill-with-docs",
        "grilling",
        "handoff",
        "implement",
        "improve-codebase-architecture",
        "prototype",
        "research",
        "resolving-merge-conflicts",
        "setup-matt-pocock-skills",
        "tdd",
        "teach",
        "to-spec",
        "to-tickets",
        "triage",
        "wayfinder",
        "writing-great-skills",
    }
    retained = {
        "batch-grill-me",
        "claude-handoff",
        "design-an-interface",
        "edit-article",
        "git-guardrails-claude-code",
        "loop-me",
        "migrate-to-shoehorn",
        "obsidian-vault",
        "qa",
        "request-refactor-plan",
        "scaffold-exercises",
        "setup-pre-commit",
        "setup-ts-deep-modules",
        "to-questionnaire",
        "ubiquitous-language",
        "wizard",
        "writing-beats",
        "writing-fragments",
        "writing-shape",
    }
    local_vendored = {
        "cavecrew",
        "caveman",
        "caveman-commit",
        "caveman-compress",
        "caveman-help",
        "caveman-review",
        "caveman-stats",
    }

    assert claude["name"] == codex["name"] == "mattpocock-skills"
    assert claude["version"] == codex["version"] == "1.2.0"
    assert claude_skills == codex_skills == promoted
    assert codex["skills"] == "./skills/"
    assert not (plugin / "skills").exists()
    assert locked == retained | local_vendored
    assert all((ROOT / ".agents/skills" / name).exists() for name in retained)
    assert all(not (ROOT / ".agents/skills" / name).exists() for name in promoted)
    assert all(not (ROOT / ".claude/skills" / name).exists() for name in promoted)

    entry = next(item for item in marketplace["plugins"] if item["name"] == "mattpocock-skills")
    assert entry["source"] == {"source": "local", "path": "./plugins/mattpocock-skills/codex"}
    claude_entry = next(item for item in claude_marketplace["plugins"] if item["name"] == "mattpocock-skills")
    assert claude_entry["source"] == "./"

    explicit_only = {
        "ask-matt",
        "grill-me",
        "grill-with-docs",
        "handoff",
        "implement",
        "improve-codebase-architecture",
        "setup-matt-pocock-skills",
        "teach",
        "to-spec",
        "to-tickets",
        "triage",
        "wayfinder",
        "writing-great-skills",
    }
    for name in promoted:
        claude_root = plugin / "claude-skills" / name
        codex_root = plugin / "codex/skills" / name
        claude_files = {path.relative_to(claude_root) for path in claude_root.rglob("*") if path.is_file()}
        codex_files = {path.relative_to(codex_root) for path in codex_root.rglob("*") if path.is_file()}
        assert claude_files == codex_files

        for relative in claude_files:
            claude_bytes = (claude_root / relative).read_bytes()
            codex_bytes = (codex_root / relative).read_bytes()
            if relative == Path("SKILL.md") and name in explicit_only:
                claude_bytes = claude_bytes.replace(b"disable-model-invocation: true\n", b"", 1)
            assert claude_bytes == codex_bytes

        claude_skill = (claude_root / "SKILL.md").read_text(encoding="utf-8")
        has_explicit_flag = "disable-model-invocation: true" in claude_skill.partition("\n---\n")[0].splitlines()
        assert has_explicit_flag == (name in explicit_only)
        if name in explicit_only:
            codex_metadata = (codex_root / "agents/openai.yaml").read_text(encoding="utf-8")
            assert "allow_implicit_invocation: false" in codex_metadata
