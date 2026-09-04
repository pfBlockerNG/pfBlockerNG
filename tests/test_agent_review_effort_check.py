"""Reviewer/verifier effort matrix tests for the shared role checker."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import test_agent_roles_check as roles


def _agent_toml(model: str, effort: str | None) -> str:
    effort_line = "" if effort is None else f'model_reasoning_effort = "{effort}"\n'
    return f'name = "x"\nmodel = "{model}"\n{effort_line}sandbox_mode = "read-only"\n'


def _review_tree(
    root: Path,
    role: str,
    small_effort: str | None,
    other_effort: str | None,
    other_model: str = "codex-top",
) -> Path:
    rows = tuple(row.replace("| checker |", f"| {role} |").replace("small+top", "small+top+mid") for row in roles._ROWS)
    sections = tuple(role if name == "checker" else name for name in roles._ROLE_NAMES)
    return roles.make_tree(
        root,
        doc=roles._doc(rows=rows, sections=sections),
        checker_toml=_agent_toml("codex-small", small_effort),
        checker_top_toml=_agent_toml(other_model, other_effort),
    )


@pytest.mark.parametrize("role", ["reviewer", "verifier"])
@pytest.mark.parametrize("other_model", ["codex-top", "codex-mid"])
def test_codex_review_matrix_accepts_luna_high_and_other_models_medium(
    tmp_path: Path, role: str, other_model: str
) -> None:
    assert roles._problems(_review_tree(tmp_path, role, "high", "medium", other_model)) == []


@pytest.mark.parametrize("role", ["reviewer", "verifier"])
@pytest.mark.parametrize("effort", [None, "medium", "xhigh"])
def test_codex_luna_reviewer_requires_high(tmp_path: Path, role: str, effort: str | None) -> None:
    problems = roles._problems(_review_tree(tmp_path, role, effort, "medium"))
    roles._assert_flags(problems, f"checker.toml model_reasoning_effort {effort!r} != required 'high'")


@pytest.mark.parametrize("role", ["reviewer", "verifier"])
@pytest.mark.parametrize("other_model", ["codex-top", "codex-mid"])
@pytest.mark.parametrize("effort", [None, "high", "xhigh"])
def test_codex_non_luna_reviewer_requires_medium(
    tmp_path: Path, role: str, other_model: str, effort: str | None
) -> None:
    problems = roles._problems(_review_tree(tmp_path, role, "high", effort, other_model))
    roles._assert_flags(problems, f"checker-top.toml model_reasoning_effort {effort!r} != required 'medium'")


def _claude_agent_md(model: str, effort: str | None) -> str:
    effort_line = "" if effort is None else f"effort: {effort}\n"
    return (
        f"---\nname: x\ndescription: test claude reviewer\nmodel: {model}\n{effort_line}---\n\n"
        f"<!-- mutation: read-only -->\n"
    )


def _claude_review_tree(
    root: Path,
    role: str,
    small_effort: str | None,
    other_effort: str | None,
    other_model: str = "claude-top-x",
) -> Path:
    rows = tuple(
        row.replace("| checker |", f"| {role} |")
        .replace("small+top", "small+top+mid")
        .replace("workflow:check", "agent:checker, agent:checker-top")
        for row in roles._ROWS
    )
    sections = tuple(role if name == "checker" else name for name in roles._ROLE_NAMES)
    tree = roles.make_tree(
        root,
        doc=roles._doc(rows=rows, sections=sections),
        checker_toml=_agent_toml("codex-small", "high"),
        checker_top_toml=_agent_toml("codex-top", "medium"),
    )
    (tree / ".claude/workflows/check.js").unlink()
    roles._write(tree / ".claude/agents/checker.md", _claude_agent_md("claude-small-x", small_effort))
    roles._write(tree / ".claude/agents/checker-top.md", _claude_agent_md(other_model, other_effort))
    return tree


@pytest.mark.parametrize("role", ["reviewer", "verifier"])
@pytest.mark.parametrize("other_model", ["claude-top-x", "claude-mid-x"])
def test_claude_review_matrix_accepts_all_models_medium(tmp_path: Path, role: str, other_model: str) -> None:
    assert roles._problems(_claude_review_tree(tmp_path, role, "medium", "medium", other_model)) == []


@pytest.mark.parametrize("role", ["reviewer", "verifier"])
@pytest.mark.parametrize("effort", [None, "high", "xhigh"])
def test_claude_reviewer_requires_medium(tmp_path: Path, role: str, effort: str | None) -> None:
    problems = roles._problems(_claude_review_tree(tmp_path, role, effort, "medium"))
    roles._assert_flags(problems, f"checker.md effort {effort!r} != required 'medium'")
