"""Reviewer/verifier effort matrix tests for the shared role checker."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import test_agent_roles_check as roles


def _agent_toml(model: str, effort: str | None) -> str:
    effort_line = "" if effort is None else f'model_reasoning_effort = "{effort}"\n'
    return f'name = "x"\nmodel = "{model}"\n{effort_line}sandbox_mode = "read-only"\n'


def _review_tree(root: Path, role: str, small_effort: str | None, top_effort: str | None) -> Path:
    rows = tuple(row.replace("| checker |", f"| {role} |") for row in roles._ROWS)
    sections = tuple(role if name == "checker" else name for name in roles._ROLE_NAMES)
    return roles.make_tree(
        root,
        doc=roles._doc(rows=rows, sections=sections),
        checker_toml=_agent_toml("codex-small", small_effort),
        checker_top_toml=_agent_toml("codex-top", top_effort),
    )


@pytest.mark.parametrize("role", ["reviewer", "verifier"])
def test_codex_review_matrix_accepts_luna_high_and_other_models_medium(tmp_path: Path, role: str) -> None:
    assert roles._problems(_review_tree(tmp_path, role, "high", "medium")) == []


@pytest.mark.parametrize("effort", [None, "medium", "xhigh"])
def test_codex_luna_reviewer_requires_high(tmp_path: Path, effort: str | None) -> None:
    problems = roles._problems(_review_tree(tmp_path, "reviewer", effort, "medium"))
    roles._assert_flags(problems, f"checker.toml model_reasoning_effort {effort!r} != required 'high'")


@pytest.mark.parametrize("effort", [None, "high", "xhigh"])
def test_codex_non_luna_reviewer_requires_medium(tmp_path: Path, effort: str | None) -> None:
    problems = roles._problems(_review_tree(tmp_path, "reviewer", "high", effort))
    roles._assert_flags(problems, f"checker-top.toml model_reasoning_effort {effort!r} != required 'medium'")
