"""coderabbit-hold.yml must mute with labels only — never comment."""

from __future__ import annotations

from pathlib import Path

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "coderabbit-hold.yml"


def test_hold_workflow_labels_only() -> None:
    text = WF.read_text(encoding="utf-8")
    assert "issue_comment" in text
    assert "cr-hold" in text
    assert "Review limit reached" in text
    assert "@coderabbitai" not in text
    assert "gh pr comment" not in text
    assert "--add-label cr-hold" in text
