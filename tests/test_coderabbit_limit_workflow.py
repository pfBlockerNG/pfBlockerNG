"""Advisory limit helper is mechanical; no mute labels or hold workflow."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hold_workflow_and_mute_labels_are_gone() -> None:
    workflows = ROOT / ".github" / "workflows"
    assert not (workflows / "coderabbit-hold.yml").exists()
    yaml = (ROOT / ".coderabbit.yaml").read_text(encoding="utf-8")
    assert "cr-hold" not in yaml
    assert "cr-go" not in yaml
    assert "auto_pause_after_reviewed_commits: 2" in yaml
    assert "auto_incremental_review: false" not in yaml


def test_before_pr_create_invokes_status() -> None:
    text = (ROOT / "scripts" / "agent" / "before-pr-create.sh").read_text(encoding="utf-8")
    assert "coderabbit_limit.py" in text
    assert "status" in text
    assert "gh pr comment" not in text
    py = (ROOT / "scripts" / "agent" / "coderabbit_limit.py").read_text(encoding="utf-8")
    assert "cr-hold" not in py
    assert "add-label" not in py
    assert "created_at" in py
    assert "issues/comments?since=" in py
