"""coderabbit-hold.yml mutes with labels only and can release the mute."""

from __future__ import annotations

from pathlib import Path

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "coderabbit-hold.yml"


def test_hold_workflow_contract() -> None:
    text = WF.read_text(encoding="utf-8")
    assert "issue_comment" in text
    assert "pull_request:" in text
    assert "schedule:" in text
    assert 'cron: "*/15 * * * *"' in text
    assert "github.event.comment.user.login == 'coderabbitai[bot]'" in text
    assert '[ "${n}" = "${SOURCE}" ] && continue' in text
    assert "*,cr-go,*) continue" in text
    assert "--add-label cr-hold" in text
    assert "coderabbit_hold.py poll" in text
    assert "Reviews are available now" in text
    assert "Actionable comments posted" in text
    assert "CODERABBIT_PLAN: pro+" in text
    assert "--limit 100" in text
    assert "gh pr comment" not in text
    assert " -X POST" not in text
    assert " -f body=" not in text
    assert "CODERABBIT_API_KEY" not in text


def test_coderabbit_yaml_keeps_apply_incremental() -> None:
    text = (WF.parents[2] / ".coderabbit.yaml").read_text(encoding="utf-8")
    assert "auto_pause_after_reviewed_commits: 2" in text
    assert "auto_incremental_review: false" not in text
    assert "!cr-hold" in text
