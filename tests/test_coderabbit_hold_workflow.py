"""coderabbit-hold.yml mutes with labels only and can release the mute."""

from __future__ import annotations

from pathlib import Path

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "coderabbit-hold.yml"


def test_hold_workflow_contract() -> None:
    text = WF.read_text(encoding="utf-8")
    assert "issue_comment" in text
    assert "schedule:" in text
    assert 'cron: "*/15 * * * *"' in text
    assert "github.event.comment.user.login == 'coderabbitai[bot]'" in text
    assert '[ "${n}" = "${SOURCE}" ] && continue' in text
    assert "--add-label cr-hold" in text
    assert "--remove-label" in text
    assert "gh pr comment" not in text
    assert " -X POST" not in text
    assert " -f body=" not in text
