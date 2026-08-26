"""coderabbit-cli.yml is dispatch-only and never posts a bot chat command."""

from __future__ import annotations

from pathlib import Path

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "coderabbit-cli.yml"


def test_cli_workflow_is_dispatch_only() -> None:
    text = WF.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text
    assert "schedule:" not in text
    assert "CODERABBIT_API_KEY" in text
    assert "coderabbit_cli_report.py" in text
    assert " --agent" in text
    assert "gh pr comment" not in text
    assert "rate limit" not in text.lower()
