from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_scanner_findings_require_actionability_before_issue_creation() -> None:
    policy = _read("CLAUDE.md")
    batch_triage = _read(".claude/workflows/triage-findings.js")
    issue_triage = _read(".claude/workflows/issue-triage.js")
    pr_comments = _read(".claude/skills/pr-comments/SKILL.md")

    assert "### Scanner/audit finding gate" in policy
    assert "Every newly found **actionable** TypeError-class defect" in policy

    assert "'issue_gate'" in batch_triage
    for field in (
        "producer",
        "supported_path",
        "required_privilege",
        "hand_crafted",
        "impact_scope",
        "black_box_repro",
    ):
        assert f"'{field}'" in batch_triage
    assert "DEFER requires an actionable issue_gate" in batch_triage

    assert "'reachability'" in issue_triage
    assert "supported producer" in issue_triage
    assert "validated issue-gate block" in pr_comments


def test_hardening_only_is_terminal_across_issue_workflows() -> None:
    policy = _read("CLAUDE.md")
    batch_triage = _read(".claude/workflows/triage-findings.js")
    issue_triage = _read(".claude/workflows/issue-triage.js")
    gh_issue = _read(".claude/skills/gh-issue/SKILL.md")
    pr_comments = _read(".claude/skills/pr-comments/SKILL.md")

    assert "**HARDENING-ONLY**" in policy
    assert "HARDENING-ONLY findings do not become tracker children" in policy
    assert "hardening-only findings must be SKIP" in batch_triage
    assert "'HARDENING-ONLY'" in issue_triage
    assert "DUPLICATE / HARDENING-ONLY" in gh_issue
    assert "HARDENING-ONLY closes as not planned" in gh_issue
    assert "HARDENING-ONLY finding is `SKIP`" in pr_comments
