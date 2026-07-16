"""Vocabulary-consistency tripwires for scanner-finding policy artifacts.

Behavioral enforcement coverage lives in ``tests/js/triage_findings_guard.test.js``;
these checks only keep policy, workflow schemas, and skill text on one vocabulary.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _assert_vocabulary(source: str, text: str, expected: str) -> None:
    actual = expected if expected in text else None
    assert actual == expected, f"{source}: expected vocabulary {expected!r}, got {actual!r}"


def test_scanner_finding_actionability_vocabulary_is_consistent() -> None:
    policy = _read("CLAUDE.md")
    batch_triage = _read(".claude/workflows/triage-findings.js")
    issue_triage = _read(".claude/workflows/issue-triage.js")
    pr_comments = _read(".claude/skills/pr-comments/SKILL.md")

    _assert_vocabulary("CLAUDE.md", policy, "### Scanner/audit finding gate")
    _assert_vocabulary("CLAUDE.md", policy, "Every newly found **actionable** TypeError-class defect")

    _assert_vocabulary("triage-findings.js", batch_triage, "'issue_gate'")
    for field in (
        "disposition",
        "producer",
        "supported_path",
        "required_privilege",
        "hand_crafted",
        "impact_scope",
        "black_box_repro",
    ):
        _assert_vocabulary("triage-findings.js", batch_triage, f"'{field}'")
    _assert_vocabulary("triage-findings.js", batch_triage, "DEFER requires an actionable issue_gate")

    _assert_vocabulary("issue-triage.js", issue_triage, "'reachability'")
    _assert_vocabulary("issue-triage.js", issue_triage, "supported producer")
    _assert_vocabulary("pr-comments/SKILL.md", pr_comments, "validated issue-gate block")


def test_hardening_only_vocabulary_is_consistent_across_issue_workflows() -> None:
    policy = _read("CLAUDE.md")
    batch_triage = _read(".claude/workflows/triage-findings.js")
    issue_triage = _read(".claude/workflows/issue-triage.js")
    gh_issue = _read(".claude/skills/gh-issue/SKILL.md")
    pr_comments = _read(".claude/skills/pr-comments/SKILL.md")

    _assert_vocabulary("CLAUDE.md", policy, "**HARDENING-ONLY**")
    _assert_vocabulary("CLAUDE.md", policy, "HARDENING-ONLY findings do not become tracker children")
    _assert_vocabulary("triage-findings.js", batch_triage, "hardening-only findings must be SKIP")
    _assert_vocabulary("issue-triage.js", issue_triage, "'HARDENING-ONLY'")
    _assert_vocabulary("gh-issue/SKILL.md", gh_issue, "DUPLICATE / HARDENING-ONLY")
    _assert_vocabulary("gh-issue/SKILL.md", gh_issue, "HARDENING-ONLY closes as not planned")
    _assert_vocabulary("pr-comments/SKILL.md", pr_comments, "HARDENING-ONLY finding is `SKIP`")
