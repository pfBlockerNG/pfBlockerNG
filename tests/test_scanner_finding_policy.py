"""Vocabulary-consistency tripwires for scanner-finding policy artifacts.

Keeps CLAUDE.md and the landing policy (.agents/policy/landing.md) on one
vocabulary for the scanner/audit finding gate and HARDENING-ONLY handling.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    # Collapse whitespace: policy prose hard-wraps mid-phrase.
    return re.sub(r"\s+", " ", (ROOT / relative_path).read_text(encoding="utf-8"))


def _assert_vocabulary(source: str, text: str, expected: str) -> None:
    actual = expected if expected in text else None
    assert actual == expected, f"{source}: expected vocabulary {expected!r}, got {actual!r}"


def test_scanner_finding_actionability_vocabulary_is_consistent() -> None:
    policy = _read("CLAUDE.md")
    landing = _read(".agents/policy/landing.md")

    _assert_vocabulary("CLAUDE.md", policy, "### Scanner/audit finding gate")
    _assert_vocabulary("CLAUDE.md", policy, "Every newly found **actionable** TypeError-class defect")

    _assert_vocabulary(
        "landing.md",
        landing,
        "validated issue-gate block (producer, supported path, privilege, "
        "hand-crafted yes/no, impact scope, black-box reproduction)",
    )


def test_hardening_only_vocabulary_is_consistent_across_policy() -> None:
    policy = _read("CLAUDE.md")
    landing = _read(".agents/policy/landing.md")

    _assert_vocabulary("CLAUDE.md", policy, "**HARDENING-ONLY**")
    _assert_vocabulary("CLAUDE.md", policy, "HARDENING-ONLY findings do not become tracker children")
    _assert_vocabulary(
        "landing.md",
        landing,
        "HARDENING-ONLY finding (per the CLAUDE.md scanner gate) is SKIP",
    )
