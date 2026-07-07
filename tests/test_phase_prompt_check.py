"""Tests for scripts/check_phase_prompts.py.

Intent: a phase prompt authored after the delegation contract (ADR >= 60) must
carry the contract's mandatory blocks — a VERIFICATION section, a HANDOFF block
naming its RESULTS file, a declared test mode (red-run vs behaviour-preserving
oracle), and the reality-override line — so a weak spec is caught before a
Sonnet implementer executes it. Pre-contract ADRs (<= 59) are grandfathered and
must never be flagged.

Per the test mandate, every flagged case is paired with the compliant form that
must stay clean, so green proves the check DISCRIMINATES rather than always or
never firing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_phase_prompts.py"
_spec = importlib.util.spec_from_file_location("check_phase_prompts", _TOOL)
assert _spec is not None and _spec.loader is not None
cpp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cpp
_spec.loader.exec_module(cpp)


_COMPLIANT = """\
================================================================================
PHASE 1 PROMPT — Example (behaviour-preserving)
Target model: Claude Sonnet 5
================================================================================

ROLE
Phase 1 of 2. BEHAVIOUR-PRESERVING refactor.

REQUIRED READING
- src/example.inc — the helper (~line 10).
Line numbers and code-state claims in this prompt were written before earlier
phases ran; the prior RESULTS files and the live tree override this prompt on
any conflict — verify each claim before acting on it.

ACTION PLAN
1. Do the thing.

VERIFICATION (must all pass)
- python -m pytest → green
- oracle test pins the resolved URL byte-identically

HANDOFF — write .ADRs/ADR_60_Example/RESULTS/01_Results.txt with the fixed
fields (CLAUDE.md "THE HANDOFF").
"""


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _violations(tmp_path: Path, rel: str, text: str) -> list[str]:
    """Check ids flagged for one prompt file written at ``rel``."""
    path = _write(tmp_path, rel, text)
    return [check for (_, check, _) in cpp.find_violations([path])]


PROMPT_60 = ".ADRs/ADR_60_Example/01_Example.txt"


def test_compliant_prompt_is_clean(tmp_path: Path) -> None:
    assert _violations(tmp_path, PROMPT_60, _COMPLIANT) == []


def test_missing_verification_section_is_flagged(tmp_path: Path) -> None:
    text = _COMPLIANT.replace("VERIFICATION (must all pass)", "CHECKS (informal)")
    assert _violations(tmp_path, PROMPT_60, text) == ["verification-section"]


def test_handoff_without_results_file_is_flagged(tmp_path: Path) -> None:
    text = _COMPLIANT.replace(
        "HANDOFF — write .ADRs/ADR_60_Example/RESULTS/01_Results.txt with the fixed",
        "HANDOFF — summarize what you did in the chat, with the fixed",
    )
    assert _violations(tmp_path, PROMPT_60, text) == ["handoff-results"]


def test_missing_mode_declaration_is_flagged(tmp_path: Path) -> None:
    text = _COMPLIANT.replace("(behaviour-preserving)", "").replace("BEHAVIOUR-PRESERVING refactor.", "A refactor.")
    text = text.replace("- oracle test pins the resolved URL byte-identically\n", "")
    assert _violations(tmp_path, PROMPT_60, text) == ["mode-declared"]


@pytest.mark.parametrize(
    "token",
    ["red-run", "red->green", "red→green", "behaviour-preserving", "oracle"],
)
def test_each_mode_token_satisfies_the_mode_check(tmp_path: Path, token: str) -> None:
    # Strip every mode token from the compliant prompt, then re-add exactly one.
    text = _COMPLIANT.replace("(behaviour-preserving)", "").replace("BEHAVIOUR-PRESERVING refactor.", "A refactor.")
    text = text.replace("- oracle test pins the resolved URL byte-identically\n", "")
    text += f"\nMODE NOTE: this phase is {token}.\n"
    assert _violations(tmp_path, PROMPT_60, text) == []


def test_missing_reality_override_line_is_flagged(tmp_path: Path) -> None:
    text = _COMPLIANT.replace(
        "phases ran; the prior RESULTS files and the live tree override this prompt on\n"
        "any conflict — verify each claim before acting on it.\n",
        "",
    )
    assert _violations(tmp_path, PROMPT_60, text) == ["reality-override"]


def test_noncompliant_prompt_reports_every_missing_block(tmp_path: Path) -> None:
    assert sorted(_violations(tmp_path, PROMPT_60, "just do the thing\n")) == [
        "handoff-results",
        "mode-declared",
        "reality-override",
        "verification-section",
    ]


def test_pre_contract_adr_is_grandfathered(tmp_path: Path) -> None:
    # Same fully non-compliant text, but under ADR_59 — must not be flagged.
    rel = ".ADRs/ADR_59_Legacy/01_Legacy.txt"
    assert _violations(tmp_path, rel, "just do the thing\n") == []


def test_results_handoffs_and_non_phase_files_are_skipped(tmp_path: Path) -> None:
    # RESULTS handoffs match the NN_*.txt shape but are outputs, not prompts;
    # non-numeric .txt notes are not phase prompts either.
    results = ".ADRs/ADR_60_Example/RESULTS/01_Results.txt"
    notes = ".ADRs/ADR_60_Example/notes.txt"
    assert _violations(tmp_path, results, "no blocks here\n") == []
    assert _violations(tmp_path, notes, "no blocks here\n") == []


def test_repo_tree_is_clean() -> None:
    # CI enforcement: every tracked post-contract phase prompt in THIS repo
    # complies. (Trivially green until ADR_60 exists; from then on it gates.)
    assert cpp.find_violations(cpp.tracked_phase_prompts()) == []
