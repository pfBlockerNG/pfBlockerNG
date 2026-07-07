#!/usr/bin/env python3
"""Forbid delegation-process narration in newly added code comments.

ADR phase numbers ("wired in Phase 4"), `RESULTS/` handoff refs, and review
archaeology ("review-fanout C9", "Copilot, PR #947") narrate how a change was
produced, not what the code must uphold — that evidence belongs in the ADR,
the handoff, or the PR body (CLAUDE.md "Comments — constraint, not
narration"). One-line `issue #NNN` regression breadcrumbs stay legal.

DIFF-SCOPED: only ADDED lines are judged (`--staged` for the pre-commit hook,
`--diff <base>` for CI's PR gate), so the pre-existing narration is
grandfathered until its cleanup lands and this gate never blocks an unrelated
change. Scope: `src/` and `scripts/`, minus `*.md` and the files whose subject
IS phases/narration (this checker, its test, `check_phase_prompts.py`).

Escape a genuine need inline with `# narration-ok: <reason>`.

Exit status: 0 = clean, 1 = violations (printed file:line), 2 = usage/git error.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import PurePosixPath
from typing import NamedTuple

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"RESULTS/"), "delegation handoff artifact (RESULTS/...)"),
    # Capitalised only: ADR narration always writes "Phase N"; ordinary prose
    # about a protocol's "phase 2" stays legal.
    (re.compile(r"\bPhase [0-9]"), "ADR phase narration (Phase N)"),
    (re.compile(r"review-fanout"), "review archaeology (review-fanout)"),
    (re.compile(r"\bPR #[0-9]"), "review archaeology (PR #N)"),
)

_ESCAPE = "narration-ok"

_SCAN_ROOTS = ("src", "scripts")

# Self-reference: these define/validate the banned vocabulary.
_EXCLUDED_NAMES = (
    "check_comment_narration.py",
    "test_comment_narration_check.py",
    "check_phase_prompts.py",
)


class Violation(NamedTuple):
    path: str
    line: int
    text: str
    reason: str


def _in_scope(path: str) -> bool:
    p = PurePosixPath(path)
    if p.suffix == ".md" or p.name in _EXCLUDED_NAMES:
        return False
    return any(p.parts and p.parts[0] == root for root in _SCAN_ROOTS)


def find_violations(diff_text: str) -> list[Violation]:
    """Scan a unified diff (``git diff`` output) and judge its ADDED lines."""
    violations: list[Violation] = []
    path: str | None = None
    lineno = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            name = raw[4:]
            path = name[2:] if name.startswith("b/") else None  # +++ /dev/null
            continue
        if raw.startswith("@@"):
            m = re.match(r"@@ -\S+ \+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            line = raw[1:]
            if path is not None and _in_scope(path) and _ESCAPE not in line:
                for pattern, reason in _PATTERNS:
                    if pattern.search(line):
                        violations.append(Violation(path, lineno, line.strip(), reason))
                        break
            lineno += 1
        elif not raw.startswith("-"):
            lineno += 1  # context line (absent under --unified=0, tolerated)
    return violations


def _git_diff(args: list[str]) -> str:
    out = subprocess.run(
        ["git", "diff", "--unified=0", "--no-color", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout


def main(argv: list[str]) -> int:
    try:
        if argv == ["--staged"]:
            diff = _git_diff(["--cached"])
        elif len(argv) == 2 and argv[0] == "--diff":
            diff = _git_diff([f"{argv[1]}...HEAD"])
        else:
            print("usage: check_comment_narration.py --staged | --diff <base>", file=sys.stderr)
            return 2
    except subprocess.CalledProcessError as exc:
        print(f"git diff failed: {exc.stderr.strip()}", file=sys.stderr)
        return 2
    violations = find_violations(diff)
    if not violations:
        return 0
    print("Process-narration comment(s) in added lines:\n", file=sys.stderr)
    for v in violations:
        print(f"  {v.path}:{v.line}: [{v.reason}] {v.text}", file=sys.stderr)
    print(
        "\nPhase numbers, RESULTS/ refs, and review archaeology narrate how a change\n"
        "was produced — put that in the ADR / handoff / PR body and keep the comment\n"
        'to the constraint itself (CLAUDE.md "Comments — constraint, not narration").\n'
        "Escape a genuine need inline with `# narration-ok: <reason>`.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
