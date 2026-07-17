#!/usr/bin/env python3
"""Enforce the context-taxonomy byte budgets and routing headers (map #1383, #1437).

AGENTS.md is the canonical agent bootstrap; `.agents/policy/` + `.agents/context/`
hold the routed policy/context files; hook capsules ride `.claude/settings.json`.
Every surface has a byte budget so the hot context cannot silently re-accrete
(taxonomy #1386 anti-monolith rules), and every file the bootstrap's routing
table references must carry a `Scope:` + `Load-when:` header so it stays
routable. Budgets (calibrated on the measured Stage 1/2 tree, not the matrix
estimates):

- `AGENTS.md` (bootstrap)                          10,240 B
- `CLAUDE.md` (thin adapter + tool-managed blocks)  8,192 B
- `.agents/policy/*.md` / `.agents/context/*.md`   12,288 B default; grandfathered
  ratchet caps for the pre-taxonomy files (landing 26,000, agent-roles 19,000,
  delegation 18,000 — may shrink, never grow)
- nested `CLAUDE.md`/`AGENTS.md` dir stubs            400 B
- each hook-capsule `additionalContext` payload     1,800 B

CONDITIONAL: in --staged / --diff mode the checks run IF AND ONLY IF the change
touches a context surface (AGENTS.md, CLAUDE.md, .agents/policy/,
.agents/context/, .claude/settings.json, any nested CLAUDE.md/AGENTS.md, or this
checker); otherwise it reports the skip and exits 0. --all checks unconditionally.

Usage:
    check_context_budget.py --staged        # pre-commit: staged diff decides
    check_context_budget.py --diff <base>   # CI PR gate: base...HEAD decides
    check_context_budget.py --all           # unconditional full check
    [--root PATH]                           # repo root (default: script's repo)

Exit status: 0 = clean or skipped, 1 = violations (printed), 2 = usage/git error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

BOOTSTRAP_BUDGET = 10_240
ADAPTER_BUDGET = 8_192
POLICY_BUDGET = 12_288
STUB_BUDGET = 400
CAPSULE_BUDGET = 1_800

# Grandfathered ratchet caps for files predating the taxonomy budgets: they may
# shrink toward POLICY_BUDGET, never grow past their cap.
FILE_BUDGETS = {
    "AGENTS.md": BOOTSTRAP_BUDGET,
    "CLAUDE.md": ADAPTER_BUDGET,
    ".agents/policy/landing.md": 26_000,
    ".agents/policy/agent-roles.md": 19_000,
    ".agents/policy/delegation.md": 18_000,
}

SETTINGS = ".claude/settings.json"

# Accepts both header shapes in the first HEADER_WINDOW lines: the plain
# "Scope: ... Load when: ..." prose and the bulleted "- **Scope:** / - **Load-when:**".
HEADER_WINDOW = 12
_SCOPE_RE = re.compile(r"\*\*Scope:?\*\*|^Scope:|\bScope: ", re.MULTILINE)
_LOADWHEN_RE = re.compile(r"Load[- ]when:", re.IGNORECASE)

_MD_TOKEN_RE = re.compile(r"`([^`\s]+\.md)`")
_RESOLVE_DIRS = (".agents/policy", ".agents/context", "docs/misc")


def budget_for(rel: str) -> int | None:
    """Byte budget for a tracked file, or None when unbudgeted."""
    if rel in FILE_BUDGETS:
        return FILE_BUDGETS[rel]
    if rel.startswith((".agents/policy/", ".agents/context/")) and rel.endswith(".md"):
        return POLICY_BUDGET
    base = rel.rsplit("/", 1)[-1]
    if "/" in rel and base in ("CLAUDE.md", "AGENTS.md") and not rel.startswith("plugins/"):
        # plugins/ is vendored — its instruction files are not our dir stubs.
        return STUB_BUDGET
    return None


def check_sizes(root: Path, tracked: list[str]) -> list[str]:
    violations = []
    for rel in tracked:
        budget = budget_for(rel)
        if budget is None:
            continue
        size = (root / rel).stat().st_size
        if size > budget:
            violations.append(f"{rel}: {size} bytes > budget {budget}")
    return violations


def routing_targets(bootstrap_text: str) -> tuple[list[str], list[str]]:
    """Backticked *.md targets of the bootstrap routing table.

    Returns (raw_tokens, non_literal_tokens_skipped). Tokens containing template
    characters (<, |) are skipped — they name a file family, not a file.
    """
    lines = bootstrap_text.split("\n")
    in_table = False
    tokens: list[str] = []
    skipped: list[str] = []
    for line in lines:
        if line.startswith("## "):
            in_table = "Routing table" in line
            continue
        if in_table and line.startswith("|"):
            for tok in _MD_TOKEN_RE.findall(line):
                if "<" in tok or "|" in tok:
                    skipped.append(tok)
                else:
                    tokens.append(tok)
    return tokens, skipped


def resolve_target(root: Path, token: str) -> str | None:
    """Resolve a routing token to a repo-relative path, or None."""
    if "/" in token:
        return token if (root / token).is_file() else None
    for d in _RESOLVE_DIRS:
        rel = f"{d}/{token}"
        if (root / rel).is_file():
            return rel
    return None


def has_context_header(text: str) -> bool:
    head = "\n".join(text.split("\n")[:HEADER_WINDOW])
    return bool(_SCOPE_RE.search(head)) and bool(_LOADWHEN_RE.search(head))


def check_headers(root: Path) -> list[str]:
    bootstrap = root / "AGENTS.md"
    if not bootstrap.is_file():
        return ["AGENTS.md: bootstrap missing — nothing to route from"]
    tokens, _ = routing_targets(bootstrap.read_text(encoding="utf-8"))
    violations = []
    for token in dict.fromkeys(tokens):
        rel = resolve_target(root, token)
        if rel is None:
            violations.append(f"AGENTS.md: routing target `{token}` does not resolve to a file")
            continue
        if not has_context_header((root / rel).read_text(encoding="utf-8")):
            violations.append(f"{rel}: routed file lacks a Scope: + Load-when: header (first {HEADER_WINDOW} lines)")
    return violations


def extract_capsules(settings_text: str) -> tuple[list[tuple[str, int]], list[str]]:
    """(event, payload-bytes) per hook capsule; second element = extraction errors."""
    capsules: list[tuple[str, int]] = []
    errors: list[str] = []
    settings = json.loads(settings_text)
    for event, entries in settings.get("hooks", {}).items():
        for entry in entries:
            for hook in entry.get("hooks", []):
                command = hook.get("command", "")
                if "additionalContext" not in command:
                    continue
                start, end = command.find("'"), command.rfind("'")
                try:
                    payload = json.loads(command[start + 1 : end])
                    text = payload["hookSpecificOutput"]["additionalContext"]
                except (ValueError, KeyError, TypeError):
                    errors.append(f"{SETTINGS}: {event} capsule payload is not extractable JSON")
                    continue
                capsules.append((event, len(text.encode("utf-8"))))
    return capsules, errors


def check_capsules(root: Path) -> list[str]:
    settings = root / SETTINGS
    if not settings.is_file():
        return []
    capsules, violations = extract_capsules(settings.read_text(encoding="utf-8"))
    for event, size in capsules:
        if size > CAPSULE_BUDGET:
            violations.append(f"{SETTINGS}: {event} capsule {size} bytes > budget {CAPSULE_BUDGET}")
    return violations


def run_checks(root: Path, tracked: list[str]) -> list[str]:
    return check_sizes(root, tracked) + check_headers(root) + check_capsules(root)


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True)
    return proc.stdout


def touches_context_surface(changed: list[str]) -> bool:
    for rel in changed:
        base = rel.rsplit("/", 1)[-1]
        if (
            rel in ("AGENTS.md", "CLAUDE.md", SETTINGS, "scripts/check_context_budget.py")
            or rel.startswith((".agents/policy/", ".agents/context/"))
            or base in ("CLAUDE.md", "AGENTS.md")
        ):
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="scope by the staged diff")
    mode.add_argument("--diff", metavar="BASE", help="scope by BASE...HEAD")
    mode.add_argument("--all", action="store_true", help="check unconditionally")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if not args.all:
            diff_args = (
                ["diff", "--cached", "--name-only"] if args.staged else ["diff", "--name-only", f"{args.diff}...HEAD"]
            )
            changed = _git(root, *diff_args).split()
            if not touches_context_surface(changed):
                print("context-budget: no context surface in the diff — skipped")
                return 0
        tracked = _git(root, "ls-files").split("\n")
        tracked = [t for t in tracked if t]
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"context-budget: git failed: {exc}", file=sys.stderr)
        return 2
    violations = run_checks(root, tracked)
    for violation in violations:
        print(violation)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
