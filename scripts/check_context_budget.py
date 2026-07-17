#!/usr/bin/env python3
"""Enforce the context-taxonomy byte budgets and routing headers (map #1383, #1437).

AGENTS.md is the canonical agent bootstrap; `.agents/policy/` + `.agents/context/`
hold the routed policy/context files; hook capsules ride `.claude/settings.json`.
Every surface has a byte budget so the hot context cannot silently re-accrete
(taxonomy #1386 anti-monolith rules), and every file the bootstrap's routing
table references must carry a `Scope:` + `Load-when:` header so it stays
routable. Budgets (calibrated on the measured tree, not the matrix estimates):

- `AGENTS.md` (bootstrap)                          10,240 B
- `CLAUDE.md` (thin adapter + tool-managed blocks)  8,192 B
- `.agents/policy/*.md` / `.agents/context/*.md`   12,288 B default; grandfathered
  ratchet caps for the pre-taxonomy files (landing 26,000, agent-roles 19,000,
  delegation 18,000 — frozen constants: lower them as the files shrink)
- nested `CLAUDE.md`/`AGENTS.md` dir stubs            400 B
- `.claude/rules/*.md` (Claude soft routing backstops) 400 B
- each hook-capsule `additionalContext` payload     1,800 B

CONDITIONAL: in --staged / --diff mode the checks run IF AND ONLY IF the change
touches a context surface (AGENTS.md, CLAUDE.md, .agents/policy/,
.agents/context/, .claude/settings.json, any nested CLAUDE.md/AGENTS.md, or this
checker); otherwise it reports the skip and exits 0. --all checks unconditionally.

Usage:
    check_context_budget.py --staged        # pre-commit: staged diff decides, index content checked
    check_context_budget.py --diff <base>   # local/ad-hoc: base...HEAD decides
    check_context_budget.py --all           # CI gate (context-budget.yml) + unconditional full check
    [--root PATH]                           # repo root (default: script's repo)

Exit status: 0 = clean or skipped, 1 = violations (printed), 2 = usage/git error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
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

# A single well-formed `<a|b|c>` alternation group: prefix/suffix may not carry
# any further `<`/`>` — that rejects more-than-one-group tokens structurally.
_TEMPLATE_RE = re.compile(r"^(?P<prefix>[^<>]*)<(?P<body>[^<>]*)>(?P<suffix>[^<>]*)$")


def _expand_template(tok: str) -> list[str] | None:
    """Expand a lone `<a|b|c>` group into one token per alternative, or None.

    None means "not a clean single-group template" — either a plain literal
    token (no `<`/`>` at all) or a malformed/ambiguous one (unclosed `<`, more
    than one group, or any empty alternative like `<>`/`<|>`/`<a||b>`); the
    caller SKIPS those, it never crashes or invents a resolved target.
    """
    match = _TEMPLATE_RE.fullmatch(tok)
    if match is None:
        return None
    alts = match["body"].replace("\\", "").split("|")
    if any(alt == "" for alt in alts):
        return None
    return [f"{match['prefix']}{alt}{match['suffix']}" for alt in alts]


def budget_for(rel: str) -> int | None:
    """Byte budget for a tracked file, or None when unbudgeted."""
    if rel in FILE_BUDGETS:
        return FILE_BUDGETS[rel]
    if rel.startswith(".claude/rules/") and rel.endswith(".md"):
        return STUB_BUDGET
    base = rel.rsplit("/", 1)[-1]
    # A `plugins/` path segment ANYWHERE (not just root-anchored) is vendored —
    # its instruction files are not our dir stubs. Checked before the
    # policy/context prefix: a nested AGENTS.md/CLAUDE.md under .agents/ is a
    # dir stub, not a routed policy file.
    if "/" in rel and base in ("CLAUDE.md", "AGENTS.md") and "plugins" not in rel.split("/")[:-1]:
        return STUB_BUDGET
    if rel.startswith((".agents/policy/", ".agents/context/")) and rel.endswith(".md"):
        return POLICY_BUDGET
    return None


def check_sizes(root: Path, tracked: list[str]) -> list[str]:
    violations = []
    for rel in tracked:
        budget = budget_for(rel)
        if budget is None:
            continue
        try:
            size = (root / rel).stat().st_size
        except OSError as exc:
            # Tracked but unreadable (e.g. deleted from the worktree with the
            # deletion unstaged) — fail closed with a violation, not a traceback.
            violations.append(f"{rel}: unreadable ({exc.strerror or exc})")
            continue
        if size > budget:
            violations.append(f"{rel}: {size} bytes > budget {budget}")
    return violations


def routing_targets(bootstrap_text: str) -> tuple[list[str], list[str]]:
    """Backticked *.md targets of the bootstrap routing table.

    Returns (raw_tokens, non_literal_tokens_skipped). A token with exactly one
    well-formed `<a|b|c>` alternation group (markdown-escaped `\\|` stripped
    first) expands into one token per alternative; any other token carrying
    `<` or `|` (malformed/ambiguous template, or more than one group) is
    skipped — it names a file family, not a file.
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
                expanded = _expand_template(tok)
                if expanded is not None:
                    tokens.extend(expanded)
                elif "<" in tok or "|" in tok:
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
    if not tokens:
        # A renamed/removed "## Routing table" heading would otherwise disarm
        # the whole header gate silently (zero targets = vacuous pass).
        return ["AGENTS.md: no routing-table targets extracted — heading renamed or table removed?"]
    violations = []
    for token in dict.fromkeys(tokens):
        rel = resolve_target(root, token)
        if rel is None:
            violations.append(f"AGENTS.md: routing target `{token}` does not resolve to a file")
            continue
        if not has_context_header((root / rel).read_text(encoding="utf-8")):
            violations.append(f"{rel}: routed file lacks a Scope: + Load-when: header (first {HEADER_WINDOW} lines)")
    return violations


def extract_capsules(settings_text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """(event, payload-text) per hook capsule; second element = extraction errors."""
    capsules: list[tuple[str, str]] = []
    errors: list[str] = []
    try:
        settings = json.loads(settings_text)
        # The whole traversal sits in the try: a parse error OR a valid-JSON
        # wrong-shape file (hooks as a list, entries as strings, …) fails closed
        # as a violation, never a traceback that would also swallow the other
        # checks' already-found violations.
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
                    capsules.append((event, text))
    except (ValueError, AttributeError, TypeError):
        return [], [f"{SETTINGS}: not a parseable hooks structure — capsule budgets unverifiable"]
    return capsules, errors


def check_capsules(root: Path) -> list[str]:
    settings = root / SETTINGS
    if not settings.is_file():
        return []
    capsules, violations = extract_capsules(settings.read_text(encoding="utf-8"))
    for event, text in capsules:
        size = len(text.encode("utf-8"))
        if size > CAPSULE_BUDGET:
            violations.append(f"{SETTINGS}: {event} capsule {size} bytes > budget {CAPSULE_BUDGET}")
    return violations


def _normalize(text: str) -> str:
    """Fold markdown bold markers + whitespace runs for prose substring comparison."""
    return re.sub(r"\s+", " ", text.replace("*", ""))


def check_parity(root: Path) -> list[str]:
    """Every UserPromptSubmit capsule's `label: seg · seg · ...` segments must each be a
    normalized substring of AGENTS.md — the capsule paraphrases the bootstrap, never drifts."""
    settings = root / SETTINGS
    agents = root / "AGENTS.md"
    if not settings.is_file() or not agents.is_file():
        return []  # missing AGENTS.md is already a check_headers violation
    capsules, _ = extract_capsules(settings.read_text(encoding="utf-8"))
    agents_norm = _normalize(agents.read_text(encoding="utf-8"))
    violations = []
    for event, text in capsules:
        if event != "UserPromptSubmit":
            continue
        _label, sep, remainder = text.partition(": ")
        if not sep:
            violations.append(f"{SETTINGS}: UserPromptSubmit capsule has no '<label>: ' shape")
            continue
        for segment in remainder.split(" · "):
            if _normalize(segment) not in agents_norm:
                snippet = segment if len(segment) <= 60 else segment[:60] + "..."
                violations.append(f'{SETTINGS}: UserPromptSubmit capsule segment not in AGENTS.md: "{snippet}"')
    return violations


def run_checks(root: Path, tracked: list[str]) -> list[str]:
    return check_sizes(root, tracked) + check_headers(root) + check_capsules(root) + check_parity(root)


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True)
    return proc.stdout


# The CI workflow (.github/workflows/context-budget.yml) path-filters on these same
# surfaces; pinned by tests/test_context_budget.py::test_ci_workflow_paths_match_checker_triggers.
_TRIGGER_FILES = ("AGENTS.md", "CLAUDE.md", SETTINGS, "scripts/check_context_budget.py")
_TRIGGER_DIRS = (".agents/policy/", ".agents/context/", "docs/misc/", ".claude/rules/")


def touches_context_surface(changed: list[str]) -> bool:
    for rel in changed:
        base = rel.rsplit("/", 1)[-1]
        if rel in _TRIGGER_FILES or rel.startswith(_TRIGGER_DIRS) or base in ("CLAUDE.md", "AGENTS.md"):
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
            changed = _git(root, "-c", "core.quotePath=off", *diff_args).split("\n")
            if not touches_context_surface([c for c in changed if c]):
                print("context-budget: no context surface in the diff — skipped")
                return 0
        # quotePath=off: a non-ASCII filename would otherwise come back
        # C-quoted ("…") and silently match no budget.
        tracked = _git(root, "-c", "core.quotePath=off", "ls-files").split("\n")
        tracked = [t for t in tracked if t]
        if args.staged:
            # Validate the INDEX snapshot, not the working tree: staged and
            # worktree content can diverge, and the commit ships the index.
            with tempfile.TemporaryDirectory() as staged_root:
                _git(root, "checkout-index", "--all", f"--prefix={staged_root}/")
                violations = run_checks(Path(staged_root), tracked)
        else:
            violations = run_checks(root, tracked)
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"context-budget: git failed: {exc}", file=sys.stderr)
        return 2
    for violation in violations:
        print(violation)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
