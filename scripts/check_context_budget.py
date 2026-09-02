#!/usr/bin/env python3
"""Enforce the context-taxonomy byte budgets and routing headers (map #1383, #1437).

AGENTS.md is the canonical agent bootstrap; `.agents/policy/` + `.agents/context/`
hold the routed policy/context files; hook capsules ride `.claude/settings.json`.
Every surface has a byte budget so the hot context cannot silently re-accrete
(taxonomy #1386 anti-monolith rules), and every file the bootstrap's routing
table references must carry a `Scope:` + `Load-when:` header so it stays
routable. Budgets (calibrated on the measured tree, not the matrix estimates):

- `AGENTS.md` (bootstrap)                          10,240 B
- `CLAUDE.md` / `GROK.md` (thin vendor adapters)    8,192 B
- `.agents/policy/*.md` / `.agents/context/*.md`   12,288 B default; grandfathered
  ratchet caps for the pre-taxonomy files (landing 26,000, agent-roles 19,000,
  delegation 18,000 — frozen constants: lower them as the files shrink)
- nested `CLAUDE.md`/`AGENTS.md` dir stubs            400 B
- `.claude/rules/*.md` (Claude soft routing backstops) 400 B
- each hook-capsule `additionalContext` payload     1,800 B
- any single hook command (pre-tokenization cap)   11,000 B
- each `coderabbit-misses.md` ledger entry            200 B
- that ledger's header prose (above the list)      1,200 B

A hook command may also invoke a repo helper script (under scripts/ or
.claude/hooks/, both trigger surfaces). Detection recognizes `*.sh`/`*.py`
command tokens (including one nested inside a quoted compound fragment,
`sh -c '...'`) plus any helper-dir-rooted path that resolves to a committed
file regardless of extension, even when a glued shell metacharacter
(`x.sh$()`, backtick) would strip the recognizable suffix off the token; a
recognized helper whose content could emit
`hookSpecificOutput.additionalContext` — directly (the literal string) or by
delegating execution to another program/module the checker cannot read (a
shell `exec`, a `subprocess`/`os.exec*`/`os.system` call) — must be a
registered DYNAMIC_CAPSULE_PRODUCERS entry, and a recognized reference the
checker cannot statically resolve and read fails closed (#1501).

CONDITIONAL: in --staged / --diff mode the checks run IF AND ONLY IF the change
touches a context surface (AGENTS.md, CLAUDE.md, GROK.md,
.github/copilot-instructions.md, .agents/policy/, .agents/context/, docs/misc/,
.claude/rules/, .grok/rules/, .claude/hooks/, scripts/, .claude/settings.json,
any nested CLAUDE.md/AGENTS.md/GROK.md, or this checker);
otherwise it reports the skip and exits 0. --all checks unconditionally.

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
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

from _git_paths import nul_listing

BOOTSTRAP_BUDGET = 10_240
ADAPTER_BUDGET = 8_192
POLICY_BUDGET = 12_288
STUB_BUDGET = 400
CAPSULE_BUDGET = 1_800
# The parity label (everything before the first ": ") is the one uncheckable part of
# the UserPromptSubmit capsule; the bound keeps it a label, not a smuggling channel.
PARITY_LABEL_MAX = 80
# Ceiling for any hook command: decoded 1,800 B capsule budget × 6 (generous safety
# margin over the ×3 worst-case \uXXXX JSON-escaping ratio) + envelope/quoting slack.
# shlex is nonlinear on huge quoted strings (~25 s at 1 MB — issue #1504), so longer
# commands are rejected before tokenization.
COMMAND_BYTES_MAX = CAPSULE_BUDGET * 6 + 200

# Grandfathered ratchet caps for files predating the taxonomy budgets: they may
# shrink toward POLICY_BUDGET, never grow past their cap.
FILE_BUDGETS = {
    "AGENTS.md": BOOTSTRAP_BUDGET,
    "CLAUDE.md": ADAPTER_BUDGET,
    "GROK.md": ADAPTER_BUDGET,
    ".agents/policy/landing.md": 26_000,
    ".agents/policy/agent-roles.md": 19_000,
    ".agents/policy/delegation.md": 18_000,
}

# The append-only missed-review ledger (coderabbit.md "Missed-review backlog").
# It gains one line per missed review forever, so the only thing keeping it
# inside POLICY_BUDGET is the one-line format its own header documents. Entries
# that drifted into 1,500-2,000-byte review narratives ate the whole budget and
# left 17 bytes of headroom (#2829); the narrative belongs in that PR's audit
# comments, and the ledger carries the pointer newest first.
LEDGER = ".agents/policy/coderabbit-misses.md"
# The policy that mandates the ledger. Present without the ledger means the file
# was deleted (staged or committed), which drops it out of `git ls-files` and so
# out of check_sizes's reach — this check is the one that can still fail closed.
LEDGER_OWNER = ".agents/policy/coderabbit.md"
LEDGER_ENTRY_MAX = 200
LEDGER_ENTRY_RE = re.compile(r"^- `(?P<sha>[0-9a-f]{7,40})`  (?P<title>\S.*\S)  \(#(?P<pr>\d+)\)(?: — \S.*)?$")
# Everything above the first entry is prose, and prose is where a narrative can
# park unnoticed: enumerating the markers it could wear (`-`, `*`, `1.`, `#`,
# `>`, `:`, `•`, an HTML comment, an invisible U+FEFF …) is a game the next
# reviewer wins. The header answers to its own byte cap instead, which bounds
# every shape at once and leaves ordinary prose alone.
LEDGER_HEADER_MAX = 1_200

SETTINGS = ".claude/settings.json"

# Registered (event, script) hook helpers whose additionalContext is a RUNTIME-computed
# diagnostic — no static payload exists to budget/parity-check. Any unregistered helper
# that could emit a capsule fails closed (inline as canonical `echo '<JSON>'` or register).
DYNAMIC_CAPSULE_PRODUCERS = {
    ("SessionStart", ".claude/hooks/session-branch-sync.sh"),
}

# Helper scripts must live under these roots: both are trigger surfaces
# (_TRIGGER_DIRS), so editing a helper re-runs this gate.
_HELPER_DIRS = ("scripts/", ".claude/hooks/")
_PROJECT_DIR_PREFIXES = ("${CLAUDE_PROJECT_DIR:-.}/", "${CLAUDE_PROJECT_DIR}/")

# A helper that hands execution off to another program/module the checker cannot
# read (a POSIX shell `exec` re-invocation, a `subprocess` call, an `os.exec*`/
# `os.system` call) is exactly as unverifiable as one that contains the
# `additionalContext` literal directly — the delegation-mediated bypass #1501's
# own fix would otherwise still miss.
_DELEGATES_RE = re.compile(r"(?m)^\s*exec\b|\bsubprocess\.\w+\(|\bos\.exec\w*\(|\bos\.system\(")

# Helper-dir-rooted path candidates in a raw hook command. Suffix-gated
# tokenization misses a helper whose recognizable .sh/.py suffix is either absent
# (a non-.sh/.py extension) or stripped by a shell metacharacter glued to the path
# (`x.sh$()`, backtick) — both still run the file. This finds the path regardless;
# derived from _HELPER_DIRS so the two never drift.
# The path token runs to the next shell metacharacter/quote/whitespace, so it
# captures the whole unquoted filename — including valid path chars the shell
# keeps but a `\w` class drops (`+`, `@`, `~`, `=`, `,`) — while still stopping at
# a glued `$()`/backtick. Over-matching is harmless: the result is existence-gated.
_HELPER_PATH_RE = re.compile(
    r"(?:" + "|".join(re.escape(d.rstrip("/")) for d in _HELPER_DIRS) + r")/[^\s'\"()|&;<>$`]+"
)

# Accepts both header shapes in the first HEADER_WINDOW lines: the plain
# "Scope: ... Load when: ..." prose and the bulleted "- **Scope:** / - **Load-when:**".
HEADER_WINDOW = 12
_SCOPE_RE = re.compile(r"\*\*Scope:?\*\*|^Scope:|\bScope: ", re.MULTILINE)
_LOADWHEN_RE = re.compile(r"Load[- ]when:", re.IGNORECASE)

_MD_TOKEN_RE = re.compile(r"`([^`]*\.md[^`]*)`")
_RESOLVE_DIRS = (".agents/policy", ".agents/context", "docs/misc")

# A single well-formed `<a|b|c>` alternation group: prefix/suffix may not carry
# any further `<`/`>` — that rejects more-than-one-group tokens structurally.
_TEMPLATE_RE = re.compile(r"^(?P<prefix>[^<>]*)<(?P<body>[^<>]*)>(?P<suffix>[^<>]*)$")


def _expand_template(tok: str) -> list[str] | None:
    """Expand a lone `<a|b|c>` group into one token per alternative, or None.

    None means "not a clean single-group template" — either a plain literal
    token (no `<`/`>` at all) or a malformed/ambiguous one (unclosed `<`, more
    than one group, a group with no alternation like `<php>`, or any empty
    alternative like `<>`/`<|>`/`<a||b>`); the caller SKIPS those, it never
    crashes or invents a resolved target.
    """
    match = _TEMPLATE_RE.fullmatch(tok)
    if match is None:
        return None
    if any(char.isspace() for char in tok):
        return None
    alts = match["body"].replace("\\", "").split("|")
    if len(alts) < 2 or any(alt == "" for alt in alts):
        return None
    return [f"{match['prefix']}{alt}{match['suffix']}" for alt in alts]


def budget_for(rel: str) -> int | None:
    """Byte budget for a tracked file, or None when unbudgeted."""
    if rel in FILE_BUDGETS:
        return FILE_BUDGETS[rel]
    if rel.startswith(".claude/rules/") and rel.endswith(".md"):
        return STUB_BUDGET
    base = rel.rsplit("/", 1)[-1]
    # Checked before the policy/context prefix: a nested AGENTS.md/CLAUDE.md
    # under .agents/ is a dir stub, not a routed policy file.
    if "/" in rel and base in ("CLAUDE.md", "AGENTS.md", "GROK.md"):
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


def check_ledger_entries(root: Path) -> list[str]:
    """Capped header, then one line per merged SHA within LEDGER_ENTRY_MAX, no SHA twice."""
    try:
        # Bytes, not universal-newline text: read_text() folds a CRLF away, and
        # the header cap must weigh what the file actually ships.
        text = (root / LEDGER).read_bytes().decode("utf-8")
    except FileNotFoundError:
        if (root / LEDGER_OWNER).exists():
            return [f"{LEDGER}: missing — {LEDGER_OWNER} routes every recorded miss to it"]
        return []  # a tree that never carried the ledger (scratch roots)
    except (OSError, UnicodeDecodeError) as exc:
        # A directory, a permission denial or a non-UTF-8 byte: fail closed with
        # a verdict rather than a pass, and never a traceback out of main().
        return [f"{LEDGER}: unreadable ({getattr(exc, 'strerror', None) or exc})"]
    violations: list[str] = []
    first_line_of: dict[str, int] = {}
    entries = 0
    header_bytes = 0
    for lineno, raw in enumerate(text.splitlines(keepends=True), 1):
        # keepends: a CRLF header line ships two bytes of terminator, and
        # counting a normalized one lets 1,800 bytes of header measure 1,200.
        line = raw.rstrip("\r\n")
        match = LEDGER_ENTRY_RE.match(line)
        if match is None:
            if entries or line.startswith("- "):
                # The list opens at the documented marker, and from there the
                # file is entries: a malformed one, or a narrative continuation
                # line, is the drift this gate exists to stop. Anything above
                # that first `- ` is header prose, bounded by the header cap.
                if line.strip():
                    violations.append(f"{LEDGER}:{lineno}: entry does not match `SHA`  title  (#PR) — clause")
                    entries += 1
            else:
                header_bytes += len(raw.encode("utf-8"))
            continue
        entries += 1
        size = len(line.encode("utf-8"))
        if size > LEDGER_ENTRY_MAX:
            violations.append(f"{LEDGER}:{lineno}: entry is {size} bytes > cap {LEDGER_ENTRY_MAX}")
        first = first_line_of.setdefault(match["sha"], lineno)
        if first != lineno:
            violations.append(f"{LEDGER}:{lineno}: SHA `{match['sha']}` is listed twice (first at line {first})")
    if header_bytes > LEDGER_HEADER_MAX:
        violations.append(f"{LEDGER}: header is {header_bytes} bytes > cap {LEDGER_HEADER_MAX}")
    if entries == 0:
        # Zero parsed entries is drift (or an emptied list), never a clean pass —
        # the same rule the routing-table extraction already follows.
        violations.append(f"{LEDGER}: no entries parsed — has the one-line format drifted?")
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
    tokens, skipped = routing_targets(bootstrap.read_text(encoding="utf-8"))
    violations = [
        f"AGENTS.md: malformed routing target `{token}` skipped"
        for token in skipped
        if any(char.isspace() for char in token)
    ]
    if not tokens:
        # A renamed/removed "## Routing table" heading would otherwise disarm
        # the whole header gate silently (zero targets = vacuous pass).
        return violations or ["AGENTS.md: no routing-table targets extracted — heading renamed or table removed?"]
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
                    try:
                        size = len(command.encode("utf-8"))
                    except UnicodeEncodeError:
                        # A lone/unpaired surrogate (valid in a JSON \uXXXX escape,
                        # invalid UTF-8) must not crash out to the file-level catch
                        # and discard every other hook's already-found violations.
                        errors.append(f"{SETTINGS}: {event} capsule command has an unencodable character")
                        continue
                    if size > COMMAND_BYTES_MAX:
                        errors.append(f"{SETTINGS}: {event} capsule command {size} bytes > cap {COMMAND_BYTES_MAX}")
                        continue
                    try:
                        argv = shlex.split(command)
                        if len(argv) != 2 or argv[0] != "echo" or shlex.join(argv) != command:
                            raise ValueError("noncanonical capsule command")
                        payload = json.loads(argv[1])
                        text = payload["hookSpecificOutput"]["additionalContext"]
                        if not isinstance(text, str):
                            raise TypeError("additionalContext is not text")
                    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
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
    non-empty normalized substring of AGENTS.md, with the unchecked label bounded to
    PARITY_LABEL_MAX chars — the capsule quotes the bootstrap verbatim, never drifts."""
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
        label, sep, remainder = text.partition(": ")
        if not sep:
            violations.append(f"{SETTINGS}: UserPromptSubmit capsule has no '<label>: ' shape")
            continue
        if len(label) > PARITY_LABEL_MAX:
            violations.append(
                f"{SETTINGS}: UserPromptSubmit capsule label {len(label)} chars > {PARITY_LABEL_MAX}"
                " — invariant text belongs in the parity-checked segments"
            )
        for segment in remainder.split(" · "):
            if not _normalize(segment).strip():
                violations.append(f"{SETTINGS}: UserPromptSubmit capsule has an empty parity segment")
                continue
            if _normalize(segment) not in agents_norm:
                snippet = segment if len(segment) <= 60 else segment[:60] + "..."
                violations.append(f'{SETTINGS}: UserPromptSubmit capsule segment not in AGENTS.md: "{snippet}"')
    return violations


def _script_refs(root: Path, command: str, _depth: int = 0) -> list[str] | None:
    """Repo-script references of a hook command, or None when untokenizable.

    A token that itself contains embedded whitespace after tokenization is a quoted
    compound shell fragment (`sh -c 'python3 scripts/emit.py --flag'` collapses to
    one opaque token) — its script reference would otherwise hide inside that one
    token, so it is recursively re-tokenized. Depth is bounded (nested quoting is
    finite, and the caller already caps the command's raw byte length before this
    ever runs) purely as a defensive limit, not because it is reachable in practice.
    """
    try:
        # punctuation_chars: split glued shell operators (`x.sh;sh`, `x.sh>log`) into
        # their own tokens so an operator can never hide a script reference.
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        argv = list(lex)
    except ValueError:
        return None
    refs = []
    for tok in argv:
        if not tok.lower().endswith((".sh", ".py")):
            if _depth < 4 and any(char.isspace() for char in tok):
                nested = _script_refs(root, tok, _depth + 1)
                if nested is None:
                    return None
                refs.extend(nested)
            continue
        for prefix in _PROJECT_DIR_PREFIXES:
            tok = tok.removeprefix(prefix)
        refs.append(tok.removeprefix("./"))
    # Suffix-gated tokenization misses two real references (#1501): a helper with a
    # non-.sh/.py extension is never matched, and a metacharacter glued to a helper
    # path (`x.sh$()`, backtick) strips the recognizable suffix off every surviving
    # token though the shell still runs the file. Union in any helper-dir-rooted
    # path in the raw command that resolves to a committed file, regardless of
    # extension. Existence-gated, so a spurious fragment never adds a false
    # fail-closed violation (the live tree stays clean).
    for match in _HELPER_PATH_RE.finditer(command):
        cand = match.group(0)
        if cand not in refs and (root / cand).is_file():
            refs.append(cand)
    return refs


def _check_helper(root: Path, event: str, ref: str) -> list[str]:
    """Fail-closed verdicts for one helper-script reference of a hook command."""
    if "$" in ref or ref.startswith("/") or ".." in ref.split("/"):
        return [f"{SETTINGS}: {event} hook references unresolvable script `{ref}` — cannot verify capsule emission"]
    if not ref.startswith(_HELPER_DIRS):
        return [f"{SETTINGS}: {event} hook helper `{ref}` outside the checked roots {', '.join(_HELPER_DIRS)}"]
    path = root / ref
    if not path.is_file():
        return [f"{SETTINGS}: {event} hook helper `{ref}` not found — cannot verify capsule emission"]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"{SETTINGS}: {event} hook helper `{ref}` unreadable ({exc.strerror or exc})"]
    if (event, ref) in DYNAMIC_CAPSULE_PRODUCERS:
        return []
    if "additionalContext" not in text and not _DELEGATES_RE.search(text):
        return []
    return [
        f"{SETTINGS}: {event} hook helper `{ref}` may emit additionalContext the checker cannot validate — "
        "inline it as a canonical echo '<JSON>' capsule or register it in DYNAMIC_CAPSULE_PRODUCERS"
    ]


def check_indirect_producers(root: Path) -> list[str]:
    """Flag hook helper scripts that could emit a capsule the budget/parity gate never sees (#1501)."""
    settings = root / SETTINGS
    if not settings.is_file():
        return []
    violations: list[str] = []
    try:
        parsed = json.loads(settings.read_text(encoding="utf-8"))
        for event, entries in parsed.get("hooks", {}).items():
            for entry in entries:
                for hook in entry.get("hooks", []):
                    command = hook.get("command", "")
                    if "additionalContext" in command:
                        continue  # the canonical inline-capsule path (extract_capsules) owns it
                    try:
                        size = len(command.encode("utf-8"))
                    except UnicodeEncodeError:
                        # Same fail-closed-per-command discipline as extract_capsules:
                        # one hostile command must not crash out and silently drop
                        # every other hook's already-found indirect-producer violations.
                        violations.append(
                            f"{SETTINGS}: {event} hook command has an unencodable character — cannot rule out a capsule"
                        )
                        continue
                    if size > COMMAND_BYTES_MAX:
                        violations.append(
                            f"{SETTINGS}: {event} hook command {size} bytes > cap {COMMAND_BYTES_MAX}"
                            " — cannot rule out a capsule"
                        )
                        continue
                    refs = _script_refs(root, command)
                    if refs is None:
                        violations.append(
                            f"{SETTINGS}: {event} hook command has unparseable quoting — cannot rule out a capsule"
                        )
                        continue
                    for ref in refs:
                        violations.extend(_check_helper(root, event, ref))
    except (ValueError, AttributeError, TypeError):
        # Unparseable/wrong-shape settings: check_capsules already fails closed on the file.
        return []
    return violations


def run_checks(root: Path, tracked: list[str]) -> list[str]:
    return (
        check_sizes(root, tracked)
        + check_headers(root)
        + check_capsules(root)
        + check_parity(root)
        + check_indirect_producers(root)
        + check_ledger_entries(root)
    )


def _git(root: Path, *args: str) -> str:
    # encoding pinned, not locale-derived: a -z listing carries raw path bytes,
    # and under LANG=C a non-ASCII one would raise instead of being classified.
    proc = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, encoding="utf-8", errors="replace", check=True
    )
    return proc.stdout


# The CI workflow (.github/workflows/context-budget.yml) path-filters on these same
# surfaces; pinned by tests/test_context_budget.py::test_ci_workflow_paths_match_checker_triggers.
_TRIGGER_FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "GROK.md",
    ".github/copilot-instructions.md",
    SETTINGS,
    "scripts/check_context_budget.py",
)
_TRIGGER_DIRS = (
    ".agents/policy/",
    ".agents/context/",
    "docs/misc/",
    ".claude/rules/",
    ".grok/rules/",
    ".claude/hooks/",
    "scripts/",
)


def touches_context_surface(changed: list[str]) -> bool:
    for rel in changed:
        base = rel.rsplit("/", 1)[-1]
        if rel in _TRIGGER_FILES or rel.startswith(_TRIGGER_DIRS) or base in ("CLAUDE.md", "AGENTS.md", "GROK.md"):
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
                ["diff", "--cached", "--name-only", "-z"]
                if args.staged
                else ["diff", "--name-only", "-z", f"{args.diff}...HEAD"]
            )
            if not touches_context_surface(nul_listing(root, *diff_args)):
                print("context-budget: no context surface in the diff — skipped")
                return 0
        # -z: git C-quotes any path holding a quote, backslash, control byte or
        # (by default) a non-ASCII byte, and a quoted path matches no budget.
        tracked = nul_listing(root, "ls-files", "-z")
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
        # A tracked name that is not valid UTF-8 reaches here byte-exactly, as
        # os.fsdecode renders it -- lone surrogates no stdout codec can encode.
        # Escaping them through UTF-8 in BOTH directions keeps every other name
        # intact whatever stdout's codec is, so the gate reports the file it
        # measured instead of dying on the report (issue #3073).
        print(violation.encode("utf-8", "backslashreplace").decode())
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
