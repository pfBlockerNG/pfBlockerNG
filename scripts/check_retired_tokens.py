#!/usr/bin/env python3
"""Detect a retirement signature in a diff and flag any surviving stragglers.

PROBLEM
-------
A change that RETIRES a quoted string-literal token tree-wide (e.g. removing
a dead log-format marker from every call site) is easy to under-apply: the
author fixes the file(s) they were looking at and misses a sibling file with
the same token. Commit ``958e679f`` removed a legacy bracketed ``NOW`` log
marker from 29+ call sites in ``pfblockerng.inc`` but missed 9 sibling sites
in ``www/pfblockerng/pfblockerng.php`` (issue #1047) -- caught only by a
manual post-merge tree grep, not by review or CI. (The marker is deliberately
not written out here: this docstring would otherwise be a permanent
"surviving site" in its own tool's report.)

WHAT THIS CHECKS
-----------------
Given a git diff, this tool infers which quoted tokens were RETIRED (removed
tree-wide, never re-added) and then tree-greps the post-change tree for any
occurrence still surviving -- a straggler the same commit should have caught.

CANDIDATE RULE
--------------
From every REMOVED line under the scan roots (``src/``, ``scripts/``,
``.github/workflows/``), extract each single- or double-quoted span's inner
text. A candidate token is the raw (whitespace-preserving) inner text of one
such span, kept only if its TRIMMED form is at least 4 characters long and
contains at least one ASCII alphanumeric character (drops noise like bare
punctuation or single-character quoting artefacts).

A candidate is RETIRED iff it appears (plain substring, not regex) on at
least 3 removed scan-root lines and on ZERO added scan-root lines -- a token
that moved (removed here, re-added elsewhere) is not a retirement. Lines
outside the scan roots (e.g. ``tests/``) never contribute to either count,
matching the class of files the retiring commit itself was expected to fix.

For each retired token, the post-change tree is searched with a fixed-string
``git grep -F`` (never a regex) over the same scan roots. Every surviving hit
is a straggler UNLESS its line carries the escape comment (see below).

MODES
-----
``--staged``
    Diff = ``git diff --cached --unified=0``; stragglers are searched in the
    INDEX (``git grep --cached``) -- for a pre-commit hook.
``--diff <base>``
    Diff = ``git diff <base>...HEAD --unified=0``; stragglers are searched in
    ``HEAD`` -- for CI/ad-hoc invocation against a PR branch.
``--token-allowlist <token>`` (repeatable)
    Skip a retired token entirely -- an escape hatch for a deliberate,
    staged, multi-commit migration. Combines with ``--staged``/``--diff``.
``--claude-hook``
    A Claude Code PreToolUse hook (Bash tool) form. Reads the whole stdin
    hook payload, normalizes it (strip ``"``/``\\``, collapse whitespace
    runs to one space -- mirrors ``claude-bash-guard.sh``), and only runs
    the ``--staged``-equivalent analysis when the normalized text contains
    ``git commit`` (i.e. the agent is about to commit). Findings are
    reported as ONE JSON line
    (``{"hookSpecificOutput": {"hookEventName": "PreToolUse",
    "additionalContext": <report>}}``) on stdout. FAIL-OPEN: any exception
    (garbled stdin, no git, not a repo) or a clean result exits 0 with no
    output -- this mode never blocks a commit and never exits nonzero.

ESCAPE HATCHES
---------------
* A surviving line containing the substring ``retired-token-ok:`` is exempt
  (any comment syntax; plain substring test) -- mark an intentional survivor
  inline with ``# retired-token-ok: <reason>``.
* ``--token-allowlist <token>`` skips a token for a staged migration.

EXIT STATUS
-----------
``--staged``/``--diff``: 0 = clean, 1 = stragglers reported, 2 = usage or git
error. ``--claude-hook``: always 0.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

# Tracked-tree roots a retiring commit is expected to have fixed everywhere.
_SCAN_ROOTS = ("src", "scripts", ".github/workflows")

# Mirrors check_version_literals._QUOTED_RE (double-quote escape-aware,
# single-quote naive); extra/missed candidates from an edge-case quote
# parse self-correct at the retirement-count stage below.
_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|`(?:[^`\\]|\\.)*`')

_ASCII_ALNUM_RE = re.compile(r"[A-Za-z0-9]")

_ESCAPE = "retired-token-ok:"

_REPORT_HINT = (
    "Fix the straggler(s) tree-wide, mark an intentional survivor with "
    "`# retired-token-ok: <reason>`, or pass --token-allowlist for a staged migration."
)


class _GitError(Exception):
    """Raised when a git subprocess exits with an unexpected (non 0/1) status."""


def _in_scan_roots(path_str: str) -> bool:
    """True if a diff path lives under a scan root."""
    return any(path_str == root or path_str.startswith(f"{root}/") for root in _SCAN_ROOTS)


def _quoted_literals(line: str) -> list[str]:
    """Return the inner text of every single- or double-quoted span on ``line``."""
    return [g for m in _QUOTED_RE.finditer(line) for g in m.groups() if g is not None]


def _is_candidate(token: str) -> bool:
    stripped = token.strip()
    return len(stripped) >= 4 and bool(_ASCII_ALNUM_RE.search(stripped))


def _parse_diff(diff_text: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Split a unified diff into per-path removed/added CONTENT lines (scan-root-scoped).

    A deleted file's ``+++`` target is ``/dev/null``; its path comes from the
    preceding ``--- a/<path>`` instead -- deleted files are prime retirement
    sources and must still contribute their removed lines.
    """
    removed: dict[str, list[str]] = {}
    added: dict[str, list[str]] = {}
    path: str | None = None
    a_path: str | None = None
    in_hunk = False
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git"):
            path = None
            a_path = None
            in_hunk = False
            continue
        if raw.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk:
            if raw.startswith("--- "):
                name = raw[4:]
                if name.startswith("a/"):
                    a_path = name[2:].split("\t", 1)[0]
            elif raw.startswith("+++ "):
                name = raw[4:]
                if name.startswith("b/"):
                    path = name[2:].split("\t", 1)[0]
                elif name.split("\t", 1)[0] == "/dev/null":
                    path = a_path
            continue
        if raw.startswith("\\"):
            continue  # issue #1051: skip the backslash marker -- it is not content
        if path is None or not _in_scan_roots(path):
            continue
        if raw.startswith("-"):
            removed.setdefault(path, []).append(raw[1:])
        elif raw.startswith("+"):
            added.setdefault(path, []).append(raw[1:])
    return removed, added


def _candidate_tokens(removed: dict[str, list[str]]) -> set[str]:
    return {lit for lines in removed.values() for line in lines for lit in _quoted_literals(line) if _is_candidate(lit)}


def find_retired_tokens(removed: dict[str, list[str]], added: dict[str, list[str]]) -> list[str]:
    """Return, sorted, every candidate token retired by this diff (>=3 removed, 0 added hits)."""
    all_removed = [line for lines in removed.values() for line in lines]
    all_added = [line for lines in added.values() for line in lines]
    retired = []
    for token in _candidate_tokens(removed):
        removed_count = sum(1 for line in all_removed if token in line)
        added_count = sum(1 for line in all_added if token in line)
        if removed_count >= 3 and added_count == 0:
            retired.append(token)
    return sorted(retired)


def _git_diff(args: list[str]) -> str:
    # Same flag set as check_version_literals._git_diff: pin quotePath/prefixes/
    # ext-diff so config/env cannot defeat the +++ b/ parse.
    out = subprocess.run(
        [
            "git",
            "-c",
            "core.quotePath=false",
            "diff",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return out.stdout


def _grep_token(token: str, cached: bool) -> list[str]:
    """Fixed-string search the post-change tree for ``token``; exit 1 = clean, not an error."""
    cmd = ["git", "grep", "-Fn"]
    if cached:
        cmd.append("--cached")
    cmd += ["-e", token]
    if not cached:
        cmd.append("HEAD")
    cmd += ["--", *_SCAN_ROOTS]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if out.returncode == 1:
        return []
    if out.returncode != 0:
        raise _GitError(out.stderr.strip())
    lines = out.stdout.splitlines()
    if not cached:
        lines = [ln.removeprefix("HEAD:") for ln in lines]
    return [ln for ln in lines if _ESCAPE not in ln]


def analyze_diff(diff_text: str, allowlist: set[str], cached: bool) -> dict[str, list[str]]:
    """Return, per retired token still present post-change, its (exemption-filtered) hit lines."""
    removed, added = _parse_diff(diff_text)
    findings: dict[str, list[str]] = {}
    for token in find_retired_tokens(removed, added):
        if token in allowlist:
            continue
        hits = _grep_token(token, cached)
        if hits:
            findings[token] = hits
    return findings


def format_report(findings: dict[str, list[str]]) -> str:
    lines: list[str] = []
    for token in sorted(findings):
        hits = sorted(findings[token])
        lines.append(f"{token!r}: {len(hits)} site(s) remain:")
        lines.extend(f"  {hit}" for hit in hits)
    lines.append(_REPORT_HINT)
    return "\n".join(lines)


def _usage() -> int:
    print(
        "usage: check_retired_tokens.py --staged | --diff <base> [--token-allowlist <token> ...] | --claude-hook",
        file=sys.stderr,
    )
    return 2


def _run_claude_hook() -> None:
    try:
        payload = sys.stdin.read()
        normalized = re.sub(r"\s+", " ", payload.replace('"', "").replace("\\", ""))
        if "git commit" not in normalized:
            return
        diff_text = _git_diff(["--cached"])
        findings = analyze_diff(diff_text, allowlist=set(), cached=True)
        if not findings:
            return
        report = format_report(findings)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": report}}))
    except Exception:
        return  # FAIL-OPEN: never block a commit on a parse/git failure


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--claude-hook":
        _run_claude_hook()
        return 0
    mode: str | None = None
    base: str | None = None
    allowlist: set[str] = set()
    it = iter(argv)
    for arg in it:
        if arg == "--staged":
            if mode is not None:
                return _usage()
            mode = "staged"
        elif arg == "--diff":
            if mode is not None:
                return _usage()
            mode = "diff"
            base = next(it, None)
            if not base:
                return _usage()
        elif arg == "--token-allowlist":
            token = next(it, None)
            if token is None:
                return _usage()
            allowlist.add(token)
        else:
            return _usage()
    if mode is None:
        return _usage()
    diff_args = ["--cached"] if mode == "staged" else [f"{base}...HEAD"]
    try:
        diff_text = _git_diff(diff_args)
    except subprocess.CalledProcessError as exc:
        print(f"git diff failed: {exc.stderr.strip()}", file=sys.stderr)
        return 2
    try:
        findings = analyze_diff(diff_text, allowlist, cached=(mode == "staged"))
    except _GitError as exc:
        print(f"git grep failed: {exc}", file=sys.stderr)
        return 2
    if not findings:
        return 0
    print(format_report(findings))
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
