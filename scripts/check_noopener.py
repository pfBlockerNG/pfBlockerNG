#!/usr/bin/env python3
"""Forbid a `target="_blank"` link with no adjacent `rel="noopener…"`.

PROBLEM
-------
A link opened with `target="_blank"` and no `rel="noopener noreferrer"` lets
the new tab's page run JavaScript that reaches back into `window.opener` and
repoints the ORIGINATING tab (reverse tabnabbing) — a real risk when the href
is attacker-influenced, and cheap defence-in-depth even when it is not
(issue #1217). Every external/new-tab link in the Web UI must carry the
`rel` value.

HEURISTIC (deliberately strict-adjacency, not an HTML parser)
---------------------------------------------------------------
A `target=…_blank…` occurrence (double/single/no quotes; a `(?<![\\w-])`
guard excludes `data-target="_blank"`) is a VIOLATION unless it is
IMMEDIATELY followed — only whitespace between — by `rel=["']?noopener`.
That is the house convention this codebase now follows: `rel` sits directly
after `target`, so it survives even the multi-line PHP string-concatenation
tag shape (`'target="_blank"' . ' rel="noopener noreferrer"'` would NOT be
adjacent on one physical line and is intentionally out of the convention —
every current site keeps both attributes on the same line). `rel` BEFORE
`target`, or a `rel` with the wrong value (e.g. `rel="opener"`), still flags:
this checker enforces the convention's exact shape, not just noopener's
presence somewhere on the tag.

Escape hatch: a line containing the substring `noopener-ok` is never
scanned (mirrors `check_comment_narration.py`'s `narration-ok`) — for a
tag genuinely exempt (e.g. a `target=…` inside a `<textarea>` code sample).

The detection logic lives in :func:`find_violations` (pure, importable) so it
is unit-tested directly without a subprocess. The :func:`main` CLI, with no
args, resolves the file list via ``git ls-files`` — every tracked
``src/usr/local/www/**`` file ending ``.php``/``.inc``/``.xml`` (the Web UI
surface `target="_blank"` links live in; deliberately excludes ``tests/`` so
this checker's own bad-input fixtures never trip its tree scan) — or scans
the explicit paths passed as args. It prints ``path:line: <message>`` to
stderr, exiting 1 if any violation is found.

This is dev-only tooling (release archives contain only ``src/``); it lives
under ``scripts/`` and is wired into ``.githooks/pre-commit`` and CI.
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import NamedTuple

# `target=…_blank…` in any of the three HTML quote forms. `(?<![\w-])` excludes
# a `data-target="_blank"` tail (word/hyphen boundary before `target`).
_TARGET_BLANK_RE = re.compile(r'(?<![\w-])target=(?P<q>["\']?)_blank(?P=q)')

# `rel="noopener…"` (or single-quoted / unquoted), immediately after `target=…`
# with only whitespace between -- the strict-adjacency house convention.
_REL_NOOPENER_ADJACENT_RE = re.compile(r'\s+rel=(["\']?)noopener\b')

# Escape hatch, mirroring check_comment_narration.py's `narration-ok`.
_ESCAPE_MARKER = "noopener-ok"


class Violation(NamedTuple):
    """One `target=_blank` site missing its adjacent `rel="noopener…"`."""

    source: str  # file path
    line: int  # 1-based line number
    snippet: str  # the offending line (trimmed)


def find_violations(text: str, source: str) -> list[Violation]:
    """Find every `target=…_blank…` site with no adjacent `rel="noopener…"`.

    Scanned per physical line — every current/expected site keeps `target`
    and its `rel` on the same line (see module docstring). A line carrying
    the `noopener-ok` escape marker is skipped entirely.
    """
    violations: list[Violation] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _ESCAPE_MARKER in line:
            continue
        for m in _TARGET_BLANK_RE.finditer(line):
            rest = line[m.end() :]
            if _REL_NOOPENER_ADJACENT_RE.match(rest):
                continue
            violations.append(Violation(source=source, line=line_no, snippet=line.strip()))
    return violations


def _git_tracked_www() -> list[str]:
    """Return tracked src/usr/local/www files ending .php/.inc/.xml (sorted)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "src/usr/local/www"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    return sorted(p for p in out.split("\0") if p and p.endswith((".php", ".inc", ".xml")))


def _scan_path(path: str) -> list[Violation]:
    """Scan one file; unreadable files are skipped silently."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return find_violations(text, path)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 (clean) or 1 (violations found)."""
    args = list(sys.argv[1:] if argv is None else argv)
    paths = args if args else _git_tracked_www()

    violations: list[Violation] = []
    for path in paths:
        violations.extend(_scan_path(path))

    for v in violations:
        print(
            f'{v.source}:{v.line}: target=_blank with no adjacent rel="noopener noreferrer" '
            "(reverse-tabnabbing defence; rel must sit directly after target)",
            file=sys.stderr,
        )
        print(f"    {v.snippet}", file=sys.stderr)

    if violations:
        print(
            f"\n{len(violations)} target=_blank violation(s). "
            'Add rel="noopener noreferrer" (matching the target attribute\'s quote '
            "style) directly after target, or mark a genuine exemption with "
            "`noopener-ok` on the line.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
