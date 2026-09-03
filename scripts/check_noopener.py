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
A `target … = … _blank…` occurrence (HTML ASCII case; double/single/no quotes;
spaces/tabs around `=`; a `(?<![\\w-])` guard excludes `data-target="_blank"`)
is a VIOLATION unless it is
IMMEDIATELY followed — only whitespace between — by `rel=["']?noopener`.
An unquoted `_blank/` prefix is deliberately treated as a flaggable near-miss:
WHATWG includes the slash in the attribute value, but the likely typo must fail
review rather than silently escape this checker.
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
``src/usr/local/www/**`` and ``src/usr/local/pkg/**`` file ending
``.php``/``.inc``/``.xml`` (the Web UI surface `target="_blank"` links live in;
pkg holds help text that renders on those same pages, issue #3075; deliberately
excludes ``tests/`` so this checker's own bad-input fixtures never trip its tree
scan) — or scans the explicit paths passed as args. It prints ``path:line: <message>`` to
stderr, exiting 1 if any violation is found, or 2 if the default (argless)
scan set could not be enumerated (git absent / not a checkout) — failing
closed rather than silently passing a gate it could not run.

This is dev-only tooling (release archives contain only ``src/``); it lives
under ``scripts/`` and is wired into ``.githooks/pre-commit`` and CI.
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import NamedTuple

# HTML ASCII case/whitespace only. The unquoted branch requires a value delimiter
# or the deliberate slash near-miss and leaves it untouched for the adjacent-rel
# matcher; quoted trailing spaces/tabs are included.
#
# issue #3085: the quote may be backslash-escaped -- HTML assembled inside a PHP
# quoted string reads target=\"_blank\". Both delimiters take an optional escape,
# and the `rel` matcher below must accept the same form or a correctly escaped
# link would start reporting as a violation.
_TARGET_BLANK_RE = re.compile(
    r'(?<![\w-])(?ai:target)[ \t]*=[ \t]*(?:\\?(?P<q>["\'])(?ai:_blank)[ \t]*\\?(?P=q)|(?ai:_blank)(?=[ \t>/]|$))'
)

# `rel="noopener…"` (or single-quoted / unquoted), immediately after `target=…`
# with only whitespace between -- the strict-adjacency house convention. The
# `(?![\w-])` token-end guard (not `\b`) is required so `rel="noopener-evil"` -- a
# DIFFERENT rel token that grants none of noopener's protection -- is NOT accepted
# (a `\b` boundary treats the hyphen as a token end and would pass it).
_REL_NOOPENER_ADJACENT_RE = re.compile(r'\s+rel=\\?(["\']?)noopener(?![\w-])')

# Escape hatch, mirroring check_comment_narration.py's `narration-ok`.
_ESCAPE_MARKER = "noopener-ok"


class Violation(NamedTuple):
    """One `target=_blank` site missing its adjacent `rel="noopener…"`."""

    source: str  # file path
    line: int  # 1-based line number
    snippet: str  # the offending line (trimmed)


def find_violations(text: str, source: str) -> list[Violation]:
    """Find every HTML ASCII `target=…_blank…` spelling with no adjacent `rel="noopener…"`.

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


def _git_tracked_ui() -> list[str]:
    """Return tracked www + pkg files ending .php/.inc/.xml (sorted)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "src/usr/local/www", "src/usr/local/pkg"],
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
    """CLI entry point. Returns 0 (clean), 1 (violations found), or 2 (the argless
    default scan set could not be enumerated — fail-closed)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        paths = args
    else:
        paths = _git_tracked_ui()
        # Fail CLOSED: an empty default scan set means `git ls-files` could not
        # enumerate the UI trees (git absent / not a checkout) -- this repo always
        # has such files -- so error rather than exit 0 and silently skip the gate.
        if not paths:
            print(
                "check_noopener: `git ls-files src/usr/local/www src/usr/local/pkg` returned nothing "
                "(git unavailable or not a checkout) -- failing closed rather than "
                "skipping the gate.",
                file=sys.stderr,
            )
            return 2

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
