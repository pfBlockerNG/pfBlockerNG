#!/usr/bin/env python3
"""Forbid hardcoded pfSense/FreeBSD version tokens in VALUE positions.

PROBLEM
-------
``supported-versions.json`` on the ``origin/ci-metadata`` orphan ref is the
single machine-readable source of truth for every supported pfSense/FreeBSD
version pairing (CE ``2.8``/FreeBSD ``15``/``php8.3``, Plus ``26.03``/FreeBSD
``16``/``php8.5``, both ``py311``). A script or workflow that restates one of
those values as a literal —

    _ABI="FreeBSD:15:amd64"
    default: "py311"

— silently drifts from the matrix the moment a version is added or dropped
there (a new CE goes GA, an old one is EOL'd): the literal still "works" but
now lies about what is actually supported. The fix is always to read the
value from the matrix at runtime/generation time (``scripts/read-version-matrix.sh``),
never to spell it out again.

This check is PREVENTATIVE — it guards against re-introducing the footgun,
not against a bug already shipped.

SCOPE (deliberately low false-positive: VALUES only, never prose)
-------------------------------------------------------------------
* Scans tracked files under ``src/``, ``scripts/``, and ``.github/workflows/``
  (production code, dev/CI tooling, and workflow YAML — everywhere a version
  literal could plausibly be pasted).
* Excludes: any ``*.md`` path (docs describe value *formats*, not enforce
  them — the user chose values-only enforcement); any ``install_deps_*`` file
  (real FreeBSD package names such as ``py311-sqlite3`` legitimately hardcode
  a flavor there — an intentional allowlist, matched by filename); this file and its own test
  (they define/contain the patterns being matched, so scanning them is
  meaningless self-reference). ``docs/misc/pfSense_versions.md`` is outside
  the scan roots anyway; it is named here only to document that intent.
* A line containing the substring ``version-literal-ok`` is exempt (inline
  escape: ``# version-literal-ok: <reason>``).
* A ``#``-comment line, an unquoted trailing ``# ...`` comment on an
  otherwise-real code line, and any line inside a triple-quoted
  docstring/prose block are all exempt outright — a doc example illustrating
  a transformation (e.g. an arrow mapping shown inside a docstring, or a
  trailing ``# e.g. "ce-2.8"``) is prose, not a value assignment, even though
  the quoted span alone would otherwise fullmatch a token.
* Flags a token ONLY when it stands ALONE as a value: the entire inner text
  of a quoted string literal (``"2.8"``, ``'py311'``), or the entire unquoted
  right-hand side of a ``key: value`` / ``key=value`` assignment. A token
  embedded in a longer string (prose, ``--help`` text, a comment) is NOT
  flagged — e.g. ``help="target ABI, e.g. FreeBSD:15:amd64 (CE 2.8)"`` and
  ``# FreeBSD:15:amd64 -> freebsd-15-amd64`` both stay clean, because the
  token is not the ENTIRE value there.

Exit status: 0 = clean, 1 = one or more violations (printed with file:line).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Each alternative is a full-value token shape (no anchors here -- anchors are
# added once, around the whole alternation, at the two call sites below).
_TOKEN_ALTERNATIVES = (
    r"2\.[89]",  # CE version: 2.8 / 2.9
    r"2[56]\.[0-9]{2}",  # Plus version: 25.NN / 26.NN
    r"FreeBSD:1[56](?::[a-z0-9_]+)?",  # FreeBSD ABI: FreeBSD:15/:16, optional :arch
    r"php8[0-9]",  # php flavor: php80..php89
    r"py31[0-9]",  # py flavor: py310..py319
    r"ce-[0-9]\.[0-9]",  # varver: ce-X.Y
    r"plus-[0-9]{2}\.[0-9]{2}",  # varver: plus-NN.NN
)

# ponytail: a flavor token embedded in a hardcoded package name (e.g.
# "py311-sqlite3" outside the install_deps_* allowlist) is not caught -- this
# checker only matches a token that is the WHOLE value. Upgrade to substring
# matching if hardcoded dependency names spread beyond the allowlisted file.
#
# ponytail: the unquoted-RHS check (_ASSIGNMENT_RE) matches a single whole-line
# `key: value` / `key=value` (optionally `export`/`readonly`-prefixed) only. It
# does NOT catch a token in a compound statement (`A=x; B=y`) or an unquoted
# YAML sequence item (`- FreeBSD:15:amd64` / `[a, b]`); none occur in the tree
# and the spec scopes to key/value. A QUOTED token in any of these is still
# caught by the quoted-literal path.
#
# ponytail: a quoted illustrative example inside a multi-line YAML folded/
# literal scalar (`description: >` ... "e.g. \"2.8\"" on a continuation line)
# is not recognised as prose -- only `#` comments and Python triple-quoted
# docstrings are tracked. The single such site today (version-tracker.yml) was
# fixed by DE-QUOTING the example, because a `version-literal-ok` comment cannot
# sit inside a folded-scalar body without corrupting the visible description.
# Upgrade to a YAML block-scalar tracker (indentation-based, mirroring
# _prose_line_flags's docstring state machine) if more than one line ever needs it.
_FULL_VALUE_RE = re.compile("^(?:" + "|".join(_TOKEN_ALTERNATIVES) + ")$")
# Optional `export`/`readonly` prefix: an unquoted `export ABI=FreeBSD:15:amd64`
# is a real hardcode the quoted-literal path can't see (Copilot, PR #937).
_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+|readonly\s+)?[\w.-]+\s*[:=]\s*(?:" + "|".join(_TOKEN_ALTERNATIVES) + r")\s*$"
)

_QUOTED_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'')

# Inline per-line escape, mirroring the URL-encoding checker's convention.
_ESCAPE = "version-literal-ok"

# Tracked-tree roots where a version literal could plausibly be pasted.
_SCAN_ROOTS = ("src", "scripts", ".github/workflows")

# Self-reference: this checker and its own test define/contain the patterns.
_EXCLUDED_SELF_NAMES = ("check_version_literals.py", "test_version_literal_check.py")


def _is_excluded(path: Path) -> bool:
    """True if ``path`` is out of scope for the value-literal scan."""
    if path.suffix == ".md":
        return True
    if path.name in _EXCLUDED_SELF_NAMES:
        return True
    # install_deps_* (e.g. scripts/misc/install_deps_CE_2.8.sh): real FreeBSD
    # package names (py311-sqlite3) legitimately hardcode a flavor -- the spec's
    # one intentional allowlist, matched by filename.
    return path.name.startswith("install_deps_")


def _quoted_literals(line: str) -> list[str]:
    """Return the inner text of every single- or double-quoted span on ``line``."""
    return [m.group(1) if m.group(1) is not None else m.group(2) for m in _QUOTED_RE.finditer(line)]


def _strip_inline_comment(line: str) -> str:
    """Return ``line`` with any unquoted trailing ``#...`` comment removed.

    A trailing ``# e.g. "ce-2.8"`` on an otherwise-real code line is a comment
    illustrating the value, not the value itself -- same "prose" exemption as
    a full comment line, just not confined to the start of the line. A ``#``
    INSIDE a quoted string is left alone (rare, but real content).
    """
    quote: str | None = None
    for i, ch in enumerate(line):
        if quote is not None:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == "#":
            return line[:i]
    return line


def _line_has_value_literal(line: str) -> bool:
    """True if ``line`` holds a version token standing ALONE as a value."""
    code = _strip_inline_comment(line)
    for literal in _quoted_literals(code):
        if _FULL_VALUE_RE.fullmatch(literal):
            return True
    return bool(_ASSIGNMENT_RE.match(code))


def _tracked_files(roots: tuple[str, ...]) -> list[Path]:
    """Return every git-tracked, non-excluded file under the given roots."""
    out = subprocess.run(
        ["git", "ls-files", "-z", *roots],
        capture_output=True,
        text=True,
        check=True,
    )
    return [Path(p) for p in out.stdout.split("\0") if p and not _is_excluded(Path(p))]


_TRIPLE_QUOTE_TOKENS = ('"""', "'''")


def _prose_line_flags(lines: list[str], is_python: bool) -> list[bool]:
    """Return, per line, whether it is a ``#`` comment or (in a .py file) prose.

    ``#`` comment lines are prose in every scanned language (sh/yaml/py), so
    that exemption is unconditional.

    The triple-quote (docstring) state machine runs ONLY for Python sources
    (``is_python``): once a line opens an odd number of triple-double- or
    triple-single-quote tokens, every following line is prose until the matching
    token closes it, so a docstring example (an arrow-mapping transformation)
    stays out of the value scan. It is deliberately NOT applied to shell/YAML:
    a shell value wrapped in triple quotes is valid POSIX adjacent-quote
    concatenation that evaluates to the exact inner literal, so treating such a
    line as prose outside .py would let a hardcoded token bypass the gate
    entirely (PR #937).
    """
    flags: list[bool] = []
    open_token = ""
    for line in lines:
        if open_token:
            flags.append(True)
            if open_token in line:
                open_token = ""
            continue
        if line.lstrip().startswith("#"):
            flags.append(True)
            continue
        prose = False
        if is_python:
            for token in _TRIPLE_QUOTE_TOKENS:
                count = line.count(token)
                if count:
                    prose = True
                    if count % 2 == 1:
                        open_token = token
                    break
        flags.append(prose)
    return flags


def find_violations(paths: list[Path]) -> list[tuple[Path, int, str]]:
    """Return ``(path, lineno, line)`` for every value-position version literal."""
    violations: list[tuple[Path, int, str]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        lines = text.splitlines()
        prose_flags = _prose_line_flags(lines, path.suffix == ".py")
        for lineno, (line, is_prose) in enumerate(zip(lines, prose_flags, strict=True), start=1):
            if is_prose or _ESCAPE in line:
                continue
            if _line_has_value_literal(line):
                violations.append((path, lineno, line.strip()))
    return violations


def main(argv: list[str]) -> int:
    if argv:
        paths = [p for p in (Path(a) for a in argv) if not _is_excluded(p)]
    else:
        paths = _tracked_files(_SCAN_ROOTS)
    violations = find_violations(paths)
    if not violations:
        return 0
    print("Hardcoded pfSense/FreeBSD version literal(s) in value position:\n", file=sys.stderr)
    for path, lineno, line in violations:
        print(f"  {path}:{lineno}: {line}", file=sys.stderr)
    print(
        "\nsupported-versions.json (origin/ci-metadata) is the single source of truth for "
        "every supported version pairing -- read it at runtime/generation time via "
        "scripts/read-version-matrix.sh instead of restating a value here.\n"
        "Escape a genuine one-off with an inline `# version-literal-ok: <reason>` comment. "
        "See CLAUDE.md and docs/misc/pfSense_versions.md.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
