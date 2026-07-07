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
* Comments are prose in every scanned language, per that language's syntax
  (enumerated from the scan roots' actual file types — issue #941): ``#``
  line/trailing comments everywhere; ``//`` and ``/* ... */`` in PHP/JS
  (``.php``/``.inc``/``.js``, where ``#`` is PHP-only); Python triple-quoted
  docstring bodies in ``.py``. A doc example illustrating a transformation
  (an arrow mapping in a docstring, a trailing ``# e.g. "ce-2.8"``, a
  ``@example "2.8"`` docblock line) is prose, not a value assignment, even
  though the quoted span alone would otherwise fullmatch a token.
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
# `key: value` / `key=value` (optionally prefixed by a shell assignment builtin)
# only. It does NOT catch a token in a compound statement (`A=x; B=y`) or an
# unquoted YAML sequence item (`- FreeBSD:15:amd64` / `[a, b]`); none occur in
# the tree and the spec scopes to key/value. A QUOTED token in any of these is
# still caught by the quoted-literal path.
#
# ponytail: a quoted illustrative example inside a multi-line YAML folded/
# literal scalar (`description: >` ... "e.g. \"2.8\"" on a continuation line)
# is not recognised as prose -- only comments and Python triple-quoted
# docstrings are tracked. The single such site today (version-tracker.yml) was
# fixed by DE-QUOTING the example, because a `version-literal-ok` comment cannot
# sit inside a folded-scalar body without corrupting the visible description.
# Upgrade to a YAML block-scalar tracker (indentation-based, mirroring
# _code_lines's docstring state machine) if more than one line ever needs it.
#
# ponytail: XML comments (`<!-- -->`) are not tracked -- the scan roots hold 3
# XML files with no version-token history; add a tracker if one ever bites.
# Same for JS private fields (`this.#x`): `#` is treated as a comment opener
# only in PHP-family files, so JS is safe from that, but a token inside a JS
# regex literal containing `//` could be mis-stripped (2 JS files, none such).
_FULL_VALUE_RE = re.compile("^(?:" + "|".join(_TOKEN_ALTERNATIVES) + ")$")
# Optional assignment-builtin prefix. The class is enumerated, not example-driven
# (PR #937 pinned only the two keywords Copilot named -- issue #941): POSIX
# `export`/`readonly`, the near-universal `local`, and bash/ksh
# `declare`/`typeset` (with option words), which shellcheck bans here but a
# hardcode guard should still see.
_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:export|readonly|local|declare|typeset)(?:\s+-\w+)*\s+)?"
    r"[\w.-]+\s*[:=]\s*(?:" + "|".join(_TOKEN_ALTERNATIVES) + r")\s*$"
)

_QUOTED_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'')

# Inline per-line escape (`# version-literal-ok: <reason>`), spec'd in issue #922.
_ESCAPE = "version-literal-ok"

# Tracked-tree roots where a version literal could plausibly be pasted.
_SCAN_ROOTS = ("src", "scripts", ".github/workflows")

# Self-reference: this checker and its own test define/contain the patterns.
_EXCLUDED_SELF_NAMES = ("check_version_literals.py", "test_version_literal_check.py")

# File types using C-style comments (`//`, `/* ... */`); `#` is a comment in
# the PHP family but NOT in JS (private fields).
_C_COMMENT_EXTS = (".php", ".inc", ".js")


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


def _split_c_comment(line: str, hash_comments: bool) -> tuple[str, bool]:
    """Return (code part of ``line``, True if an unclosed ``/*`` block opens here).

    Quote-aware: ``//``, ``/*`` and ``#`` inside a quoted string are content,
    not comments. A ``/*...*/`` pair closed on the same line is dropped and the
    code after it is kept. ``hash_comments`` enables ``#`` (PHP family only --
    in JS, ``#`` is a private-field sigil).
    """
    out: list[str] = []
    quote: str | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote is not None:
            if ch == quote:
                quote = None
            out.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#" and hash_comments:
            return "".join(out), False
        if ch == "/" and i + 1 < n and line[i + 1] == "/":
            return "".join(out), False
        if ch == "/" and i + 1 < n and line[i + 1] == "*":
            end = line.find("*/", i + 2)
            if end == -1:
                return "".join(out), True
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out), False


def _line_has_value_literal(code: str) -> bool:
    """True if ``code`` (comments already stripped) holds a token standing ALONE as a value."""
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


def _code_lines(lines: list[str], suffix: str) -> list[str | None]:
    """Return, per line, the code portion to scan -- or ``None`` for prose.

    Comment syntax follows the file type (the axis is enumerated from the scan
    roots' actual extensions, issue #941):

    * ``.php``/``.inc``/``.js``: ``//`` and ``/* ... */`` (state-tracked across
      lines); ``#`` in the PHP family only. ponytail: code after a ``*/`` that
      closes a MULTI-line block is not scanned until the next line (none in
      the tree; a same-line `/*...*/` pair keeps its trailing code).
    * everything else: ``#`` line/trailing comments.
    * ``.py`` additionally tracks triple-quoted docstrings: an ODD number of
      triple-quote tokens toggles the docstring state (a close-and-reopen on
      one line therefore stays open -- the PR #937 parity bug, issue #941),
      while an EVEN count on a non-docstring line falls through to the value
      scan, so a one-line triple-quoted assignment (X = triple-quoted token)
      is caught by the quoted-literal path instead of being swept as prose
      (the ``.py`` mirror of PR #937's blocking F1). ponytail: a one-line
      module docstring whose ENTIRE text is a bare token would now
      false-positive -- absurd corner, escape-comment it if it ever occurs.
      This is deliberately NOT applied to shell/YAML: a shell value wrapped in
      triple quotes is adjacent-quote concatenation evaluating to the exact
      inner literal (PR #937 F1).
    """
    out: list[str | None] = []
    if suffix in _C_COMMENT_EXTS:
        in_block = False
        for line in lines:
            if in_block:
                if "*/" in line:
                    in_block = False
                out.append(None)
                continue
            code, in_block = _split_c_comment(line, hash_comments=suffix != ".js")
            out.append(code)
        return out
    is_python = suffix == ".py"
    open_token = ""
    for line in lines:
        if open_token:
            out.append(None)
            if line.count(open_token) % 2 == 1:
                open_token = ""
            continue
        if line.lstrip().startswith("#"):
            out.append(None)
            continue
        if is_python:
            opened = False
            for token in _TRIPLE_QUOTE_TOKENS:
                if line.count(token) % 2 == 1:
                    open_token = token
                    opened = True
                    break
            if opened:
                out.append(None)
                continue
        out.append(_strip_inline_comment(line))
    return out


def find_violations(paths: list[Path]) -> list[tuple[Path, int, str]]:
    """Return ``(path, lineno, line)`` for every value-position version literal."""
    violations: list[tuple[Path, int, str]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        lines = text.splitlines()
        code_lines = _code_lines(lines, path.suffix)
        for lineno, (line, code) in enumerate(zip(lines, code_lines, strict=True), start=1):
            if code is None or _ESCAPE in line:
                continue
            if _line_has_value_literal(code):
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
