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

A second mode, ``--verify-matrix [--ref <git-ref> | --matrix-file <path>]``,
tripwires the WINDOWED token shapes against ``supported-versions.json``
(issue #940; a blocking CI step in ``test.yml``): exit 1 lists every
matrix-implied token the patterns no longer cover, so the window is widened
the moment the matrix moves instead of the gate narrowing silently; a
misconfigured invocation (bad ref, missing file, malformed JSON) exits 2.

DIFF-SCOPED modes ``--staged`` and ``--diff <base>`` (issue #1000) judge only
ADDED lines, like ``check_comment_narration.py`` -- but full-file comment/
docstring state is needed for a correct scan, so each changed file's WHOLE
content is re-read (index for ``--staged``, ``HEAD`` for ``--diff``) and only
violations landing on an added line are kept; pre-existing literals stay
grandfathered. A git failure exits 2. These modes are for ad-hoc/CI-PR
invocation; the argument-less full scan above remains the pre-commit/CI gate.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# Each alternative is a full-value token shape (anchored once, at the
# alternation, by the two call sites below). Unambiguous shapes (ABI/php/py/
# varver) are version-AGNOSTIC -- any restated literal is a drift hazard
# (issue #940). Only the bare CE/Plus numerics stay WINDOWED (an unbounded
# decimal shape would false-positive on unrelated numbers); --verify-matrix
# tripwires that window against the live matrix so it widens instead of
# silently narrowing.
_TOKEN_ALTERNATIVES = (
    r"2\.[89]",  # CE version window: 2.8 / 2.9 (tripwired)
    r"2[56]\.[0-9]{2}",  # Plus version window: 25.NN / 26.NN (tripwired)
    r"FreeBSD:[0-9]+(?::[a-z0-9_]+)?",  # FreeBSD ABI, any major, optional :arch
    r"php[0-9]{2}",  # php flavor: php74..php99
    r"py3[0-9]{2}",  # py flavor: py310..py399
    r"ce-[0-9]+\.[0-9]+",  # varver: ce-X.Y
    r"plus-[0-9]+\.[0-9]+",  # varver: plus-X.Y (generalized like ce-)
)

# ponytail: a flavor token embedded in a hardcoded name (e.g. "py311-sqlite3")
# is not caught -- only whole-value tokens are; extend if that ever spreads.
#
# ponytail: _ASSIGNMENT_RE matches only a single whole-line key:value/key=value
# -- misses compound statements/unquoted YAML sequences (a quoted token there still hits the quoted-literal path).
#
# ponytail: a quoted example inside a multi-line YAML folded/literal scalar is
# not recognised as prose (the one site was fixed by de-quoting instead).
#
# ponytail: XML comments and JS private-field `#x` syntax are not tracked --
# no version-token history in either today; add a tracker if one ever bites.
_FULL_VALUE_RE = re.compile("^(?:" + "|".join(_TOKEN_ALTERNATIVES) + ")$")
# Optional assignment-builtin prefix. The class is enumerated, not example-
# driven (issue #941): POSIX `export`/`readonly`, the near-universal `local`,
# and bash/ksh `declare`/`typeset` (with option words), which shellcheck bans
# here but a hardcode guard should still see.
_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:export|readonly|local|declare|typeset)(?:\s+-\w+)*\s+)?"
    r"[\w.-]+\s*[:=]\s*(?:" + "|".join(_TOKEN_ALTERNATIVES) + r")\s*$"
)

# The double-quote side is escape-aware (\" is content in sh/php/js/py alike)
# so an escaped quote cannot mispair spans and swallow a later literal. The
# single-quote side is language-scoped: PHP/JS support \', so that side is
# escape-aware too there; POSIX sh has none, so the shell/YAML variant stays
# naive (shell-correct). Both variants CONSUME backtick spans so quote pairing
# never crosses one; the C-style variant also CAPTURES that span (a JS
# template literal is a value), the shell variant does not (backticks are
# command substitution, not a value).
_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|`(?:[^`\\]|\\.)*`')
_QUOTED_C_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'|`((?:[^`\\]|\\.)*)`')

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


def _in_scan_roots(path_str: str) -> bool:
    """True if a diff-mode path lives under a scan root.

    The full scan only visits ``_SCAN_ROOTS`` (via ``git ls-files``), so the
    diff modes must match that scope -- else a version token in a changed file
    the full gate never sees (e.g. under ``tests/``, where fixtures legitimately
    carry version literals) would false-positive on a PR.
    """
    return any(path_str == root or path_str.startswith(f"{root}/") for root in _SCAN_ROOTS)


def _quoted_literals(line: str, c_style: bool = False) -> list[str]:
    """Return the inner text of every single- or double-quoted span on ``line``.

    ``c_style`` selects the PHP/JS variant whose single-quote side is
    escape-aware (``\\'`` is content there, unlike POSIX sh) and whose
    backtick spans count as values (template literals).
    """
    regex = _QUOTED_C_RE if c_style else _QUOTED_RE
    return [g for m in regex.finditer(line) for g in m.groups() if g is not None]


def _strip_inline_comment(line: str) -> str:
    """Return ``line`` with any unquoted trailing ``#...`` comment removed.

    A trailing ``# e.g. "ce-2.8"`` on an otherwise-real code line is a comment
    illustrating the value, not the value itself -- same "prose" exemption as
    a full comment line, just not confined to the start of the line. A ``#``
    INSIDE a quoted string is left alone (rare, but real content). Inside a
    DOUBLE-quoted string a backslash escapes the next char, so an escaped
    quote does not mis-close the string; single quotes stay escape-free --
    POSIX sh has no escapes there.
    """
    quote: str | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote is not None:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "#":
            return line[:i]
        i += 1
    return line


def _split_c_comment(line: str, hash_comments: bool) -> tuple[str, bool]:
    """Return (code part of ``line``, True if an unclosed ``/*`` block opens here).

    Quote-aware: ``//``, ``/*`` and ``#`` inside a quoted string are content,
    not comments, and a backslash inside a quoted string escapes the next char
    (PHP/JS support ``\\'``/``\\"`` in both quote types), so an escaped quote
    does not mis-close the string. Backticks are tracked as a third quote
    type: a JS template literal (or PHP shell-exec string) containing ``//``
    must not truncate the scan of real code after it. A ``/*...*/`` pair
    closed on the same line is dropped and the code after it is kept.
    ``hash_comments`` enables ``#`` (PHP family only -- in JS, ``#`` is a
    private-field sigil).

    ponytail: quote state is per-line, so a multi-line PHP/JS string (no
    heredoc) could hide a value on a continuation line (none today) -- carry
    the open quote across lines like ``in_block`` if that ever bites.
    """
    out: list[str] = []
    quote: str | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote is not None:
            if ch == "\\" and i + 1 < n:
                out.append(line[i : i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(ch)
            i += 1
            continue
        if ch in ("'", '"', "`"):
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


def _line_has_value_literal(code: str, c_style: bool = False) -> bool:
    """True if ``code`` (comments already stripped) holds a token standing ALONE as a value."""
    for literal in _quoted_literals(code, c_style):
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


def _py_triple_close_count(line: str, token: str) -> int:
    """Count real, escape-aware ``token`` occurrences in an OPEN docstring line.

    issue #1090: a backslash-escaped delimiter (``\\` + token``) is body text,
    not a close -- mirrors ``_py_docstring_probe``'s in-triple escape handling,
    restricted to counting the already-known open token.
    """
    count = 0
    i, n = 0, len(line)
    while i < n:
        if line[i] == "\\":
            i += 2
            continue
        if line[i : i + 3] == token:
            count += 1
            i += 3
            continue
        i += 1
    return count


def _py_docstring_probe(line: str) -> str:
    """Reduce ``line`` to its real triple-quote delimiters plus bare code.

    issue #1082: a triple-quote token (``'''`` or its double-quote form) that
    appears only inside a normal single-line ``'...'``/``"..."`` string or a
    trailing ``#`` comment (e.g. ``SEP = "'''"``) must NOT count as a delimiter -- else it
    opens a spurious docstring that swallows every following line. This blanks
    normal-string content and the trailing comment while keeping delimiters, so
    the caller's odd/even count sees only genuine triple-quote delimiters.
    """
    out: list[str] = []
    quote: str | None = None  # inside a normal single-line '...'/"..." string
    triple: str | None = None  # inside a triple-quoted span opened on THIS line
    i, n = 0, len(line)
    while i < n:
        three = line[i : i + 3]
        if triple is not None:
            # content of an open triple span is blanked; only its matching close
            # delimiter is emitted, so a quote or "#" inside it can't mislead us.
            if line[i] == "\\":
                # Escapes work inside triple quotes too: \""" is an escaped quote
                # + two quotes, not a close delimiter.
                i += 2
                continue
            if three == triple:
                out.append(three)
                triple = None
                i += 3
                continue
            i += 1
            continue
        if quote is not None:
            ch = line[i]
            if ch == "\\":
                # Python escapes inside BOTH '...' and "..." strings, so a \' or \"
                # does not close the string and a following triple-quote token stays
                # string content rather than a docstring delimiter.
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if three in _TRIPLE_QUOTE_TOKENS:
            out.append(three)
            triple = three
            i += 3
            continue
        ch = line[i]
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "#":
            break
        out.append(ch)
        i += 1
    return "".join(out)


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
      real triple-quote delimiters (outside normal strings/comments, issue
      #1082) toggles the docstring state (a close-and-reopen on
      one line therefore stays open), while an EVEN count on a non-docstring
      line falls through to the value scan, so a one-line triple-quoted
      assignment (X = triple-quoted token) is caught by the quoted-literal
      path instead of being swept as prose. ponytail: a one-line module
      docstring whose ENTIRE text is a bare token would false-positive --
      absurd corner; escape-comment it if it occurs. This is deliberately
      NOT applied to shell/YAML: a shell value wrapped in triple quotes is
      adjacent-quote concatenation evaluating to the exact inner literal.
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
            if _py_triple_close_count(line, open_token) % 2 == 1:
                open_token = ""
            continue
        if line.lstrip().startswith("#"):
            out.append(None)
            continue
        if is_python:
            probe = _py_docstring_probe(line)
            opened = False
            for token in _TRIPLE_QUOTE_TOKENS:
                if probe.count(token) % 2 == 1:
                    open_token = token
                    opened = True
                    break
            if opened:
                out.append(None)
                continue
        out.append(_strip_inline_comment(line))
    return out


def scan_text(path: Path, text: str) -> list[tuple[Path, int, str]]:
    """Return ``(path, lineno, line)`` for every value-position literal in ``text``.

    Needs the WHOLE file body: ``_code_lines`` tracks multi-line ``/*...*/``
    and Python triple-quote docstring state across lines, so a diff-scoped
    caller must feed full file content, never isolated added-line text.
    """
    violations: list[tuple[Path, int, str]] = []
    lines = text.splitlines()
    c_style = path.suffix in _C_COMMENT_EXTS
    code_lines = _code_lines(lines, path.suffix)
    for lineno, (line, code) in enumerate(zip(lines, code_lines, strict=True), start=1):
        if code is None or _ESCAPE in line:
            continue
        if _line_has_value_literal(code, c_style):
            violations.append((path, lineno, line.strip()))
    return violations


def find_violations(paths: list[Path]) -> list[tuple[Path, int, str]]:
    """Return ``(path, lineno, line)`` for every value-position version literal."""
    violations: list[tuple[Path, int, str]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        violations.extend(scan_text(path, text))
    return violations


def _git_diff(args: list[str]) -> str:
    # Same flag set (and same rationale) as check_comment_narration._git_diff:
    # pin quotePath/prefixes/ext-diff so config/env cannot defeat the +++ b/ parse.
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
        # errors='replace': a non-UTF-8 byte ANYWHERE in the diff (even in a
        # file outside the scan roots) must not crash the whole run with an
        # UnicodeDecodeError -- decode lossily, same as the full scan's read.
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return out.stdout


def _added_lines_by_path(diff_text: str) -> dict[str, set[int]]:
    """Map each changed path to the set of its added (new-file) line numbers.

    ``+++ b/<path>`` is only a file header BEFORE the first ``@@`` of a file
    section: inside a hunk an added content line whose text starts with ``++``
    renders as ``+++ ...`` and must NOT be mistaken for a header (else its --
    and every following added line's -- violation is silently dropped). The
    ``in_hunk`` flag, reset on each ``diff --git``, draws that boundary. A
    deleted file's ``+++`` target is ``/dev/null`` (no ``b/`` prefix), so it
    never gets an entry -- nothing to scan there anyway.
    """
    added: dict[str, set[int]] = {}
    path: str | None = None
    lineno = 0
    in_hunk = False
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git"):
            path = None
            in_hunk = False
            continue
        if raw.startswith("@@"):
            m = re.match(r"@@ -\S+ \+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
            in_hunk = True
            continue
        if not in_hunk:
            if raw.startswith("+++ "):
                name = raw[4:]
                path = name[2:].split("\t", 1)[0] if name.startswith("b/") else None
            continue  # header block: '---'/'index'/etc. never carry added content
        if raw.startswith("+"):
            if path is not None:
                added.setdefault(path, set()).add(lineno)
            lineno += 1
        elif not raw.startswith(("-", "\\")):
            # issue #1051: "\ No newline at end of file" is a marker, not content
            lineno += 1  # context line (absent under --unified=0, tolerated)
    return added


def _diff_mode(argv: list[str]) -> int:
    """The ``--staged``/``--diff <base>`` modes: scan whole-file content, keep only added lines.

    Full-file context is mandatory (``scan_text`` needs it for comment/docstring
    state), so raw diff text is never scanned directly -- each changed file's
    complete content is read back (index for ``--staged``, ``HEAD`` for
    ``--diff``) and every violation is filtered to lines the diff actually added.
    """
    if argv == ["--staged"]:
        diff_args = ["--cached"]
        show_ref = ":"
    elif len(argv) == 2 and argv[0] == "--diff":
        diff_args = [f"{argv[1]}...HEAD"]
        show_ref = "HEAD:"
    else:
        print("usage: check_version_literals.py --staged | --diff <base>", file=sys.stderr)
        return 2
    try:
        diff_text = _git_diff(diff_args)
    except subprocess.CalledProcessError as exc:
        print(f"git diff failed: {exc.stderr.strip()}", file=sys.stderr)
        return 2
    violations: list[tuple[Path, int, str]] = []
    for path_str, added_linenos in _added_lines_by_path(diff_text).items():
        path = Path(path_str)
        if _is_excluded(path) or not _in_scan_roots(path_str):
            continue
        try:
            out = subprocess.run(
                ["git", "show", f"{show_ref}{path_str}"],
                capture_output=True,
                text=True,
                # errors='replace' mirrors the full scan's read_text: a file
                # with a stray non-UTF-8 byte is still scanned (not silently
                # skipped), so diff mode can't miss a literal the full scan sees.
                encoding="utf-8",
                errors="replace",
                check=True,
            )
        except subprocess.CalledProcessError:
            continue  # deleted/unreadable at that ref -- nothing to scan
        for v_path, lineno, line in scan_text(path, out.stdout):
            if lineno in added_linenos:
                violations.append((v_path, lineno, line))
    return _report(violations)


def _report(violations: list[tuple[Path, int, str]]) -> int:
    """Print the shared violation report (used by full-scan, explicit-path, and diff modes)."""
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


def _matrix_tokens(matrix: dict) -> list[str]:
    """Derive every version-shaped token a ``supported-versions.json`` entry implies.

    Per entry: the bare pfSense version (a trailing ``.x`` stripped), its
    ``ce-``/``plus-`` varver, the ``FreeBSD:<major>`` ABI prefix, the php
    flavor (``php_version`` with the dot dropped), and the py flavor verbatim.

    ``role=route-only`` entries (ADR-27: EOL'd but still served, frozen
    catalog, no longer built/tested) are excluded, mirroring
    ``read-version-matrix.sh``'s BUILD/CI derivations: a frozen version's
    identity is no longer an active-development value, so the window need
    not keep covering it forever.
    """
    tokens: list[str] = []
    for entry in matrix.get("versions", []):
        if str(entry.get("role", "build")) == "route-only":
            continue
        version = str(entry.get("pfsense_version", "")).removesuffix(".x")
        channel = str(entry.get("channel", "")).lower()
        major = str(entry.get("freebsd_major", ""))
        php = str(entry.get("php_version", ""))
        py = str(entry.get("py_flavor", ""))
        if version:
            tokens.append(version)
            tokens.append(("ce-" if channel == "ce" else "plus-") + version)
        if major:
            tokens.append(f"FreeBSD:{major}")
        if php:
            tokens.append("php" + php.replace(".", ""))
        if py:
            tokens.append(py)
    return tokens


def uncovered_matrix_tokens(matrix: dict) -> list[str]:
    """Matrix-implied tokens that ``_FULL_VALUE_RE`` no longer covers (sorted, unique)."""
    return sorted({t for t in _matrix_tokens(matrix) if not _FULL_VALUE_RE.fullmatch(t)})


def _verify_matrix(argv: list[str]) -> int:
    """The ``--verify-matrix`` mode: tripwire the windowed token shapes (issue #940).

    Reads ``supported-versions.json`` from the ci-metadata ref (``--ref``,
    default ``origin/ci-metadata``) or from ``--matrix-file <path>``; exits 1
    listing any matrix-implied token the patterns no longer cover, and 2 on a
    misconfigured invocation (unknown option, bad ref, missing file, bad JSON).
    """
    ref = "origin/ci-metadata"
    matrix_file: str | None = None
    it = iter(argv)
    for arg in it:
        if arg == "--ref":
            ref = next(it, ref)
        elif arg == "--matrix-file":
            matrix_file = next(it, None)
        else:
            print(f"unknown --verify-matrix option: {arg}", file=sys.stderr)
            return 2
    # A misconfigured invocation (bad ref, missing file, malformed JSON) gets the
    # file's one-line stderr convention + exit 2, not a traceback -- distinct
    # from exit 1 (uncovered tokens) so CI logs read right.
    try:
        if matrix_file is not None:
            text = Path(matrix_file).read_text(encoding="utf-8")
        else:
            out = subprocess.run(
                ["git", "show", f"{ref}:supported-versions.json"],
                capture_output=True,
                text=True,
                check=True,
            )
            text = out.stdout
        uncovered = uncovered_matrix_tokens(json.loads(text))
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        print(f"--verify-matrix: cannot read the matrix: {detail}", file=sys.stderr)
        return 2
    if not uncovered:
        return 0
    print(
        "supported-versions.json carries version token(s) the version-literal patterns\n"
        "no longer cover -- widen the windowed shapes in _TOKEN_ALTERNATIVES\n"
        "(scripts/check_version_literals.py) or the gate silently stops seeing them:\n",
        file=sys.stderr,
    )
    for token in uncovered:
        print(f"  {token}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--verify-matrix":
        return _verify_matrix(argv[1:])
    if argv and argv[0] in ("--staged", "--diff"):
        return _diff_mode(argv)
    if argv:
        paths = [p for p in (Path(a) for a in argv) if not _is_excluded(p)]
    else:
        paths = _tracked_files(_SCAN_ROOTS)
    return _report(find_violations(paths))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
