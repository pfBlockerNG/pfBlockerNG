#!/usr/bin/env python3
"""Forbid naked shell-variable interpolation into an HTTP-client URL query.

PROBLEM
-------
A query parameter whose value is a shell variable jammed straight into the URL —

    curl "http://host/cb?ip=$PFB_CHANGED_IP_ALIASES"

— breaks the moment that value is empty or contains whitespace. pfBlockerNG's
``PFB_CHANGED_IP_ALIASES`` (and similar hook payloads) are *space-separated*
lists that may also be empty: the space splits the URL, the shell re-tokenises
the command, and the parameter silently collapses or the request fails. The
value must be percent-encoded, which curl/wget do for you when the value rides
its own option rather than the literal URL:

    curl --data-urlencode "ip=$PFB_CHANGED_IP_ALIASES" http://host/cb

This check is PREVENTATIVE — there are no offenders in shipped code today. It
guards future shell scripts and the user-facing hook/webhook recipe examples in
the docs against re-introducing the naked-interpolation footgun.

HEURISTIC (deliberately low false-positive)
-------------------------------------------
* Only *logical* lines that invoke an HTTP client are considered: a word-boundary
  ``curl``, ``wget`` or ``fetch``. Backslash-continued shell lines are joined into
  one logical line first, so a URL sitting on a continuation is still seen.
* Within such a line we inspect URL-looking TOKENS only — a token containing
  ``://``, or a quoted token that begins with ``http``/``https``, or a token that
  contains a ``?`` query separator. A violation is a query parameter assigned a
  shell variable inside that token: ``[?&]<key>=$`` (e.g. ``?ip=$VAR`` /
  ``&k=${VAR}``), including ``$`` immediately after ``?``/``&``/``=``.
* The CORRECT form ``--data-urlencode "k=$VAR"`` is NOT flagged: that value rides
  its own flag token, which has no ``://`` and no leading ``?``/``&`` query
  separator, so it never qualifies as a URL token. (Pinned by a test.)
* NOT flagged: static query params (``?fixed=1``), and a variable used only as
  base/host/path with no query value (``"$BASE/path"``, ``"http://h/$ID"``).
  Path-segment interpolation is INTENTIONALLY out of scope — it is lower
  confidence (a path segment rarely carries whitespace-bearing list payloads)
  and scoping to query values keeps the noise floor near zero.

The detection logic lives in :func:`find_violations` (pure, importable) so it is
unit-tested directly without a subprocess. The :func:`main` CLI, with no args,
resolves the file list via ``git ls-files`` — every tracked ``*.sh`` script (the
``src/**`` hook/pre-script surface, plus dev ``scripts``/``tests`` shell, mirroring
the pre-commit shebang/`sh -n` checks that also scan all tracked shell) and every
tracked ``*.md`` (scanning only the shell-tagged fenced blocks) — or it scans the
explicit paths passed as args. It prints ``path:line: <message>`` to stderr,
exiting 1 if any violation is found.

This is dev-only tooling (release archives contain only ``src/``); it lives under
``scripts/`` and is wired into ``.githooks/pre-commit`` and CI.
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import NamedTuple

# HTTP clients whose URL argument is the footgun surface.
_HTTP_CLIENT_RE = re.compile(r"(?<![\w-])(?:curl|wget|fetch)(?![\w-])")

# A query parameter assigned a shell variable: `?key=$VAR`, `&key=$VAR`, or a
# bare `$` right after the `?`/`&`/`=` separator. `[^=&\s"']*` keeps the key on
# the same token (no spaces); the trailing `\$` is the shell expansion.
_NAKED_QUERY_VAR_RE = re.compile(r"[?&][^=&\s\"']*=\$")

# Fix hint surfaced in every message (asserted by the tests).
_FIX_HINT = 'use `curl --data-urlencode "key=$VAR"` so the value is percent-encoded'

# Markdown fenced-block opener with a shell language tag (sh/bash/shell).
_SHELL_FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*(sh|bash|shell)\s*$", re.IGNORECASE)
# A generic fence opener/closer (any or no language) — to detect fence boundaries.
_FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([^\s`~]*)\s*$")


class Violation(NamedTuple):
    """One naked-interpolation finding."""

    source: str  # file path (or path with a fence note for Markdown)
    line: int  # 1-based line number within the source file
    snippet: str  # the offending logical line (trimmed)
    message: str  # actionable description incl. the --data-urlencode fix


def _looks_like_url_token(token: str) -> bool:
    """True if a shell token looks like an HTTP URL or a query string.

    Confines the naked-variable match to URL-bearing tokens, so option values
    such as ``--data-urlencode "k=$V"`` (a separate, non-URL token) are excluded.
    """
    stripped = token.strip("\"'")
    if "://" in stripped:
        return True
    if stripped.startswith(("http", "https")):
        return True
    # A bare query string token (rare, but `?k=$V` with no scheme still encodes).
    return stripped.startswith("?")


def _split_tokens(line: str) -> list[str]:
    """Whitespace-split a logical line, keeping quoted spans intact.

    Not a full shell parser — it only needs to keep a quoted URL (which may
    contain ``&`` and ``?``) as one token and keep an option's quoted value as a
    token distinct from the URL. Unmatched quotes degrade gracefully to a plain
    whitespace split of the remainder.
    """
    tokens: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    for ch in line:
        if quote is not None:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            continue
        if ch.isspace():
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _join_continuations(lines: list[str]) -> list[tuple[int, str]]:
    """Fold ``\\``-continued shell lines into logical lines.

    Returns ``(line_number, logical_line)`` pairs where ``line_number`` is the
    1-based line on which the logical line STARTS — so a violation on a
    continuation is reported at the ``curl`` invocation's own line.
    """
    logical: list[tuple[int, str]] = []
    pending: list[str] = []
    start_no = 0
    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.rstrip("\n")
        if not pending:
            start_no = line_no
        if stripped.endswith("\\"):
            pending.append(stripped[:-1])
            continue
        pending.append(stripped)
        logical.append((start_no, " ".join(p.strip() for p in pending)))
        pending = []
    if pending:
        logical.append((start_no, " ".join(p.strip() for p in pending)))
    return logical


def _scan_logical_line(line: str) -> bool:
    """True if a logical line naked-interpolates a var into an HTTP-client URL."""
    # A comment-only line (e.g. a "# curl ...?ip=$VAR" anti-pattern shown in a doc
    # or recipe) is not executed, so it must not be flagged -- otherwise a legitimate
    # "don't do this" example would fail pre-commit/CI.
    if line.lstrip().startswith("#"):
        return False
    if not _HTTP_CLIENT_RE.search(line):
        return False
    for token in _split_tokens(line):
        if _looks_like_url_token(token) and _NAKED_QUERY_VAR_RE.search(token):
            return True
    return False


def _iter_shell_fence_blocks(lines: list[str]) -> list[tuple[int, list[str]]]:
    """Yield ``(start_line, block_lines)`` for each ```sh/```bash/```shell fence.

    ``start_line`` is the 1-based file line of the fence's FIRST content line, so
    offsets within the returned block map back to absolute file lines. Only the
    block content is returned (fence markers excluded). Non-shell fences are
    skipped entirely.
    """
    blocks: list[tuple[int, list[str]]] = []
    i = 0
    n = len(lines)
    while i < n:
        m = _SHELL_FENCE_RE.match(lines[i].rstrip("\n"))
        if not m:
            # If this is some other fence opener, skip to its close so a
            # `?k=$V` inside e.g. a ```python block is never scanned.
            fm = _FENCE_RE.match(lines[i].rstrip("\n"))
            if fm and fm.group(3) != "":
                fence = fm.group(2)[0]
                i += 1
                while i < n and not _is_fence_close(lines[i], fence):
                    i += 1
                i += 1
                continue
            i += 1
            continue
        fence = m.group(2)[0]
        content_start = i + 2  # 1-based line of first content line
        body: list[str] = []
        j = i + 1
        while j < n and not _is_fence_close(lines[j], fence):
            body.append(lines[j])
            j += 1
        blocks.append((content_start, body))
        i = j + 1
    return blocks


def _is_fence_close(line: str, fence_char: str) -> bool:
    """True if ``line`` closes a fence opened with ``fence_char`` (` or ~)."""
    s = line.strip()
    return len(s) >= 3 and set(s) == {fence_char}


def find_violations(text: str, source: str) -> list[Violation]:
    """Find naked-interpolation violations in shell ``text`` from ``source``.

    ``text`` is treated as shell script content. Backslash continuations are
    joined first; each logical line is scanned and, on a hit, reported at the
    line where the invocation starts.
    """
    violations: list[Violation] = []
    for line_no, logical in _join_continuations(text.splitlines()):
        if _scan_logical_line(logical):
            violations.append(
                Violation(
                    source=source,
                    line=line_no,
                    snippet=logical.strip(),
                    message=(f"naked shell variable in an HTTP-client URL query parameter; {_FIX_HINT}"),
                )
            )
    return violations


def find_violations_in_markdown(text: str, source: str) -> list[Violation]:
    """Find violations inside the shell-tagged fenced code blocks of Markdown.

    Only ```sh / ```bash / ```shell fences are scanned; other fences (and prose)
    are ignored. Reported line numbers are absolute within the Markdown file.
    """
    violations: list[Violation] = []
    lines = text.splitlines()
    for content_start, body in _iter_shell_fence_blocks(lines):
        for rel_no, logical in _join_continuations(body):
            if _scan_logical_line(logical):
                abs_line = content_start + (rel_no - 1)
                violations.append(
                    Violation(
                        source=source,
                        line=abs_line,
                        snippet=logical.strip(),
                        message=(
                            "naked shell variable in an HTTP-client URL query "
                            f"parameter (in a shell code block); {_FIX_HINT}"
                        ),
                    )
                )
    return violations


def _git_tracked(patterns: list[str]) -> list[str]:
    """Return git-tracked files matching the given pathspecs (sorted, unique)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", *patterns],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    return sorted({p for p in out.split("\0") if p})


def _default_files() -> tuple[list[str], list[str]]:
    """Resolve the default scan set: (shell files, markdown files)."""
    shell = _git_tracked(["*.sh"])
    markdown = _git_tracked(["*.md"])
    return shell, markdown


def _scan_path(path: str) -> list[Violation]:
    """Scan one file by extension; unreadable files are skipped silently."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    if path.endswith(".md"):
        return find_violations_in_markdown(text, path)
    return find_violations(text, path)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 (clean) or 1 (violations found)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        paths = args
    else:
        shell, markdown = _default_files()
        paths = shell + markdown

    violations: list[Violation] = []
    for path in paths:
        violations.extend(_scan_path(path))

    for v in violations:
        print(f"{v.source}:{v.line}: {v.message}", file=sys.stderr)
        print(f"    {v.snippet}", file=sys.stderr)

    if violations:
        print(
            f"\n{len(violations)} naked-URL-interpolation violation(s). "
            "Percent-encode the value with curl/wget --data-urlencode instead "
            "of jamming a shell variable into the URL query.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
