#!/usr/bin/env python3
"""Read paths out of git without losing the ones git quotes.

PROBLEM
-------
Git renders a path that contains a byte it considers unsafe in C-quoted form:
wrapped in double quotes, with backslash escapes. ``core.quotePath=false`` turns
off only the *high-bit* half of that (issue #2137); a literal ``"``, ``\\``, tab
or newline is escaped unconditionally, and no configuration suppresses it::

    $ git -c core.quotePath=false diff --no-index --name-only a b
    "b/src/has\\ttab.inc"

Every gate in this repo classifies a path by prefix (``startswith("src/")``) or
suffix (``\\.(php|inc)$``). A quoted path begins with ``"`` and ends with
``".inc"`` rather than ``.inc``, so it matches nothing at all: the change ships
un-gated and the job reports a clean pass. Issue #2212.

THE TWO TRANSPORTS
------------------
``changed_paths`` is the answer wherever a *list* of paths is wanted: ``-z``
emits them raw and NUL-separated, so no quoting happens and nothing has to be
undone. It is also the only form that can carry a path containing a newline.

``unquote`` is for the one place that cannot use ``-z`` — the ``+++ b/<path>``
header of a unified diff, whose quoting no git option suppresses. Parsing the
header is the only way to attribute a hunk to its file, so the path is unquoted
on read instead.

Prefer ``changed_paths``. Reach for ``unquote`` only when the path arrives
inside a diff body that must be parsed anyway.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# git's unquote_c_style, as emitted by quote_c_style: the escapes it writes for
# bytes that are not printable ASCII. Anything else appears as \NNN octal.
_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    '"': '"',
}


def unquote(path: str) -> str:
    """Undo git's C-style quoting of ``path``; return an unquoted path as-is.

    A path git did not quote carries no escapes — its backslashes are literal —
    so it must be returned untouched rather than run through the unescaper.
    Detection is the surrounding double quotes, which is exactly the signal git
    itself uses.
    """
    if len(path) < 2 or not path.startswith('"') or not path.endswith('"'):
        return path

    body = path[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            out += char.encode("utf-8")
            index += 1
            continue
        index += 1
        if index >= len(body):
            # A trailing backslash cannot be produced by quote_c_style; keep it
            # rather than dropping a byte from a path a caller may still act on.
            out += b"\\"
            break
        char = body[index]
        if char in _ESCAPES:
            out += _ESCAPES[char].encode("utf-8")
            index += 1
        elif char.isdigit():
            octal = body[index : index + 3]
            out.append(int(octal, 8))
            index += len(octal)
        else:
            # Not an escape git emits; keep both bytes verbatim.
            out += b"\\" + char.encode("utf-8")
            index += 1

    # surrogateescape, not strict: a path need not be valid UTF-8, and a gate
    # that crashes on one is no better than a gate that skips it.
    return out.decode("utf-8", "surrogateescape")


def diff_header_name(raw: str) -> str:
    """The name a ``+++ ``/``--- `` unified-diff header carries, unquoted.

    Returns the whole token, prefix included (``b/src/x.inc``, ``/dev/null``) —
    callers keep their own prefix handling. Git quotes the token *including* its
    ``b/`` prefix (``+++ "b/src/has\\"quote.inc"``), so a caller testing
    ``startswith("b/")`` before unquoting sees no match and drops the file
    silently; unquoting first is what keeps the hunk attributed (issue #2212).
    """
    name = raw[4:]
    if name.startswith('"'):
        # A quoted name is self-delimiting: git adds no disambiguation tab.
        return unquote(name)
    # git appends a tab after an unquoted name containing a space.
    return name.split("\t", 1)[0]


def changed_paths(*args: str, cwd: Path | str | None = None) -> list[str]:
    """``git diff --name-only -z`` as a list of raw paths.

    ``-z`` is what makes this safe: it suppresses quoting entirely, so the
    result needs no unquoting and can carry a path containing a newline, which
    a newline-separated list cannot represent at all.
    """
    out = subprocess.run(
        ["git", "-c", "core.quotePath=false", "diff", "--name-only", "-z", *args],
        cwd=cwd,
        capture_output=True,
        check=True,
    ).stdout
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def split_nul_or_lines(body: str) -> list[str]:
    """Split a changed-file list that may be NUL-separated or newline-separated.

    A NUL anywhere means the producer used ``-z``, and newlines inside a path
    are then data rather than separators — so the two forms must never be mixed.
    Falling back to lines keeps a hand-typed list working at the command line.
    """
    if "\0" in body:
        return [p for p in body.split("\0") if p]
    return [line for line in body.splitlines() if line]
