"""Real paths out of git's C-quoted output.

git wraps a path in double quotes and C-escapes it whenever the path holds a
double quote, a backslash or a control byte. That quoting is unconditional:
``core.quotePath`` only governs whether HIGH-BIT bytes are escaped too. Every
changed-file gate in this repo classifies a path by prefix or suffix, so a
quoted path matches no rule and its file skips the gate while the job still
reports a clean pass (issue #2212).

``git ... -z`` emits raw NUL-separated paths and is the fix wherever it exists
(``--name-only``, ``ls-files``). A unified diff's ``---``/``+++`` header has no
``-z`` form, so those parsers decode the header here instead. ``unified_diff``
pins ``core.quotePath=true`` so a HIGH-BIT byte in that header is always
C-escaped as plain ASCII (octal, e.g. ``\\377``) instead of emitted raw --
plain ASCII survives the diff body's lossy ``errors="replace"`` decode intact,
where a raw non-UTF-8 byte would have become an unrecoverable U+FFFD and left
the gate reading a path nothing on disk answers to (issue #3076).

This module is the single place the diff-scoped gates talk to git about paths:
one invocation, and one decode per route -- byte-exact for a listing whose paths
the caller will OPEN, deliberately lossy for diff text it will only match and
print (issue #3073). Three gates previously carried byte-identical copies of the
diff command and its header parse, which is why one quoting defect reproduced
across every one of them.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

# git emits these named escapes plus 3-digit octal for any other escaped byte.
_C_ESCAPES = {
    ord("a"): 0x07,
    ord("b"): 0x08,
    ord("f"): 0x0C,
    ord("n"): 0x0A,
    ord("r"): 0x0D,
    ord("t"): 0x09,
    ord("v"): 0x0B,
    ord('"'): 0x22,
    ord("\\"): 0x5C,
}


def unquote_git_path(field: str) -> str:
    """Decode one C-quoted git path field; an unquoted field is returned as-is.

    ``os.fsdecode`` rather than a hard-coded UTF-8 decode: this field feeds
    ``diff_header_name``, whose byte-exact result callers OPEN (e.g. ``git
    show``), so it needs the same filesystem-encoding treatment ``nul_listing``
    uses -- a hard-coded UTF-8 surrogateescape only round-trips on a UTF-8
    filesystem encoding (issue #3073, issue #3076).
    """
    if len(field) < 2 or not (field.startswith('"') and field.endswith('"')):
        return field
    # Byte-level: an octal escape names a BYTE of a multi-byte character, so the
    # escapes have to be resolved before the result is decoded as text.
    raw = field[1:-1].encode("utf-8", "surrogateescape")
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] != 0x5C or i + 1 >= len(raw):
            out.append(raw[i])
            i += 1
        elif raw[i + 1] in _C_ESCAPES:
            out.append(_C_ESCAPES[raw[i + 1]])
            i += 2
        elif 0x30 <= raw[i + 1] <= 0x37:
            # git always emits exactly three octal digits; scanning for however
            # many are actually there keeps the decode total on forged input
            # rather than raising mid-run.
            end = i + 1
            while end < len(raw) and end < i + 4 and 0x30 <= raw[end] <= 0x37:
                end += 1
            out.append(int(raw[i + 1 : end], 8) & 0xFF)
            i = end
        else:
            out.append(raw[i + 1])
            i += 2
    return os.fsdecode(bytes(out))


def diff_header_name(field: str) -> str:
    """Decode the name field of a unified-diff ``---``/``+++`` header line.

    ``field`` is everything after the leading marker and space. git appends a
    literal tab to it when the path holds a space, and C-quotes the whole
    ``a/``/``b/``-prefixed name (tab marker left OUTSIDE the quotes) when the
    path holds a quote, backslash or control byte. Returned with the prefix
    still attached — the caller decides which side it wants.
    """
    if field.startswith('"'):
        return unquote_git_path(field.rstrip("\t"))
    return field.split("\t", 1)[0]


def nul_paths(listing: str) -> list[str]:
    """Split a ``git ... -z`` listing into paths, dropping the empty tail."""
    return [path for path in listing.split("\0") if path]


def _run(args: list[str]) -> bytes:
    """git's stdout, undecoded: the two routes out of this module disagree on how."""
    out = subprocess.run(args, capture_output=True, check=False)
    if out.returncode != 0:
        # stderr is a MESSAGE, not a path, and callers print it straight into
        # their own error line -- decode it here (lossily, like diff text) so
        # they get git's complaint rather than a bytes repr of it.
        raise subprocess.CalledProcessError(out.returncode, args, out.stdout, out.stderr.decode("utf-8", "replace"))
    return out.stdout


def unified_diff(args: list[str]) -> str:
    """A unified diff, pinned against everything that could defeat a header parse.

    ``core.quotePath=true`` (pinned, never left to user config) forces a
    HIGH-BIT header byte to be C-escaped as plain ASCII octal rather than
    emitted raw -- the escape survives the lossy ``errors="replace"`` decode
    below intact, where a raw non-UTF-8 byte would decode to an unrecoverable
    U+FFFD and the gate would classify a path nothing on disk answers to
    (issue #3076). ``diff_header_name`` already C-unquotes a quoted header, so
    this needs no consumer change. ``diff.mnemonicPrefix``/``noprefix``
    rewrite the ``a/``/``b/`` prefixes, and an external driver
    (``diff.external`` / ``GIT_EXTERNAL_DIFF``) replaces the unified output
    outright — each silently defeats a gate built on ``+++ b/<path>``, so user
    config and environment cannot bypass one through this.
    """
    # Lossy on purpose: diff text is somebody's file CONTENT, it is only matched
    # and printed, and a stray non-UTF-8 byte in it must neither raise here nor
    # reach a strict stdout as a lone surrogate and kill the report instead.
    return _run(
        [
            "git",
            "-c",
            "core.quotePath=true",
            "diff",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            *args,
        ]
    ).decode("utf-8", "replace")


def nul_listing(root: Path, *args: str) -> list[str]:
    """Real paths from a ``git ... -z`` listing run in ``root``.

    The caller supplies ``-z`` with the rest of the subcommand, so the flag sits
    where git wants it (``ls-files -z``, ``diff --name-only -z <rev>``).

    ``os.fsdecode`` because these paths get OPENED: it is the decode ``open`` and
    ``os.listdir`` themselves use, so every name round-trips byte-exactly, raw
    non-UTF-8 bytes included. A lossy decode instead hands back a U+FFFD name
    that opens nothing, and a gate classifying that name against no rule reports
    a clean pass over a file it never read (issue #3073). Hard-coding UTF-8
    would fix only the hosts where the filesystem encoding already is UTF-8 --
    under an ASCII one it turns a valid ``café.php`` into a ``str`` ``open``
    cannot encode back.
    """
    return nul_paths(os.fsdecode(_run(["git", "-C", str(root), *args])))
