"""Real paths out of git's C-quoted output.

git wraps a path in double quotes and C-escapes it whenever the path holds a
double quote, a backslash or a control byte. That quoting is unconditional:
``core.quotePath`` only governs whether HIGH-BIT bytes are escaped too. Every
changed-file gate in this repo classifies a path by prefix or suffix, so a
quoted path matches no rule and its file skips the gate while the job still
reports a clean pass (issue #2212).

``git ... -z`` emits raw NUL-separated paths and is the fix wherever it exists
(``--name-only``, ``ls-files``). A unified diff's ``---``/``+++`` header has no
``-z`` form, so those parsers decode the header here instead.
"""

from __future__ import annotations

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
    """Decode one C-quoted git path field; an unquoted field is returned as-is."""
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
            out.append(int(raw[i + 1 : i + 4], 8) & 0xFF)
            i += 4
        else:
            out.append(raw[i + 1])
            i += 2
    return out.decode("utf-8", "surrogateescape")


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
