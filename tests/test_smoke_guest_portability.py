"""Off-box guard: BSD-portability of the commands the smoke harness shells to the guest.

The live-VM smoke harness (``tests/smoke/**``) drives a real **FreeBSD/pfSense**
guest, issuing ``grep`` / ``sed`` / ``awk`` over SSH. Those commands must use only
POSIX regex — BSD ``grep``/``sed`` do NOT support the GNU extensions ``\\s \\d \\w
\\b`` (they match a literal letter instead), ``grep -P``, or ``sed -r``.

ShellCheck (our POSIX gate) lints shell *files*; it never sees a ``grep`` pattern
passed as a Python string argument, so guest commands in the harness are a blind
spot — exactly how a ``grep -E '^\\s*url:'`` slipped in and cost a live-VM round
trip (BSD grep read ``\\s`` as a literal ``s`` and the space-indented line never
matched). This guard catches that whole class **off-box**, in the normal pytest run.

It parses each harness module's AST and inspects the **string-literal arguments of
call expressions** (so comments and Python-side ``re`` patterns are out of scope):
a call whose string args include a ``grep``/``sed``/``awk`` token must not carry a
GNU-only regex escape or flag in any of its string args.

Scope/limit: it covers the arg-vector form (``_ssh_check(vm, "grep", "-E", pat)``)
and inline command strings/f-strings; a command assembled in a variable and passed
by name is out of reach here (the live smoke remains the backstop). New harness code
should keep guest regex POSIX (use ``[[:space:]]`` not ``\\s``, ``grep -E`` not ``-P``).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_SMOKE_DIR = Path(__file__).resolve().parent / "smoke"

# A string arg that names one of these guest utilities puts the call in scope.
_UTIL_RE = re.compile(r"\b(?:grep|sed|awk)\b")

# GNU-only regex escapes BSD grep/sed do NOT support: \s \S \d \D \w \W \b \B.
# In Python source these are written either raw (``\s``) or escaped (``\\s``); the
# parsed string value holds a single backslash + letter, which this matches.
_GNU_ESCAPE_RE = re.compile(r"\\[sSdDwWbB]")

# GNU-only flags (BSD grep has no -P/PCRE; BSD sed uses -E, not -r).
_GNU_FLAG_RE = re.compile(r"grep\s+-\w*P|grep\s+--perl-regexp|sed\s+-r\b|sed\s+--regexp-extended")


def _literal_strings(node: ast.expr) -> list[str]:
    """Every string literal directly in ``node`` (a bare str, or an f-string's text parts)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
    return []


def find_gnu_grepisms(source: str, filename: str = "<smoke>") -> list[tuple[int, str]]:
    """Return ``(lineno, offending_string)`` for each guest-command GNU-ism in ``source``.

    A call expression is in scope when any of its string-literal args contains a
    grep/sed/awk token; within such a call, any string arg carrying a GNU-only
    escape or flag is a violation.
    """
    tree = ast.parse(source, filename)
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        strings: list[tuple[int, str]] = []
        for arg in args:
            for s in _literal_strings(arg):
                strings.append((getattr(arg, "lineno", node.lineno), s))
        if not any(_UTIL_RE.search(s) for _, s in strings):
            continue
        for lineno, s in strings:
            if _GNU_ESCAPE_RE.search(s) or _GNU_FLAG_RE.search(s):
                violations.append((lineno, s))
    return violations


def _smoke_py_files() -> list[Path]:
    """Every Python module under tests/smoke/ (the harness modules to scan)."""
    return sorted(p for p in _SMOKE_DIR.rglob("*.py") if p.is_file())


def test_smoke_harness_uses_no_gnu_only_regex_in_guest_commands() -> None:
    """No grep/sed/awk command the harness sends to the FreeBSD guest uses a GNU-only regex.

    Scenario:
      Given every Python module under tests/smoke/,
      When  its call expressions' string args are scanned,
      Then  no grep/sed/awk command carries a GNU-only escape (\\s \\d \\w \\b) or
            flag (grep -P / sed -r) that BSD grep/sed would mis-handle on pfSense.
    """
    files = _smoke_py_files()
    assert files, f"no smoke modules found under {_SMOKE_DIR}"
    offenders: dict[str, list[tuple[int, str]]] = {}
    for path in files:
        hits = find_gnu_grepisms(path.read_text(), str(path))
        if hits:
            offenders[path.name] = hits
    assert not offenders, (
        "GNU-only regex in guest grep/sed/awk (BSD grep on pfSense will mis-handle it; "
        "use POSIX [[:space:]] not \\s, grep -E not -P):\n"
        + "\n".join(f"  {name}:{ln}: {s!r}" for name, hits in offenders.items() for ln, s in hits)
    )


# --------------------------------------------------------------------------- #
# Detector unit tests — prove it FLAGS the GNU forms and PASSES the POSIX ones,
# and does not false-positive on comments or Python-side re patterns.
# --------------------------------------------------------------------------- #


def test_detector_flags_gnu_backslash_s_in_grep_arg() -> None:
    """A guest grep arg carrying the GNU-only \\s escape is flagged."""
    src = '_ssh_check(vm, "grep", "-E", r"^\\s*url:", conf_path)\n'
    hits = find_gnu_grepisms(src)
    assert len(hits) == 1, hits
    assert "\\s" in hits[0][1]


def test_detector_passes_posix_space_class() -> None:
    """The POSIX [[:space:]] form (the fix) is accepted, not flagged."""
    src = '_ssh_check(vm, "grep", "-E", r"^[[:space:]]*url:", conf_path)\n'
    assert find_gnu_grepisms(src) == []


def test_detector_flags_gnu_flags() -> None:
    """GNU-only flags — grep -P and sed -r — are flagged."""
    assert find_gnu_grepisms("vm.ssh(\"grep -P '\\\\d+' /tmp/x\")\n")  # grep -P
    assert find_gnu_grepisms("vm.ssh(\"sed -r 's/a+/b/' /tmp/x\")\n")  # sed -r


def test_detector_ignores_python_side_re_without_a_guest_util() -> None:
    """A Python re pattern with \\s but no grep/sed/awk token is not a guest command — not flagged."""
    src = 'match = re.search(r\'url:\\s*"([^"]+)"\', raw)\n'
    assert find_gnu_grepisms(src) == []


def test_detector_ignores_comments_mentioning_backslash_s() -> None:
    """A comment mentioning \\s near a grep call is not flagged (comments are not AST strings)."""
    src = '# POSIX [[:space:]] not \\s for BSD grep\n_ssh_check(vm, "grep", "-E", r"^[[:space:]]*x", p)\n'
    assert find_gnu_grepisms(src) == []
