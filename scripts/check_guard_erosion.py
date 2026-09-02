#!/usr/bin/env python3
"""Forbid retiring a named-invariant test with nothing left in its place.

A test that asserts a named invariant is the only mechanical memory of it. When
one is deleted or renamed and the change ships neither a successor assertion nor
a record of the decision, the invariant is silently unguarded: `--init` was
pinned repo-wide, its guard retired the next day, the successor never carried
the assertion, and the fleet path lost its reaper with every gate green.

A retirement in the diff must therefore be matched by ONE of:

* the same declaration name added in a file the same runner collects (an edit, a
  signature change, or a move);
* an added comment in a collected test file reading ``successor: <retired
  name>`` -- the marker rides the assertion that took the invariant over;
* a dated entry in ``docs/history/retired-tests.md``:
  ``| YYYY-MM-DD | `<retired name>` | <reason> |``.

Declaration forms and the file names each runner actually collects:

| Type | Declaration | Collected |
| ---- | ----------- | --------- |
| `.py` | `def test_*` (`async` too) | `test_*.py`, `*_test.py` (pytest) |
| `.php` | `function test*` | `*Test.php` (PHPUnit) |
| `.sh` | shellspec `It`/`Example` (quoted description = name) | `*_spec.sh`, `*_env.sh` |
| `.js`/`.mjs` | `test(...)`/`it(...)` | `*.test.js`, `*.test.mjs` (node --test) |

The collected column is load-bearing on BOTH sides, and a redeclaration must
match in the same language. A declaration in a file no runner collects never
asserted anything: flagging its removal would be a false positive, and honouring
it as an excuse would let a retirement be waved through by dead code -- the same
name dropped into a module nothing ever imports.

DIFF-SCOPED: only the diff's removed declarations are judged (``--staged`` for
the pre-commit hook, ``--diff <base>`` for CI's PR gate), so a full-tree scan
never runs and an untouched test is never re-litigated. A test whose body
changes keeps its declaration line and stays neutral. ``--no-renames`` is
mandatory here: with git's default rename detection a pure ``git mv`` out of a
collected name emits no hunks at all, and the retirement is invisible.

Known blind spots, all deliberate: this file's own test module is excluded (its
fixtures are declaration-shaped by construction); a single-line regex cannot see
string context, so a declaration-shaped line inside a docstring reads as a
declaration; and the scan root is ``tests/`` alone, which leaves the node tests
under ``tools/webassets/`` uncovered. The tombstone is the escape hatch for the
first two.

Exit status: 0 = clean, 1 = violations (printed file:line), 2 = usage/git error.
"""

from __future__ import annotations

import re
import subprocess
import sys
from datetime import date
from pathlib import PurePosixPath
from typing import NamedTuple

from _git_paths import diff_header_name, unified_diff

TOMBSTONE = "docs/history/retired-tests.md"

# A helper, a `Describe` group, and a commented-out declaration carry no
# assertion, so every pattern anchors at line start modulo indentation.
_JS_DECL = re.compile(r"^\s*(?:test|it)\s*\(\s*(?P<q>[\"'`])(?P<name>.+?)(?P=q)")
_JS_COLLECTED = re.compile(r".+\.test\.m?js", re.DOTALL)


class _Lang(NamedTuple):
    decl: re.Pattern[str]
    collected: re.Pattern[str]


# A file name may hold any byte git can quote, a newline included, so the
# collected patterns are DOTALL: `.` must not stop at one (issue #2212's class).
_LANGS: dict[str, _Lang] = {
    ".py": _Lang(
        re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>test_\w+)\s*\("),
        re.compile(r"test_.+\.py|.+_test\.py", re.DOTALL),
    ),
    ".php": _Lang(
        re.compile(r"^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+(?P<name>test\w+)\s*\("),
        re.compile(r".+Test\.php", re.DOTALL),
    ),
    ".sh": _Lang(
        re.compile(r"^\s*(?:It|Example)\s+(?P<q>[\"'])(?P<name>.+?)(?P=q)"),
        # `_spec.sh` is shellspec's default glob. `_env.sh` is the one file a
        # workflow selects by hand -- build-pkg-linux.yml passes
        # `--pattern tests/shell/build_leg_ports_parity_env.sh --fail-no-examples`,
        # and that spec says in its own header that it avoids the default glob.
        re.compile(r".+_spec\.sh|.+_env\.sh", re.DOTALL),
    ),
    ".js": _Lang(_JS_DECL, _JS_COLLECTED),
    ".mjs": _Lang(_JS_DECL, _JS_COLLECTED),
}

# The marker is a comment naming exactly one retired test. Requiring equality
# rather than a substring keeps `successor: reaps every orphan` from excusing a
# shellspec example merely called `reaps`.
_SUCCESSOR = re.compile(r"(?:#|//|/\*|\*)\s*successor:\s*(?P<name>.+?)\s*(?:\*/)?$")
# One symmetric wrapping layer only: a shellspec description may itself end in a
# quote, and str.strip would eat a character that belongs to the name.
_WRAPPED = re.compile(r"([`'\"])(.*)\1", re.DOTALL)
_ROW = re.compile(r"^\|(?P<cells>.*\|)\s*$")
# The ledger has no legitimate use for a fenced block, and honouring one means
# tracking fence state across lines the diff never shows.
_FENCE = re.compile(r"^\s*(?:```|~~~)")
_ISO_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_DELIMITER = re.compile(r":?-{3,}:?")
_HEADER = ("date", "retired test", "reason")

_HUNK = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)")

# Self-reference: this file's fixtures are declaration-shaped by construction.
_EXCLUDED_PATHS = ("tests/test_guard_erosion_check.py",)

UNEXCUSED = "no successor assertion and no dated retirement entry"


class Violation(NamedTuple):
    path: str
    line: int
    name: str
    reason: str


def _side(field: str, prefix: str) -> str | None:
    """Repository-relative path from one ``---``/``+++`` header, else ``None``."""
    name = diff_header_name(field)
    return name[len(prefix) :] if name.startswith(prefix) else None


def _lang(path: str | None) -> _Lang | None:
    """The language of a test file its runner collects, else ``None``."""
    if path is None or path in _EXCLUDED_PATHS:
        return None
    p = PurePosixPath(path)
    if not p.parts or p.parts[0] != "tests":
        return None
    lang = _LANGS.get(p.suffix)
    if lang is None or not lang.collected.fullmatch(p.name):
        return None
    return lang


def _declared(path: str | None, line: str) -> tuple[str, str] | None:
    """``(suffix, name)`` this line declares in a collected test file, else ``None``."""
    lang = _lang(path)
    if lang is None:
        return None
    assert path is not None
    match = lang.decl.search(line)
    return (PurePosixPath(path).suffix, match.group("name")) if match else None


def _unwrap(value: str) -> str:
    wrapped = _WRAPPED.fullmatch(value)
    return wrapped.group(2) if wrapped else value


def _cells(line: str) -> list[str] | None:
    row = _ROW.match(line)
    if row is None:
        return None
    return [_unwrap(cell.strip()).strip() for cell in row.group("cells").split("|")[:-1]]


def tombstone_entry(line: str) -> str | None:
    """The retired name a well-formed ledger row records, else ``None``."""
    cells = _cells(line)
    if cells is None or len(cells) < 3 or not all(cells[:3]):
        return None
    # Shape first, then reality: `date.fromisoformat` also takes `20260902` and
    # `2026-W36-1`, and every text describing this ledger says `YYYY-MM-DD`.
    if not _ISO_DAY.fullmatch(cells[0]):
        return None
    try:
        date.fromisoformat(cells[0])
    except ValueError:
        return None
    return cells[1]


def _is_ledger_entry_row(line: str) -> bool:
    """True for a row meant to BE an entry -- not the header or its delimiter."""
    cells = _cells(line)
    if cells is None or len(cells) < 3:
        return False
    if tuple(cell.lower() for cell in cells[:3]) == _HEADER:
        return False
    return not all(_DELIMITER.fullmatch(cell) for cell in cells if cell)


def _marked_successor(line: str) -> str | None:
    marker = _SUCCESSOR.search(line)
    return _unwrap(marker.group("name").strip()).strip() if marker else None


def find_violations(diff_text: str) -> list[Violation]:
    """Judge one unified diff's REMOVED test declarations."""
    retired: list[tuple[str, int, str, str]] = []
    redeclared: set[tuple[str, str]] = set()
    successors: set[str] = set()
    tombstoned: set[str] = set()
    violations: list[Violation] = []
    old_path: str | None = None
    new_path: str | None = None
    old_no = new_no = 0
    in_hunk = False
    ledger_fenced = False

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git"):
            old_path = new_path = None
            in_hunk = False
            continue
        # Header only before a section's first @@ -- inside a hunk a "---"/"+++"
        # line is removed/added content and must be judged, not parsed.
        if not in_hunk and raw.startswith("--- "):
            old_path = _side(raw[4:], "a/")
            continue
        if not in_hunk and raw.startswith("+++ "):
            new_path = _side(raw[4:], "b/")
            continue
        if raw.startswith("@@"):
            hunk = _HUNK.match(raw)
            old_no, new_no = (int(hunk.group(1)), int(hunk.group(2))) if hunk else (0, 0)
            in_hunk = True
            continue
        if not in_hunk or raw.startswith("\\"):
            # "\ No newline at end of file" is a marker, not content.
            continue
        if raw.startswith("-"):
            declared = _declared(old_path, raw[1:])
            if declared is not None:
                assert old_path is not None
                retired.append((old_path, old_no, *declared))
            old_no += 1
            continue
        if raw.startswith("+"):
            line = raw[1:]
            declared = _declared(new_path, line)
            if declared is not None:
                redeclared.add(declared)
            marker = _marked_successor(line) if _lang(new_path) is not None else None
            if marker is not None:
                successors.add(marker)
            if new_path == TOMBSTONE:
                if _FENCE.match(line):
                    # Honouring a fenced example would mean carrying fence state
                    # across context lines `--unified=0` never shows, so a row
                    # added inside a fence an earlier change planted would count.
                    # A fenced ledger is therefore rejected outright, and no row
                    # in this diff is trusted -- it costs the ledger nothing.
                    ledger_fenced = True
                    violations.append(Violation(TOMBSTONE, new_no, "", f"fenced block in the ledger: {line.strip()}"))
                else:
                    entry = tombstone_entry(line)
                    if entry is not None:
                        tombstoned.add(entry)
                    elif _is_ledger_entry_row(line):
                        violations.append(
                            Violation(TOMBSTONE, new_no, "", f"malformed retirement entry: {line.strip()}")
                        )
            new_no += 1
            continue
        old_no += 1
        new_no += 1
    if ledger_fenced:
        tombstoned.clear()

    for path, line_no, suffix, name in retired:
        if (suffix, name) in redeclared or name in successors or name in tombstoned:
            continue
        violations.append(Violation(path, line_no, name, UNEXCUSED))
    return violations


def main(argv: list[str]) -> int:
    try:
        if argv == ["--staged"]:
            diff = unified_diff(["--no-renames", "--cached"])
        elif len(argv) == 2 and argv[0] == "--diff":
            diff = unified_diff(["--no-renames", f"{argv[1]}...HEAD"])
        else:
            print("usage: check_guard_erosion.py --staged | --diff <base>", file=sys.stderr)
            return 2
    except subprocess.CalledProcessError as exc:
        print(f"git diff failed: {exc.stderr.strip()}", file=sys.stderr)
        return 2
    violations = find_violations(diff)
    if not violations:
        return 0
    print("Retired test(s) with nothing left in their place:\n", file=sys.stderr)
    for v in violations:
        subject = v.name or "entry"
        print(f"  {v.path}:{v.line}: {subject}: {v.reason}", file=sys.stderr)
    print(
        "\nRetiring or renaming a test that asserts a named invariant needs a successor\n"
        "or a tombstone. Either add the assertion that takes it over -- in a file its\n"
        "runner collects -- and comment it `successor: <retired name>`, or record the\n"
        f"decision in {TOMBSTONE} as a row: | YYYY-MM-DD | `<retired name>` | <reason> |",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
