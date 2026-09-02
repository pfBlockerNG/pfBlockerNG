#!/usr/bin/env python3
"""Forbid retiring a named-invariant test with nothing left in its place.

A test that asserts a named invariant is the only mechanical memory of it. When
one is deleted or renamed and the change ships neither a successor assertion nor
a record of the decision, the invariant is silently unguarded: `--init` was
pinned repo-wide, its guard retired the next day, the successor never carried
the assertion, and the fleet path lost its reaper with every gate green.

A retirement in the diff must therefore be matched by ONE of:

* the same declaration name added anywhere under ``tests/`` (an edit, a
  signature change, or a move — not a retirement);
* an added line under ``tests/`` carrying ``successor: <retired name>``, which
  rides the assertion that took the invariant over;
* a dated entry in ``docs/history/retired-tests.md``:
  ``| YYYY-MM-DD | `<retired name>` | <reason> |``.

Declaration forms: Python ``def test_*``, PHPUnit ``function test*``, shellspec
``It``/``Example`` (its quoted description is the name).

DIFF-SCOPED: only the diff's removed declarations are judged (``--staged`` for
the pre-commit hook, ``--diff <base>`` for CI's PR gate), so a full-tree scan
never runs and an untouched test is never re-litigated. A test whose body
changes keeps its declaration line and stays neutral.

Exit status: 0 = clean, 1 = violations (printed file:line), 2 = usage/git error.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import PurePosixPath
from typing import NamedTuple

from _git_paths import diff_header_name, unified_diff

TOMBSTONE = "docs/history/retired-tests.md"

# One declaration form per in-scope file type; a helper or a `Describe` group
# carries no assertion and is not a named invariant.
_DECLS: dict[str, re.Pattern[str]] = {
    ".py": re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>test_\w+)\s*\("),
    ".php": re.compile(r"\bfunction\s+(?P<name>test\w+)\s*\("),
    ".sh": re.compile(r"^\s*(?:It|Example)\s+(?P<q>[\"'])(?P<name>.+?)(?P=q)"),
}

# Marker and ledger row. The tail is matched for the retired name on identifier
# boundaries, so `successor: test_foo_bar` cannot excuse retiring `test_foo`.
_SUCCESSOR = re.compile(r"(?<![\w-])successor:[^\S\r\n]*(?P<tail>\S.*)")
_ROW = re.compile(r"^\|(?P<cells>.*\|)\s*$")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
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


def _in_scope(path: str | None) -> bool:
    if path is None or path in _EXCLUDED_PATHS:
        return False
    p = PurePosixPath(path)
    return bool(p.parts) and p.parts[0] == "tests" and p.suffix in _DECLS


def _declared(path: str | None, line: str) -> str | None:
    """The test name this line declares, or ``None``."""
    if not _in_scope(path):
        return None
    assert path is not None
    match = _DECLS[PurePosixPath(path).suffix].search(line)
    return match.group("name") if match else None


def _names(cells: list[str]) -> list[str]:
    return [cell.strip().strip("`").strip() for cell in cells]


def tombstone_entry(line: str) -> tuple[str, str, str] | None:
    """``(date, name, reason)`` for a well-formed ledger row, else ``None``."""
    row = _ROW.match(line)
    if row is None:
        return None
    cells = _names(row.group("cells").split("|")[:-1])
    if len(cells) < 3 or not all(cells[:3]):
        return None
    date, name, reason = cells[0], cells[1], cells[2]
    return (date, name, reason) if _DATE.fullmatch(date) else None


def _is_ledger_entry_row(line: str) -> bool:
    """True for a row meant to BE an entry — not the header or its delimiter."""
    row = _ROW.match(line)
    if row is None:
        return False
    cells = _names(row.group("cells").split("|")[:-1])
    if len(cells) < 3:
        return False
    if tuple(cell.lower() for cell in cells[:3]) == _HEADER:
        return False
    return not all(_DELIMITER.fullmatch(cell) for cell in cells if cell)


def _succeeds(tail: str, name: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", tail) is not None


def find_violations(diff_text: str) -> list[Violation]:
    """Judge one unified diff's REMOVED test declarations."""
    retired: list[tuple[str, int, str]] = []
    redeclared: set[str] = set()
    successors: list[str] = []
    tombstoned: set[str] = set()
    violations: list[Violation] = []
    old_path: str | None = None
    new_path: str | None = None
    old_no = new_no = 0
    in_hunk = False

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
            name = _declared(old_path, raw[1:])
            if name is not None and old_path is not None:
                retired.append((old_path, old_no, name))
            old_no += 1
            continue
        if raw.startswith("+"):
            line = raw[1:]
            name = _declared(new_path, line)
            if name is not None:
                redeclared.add(name)
            if _in_scope(new_path):
                marker = _SUCCESSOR.search(line)
                if marker is not None:
                    successors.append(marker.group("tail"))
            if new_path == TOMBSTONE:
                entry = tombstone_entry(line)
                if entry is not None:
                    tombstoned.add(entry[1])
                elif _is_ledger_entry_row(line):
                    violations.append(Violation(TOMBSTONE, new_no, "", f"malformed retirement entry: {line.strip()}"))
            new_no += 1
            continue
        old_no += 1
        new_no += 1

    for path, line_no, name in retired:
        if name in redeclared or name in tombstoned:
            continue
        if any(_succeeds(tail, name) for tail in successors):
            continue
        violations.append(Violation(path, line_no, name, UNEXCUSED))
    return violations


def main(argv: list[str]) -> int:
    try:
        if argv == ["--staged"]:
            diff = unified_diff(["--cached"])
        elif len(argv) == 2 and argv[0] == "--diff":
            diff = unified_diff([f"{argv[1]}...HEAD"])
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
        "or a tombstone. Either add the assertion that takes it over and mark it\n"
        "`successor: <retired name>`, or record the decision in\n"
        f"{TOMBSTONE} as a row: | YYYY-MM-DD | `<retired name>` | <reason> |",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
