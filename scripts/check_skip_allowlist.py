#!/usr/bin/env python3
"""Fail CI when a suite's JUnit report skips a test that is not allowlisted (issue #2359).

PROBLEM
-------
A test that no environment executes still counts toward the suite total and still
reports "OK" — #2356 found nine PHPUnit cases that had silently skipped in CI for
a year, and the only signal was the wording of a summary line
("OK, but some tests were skipped!"), which gates nothing. Nothing failed when
the skip SET grew, so the next silently-skipped test would be found the same
way: by someone reading a skip list on purpose.

This script is that gate, wired wherever a blocking suite writes JUnit: it parses
the report, collects every skipped ``<testcase>``, and fails when any of them is
not on ``tests/skip-allowlist.txt`` — one file shared by all suites, since each id
is suite-prefixed.

ID FORMAT
---------
``<suite>:<classname>::<name>``, built from each ``<testcase>``'s ``classname``
and ``name`` attributes verbatim (no normalisation beyond what the XML parser
already does — entity-decoding, character references) — so an allowlist line
matches a report id byte-for-byte, never fuzzily.

EXIT STATUS
-----------
* ``0`` — every observed skip is allowlisted (an allowlisted id this run did
  NOT observe is reported as an informational line, never a failure — the skip
  set legitimately differs per matrix leg, e.g. a PHP-build-gated case skips on
  one PHP version and not the other, and per invoking uid).
* ``1`` — one or more observed skips are not on the allowlist; each is printed
  with its skip reason (the ``<skipped message="...">`` attribute, or the
  element's text content, when the report carries one).
* ``2`` — the report is missing, empty, or not well-formed XML; the allowlist
  file is missing; or an allowlist entry has no trailing ``# <reason>``. A gate
  that passes because its input vanished is the exact failure this issue exists
  to remove, so none of these ever fall through to 0.

No protection against an XML entity-expansion bomb is implemented beyond
stdlib ``xml.etree.ElementTree`` defaults — these reports are produced by this
repo's own pinned toolchain, not by an untrusted party.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# shellspec 0.28.1's own JUnit writer embeds a raw XML-1.0-illegal control byte
# verbatim when a spec description carries one (tests/shell/agent_run_gates_git_spec.sh's
# C-quoted-path fixtures use a literal 0x01 byte, by design) -- such a byte has no legal
# XML representation, so a strict parse of shellspec's REAL report always raises. Replace
# it before parsing; a genuinely truncated/malformed report still fails below.
_XML_ILLEGAL_CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# An allowlist line is "<id>  # <reason>": the separator is TWO OR MORE spaces before the
# '#'. The suites own the id and put every kind of '#' in it -- a pytest parametrised id
# renders its parameter verbatim (test_x[a#b], and even test_x[see # this]), and PHPUnit
# names an unnamed data-set case `testFoo with data set #0`. Splitting on any single '#',
# spaced or not, truncates one of those into an id no run produces, and the skip it names
# could then never be recorded. Two spaces is what every entry in the file already uses.
# The id group is GREEDY, so the split takes the RIGHTMOST separator: a parameter value can
# contain the separator shape itself, and the id is the suite's to generate while the reason
# is ours to write.
_ENTRY = re.compile(r"^(?P<id>\S.*)\s{2,}#\s*(?P<reason>\S.*)$")


# pytest and PHPUnit write <skipped>; shellspec 0.28.1 writes <skip> (probed against its
# own generator). Reading only one of them makes the gate blind for the other suite —
# a clean verdict on a report that recorded skips, which is the failure this gate exists
# to catch.
_SKIP_ELEMENTS = frozenset({"skipped", "skip"})
_NODE_SUITES = frozenset({"widget-js", "webassets-grammar", "webassets-listgrammar", "webassets-bundle"})


class ReportError(Exception):
    """The JUnit report is missing, empty, or not well-formed XML."""


class AllowlistError(Exception):
    """The allowlist file is missing, or an entry has no trailing '# reason'."""


def sanitize_xml_bytes(data: bytes) -> bytes:
    return _XML_ILLEGAL_CONTROL.sub(b"?", data)


def testcase_id(suite: str, testcase: ET.Element) -> str:
    return f"{suite}:{testcase.get('classname', '')}::{testcase.get('name', '')}"


def skip_reason(skipped: ET.Element) -> str | None:
    message = skipped.get("message")
    if message:
        return message
    text = (skipped.text or "").strip()
    return text or None


def parse_report(path: Path, suite: str) -> list[tuple[str, str | None]]:
    """Return ``(id, reason)`` for every skipped <testcase> in the report."""
    if not path.is_file():
        raise ReportError(f"report file not found: {path}")
    data = path.read_bytes()
    if not data.strip():
        raise ReportError(f"report file is empty: {path}")
    try:
        root = ET.fromstring(sanitize_xml_bytes(data))
    except ET.ParseError as exc:
        raise ReportError(f"report file is not well-formed XML: {path}: {exc}") from exc
    skips: list[tuple[str, str | None]] = []
    seen: set[str] | None = set() if suite in _NODE_SUITES else None
    for testcase in root.iter("testcase"):
        test_id = testcase_id(suite, testcase)
        if seen is not None:
            if test_id in seen:
                raise ReportError(f"report contains duplicate testcase id: {test_id}")
            seen.add(test_id)
        for child in testcase:
            if child.tag in _SKIP_ELEMENTS:
                skips.append((test_id, skip_reason(child)))
                break
    return skips


def parse_allowlist(path: Path) -> dict[str, str]:
    """Return ``{id: reason}``. Every non-comment, non-blank line MUST carry a
    trailing '# <reason>' -- an entry without one is a parse error, so the file
    cannot rot into a bare id list with no record of WHY a test skips."""
    if not path.is_file():
        raise AllowlistError(f"allowlist file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise AllowlistError(f"allowlist file is not valid UTF-8: {path}: {exc}") from exc
    reasons: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entry = _ENTRY.match(line)
        if entry is None:
            raise AllowlistError(f"{path}:{lineno}: allowlist entry needs a reason after two spaces and a '#': {raw!r}")
        reasons[entry.group("id")] = entry.group("reason").strip()
    return reasons


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--suite",
        required=True,
        choices=(
            "pytest",
            "phpunit",
            "shellspec",
            "widget-js",
            "webassets-grammar",
            "webassets-listgrammar",
            "webassets-bundle",
            "ports-parity",
            "ui",
            "smoke",
        ),
    )
    parser.add_argument("--allowlist", required=True, type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)

    try:
        allowlist = parse_allowlist(args.allowlist)
    except AllowlistError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        skips = parse_report(args.report, args.suite)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    observed = {skip_id for skip_id, _ in skips}
    suite_prefix = f"{args.suite}:"
    for entry_id in sorted(allowlist):
        if entry_id.startswith(suite_prefix) and entry_id not in observed:
            print(f"info: allowlisted skip not observed this run: {entry_id}")

    unlisted = [(skip_id, reason) for skip_id, reason in skips if skip_id not in allowlist]
    if not unlisted:
        return 0

    print(f"error: {len(unlisted)} skip(s) not on {args.allowlist}:", file=sys.stderr)
    for skip_id, reason in unlisted:
        print(f"  {skip_id}  reason: {reason or '(no reason given)'}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
