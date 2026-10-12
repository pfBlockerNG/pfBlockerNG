"""Issue #3489 -- ``scripts/update-pfsense-stubs.py`` ``_RETURN_TYPE_RE`` must neither
backtrack catastrophically on hostile input nor change what it accepts.

The return-type group once carried a redundant ``(?:\\|[...]+)*`` tail (the class
already contains ``|``), so a long ``a|a|a|...`` run with no ``{`` took
exponential time. The script feeds this regex slices of fetched upstream PHP, so
the match must terminate on any input.

Hostile inputs run in a child interpreter under a generous watchdog: ``re`` holds
the GIL for the whole match, so only a separate process can be killed and reaped
when the match never returns (duration is never the assertion, only completion).
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "update-pfsense-stubs.py"

# Far above the fixed regex's microseconds, far below the exponential blow-up of
# the old one (``"a|" * 40`` would run for hours), so only a real hang trips it.
WATCHDOG_SECONDS = 20

_CHILD = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("update_pfsense_stubs", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
m = mod._RETURN_TYPE_RE.match(sys.argv[2])
print(json.dumps(None if m is None else [m.group(0), m.group(1)]))
"""


def _load_script_regex() -> re.Pattern[str]:
    spec = importlib.util.spec_from_file_location("update_pfsense_stubs", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._RETURN_TYPE_RE


def _match_in_child(text: str) -> list[str | None] | None:
    """Run ``_RETURN_TYPE_RE.match(text)`` in a killable child; return ``[group0, group1]`` or None."""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, str(SCRIPT), text],
            capture_output=True,
            text=True,
            timeout=WATCHDOG_SECONDS,
            check=True,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"STUCK: _RETURN_TYPE_RE.match did not return within {WATCHDOG_SECONDS}s for {text[:40]!r}...")
    return json.loads(proc.stdout)


@pytest.mark.parametrize(
    "text",
    [
        ": " + "|" * 30 + ";",
        ": " + "a|" * 40 + "a;",
        ": \\" * 30 + ";",
    ],
    ids=["pipes", "alternating-pipe-runs", "backslash-runs"],
)
def test_hostile_return_type_text_terminates_with_no_match(text: str) -> None:
    """A long return-type-shaped run with no opening brace is rejected, not hung on."""
    assert _match_in_child(text) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (": ?int {", [": ?int {", "?int"]),
        (": A|B&C {", [": A|B&C {", "A|B&C"]),
        (": \\Foo\\Bar[] {", [": \\Foo\\Bar[] {", "\\Foo\\Bar[]"]),
        (" {", [" {", None]),
        (": int|null{", [": int|null{", "int|null"]),
        (": array {", [": array {", "array"]),
        ("{", ["{", None]),
        (":\t  int  {", [":\t  int  {", "int"]),
        (": {", None),
        ("x {", None),
        ("", None),
    ],
    ids=[
        "nullable",
        "union-intersection",
        "namespaced-array",
        "no-type",
        "union-no-space-before-brace",
        "plain-type",
        "bare-brace",
        "tabs-and-spaces",
        "colon-without-type",
        "junk-prefix",
        "empty",
    ],
)
def test_return_type_regex_accepts_exactly_the_declared_forms(text: str, expected: list[str | None] | None) -> None:
    """Union/intersection/nullable/namespaced return types still parse to the same group(1)."""
    m = _load_script_regex().match(text)
    assert (None if m is None else [m.group(0), m.group(1)]) == expected
