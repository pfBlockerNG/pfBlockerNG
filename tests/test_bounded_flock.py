"""Regression pin (issue #1780): every blocking flock() acquire in src/ is bounded.

The owner's premise for deferring log maintenance across a running update pass is
"an update pass cannot hang forever, since every wait is capped." An audit found
five flock() acquires that violated that premise -- plain blocking LOCK_EX/LOCK_SH
calls with no LOCK_NB and no deadline, so a wedged holder (a crashed writer that
never released, a stuck NFS mount, ...) hung the caller forever. All five were
rewritten to go through the shared bounded helper (pfb_flock_bounded() in
pfblockerng_extra.inc), which ORs in LOCK_NB itself and polls against a wall-clock
deadline.

This module scans the SHIPPED source tree (scan roots: every ``*.inc``/``*.php``
file under ``src/`` -- that is the whole `src/usr/local/pkg/pfblockerng/` package
plus the `src/usr/local/www/` Web UI; nothing under `tests/`, `stubs/`, or
`.agents/` is in scope) and fails if it finds a `flock()` call whose argument list
contains neither `LOCK_NB` (a bounded, non-blocking attempt -- how every acquire
must be spelled from now on) nor `LOCK_UN` (a release, which never blocks and so
needs no bound). A call written as plain `flock($fp, LOCK_EX)` /
`flock($fp, LOCK_SH)` -- the exact shape of all five pre-#1780 defects -- trips it;
`flock($fp, LOCK_EX | LOCK_NB, $would_block)` and `flock($fp, LOCK_UN)` do not.

The scan is intentionally low-false-positive: it only inspects the literal text
inside a `flock(...)` call's parentheses on the line where the call starts (every
call in this codebase is single-line, no call nests parentheses in its argument
list), so it needs no PHP parser. It is comment-BLIND, not comment-aware: it does
not parse `//`/`#`/`/* */` at all, so a comment line containing a literal
`flock($var, LOCK_EX)`-shaped example (a `$`-prefixed first argument, no
LOCK_NB/LOCK_UN) would match exactly like real code -- the false-positive floor
comes solely from requiring that `$`-prefixed first argument, which rules out an
argument-less prose mention like "...deadline check and flock()." (no `$` inside
the parens at all), not from any code/comment distinction.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCAN_ROOT = _REPO_ROOT / "src"
_SCAN_SUFFIXES = {".inc", ".php"}

# Captures the raw argument list of one flock(...) call. Requiring the first
# argument to start with "$" (every real call passes a resource variable) is
# what keeps this low-false-positive: it skips prose mentions of "flock()"
# in comments (e.g. "...deadline check and flock()."), which have no argument
# at all. Every real call in this codebase is single-line with no nested
# parentheses in its arguments, so a non-nesting character class is sufficient
# -- no PHP parser needed.
_FLOCK_CALL_RE = re.compile(r"flock\s*\(\s*(\$[^()]*)\)")


def find_unbounded_flock_calls(text: str) -> list[tuple[int, str]]:
    """Return (1-based line_no, stripped line) for every unbounded flock() call.

    A call is UNBOUNDED iff its argument list contains neither ``LOCK_NB``
    (bounded, non-blocking attempt) nor ``LOCK_UN`` (release -- never blocks).
    """
    violations: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in _FLOCK_CALL_RE.finditer(line):
            args = match.group(1)
            if "LOCK_NB" in args or "LOCK_UN" in args:
                continue
            violations.append((line_no, line.strip()))
    return violations


def _scanned_files() -> list[Path]:
    return sorted(path for path in _SCAN_ROOT.rglob("*") if path.is_file() and path.suffix in _SCAN_SUFFIXES)


def test_real_source_tree_has_no_unbounded_flock_calls() -> None:
    scanned = _scanned_files()

    # issue #1780 F8: a tree relocation (src/ renamed, .inc/.php files moved out from
    # under _SCAN_ROOT) would silently shrink the scan to an empty list -- offenders
    # would then vacuously stay [] and this pin would "pass" while checking nothing.
    # Guard the scan itself, not just its output.
    assert len(scanned) > 0, (
        f"expected at least one .inc/.php file under {_SCAN_ROOT} -- got zero; "
        "the scan root or suffix filter has rotted (issue #1780 F8), or src/ moved"
    )

    offenders: list[str] = []
    for path in scanned:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in find_unbounded_flock_calls(text):
            offenders.append(f"{path.relative_to(_REPO_ROOT)}:{line_no}: {line}")

    assert offenders == [], (
        "found flock() acquire(s) with no LOCK_NB and no LOCK_UN release -- every "
        "blocking acquire must go through the bounded helper (issue #1780):\n" + "\n".join(offenders)
    )


def test_scanner_flags_synthetic_unbounded_lock_ex(tmp_path: Path) -> None:
    """Self-check: the scanner can actually fail, not just always pass."""
    synthetic = tmp_path / "synthetic.inc"
    synthetic.write_text("<?php\nflock($fp, LOCK_EX);\n")

    violations = find_unbounded_flock_calls(synthetic.read_text())

    assert len(violations) == 1
    line_no, line = violations[0]
    assert line_no == 2
    assert "flock($fp, LOCK_EX);" == line


def test_scanner_does_not_flag_bounded_synthetic_call() -> None:
    """Discrimination check: the nearest CLEAN sibling of the flagged call above
    must not be flagged -- proving the scanner tells bounded and unbounded apart
    rather than flagging every flock() call unconditionally."""
    text = "<?php\n@flock($fp, LOCK_EX | LOCK_NB, $would_block);\n"

    assert find_unbounded_flock_calls(text) == []


def test_scanner_does_not_flag_lock_un_release() -> None:
    """A release never blocks, so it needs no bound and must not be flagged."""
    text = "<?php\n@flock($lock, LOCK_UN);\n"

    assert find_unbounded_flock_calls(text) == []
