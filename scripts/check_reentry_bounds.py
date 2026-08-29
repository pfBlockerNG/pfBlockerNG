#!/usr/bin/env python3
"""Forbid a new UNBOUNDED nested `pfblockerng.php` re-entry.

PROBLEM
-------
Production code under `src/` re-enters `pfblockerng.php` to run a whole download or
transform pass (`al`, `bls`, `dc`, the extras jobs, `asn`, `asn_shell`, `bu`,
`dnsbl-control`). When such a child is spawned SYNCHRONOUSLY and unbounded, a stalled
fetch inside it holds the OUTER update pass -- and `pfblockerng_tick()`'s
log-maintenance gate -- open forever (issue #2016). Issue #2016 moved every one of those
eight sites onto ONE bounded spawn seam per language: `pfb_reentry_exec()` in PHP and
`pfb_reentry()` in shell, both of which run the child under `timeout(1)` in default
(reaper) mode and surface a named 124 failure. Without a mechanical gate that sweep is a
one-off: the next caller writes its own `exec("{$pfb['php']} .../pfblockerng.php ...")`
and the bound is gone again.

HEURISTIC (token pairing per physical line, deliberately not a PHP/sh parser)
----------------------------------------------------------------------------
A line is a RE-ENTRY COMPOSITION when it carries at least one INTERPRETER token AND at
least one TARGET token -- i.e. it names both halves of a `php <script>` command:

  interpreter: `/usr/local/bin/php`, `$pathphp` / `${pathphp}`,
               `$pfb['php']` / `{$pfb['php']}` (either quote style)
  target:      `pfblockerng.php`, `$pathpfbphp` / `${pathpfbphp}`

Both variable tokens carry a token-END guard, so `$pathpfbphpx` is a DIFFERENT variable
and matches nothing. A line carrying only one half (the `pathpfbphp=` assignment, the
`PFB_REENTRY_SCRIPT` define, `pfb_reentry_cmd()`'s escapeshellarg builder, an
`install_cron_job('pfblockerng.php ...')` needle) is not a composition and needs no
exemption -- which is also why none of them is allowlisted: an entry there would be dead
config that silently exempted a future line inlining the literal target path into it.

A composition is CLEAN when it is BACKGROUNDED -- it cannot hold the pass open:

  * `mwexec_bg(` or `/usr/sbin/daemon -p` on the line itself, or
  * a trailing ` &` inside the command string (`... 2>&1 &");`), or
  * `mwexec_bg(` / `daemon -p` on one of the TWO preceding physical lines -- the
    multi-line `pfblockerng_update.php` dispatch shape. Exactly two: a marker further up
    belongs to a different statement and must not exempt an unrelated composition.

A COMMENTED-OUT composition still flags. A comment is not an exemption -- it is a
copy-paste source for the next unbounded caller, and treating `//` as a silencer would
let any violation be laundered through one. The allowlist is the only exemption.

ALLOWLIST
---------
`_ALLOWLIST` below holds exactly seven entries, each carrying a one-line justification:
the bounded shell seam itself plus the six crontab COMMAND STRINGS (arguments to
`install_cron_job()` / `pfblockerng_cron_exists()`, never executed by the composing
process). Each entry is keyed on `(file basename, needle)` and exempts only the line
carrying its needle, never the whole file. Needles are matched against the line with
runs of spaces/tabs collapsed, so reformatting cannot silently widen or void one. If the
tree flags something new, that is a real finding: route it through the seam rather than
adding an eighth entry.

CLI
---
    check_reentry_bounds.py [PATH ...]
    check_reentry_bounds.py --self-test

With no PATH, scans every tracked file under `src/` ending `.php`/`.inc`/`.sh`. Prints
`path:line: <message>` to stderr. Exit 0 clean, 1 on violations, 2 when the argless
default scan set could not be enumerated (git absent / not a checkout) -- failing closed
rather than reporting clean on a gate it could not run.

`--self-test` is the red canary the testing policy requires for a blocking gate: it
feeds one synthetic violating line and one synthetic backgrounded line through the same
matcher and exits 0 only when the first flags and the second does not. It does not touch
the repository.

This is dev-only tooling (release archives contain only `src/`); it lives under
`scripts/` and is wired into `.githooks/pre-commit`, `.github/workflows/test.yml` and
`scripts/agent/run-gates.sh`.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

SRC_DIR = "src"
_SCAN_SUFFIXES = (".php", ".inc", ".sh")

# The interpreter half of a `php <script>` command. `(?![\w])` is a token-END guard
# rather than `\b` so a longer variable name (`$pathphpx`) is not this token.
_INTERPRETER_RES = (
    re.compile(r"/usr/local/bin/php"),
    re.compile(r"\$\{?pathphp(?![\w])"),
    re.compile(r"\$pfb\[\s*(['\"])php\1\s*\]"),
)

# The target half. Same token-END guard: `$pathpfbphpx` is a different variable.
_TARGET_RES = (
    re.compile(r"pfblockerng\.php"),
    re.compile(r"\$\{?pathpfbphp(?![\w])"),
    re.compile(r"PFB_REENTRY_SCRIPT(?![\w])"),
)

# Backgrounding markers on the line, or within the two-line lookback window.
_BG_MARKERS = ("mwexec_bg(", "/usr/sbin/daemon -p")
_BG_LOOKBACK_LINES = 2

# A trailing ` &` inside the command string: `... >> {$log} 2>&1 &");`. The leading
# whitespace requirement is what keeps `2>&1` (an fd dup, not a background) out.
_TRAILING_AMP_RE = re.compile(r"\s&\s*['\"]?[\s;)]*$")

# Runs of spaces/tabs collapse before a needle is matched, so retabbing a crontab
# command string neither voids its entry nor widens it.
_WS_RUN_RE = re.compile(r"[ \t]+")


class _Exempt(NamedTuple):
    """One allowlist entry: the file it applies to, the line it exempts, and why."""

    path: str  # file BASENAME
    needle: str  # whitespace-normalised substring identifying the ONE exempt line
    why: str


# Exactly seven entries, every one load-bearing (each exempts a line that the token rule
# alone would flag). Adding an eighth is a decision, never a convenience.
_ALLOWLIST: tuple[_Exempt, ...] = (
    _Exempt(
        "pfblockerng.sh",
        '"${_pfbre_tmo}"',
        "pfb_reentry(): the bounded shell seam itself -- this IS the timeout(1) spawn.",
    ),
    _Exempt(
        "pfblockerng.inc",
        "$pfb_tick_cmd =",
        "crontab command string for install_cron_job(); never executed by this process.",
    ),
    _Exempt(
        "pfblockerng_apply.inc",
        "$pfb_cmd =",
        "crontab command string for the widget clear jobs; never executed here.",
    ),
    _Exempt(
        "pfblockerng_install.inc",
        "$pfb_cmd_esc =",
        "crontab needle for stale-entry removal; a string compared, never executed.",
    ),
    _Exempt(
        "pfblockerng_install.inc",
        "$pfb_cmd =",
        "crontab command string for the widget clear jobs; never executed here.",
    ),
    _Exempt(
        "pfblockerng_update.php",
        "$pfb_cmd =",
        "crontab needle for the 'Missing cron task' check; a string compared, never run.",
    ),
    _Exempt(
        "pfblockerng.widget.php",
        "$pfb_cmd =",
        "crontab command string for the widget clear jobs; never executed here.",
    ),
)

_MESSAGE = (
    "nested pfblockerng.php re-entry is not bounded -- route it through "
    "pfb_reentry_exec() (PHP) or pfb_reentry() (shell)"
)


class Violation(NamedTuple):
    """One line composing an unbounded nested `pfblockerng.php` command."""

    source: str  # file path
    line: int  # 1-based line number
    snippet: str  # the offending line (trimmed)


def _is_composition(line: str) -> bool:
    """True when the line names BOTH an interpreter and the re-entry target."""
    return any(rx.search(line) for rx in _INTERPRETER_RES) and any(rx.search(line) for rx in _TARGET_RES)


def _is_backgrounded(line: str) -> bool:
    """True when the line itself backgrounds the spawn (marker or trailing ` &`)."""
    return any(marker in line for marker in _BG_MARKERS) or _TRAILING_AMP_RE.search(line) is not None


def _is_allowlisted(basename: str, line: str) -> bool:
    """True when an `_ALLOWLIST` entry names this file AND this line's needle.

    `_ALLOWLIST` is read from the module global on every call, so emptying it (as the
    tests do) brings every exempt line straight back.
    """
    normalised = _WS_RUN_RE.sub(" ", line)
    return any(entry.path == basename and entry.needle in normalised for entry in _ALLOWLIST)


def find_violations(text: str, source: str) -> list[Violation]:
    """Find every unbounded nested `pfblockerng.php` composition in one file's source.

    Scanned per physical line, with a two-line lookback for a backgrounding marker
    belonging to the same statement (see the module docstring).
    """
    basename = Path(source).name
    lines = text.splitlines()
    violations: list[Violation] = []
    for index, line in enumerate(lines):
        if not _is_composition(line) or _is_backgrounded(line):
            continue
        window = lines[max(0, index - _BG_LOOKBACK_LINES) : index]
        if any(marker in prev for prev in window for marker in _BG_MARKERS):
            continue
        if _is_allowlisted(basename, line):
            continue
        violations.append(Violation(source=source, line=index + 1, snippet=line.strip()))
    return violations


def _git_tracked_src() -> list[str]:
    """Return tracked src/ files ending .php/.inc/.sh (sorted)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", SRC_DIR],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    return sorted(p for p in out.split("\0") if p and p.endswith(_SCAN_SUFFIXES))


def _scan_path(path: str) -> list[Violation]:
    """Scan one file; unreadable files are skipped silently."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return find_violations(text, path)


# Synthetic canary input: the `exec()` shape issue #2016 removed, and the same command
# backgrounded. Neither path is read from the repository.
_SELF_TEST_SOURCE = "self-test/synthetic.inc"
_SELF_TEST_BLOCKING = "\texec(\"{$pfb['php']} /usr/local/www/pfblockerng/pfblockerng.php dc scheduled 2>&1\");"
_SELF_TEST_CLEAN = "\tmwexec_bg(\"{$pfb['php']} /usr/local/www/pfblockerng/pfblockerng.php dc scheduled 2>&1\");"


def _self_test() -> int:
    """Red canary: the blocking shape must flag and the backgrounded one must not."""
    flagged = find_violations(_SELF_TEST_BLOCKING, _SELF_TEST_SOURCE)
    clean = find_violations(_SELF_TEST_CLEAN, _SELF_TEST_SOURCE)
    if not flagged:
        print(
            "check_reentry_bounds --self-test: the synthetic unbounded re-entry did NOT "
            "flag. The gate cannot detect the composition it exists to detect.",
            file=sys.stderr,
        )
        return 1
    if clean:
        print(
            "check_reentry_bounds --self-test: the synthetic BACKGROUNDED re-entry flagged "
            f"({len(clean)} finding(s)). The gate no longer discriminates, so every real "
            "scan it passes is meaningless.",
            file=sys.stderr,
        )
        return 1
    print(
        "check_reentry_bounds --self-test: the unbounded composition flagged and the "
        "backgrounded one did not -- gate wiring proven."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 (clean), 1 (violations found), or 2 (the argless
    default scan set could not be enumerated -- fail-closed)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--self-test"]:
        return _self_test()

    if args:
        paths = args
    else:
        paths = _git_tracked_src()
        # Fail CLOSED: an empty default scan set means `git ls-files` could not
        # enumerate the package tree (git absent / not a checkout) -- this repo always
        # has such files -- so error rather than exit 0 and silently skip the gate.
        if not paths:
            print(
                f"check_reentry_bounds: `git ls-files {SRC_DIR}` returned nothing "
                "(git unavailable or not a checkout) -- failing closed rather than "
                "skipping the gate.",
                file=sys.stderr,
            )
            return 2

    violations: list[Violation] = []
    for path in paths:
        violations.extend(_scan_path(path))

    for v in violations:
        print(f"{v.source}:{v.line}: {_MESSAGE}", file=sys.stderr)
        print(f"    {v.snippet}", file=sys.stderr)

    if violations:
        print(
            f"\n{len(violations)} unbounded nested pfblockerng.php re-entry site(s). "
            "Call pfb_reentry_exec() (PHP) or pfb_reentry() (shell) instead of composing "
            "the child command, or background it if it genuinely must not block.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
