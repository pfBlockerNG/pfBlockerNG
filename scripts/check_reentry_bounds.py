#!/usr/bin/env python3
"""Forbid synchronous, unbounded nested `pfblockerng.php` re-entry commands.

A physical line is a composition when it names both a PHP interpreter and the
re-entry target. Compositions are clean only when backgrounded or matched by one
of seven repository-path-and-line exemptions for the bounded shell seam and
crontab command strings. Commented compositions still flag.

With no paths, scan tracked `.php`, `.inc`, and `.sh` files under `src/`.
Explicit paths scan only those files. Exit 0 when clean, 1 for violations, and
2 when the default scan cannot be enumerated. `--self-test` checks one violating
and one backgrounded input without reading the repository.
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
    """One allowlist entry: repository-relative path, line needle, and constraint."""

    path: str
    needle: str
    why: str


# Exactly seven entries, every one load-bearing (each exempts a line that the token rule
# alone would flag). Adding an eighth is a decision, never a convenience.
_ALLOWLIST: tuple[_Exempt, ...] = (
    _Exempt(
        "src/usr/local/pkg/pfblockerng/pfblockerng.sh",
        '"${_pfbre_tmo}"',
        "pfb_reentry(): the bounded shell seam itself -- this IS the timeout(1) spawn.",
    ),
    _Exempt(
        "src/usr/local/pkg/pfblockerng/pfblockerng.inc",
        "$pfb_tick_cmd =",
        "crontab command string for install_cron_job(); never executed by this process.",
    ),
    _Exempt(
        "src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc",
        "$pfb_cmd =",
        "crontab command string for the widget clear jobs; never executed here.",
    ),
    _Exempt(
        "src/usr/local/pkg/pfblockerng/pfblockerng_install.inc",
        "$pfb_cmd_esc =",
        "crontab needle for stale-entry removal; a string compared, never executed.",
    ),
    _Exempt(
        "src/usr/local/pkg/pfblockerng/pfblockerng_install.inc",
        "$pfb_cmd =",
        "crontab command string for the widget clear jobs; never executed here.",
    ),
    _Exempt(
        "src/usr/local/www/pfblockerng/pfblockerng_update.php",
        "$pfb_cmd =",
        "crontab needle for the 'Missing cron task' check; a string compared, never run.",
    ),
    _Exempt(
        "src/usr/local/www/widgets/widgets/pfblockerng.widget.php",
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


def _is_allowlisted(source: str, line: str) -> bool:
    """True when an exemption names this repository path and line needle."""
    path = Path(source)
    if path.is_absolute():
        try:
            source = path.relative_to(Path.cwd()).as_posix()
        except ValueError:
            source = path.as_posix()
    else:
        source = path.as_posix()
    normalised = _WS_RUN_RE.sub(" ", line)
    return any(entry.path == source and entry.needle in normalised for entry in _ALLOWLIST)


def find_violations(text: str, source: str) -> list[Violation]:
    """Find unbounded compositions using a two-line background-marker lookback."""
    lines = text.splitlines()
    violations: list[Violation] = []
    for index, line in enumerate(lines):
        if not _is_composition(line) or _is_backgrounded(line):
            continue
        window = lines[max(0, index - _BG_LOOKBACK_LINES) : index]
        if any(marker in prev for prev in window for marker in _BG_MARKERS):
            continue
        if _is_allowlisted(source, line):
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
