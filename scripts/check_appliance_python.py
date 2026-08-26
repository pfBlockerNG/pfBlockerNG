#!/usr/bin/env python3
"""Forbid invoking an unapproved Python interpreter ON the pfSense appliance.

PROBLEM
-------
pfSense ships a versioned Python dependency but NO ``python3`` symlink, so a command that
shells out to the interpreter on the box —

    vm.ssh(f"/usr/local/bin/python3 -c {snippet}")     # smoke test -> pfSense VM
    exec("/usr/local/bin/python3 ...")                 # package code on the box

— fails with ``rc=127`` ("not found"). Worse, when the caller ignores the exit
code (``SmokeVM.ssh`` is ``check=False``) the failure is SILENT: the command
no-ops and the surrounding logic proceeds on stale/empty state. This bit the
``apply_on_change`` and ``tick`` smoke modules — their ledger writes silently did
nothing, leaving the tests passing or failing by accident of unrelated state.

The package dependency does provide a versioned interpreter. Package code must
invoke it through ``/usr/local/pkg/pfblockerng/pfb_python.sh``, which is the sole
dependency resolver. Tests and ad-hoc appliance commands should use **PHP**
(``/usr/local/bin/php`` / ``pfSsh.php``), **POSIX sh**, or that wrapper.

This check is the mechanical backstop for that rule (AGENTS.md, "Python"). It is
PREVENTATIVE — there are no offenders in shipped code today; it guards against
re-introducing the footgun.

SCOPE (deliberately low false-positive)
---------------------------------------
* Scans tracked files under ``src/`` (package code that runs on the appliance)
  and ``tests/`` (the smoke suite, whose ``vm.ssh`` commands run on the appliance).
  ``scripts/`` is dev/CI-host tooling (it runs on the developer's box, which DOES
  have ``python3``) and is intentionally NOT scanned.
* Flags the literal appliance interpreter path ``/usr/local/bin/python`` (covers
  ``python``, ``python3``, ``python3.11``, ...) everywhere in the scan roots.
* Also flags bare ``python3`` and hardcoded ``python3.NN`` commands in shipped
  source and direct pfSense-guest SSH calls in the smoke suite. Test-runner and
  client-VM commands remain outside that appliance rule.

Exit status: 0 = clean, 1 = one or more violations (printed with file:line).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# The appliance interpreter path. pfSense has no python3 symlink here, so any
# invocation of it is a runtime rc=127 footgun. A plain substring beats a regex
# for this per-line scan (ADR-28). This file lives under scripts/, which is not
# scanned, so the literal here is harmless.
_FORBIDDEN = "/usr/local/bin/python"
_BARE_PYTHON = re.compile(r"(?<![A-Za-z0-9_./-])python3(?:\.[0-9]+)?(?=$|[\s\"'`;|&()<>\[\],])")
_GUEST_SSH = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.ssh\s*\(")
_SOURCE_EXTENSIONS = {"", ".html", ".inc", ".js", ".php", ".py", ".sh", ".xml"}
_REPO_ROOT = Path(__file__).resolve().parent.parent

# Tracked-tree roots that run ON the appliance.
_SCAN_ROOTS = ("src", "tests")


def _is_appliance_line(path: Path, line: str) -> bool:
    """Return whether a line executes in shipped source or on a pfSense guest."""
    if path.suffix.lower() not in _SOURCE_EXTENSIONS:
        return False
    stripped = line.lstrip()
    if not stripped or stripped.startswith(("#", "//", "/*", "*")):
        return False
    try:
        relative = path.resolve().relative_to(_REPO_ROOT)
    except (OSError, ValueError):
        return True
    if relative.parts and relative.parts[0] == "src":
        return True
    return relative.parts[:2] == ("tests", "smoke") and any(
        match.group(1) != "client_vm" for match in _GUEST_SSH.finditer(line)
    )


def _tracked_files(roots: tuple[str, ...]) -> list[Path]:
    """Return every git-tracked file under the given roots (binary files are
    handled gracefully by :func:`find_violations`)."""
    out = subprocess.run(
        ["git", "ls-files", "-z", *roots],
        capture_output=True,
        text=True,
        check=True,
    )
    return [Path(p) for p in out.stdout.split("\0") if p]


def find_violations(paths: list[Path]) -> list[tuple[Path, int, str]]:
    """Return ``(path, lineno, line)`` for every line invoking appliance Python."""
    violations: list[tuple[Path, int, str]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _FORBIDDEN in line or (_is_appliance_line(path, line) and _BARE_PYTHON.search(line)):
                violations.append((path, lineno, line.strip()))
    return violations


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] if argv else _tracked_files(_SCAN_ROOTS)
    violations = find_violations(paths)
    if not violations:
        return 0
    print("Forbidden Python interpreter invocation on the pfSense appliance:\n", file=sys.stderr)
    for path, lineno, line in violations:
        print(f"  {path}:{lineno}: {line}", file=sys.stderr)
    print(
        "\nThe appliance has no `python` or `python3` symlink. Use PHP/POSIX sh, "
        "or /usr/local/pkg/pfblockerng/pfb_python.sh. "
        'See AGENTS.md ("Python").',
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
