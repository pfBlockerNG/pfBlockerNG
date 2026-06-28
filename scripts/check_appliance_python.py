#!/usr/bin/env python3
"""Forbid invoking a Python interpreter ON the pfSense appliance.

PROBLEM
-------
pfSense ships ``python3.11`` but NO ``python3`` symlink, so a command that
shells out to the interpreter on the box —

    vm.ssh(f"/usr/local/bin/python3 -c {snippet}")     # smoke test -> pfSense VM
    exec("/usr/local/bin/python3 ...")                 # package code on the box

— fails with ``rc=127`` ("not found"). Worse, when the caller ignores the exit
code (``SmokeVM.ssh`` is ``check=False``) the failure is SILENT: the command
no-ops and the surrounding logic proceeds on stale/empty state. This bit the
``apply_on_change`` and ``tick`` smoke modules — their ledger writes silently did
nothing, leaving the tests passing or failing by accident of unrelated state.

The right tool on the appliance is **PHP** (``/usr/local/bin/php`` / ``pfSsh.php``,
which pfSense ships and which already owns the package's data structures) or
**POSIX sh**. Python on the appliance is reserved for ``pfb_unbound.py`` alone —
and that runs inside Unbound's *embedded* Python loader (configured via
``python-script:``), never spawned through ``/usr/local/bin/python``.

This check is the mechanical backstop for that rule (CLAUDE.md, "Python"). It is
PREVENTATIVE — there are no offenders in shipped code today; it guards against
re-introducing the footgun.

SCOPE (deliberately low false-positive)
---------------------------------------
* Scans tracked files under ``src/`` (package code that runs on the appliance)
  and ``tests/`` (the smoke suite, whose ``vm.ssh`` commands run on the appliance).
  ``scripts/`` is dev/CI-host tooling (it runs on the developer's box, which DOES
  have ``python3``) and is intentionally NOT scanned.
* Flags the literal appliance interpreter path ``/usr/local/bin/python`` (covers
  ``python``, ``python3``, ``python3.11``, ...). Bare ``python3`` is NOT flagged:
  it legitimately names the dev-host / client-VM interpreter, and the appliance
  footgun has always used the full path. The CLAUDE.md rule covers the rest as
  human discipline.

Exit status: 0 = clean, 1 = one or more violations (printed with file:line).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# The appliance interpreter path. pfSense has no python3 symlink here, so any
# invocation of it is a runtime rc=127 footgun. (Built so this file does not
# match its own check — though scripts/ is not scanned anyway.)
_FORBIDDEN = re.compile(r"/usr/local/bin/" + r"python")

# Tracked-tree roots that run ON the appliance.
_SCAN_ROOTS = ("src", "tests")


def _tracked_files(roots: tuple[str, ...]) -> list[Path]:
    """Return the git-tracked files under the given roots (text files only)."""
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
            if _FORBIDDEN.search(line):
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
        "\nThe appliance ships python3.11 with no `python3` symlink, so "
        "`/usr/local/bin/python*` is rc=127 (and silent under check=False ssh).\n"
        "Use PHP (php / pfSsh.php / h.php_eval — it owns the package's data structures) "
        "or POSIX sh instead.\n"
        "Only pfb_unbound.py may be Python, and it runs in Unbound's embedded loader, "
        'not via /usr/local/bin/python. See CLAUDE.md ("Python").',
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
