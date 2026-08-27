#!/usr/bin/env python3
"""Verify the committed CodeMirror 6 vendor tree matches its pinned source.

PROBLEM
-------
pfBlockerNG is a NO_BUILD FreeBSD port: ``make package`` / build-pkg-portable.py
/ ``deploy.sh`` copy ``src/`` verbatim, so the CodeMirror 6 regex-list editor
bundle under ``src/usr/local/www/pfblockerng/vendor/codemirror/`` (issue #1669)
must be a committed, built static file -- there is no build step on the
appliance or in the package build to regenerate it. ``tools/webassets/`` (its
``package-lock.json``, the two Lezer grammar packages, and the ``cm-regex.js``
esbuild entry) is the pinned source; ``scripts/build-webassets.sh`` is the only
thing that may write that vendor tree.

This mirrors ``scripts/check_composer_vendor.py``'s role for the PHP vendor/
tree, but the drift can only be proven by actually rebuilding (there's no
single upstream file to hash-compare -- the bundle is esbuild's own output) --
so this checker re-runs the build script and diffs its output, rather than
comparing lockfile metadata.

Exit status: 0 = the vendor tree matches its pinned source, 1 = it has
drifted (regenerate with ``scripts/build-webassets.sh`` and commit the
result), 2 = the build itself failed to run.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

VENDOR_DIR = "src/usr/local/www/pfblockerng/vendor/codemirror"
REMEDIATION = "remediation: sh scripts/build-webassets.sh, then commit the result"


def _repo_root() -> Path:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True)
    return Path(out.stdout.strip())


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        print("usage: check_webassets_vendor.py", file=sys.stderr)
        return 2
    root = _repo_root()
    build = subprocess.run(["sh", str(root / "scripts" / "build-webassets.sh")], cwd=root)
    if build.returncode != 0:
        print(f"build-webassets.sh failed (exit {build.returncode})", file=sys.stderr)
        return 2
    diff = subprocess.run(["git", "diff", "--exit-code", "--", VENDOR_DIR], cwd=root)
    if diff.returncode != 0:
        print(f"vendor tree drifted from its pinned source -- {REMEDIATION}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
