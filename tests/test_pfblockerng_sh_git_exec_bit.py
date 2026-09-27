"""pfblockerng.sh must stay executable in git's index (issue #3305).

Nightly smoke shard 1 logged 30x ``sh: /usr/local/pkg/pfblockerng/pfblockerng.sh:
Permission denied`` starting right after the fresh-install test. ``scripts/install-from-repo.sh``
rsyncs ``src/usr/local/`` onto the box with ``-a`` (preserving git's file mode), and production
exec's the script directly by path (no ``/bin/sh`` prefix) in pfblockerng.inc/pfblockerng_apply.inc
-- so a 100644 mode in the index breaks both a repo-source install and, per
``scripts/install-from-repo.sh``'s own docs, a fresh box. Mirrors
``tests/test_install_sh_git_exec_bit.py`` (issue #2754) for install.sh.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pfblockerng_sh_is_executable_in_the_git_index() -> None:
    """Given src/usr/local/pkg/pfblockerng/pfblockerng.sh in the git index
    When git reports its mode
    Then the exec bit is set (100755), independent of checkout umask.
    """
    out = subprocess.check_output(
        ["git", "ls-files", "-s", "--", "src/usr/local/pkg/pfblockerng/pfblockerng.sh"],
        cwd=ROOT,
        text=True,
    )
    lines = out.splitlines()
    assert len(lines) == 1 and lines[0].split()[0] == "100755", out
