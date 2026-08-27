"""install.sh must stay executable in git's index (issue #2754).

Git tracks one mode bit: 100644 vs 100755. An exact-mode assert like 0o755
tests the checkout umask, not the repository — that is why the old
test_gen_landing.py equality died under umask 002 (0775 vs 0755).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_install_sh_is_executable_in_the_git_index() -> None:
    """Given scripts/install.sh in the git index
    When git reports its mode
    Then the exec bit is set (100755), independent of checkout umask.
    """
    out = subprocess.check_output(
        ["git", "ls-files", "-s", "--", "scripts/install.sh"],
        cwd=ROOT,
        text=True,
    )
    lines = out.splitlines()
    assert len(lines) == 1 and lines[0].split()[0] == "100755", out
