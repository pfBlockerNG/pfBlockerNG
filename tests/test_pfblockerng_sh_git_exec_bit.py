"""Directly exec'd package scripts must stay executable in git's index (issue #3305).

``scripts/install-from-repo.sh`` rsyncs ``src/usr/local/`` onto the box with ``-a``,
so the installed mode is git's. Production runs these by bare path, with no
``/bin/sh`` prefix: ``$pfb['script']`` (pfblockerng.sh) and ``pfb_list_script_exec()``
(the list_scripts/ pre/post scripts). A 100644 entry is ``Permission denied`` on a
source install; the built .pkg installs them 0555 either way. Mirrors
``tests/test_install_sh_git_exec_bit.py`` (issue #2754).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = "src/usr/local/pkg/pfblockerng"


def _index_modes(*pathspecs: str) -> dict[str, str]:
    out = subprocess.check_output(["git", "ls-files", "-s", "--", *pathspecs], cwd=ROOT, text=True)
    return {line.split("\t", 1)[1]: line.split()[0] for line in out.splitlines()}


def test_pfblockerng_sh_is_executable_in_the_git_index() -> None:
    """Given pfblockerng.sh in the git index
    When git reports its mode
    Then the exec bit is set (100755), independent of checkout umask.
    """
    assert _index_modes(f"{PKG_DIR}/pfblockerng.sh") == {f"{PKG_DIR}/pfblockerng.sh": "100755"}


def test_every_list_script_is_executable_in_the_git_index() -> None:
    """Given every shell script under list_scripts/ in the git index
    When git reports their modes
    Then each has the exec bit set (100755).
    """
    modes = _index_modes(f"{PKG_DIR}/list_scripts/*.sh")
    assert modes, "no list_scripts/*.sh found in the git index"
    assert {path: mode for path, mode in modes.items() if mode != "100755"} == {}
