from __future__ import annotations

import subprocess

import pytest

from tests.smoke.test_repo_install import _wait_for_pkg_quiescence


class _BrokenProbeVM:
    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(remote, 2, "", "pgrep failed")


def test_pkg_quiescence_probe_error_fails_loudly() -> None:
    with pytest.raises(RuntimeError, match=r"package-manager probe failed: rc=2 'pgrep failed'"):
        _wait_for_pkg_quiescence(_BrokenProbeVM())  # type: ignore[arg-type]
