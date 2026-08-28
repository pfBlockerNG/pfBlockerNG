from __future__ import annotations

import subprocess

import pytest

from tests.smoke import test_repo_install as repo


class _UnexpectedVM:
    def __init__(self) -> None:
        self.probes = 0

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        self.probes += 1
        raise AssertionError(f"expired deadline reached SSH with timeout={timeout}")


def test_pkg_retry_skips_initial_attempt_after_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _UnexpectedVM()
    clock = iter((0.0, 5.0))
    monkeypatch.setattr(repo.time, "monotonic", lambda: next(clock))

    with pytest.raises(subprocess.TimeoutExpired):
        repo.pkg_update(vm, timeout=5.0)  # type: ignore[arg-type]

    assert vm.probes == 0
