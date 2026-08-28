from __future__ import annotations

import subprocess

import pytest

from tests.smoke import test_repo_install as repo


class _FailingVM:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        self.timeouts.append(timeout)
        return subprocess.CompletedProcess(remote, 1, "", "repository unavailable")


def test_pkg_retry_caps_initial_attempt_to_remaining_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _FailingVM()
    clock = iter((0.0, 1.0))
    monkeypatch.setattr(repo.time, "monotonic", lambda: next(clock))

    with pytest.raises(RuntimeError, match="repository unavailable"):
        repo.pkg_update(vm, timeout=5.0)  # type: ignore[arg-type]

    assert vm.timeouts == [4.0]
