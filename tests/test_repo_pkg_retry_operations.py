from __future__ import annotations

import subprocess
from collections.abc import Callable

import pytest

from tests.smoke import test_repo_install as repo


class _LockedThenReadyVM:
    def __init__(self) -> None:
        locked = subprocess.CompletedProcess((), 1, "", "pkg: database is locked")
        ready = subprocess.CompletedProcess((), 0, "", "")
        self.results = iter((locked, ready))
        self.commands: list[tuple[str, ...]] = []

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        self.commands.append(remote)
        return next(self.results)


@pytest.mark.parametrize(
    ("operation", "verb"),
    [
        (repo.pkg_install_from_repo, "install"),
        (repo.pkg_upgrade, "upgrade"),
    ],
)
def test_pkg_write_operations_retry_lock_contention(
    monkeypatch: pytest.MonkeyPatch,
    operation: Callable[..., subprocess.CompletedProcess[str]],
    verb: str,
) -> None:
    vm = _LockedThenReadyVM()
    expected = ("env", "ASSUME_ALWAYS_YES=yes", "pkg", verb, "-y", repo.PKG_NAME)
    monkeypatch.setattr(repo.time, "sleep", lambda _: None)

    result = operation(vm, timeout=5.0)

    assert result.returncode == 0
    assert vm.commands == [expected, expected]
