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
        self.timeouts: list[float] = []

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        if remote == ("pkg", "query", "%v", repo.PKG_NAME):
            return subprocess.CompletedProcess(remote, 0, "4.0.0\n", "")
        self.commands.append(remote)
        self.timeouts.append(timeout)
        return next(self.results)


class _NoopThenInstalledVM:
    def __init__(self) -> None:
        self.installs = 0
        self.queries = 0

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        if remote[:4] == ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install"):
            self.installs += 1
            return subprocess.CompletedProcess(remote, 0, "", "")
        assert remote == ("pkg", "query", "%v", repo.PKG_NAME)
        self.queries += 1
        if self.queries == 1:
            return subprocess.CompletedProcess(remote, 1, "", "")
        return subprocess.CompletedProcess(remote, 0, "4.0.0\n", "")


class _QueryErrorVM:
    def __init__(self) -> None:
        self.installs = 0

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        if remote[:4] == ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install"):
            self.installs += 1
            return subprocess.CompletedProcess(remote, 0, "", "")
        assert remote == ("pkg", "query", "%v", repo.PKG_NAME)
        return subprocess.CompletedProcess(remote, 2, "", "query unavailable")


class _InstalledTooLateVM:
    def __init__(self) -> None:
        self.installs = 0
        self.queries = 0

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        if remote[:4] == ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install"):
            self.installs += 1
            return subprocess.CompletedProcess(remote, 0, "", "")
        self.queries += 1
        return subprocess.CompletedProcess(remote, 0, "4.0.0\n", "")


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
    clock = iter((0.0, 1.0, 2.0, 3.0, 4.0))
    monkeypatch.setattr(repo.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(repo.time, "sleep", lambda _: None)

    result = operation(vm, timeout=5.0)

    assert result.returncode == 0
    assert vm.commands == [expected, expected]
    assert vm.timeouts == [4.0, 2.0]


def test_pkg_install_retries_success_without_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _NoopThenInstalledVM()
    monkeypatch.setattr(repo.time, "sleep", lambda _: None)

    result = repo.pkg_install_from_repo(vm, timeout=5.0)  # type: ignore[arg-type]

    assert result.returncode == 0
    assert vm.installs == 2
    assert vm.queries == 2


def test_pkg_install_does_not_retry_unrelated_query_error() -> None:
    vm = _QueryErrorVM()

    with pytest.raises(RuntimeError, match="query unavailable"):
        repo.pkg_install_from_repo(vm, timeout=0.01)  # type: ignore[arg-type]

    assert vm.installs == 1


def test_pkg_install_does_not_query_after_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _InstalledTooLateVM()
    clock = iter((0.0, 1.0, 5.0))
    monkeypatch.setattr(repo.time, "monotonic", lambda: next(clock))

    with pytest.raises(subprocess.TimeoutExpired):
        repo.pkg_install_from_repo(vm, timeout=5.0)  # type: ignore[arg-type]

    assert vm.installs == 1
    assert vm.queries == 0
