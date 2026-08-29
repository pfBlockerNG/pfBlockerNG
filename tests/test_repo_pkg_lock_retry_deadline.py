from __future__ import annotations

import subprocess

import pytest

from tests.smoke import test_repo_install as repo


class _LockedVM:
    def __init__(self) -> None:
        self.probes = 0

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        self.probes += 1
        return subprocess.CompletedProcess(remote, 1, "", "pkg: database is locked")


@pytest.mark.parametrize(
    ("ticks", "expected_sleeps"),
    [
        ((0.0, 0.0, 5.0), []),
        ((0.0, 0.0, 0.0, 5.0), [1.0]),
    ],
)
def test_pkg_lock_retry_stops_at_deadline(
    monkeypatch: pytest.MonkeyPatch, ticks: tuple[float, ...], expected_sleeps: list[float]
) -> None:
    vm = _LockedVM()
    clock = iter(ticks)
    sleeps: list[float] = []
    monkeypatch.setattr(repo.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(repo.time, "sleep", sleeps.append)

    with pytest.raises(RuntimeError, match="database is locked"):
        repo.pkg_update(vm, timeout=5.0)  # type: ignore[arg-type]

    assert vm.probes == 1
    assert sleeps == expected_sleeps
