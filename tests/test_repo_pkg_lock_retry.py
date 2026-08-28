from __future__ import annotations

import subprocess

import pytest

from tests.smoke.test_repo_install import pkg_update


class _FakeVM:
    def __init__(self, results: list[subprocess.CompletedProcess[str]]) -> None:
        self.results = iter(results)
        self.probes = 0

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        self.probes += 1
        assert remote == ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "update", "-f")
        return next(self.results)


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [
        ("Waiting for another process to update repository pfSense\n", ""),
        ("", "pkg: database is locked\n"),
    ],
)
def test_pkg_update_retries_only_lock_contention(monkeypatch: pytest.MonkeyPatch, stdout: str, stderr: str) -> None:
    locked = subprocess.CompletedProcess((), 1, stdout, stderr)
    success = subprocess.CompletedProcess((), 0, "", "")
    vm = _FakeVM([locked, success])
    monkeypatch.setattr("tests.smoke.test_repo_install.time.sleep", lambda _: None)

    pkg_update(vm, timeout=5.0)  # type: ignore[arg-type]

    assert vm.probes == 2


def test_pkg_update_does_not_retry_an_unrelated_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = subprocess.CompletedProcess((), 1, "", "repository unavailable")
    vm = _FakeVM([failure])
    monkeypatch.setattr("tests.smoke.test_repo_install.time.sleep", lambda _: None)

    with pytest.raises(RuntimeError, match="repository unavailable"):
        pkg_update(vm, timeout=5.0)  # type: ignore[arg-type]

    assert vm.probes == 1
