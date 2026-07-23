from __future__ import annotations

import inspect
import subprocess

import pytest

from tests.smoke import test_repo_install as repo


class _BrokenProbeVM:
    def __init__(self) -> None:
        self.probes = 0

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        self.probes += 1
        assert remote == ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "update", "-f")
        return subprocess.CompletedProcess(remote, 2, "", "repository unavailable")


def test_pkg_quiescence_probe_error_fails_loudly() -> None:
    vm = _BrokenProbeVM()
    with pytest.raises(RuntimeError, match=r"pkg readiness check failed: rc=2 'repository unavailable'"):
        repo._wait_for_pkg_quiescence(vm)  # type: ignore[arg-type]
    assert vm.probes == 1


class _ActiveVM:
    def __init__(self, ps_rc: int = 0) -> None:
        self.ps_rc = ps_rc
        self.probe_timeouts: list[float] = []

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        if remote[0] == "ps":
            return subprocess.CompletedProcess(remote, self.ps_rc, "", "ps failed")
        self.probe_timeouts.append(timeout)
        return subprocess.CompletedProcess(remote, 1, "Waiting for another process to update repository pfSense\n", "")


def test_pkg_quiescence_caps_probe_and_sleep_to_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    probe_overran = _ActiveVM(ps_rc=2)
    ticks = iter((0.0, 0.0, 6.0))
    monkeypatch.setattr(repo.time, "monotonic", lambda: next(ticks))
    with pytest.raises(RuntimeError, match=r"ps rc=2.*stderr='ps failed'"):
        repo._wait_for_pkg_quiescence(probe_overran, deadline_s=5.0, poll_s=10.0)  # type: ignore[arg-type]
    assert probe_overran.probe_timeouts == [5.0]

    sleep_capped = _ActiveVM()
    ticks = iter((0.0, 0.0, 4.0, 5.0))
    sleeps: list[float] = []
    monkeypatch.setattr(repo.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(repo.time, "sleep", sleeps.append)
    with pytest.raises(RuntimeError):
        repo._wait_for_pkg_quiescence(sleep_capped, deadline_s=5.0, poll_s=10.0)  # type: ignore[arg-type]
    assert sleeps == [1.0]


def test_repo_fixture_waits_after_egress_before_catalog_builds() -> None:
    source = inspect.getsource(repo.repo_vm)
    egress = source.index("_ensure_egress_open")
    quiescence = source.index("_wait_for_pkg_quiescence")
    catalog = source.index("build_guest_repo")
    assert egress < quiescence < catalog
