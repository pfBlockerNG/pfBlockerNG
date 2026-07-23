from __future__ import annotations

import subprocess

import pytest

from tests.smoke.test_repo_install import _wait_for_pkg_quiescence


class _FakeVM:
    def __init__(self, busy: list[bool]) -> None:
        self.busy = iter(busy)
        self.probes = 0

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        if remote[0] == "ps":
            return subprocess.CompletedProcess(remote, 0, "123 pkg update -f\n", "")
        self.probes += 1
        return subprocess.CompletedProcess(remote, 0 if next(self.busy) else 1, "", "")


def test_pkg_quiescence_waits_and_times_out_loudly() -> None:
    vm = _FakeVM([True, True, False])
    _wait_for_pkg_quiescence(vm, deadline_s=1.0, poll_s=0.0)  # type: ignore[arg-type]
    assert vm.probes == 3

    stuck = _FakeVM([True])
    with pytest.raises(RuntimeError, match=r"package manager still active.*123 pkg update -f"):
        _wait_for_pkg_quiescence(stuck, deadline_s=0.0, poll_s=0.0)  # type: ignore[arg-type]
