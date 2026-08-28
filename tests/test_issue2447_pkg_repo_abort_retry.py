"""Issue #2447: ``pkg repo`` on the guest can SIGABRT (rc=134) inside libpkg (a jemalloc
invalid-free assertion) once in many runs, on an input that indexes fine on the very
next run. The catalog build retries that abort ONCE — and only that abort: any other
failure (an rc=1 with a real error) still surfaces on the first try.
"""

from __future__ import annotations

import subprocess

import pytest

from tests.smoke.test_repo_install import UPGRADE_REPO_DIR, pkg_repo_index

PKG_REPO = ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "repo", UPGRADE_REPO_DIR)
ABORT_STDERR = (
    '<jemalloc>: jemalloc_jemalloc.c:2576: Failed assertion: "alloc_ctx.szind != SC_NSIZES"\n'
    "Child process pid=90168 terminated abnormally: Abort trap\n"
)


class _FakeVM:
    def __init__(self, results: list[subprocess.CompletedProcess[str]]) -> None:
        self.results = iter(results)
        self.calls: list[tuple[str, ...]] = []

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        assert remote == PKG_REPO
        assert timeout == 180.0  # the guest `pkg repo` budget build_guest_repo always had
        self.calls.append(remote)
        return next(self.results)


def test_pkg_repo_retries_a_libpkg_abort_once(capsys: pytest.CaptureFixture[str]) -> None:
    aborted = subprocess.CompletedProcess((), 134, f"Creating repository in {UPGRADE_REPO_DIR}: .\n", ABORT_STDERR)
    success = subprocess.CompletedProcess((), 0, "", "")
    vm = _FakeVM([aborted, success])

    pkg_repo_index(vm, UPGRADE_REPO_DIR)  # type: ignore[arg-type]

    assert vm.calls == [PKG_REPO, PKG_REPO]
    out = capsys.readouterr().out
    assert f"PFB_NOTE pkg repo {UPGRADE_REPO_DIR} aborted (rc=134)" in out
    assert ABORT_STDERR in out


def test_pkg_repo_second_abort_raises_with_the_abort_output() -> None:
    aborted = subprocess.CompletedProcess((), 134, "", ABORT_STDERR)
    vm = _FakeVM([aborted, aborted])

    # The same `guest cmd (...) failed: rc=N` / stdout / stderr shape `_ssh_check` raises —
    # that exact line is what issue #2447 was triaged from.
    with pytest.raises(
        RuntimeError,
        match=(
            r"guest cmd \('env', 'ASSUME_ALWAYS_YES=yes', 'pkg', 'repo', '.*'\) failed: rc=134"
            r"\nstdout:\n[\s\S]*stderr:\n[\s\S]*Abort trap"
        ),
    ):
        pkg_repo_index(vm, UPGRADE_REPO_DIR)  # type: ignore[arg-type]

    assert len(vm.calls) == 2


def test_pkg_repo_does_not_retry_an_ordinary_failure() -> None:
    failure = subprocess.CompletedProcess((), 1, "", "pkg: /tmp/pfb_repo_spike/upgrade: No such file or directory\n")
    vm = _FakeVM([failure])

    with pytest.raises(RuntimeError, match="No such file or directory"):
        pkg_repo_index(vm, UPGRADE_REPO_DIR)  # type: ignore[arg-type]

    assert len(vm.calls) == 1
