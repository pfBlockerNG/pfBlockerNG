"""Issue #3489 -- the QEMU QMP control socket must live in a fresh private directory.

``tempfile.mktemp`` only *names* a file in a shared tmp dir; another local user can
claim that name between naming and QEMU's bind. ``_qmp_sock_path`` now creates a
0700 directory (``mkdtemp``) and returns the socket path inside it: boot_vm.sh still
``rm -f``s the (absent) socket and QEMU binds it, but nobody else can reach the name.
The path must still fit AF_UNIX ``sun_path`` (108 bytes), which is why the directory is
anchored under RUNNER_TEMP or /tmp rather than pytest's deep tmp_path tree.
"""

from __future__ import annotations

import importlib
import inspect
import os
import shutil
import stat
from pathlib import Path

import pytest

from tests.smoke import conftest as smoke_conftest

SUN_PATH_MAX = 108  # AF_UNIX sun_path size on Linux, trailing NUL included

# The tag boot_and_probe() uses for the pfSense VM, read from its signature so the
# length check follows the real default instead of a copy of it.
PFSENSE_TAG = inspect.signature(smoke_conftest.boot_and_probe).parameters["diag_name"].default


def test_qmp_socket_lives_in_a_fresh_private_directory_under_runner_temp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    first = Path(smoke_conftest._qmp_sock_path("civm"))
    second = Path(smoke_conftest._qmp_sock_path("civm"))

    for sock in (first, second):
        assert sock.parent.is_dir(), f"{sock.parent} must exist so QEMU can bind inside it"
        assert sock.parent.parent == tmp_path, f"{sock.parent} must sit directly under RUNNER_TEMP={tmp_path}"
        assert stat.S_IMODE(sock.parent.stat().st_mode) == 0o700, f"{sock.parent} must be private to the owner"
        assert not sock.exists(), f"{sock} must not pre-exist: QEMU creates the socket"
    assert first.parent != second.parent, "each call needs its own directory"


@pytest.mark.parametrize("tag", ["civm", PFSENSE_TAG])
def test_qmp_socket_path_fits_sun_path_under_the_tmp_fallback(monkeypatch: pytest.MonkeyPatch, tag: str) -> None:
    monkeypatch.delenv("RUNNER_TEMP", raising=False)

    sock = smoke_conftest._qmp_sock_path(tag)
    parent = Path(sock).parent
    try:
        assert len(os.fsencode(sock)) < SUN_PATH_MAX, f"{sock} is too long for an AF_UNIX socket"
    finally:
        # Only ever remove the directory this call made; never a shared base like /tmp itself.
        if parent.name.startswith("pfb-qmp-"):
            shutil.rmtree(parent, ignore_errors=True)


class _FakeQemu:
    pid = 4321

    def __init__(self) -> None:
        self.stopped = False

    def poll(self) -> int | None:
        return 0 if self.stopped else None

    def terminate(self) -> None:
        self.stopped = True

    def wait(self, timeout: float | None = None) -> int:
        return 0


def _raise(*a: object, **k: object) -> None:
    raise OSError("simulated boot failure")


def _boot(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None = None) -> smoke_conftest.BootHandle:
    """Boot with faked qemu; ``failure`` picks which boot_and_probe failure path fires."""
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path / "runner-temp"))
    (tmp_path / "runner-temp").mkdir()
    monkeypatch.setattr(smoke_conftest.subprocess, "Popen", lambda *a, **k: _FakeQemu())
    ready_rc = 1 if failure == "wait_ready_exit" else 0
    monkeypatch.setattr(
        smoke_conftest.subprocess,
        "run",
        _raise
        if failure == "wait_ready_raises"
        else lambda argv, **k: smoke_conftest.subprocess.CompletedProcess(argv, ready_rc, "", "never ready"),
    )
    monkeypatch.setattr(smoke_conftest, "_capture_boot_failure", lambda *a, **k: None)
    live_helpers = importlib.import_module("tests.smoke.helpers")
    monkeypatch.setattr(
        live_helpers, "wait_boot_complete", _raise if failure == "boot_complete_raises" else lambda vm: None
    )
    monkeypatch.setattr(live_helpers, "_write_cron_disable_flag", lambda vm: None)
    monkeypatch.setattr(smoke_conftest, "_log_guest_identity", lambda vm: None, raising=False)
    return smoke_conftest.boot_and_probe(Path("base.qcow2"), "key", log_path=tmp_path / "vm.log")


@pytest.mark.parametrize("failure", ["wait_ready_exit", "wait_ready_raises", "boot_complete_raises"])
def test_a_failed_boot_removes_its_qmp_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str) -> None:
    with pytest.raises((RuntimeError, OSError)):
        _boot(monkeypatch, tmp_path, failure)

    assert list((tmp_path / "runner-temp").iterdir()) == [], "a failed boot must not leave its QMP directory behind"


def test_stopping_a_booted_vm_removes_its_qmp_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    handle = _boot(monkeypatch, tmp_path)
    handle.log_file.close()
    assert len(list((tmp_path / "runner-temp").iterdir())) == 1, "the running VM owns one QMP directory"

    smoke_conftest._kill(handle.process, handle.qmp_sock, handle.overlay)

    assert list((tmp_path / "runner-temp").iterdir()) == [], "stopping the VM must remove its QMP directory"
