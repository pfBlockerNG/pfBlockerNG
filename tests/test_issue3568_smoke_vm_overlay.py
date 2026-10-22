"""Issue #3568 -- a smoke VM's copy-on-write overlay must not outlive the VM.

``boot_vm.sh`` ``exec``s qemu, so no shell trap survives to delete the overlay it made; on the smoke
boxes /tmp is tmpfs, so every boot leaked 100-400 MB of RAM. These tests start the real ``smoke_vm`` /
``peer_vm`` / ``client_vm`` fixtures through the real ``boot_vm.sh`` with a stand-in qemu, stop them the
way pytest does, and require that every disk image qemu-img was asked to create is gone and was never
placed in the shared TMPDIR.
"""

from __future__ import annotations

import importlib
import os
import pathlib
import select
import shutil
import signal
import subprocess
from collections.abc import Generator, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from tests.smoke import conftest as smoke_conftest

# Stand-in qemu: say "running" on the FIFO, then stay up / ignore SIGTERM / die, as $PFB_TEST_QEMU says.
_QEMU = """#!/bin/sh
[ "$PFB_TEST_QEMU" = ignore-term ] && trap '' TERM
echo up > "$PFB_TEST_UP_FIFO"
case "$PFB_TEST_QEMU" in
    exit) exit 1 ;;
    ignore-term) while true; do sleep 1; done ;;
    *) exec sleep 300 ;;
esac
"""

# Stand-in qemu-img: log and create the overlay (its LAST argument), as the real `create` does.
_QEMU_IMG = """#!/bin/sh
for last; do :; done
echo "$last" >> "$PFB_TEST_IMG_LOG"
true > "$last"
"""

WORK_DIR_OF = {"smoke_vm": "smoke-vm", "peer_vm": "peer-vm", "client_vm": "client-vm"}


class _WorkDirs:
    """Stands in for ``tmp_path_factory``: named dirs under one scratch root."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def mktemp(self, basename: str, numbered: bool = True) -> Path:
        path = self.root / basename
        path.mkdir(parents=True)
        return path


class _Rig:
    """Scratch tree + stand-in qemu wired in front of the real conftest fixtures and boot_vm.sh."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
        self.monkeypatch = monkeypatch
        self.root = root
        self.tmpdir = root / "tmp dir"  # TMPDIR: where boot_vm.sh used to mktemp its overlay
        self.work = root / "work dir"  # space on purpose: every path must stay quoted
        self.img_log = root / "img.log"
        self.fifo = root / "up.fifo"
        self.qemu_mode = "stay"  # stay | ignore-term | exit
        self.failure: str | None = None
        self.started: list[subprocess.Popen[bytes]] = []
        self._build(monkeypatch)

    def _build(self, monkeypatch: pytest.MonkeyPatch) -> None:
        root = self.root
        bins = root / "bin"
        for directory in (self.tmpdir, bins, root / "runner-temp", root / "images", root / "client-images"):
            directory.mkdir()
        for name, body in (("qemu", _QEMU), ("qemu-img", _QEMU_IMG)):
            (bins / name).write_text(body)
            (bins / name).chmod(0o755)
        os.mkfifo(self.fifo)
        (root / "images" / "base.qcow2").write_text("")
        (root / "client-images" / "civm.qcow2").write_text("")
        (root / "ssh-key").write_text("")
        for key, value in {
            "TMPDIR": str(self.tmpdir),
            "RUNNER_TEMP": str(root / "runner-temp"),
            "SMOKE_QEMU_BIN": str(bins / "qemu"),
            "SMOKE_QEMU_IMG_BIN": str(bins / "qemu-img"),
            "PFB_TEST_UP_FIFO": str(self.fifo),
            "PFB_TEST_IMG_LOG": str(self.img_log),
            "SMOKE_PKG": "pkg.pkg",
            "SMOKE_CLIENT_IMAGE_DIR": str(root / "client-images"),
            "SMOKE_SSH_KEY": str(root / "ssh-key"),
        }.items():
            monkeypatch.setenv(key, value)

        rig = self

        class RecordingPopen(subprocess.Popen[bytes]):
            """The real Popen, remembered for reaping; bounded waits capped at 0.5 s so a qemu that ignores
            SIGTERM reaches ``_kill``'s SIGKILL step without the production 15 s grace."""

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                rig.started.append(self)

            def wait(self, timeout: float | None = None) -> int:
                return super().wait(None if timeout is None else min(timeout, 0.5))

        live_helpers = importlib.import_module("tests.smoke.helpers")

        def boot_complete(vm: object) -> None:
            if rig.failure == "boot_complete_raises":
                raise RuntimeError("simulated boot-complete failure")

        monkeypatch.setattr(smoke_conftest.subprocess, "Popen", RecordingPopen)
        monkeypatch.setattr(smoke_conftest.subprocess, "run", self._wait_ready)
        monkeypatch.setattr(smoke_conftest, "_capture_boot_failure", lambda *a, **k: None)
        monkeypatch.setattr(smoke_conftest, "_pfsense_image", lambda work: (root / "images" / "base.qcow2", "key"))
        monkeypatch.setattr(smoke_conftest, "_log_guest_identity", lambda vm: None)
        monkeypatch.setattr(smoke_conftest, "own_variant", lambda: SimpleNamespace(variant="CE"))
        monkeypatch.setattr(live_helpers, "wait_boot_complete", boot_complete)
        monkeypatch.setattr(live_helpers, "_write_cron_disable_flag", lambda vm: None)
        monkeypatch.setattr(live_helpers, "enable_strict_php_error_reporting", lambda vm: None)
        # client_vm's own prerequisites: KVM and the binaries on PATH.
        real_exists = pathlib.Path.exists
        monkeypatch.setattr(
            pathlib.Path, "exists", lambda self, **kw: str(self) == "/dev/kvm" or real_exists(self, **kw)
        )
        monkeypatch.setattr(shutil, "which", lambda binary, **kw: f"/usr/bin/{binary}")

    def _wait_ready(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        """wait_ready.sh stand-in: returns only once the stand-in qemu is running, then reports the scenario."""
        fd = os.open(self.fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            ready, _, _ = select.select([fd], [], [], 30)
        finally:
            os.close(fd)
        assert ready, "the stand-in qemu never started"
        if self.failure == "wait_ready_raises":
            raise OSError("simulated wait_ready crash")
        if self.failure in ("wait_ready_exit", "qemu_exit"):
            return subprocess.CompletedProcess(argv, 1, "", "never ready")
        return subprocess.CompletedProcess(argv, 0, "boot-to-ready: 1 second\n", "")

    def start(self, name: str) -> Generator[Any, None, None]:
        """Run the real fixture ``name`` to its yield (raises if the boot fails) and return its generator."""
        self.monkeypatch.setenv("PFB_TEST_QEMU", self.qemu_mode)
        factory = cast(Any, _WorkDirs(self.work))
        items = [SimpleNamespace(fixturenames=["ha_pair"])] if name == "peer_vm" else []
        request = SimpleNamespace(session=SimpleNamespace(items=items, stash={}))
        fixture = cast(Any, getattr(smoke_conftest, name)).__wrapped__
        if name == "client_vm":
            gen = fixture(object(), 12340, factory)
        elif name == "smoke_vm":
            gen = fixture(12340, factory, request)
        else:
            gen = fixture(object(), factory, request)
        next(gen)
        return cast(Generator[Any, None, None], gen)

    def created(self) -> list[Path]:
        """Every disk image qemu-img was asked to create, in order."""
        return [Path(line) for line in self.img_log.read_text().splitlines()] if self.img_log.exists() else []

    def only_overlay(self) -> Path:
        created = self.created()
        assert len(created) == 1, f"expected exactly one overlay to be created, got {created}"
        return created[0]


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[_Rig]:
    scratch = _Rig(monkeypatch, tmp_path)
    yield scratch
    for process in scratch.started:  # a failed assertion must not leave a stand-in qemu running
        if process.poll() is None:
            process.kill()
            process.wait()


@pytest.mark.parametrize("name", sorted(WORK_DIR_OF))
def test_stopping_a_booted_vm_deletes_its_overlay(rig: _Rig, name: str) -> None:
    fixture = rig.start(name)
    overlay = rig.only_overlay()
    assert overlay.exists(), f"qemu runs on {overlay}, so it must exist until the VM is stopped"

    fixture.close()

    assert not overlay.exists(), f"stopped {name} left its overlay behind: {overlay}"


@pytest.mark.parametrize("name", sorted(WORK_DIR_OF))
def test_overlay_lives_in_the_vms_work_dir_never_in_the_shared_tmpdir(rig: _Rig, name: str) -> None:
    fixture = rig.start(name)
    try:
        overlay = rig.only_overlay()

        assert overlay.parent == rig.work / WORK_DIR_OF[name], f"{name} put its overlay at {overlay}"
        assert list(rig.tmpdir.iterdir()) == [], f"{name} left files in the shared TMPDIR"
    finally:
        fixture.close()


def test_each_vm_gets_its_own_overlay(rig: _Rig) -> None:
    fixtures = [rig.start(name) for name in ("smoke_vm", "peer_vm", "client_vm")]
    try:
        created = rig.created()

        assert len(set(created)) == len(WORK_DIR_OF), f"the three VMs must not share an overlay: {created}"
        assert all(path.exists() for path in created), f"an overlay was clobbered or removed early: {created}"
    finally:
        for fixture in reversed(fixtures):
            fixture.close()


@pytest.mark.parametrize(
    ("name", "failure"),
    [
        ("smoke_vm", "wait_ready_exit"),
        ("smoke_vm", "wait_ready_raises"),
        ("smoke_vm", "boot_complete_raises"),
        ("smoke_vm", "qemu_exit"),
        ("client_vm", "wait_ready_exit"),
        ("client_vm", "wait_ready_raises"),
    ],
)
def test_a_failed_boot_deletes_its_overlay(rig: _Rig, name: str, failure: str) -> None:
    rig.failure = failure
    rig.qemu_mode = "exit" if failure == "qemu_exit" else "stay"

    with pytest.raises((RuntimeError, OSError)):
        rig.start(name)

    overlay = rig.only_overlay()
    assert not overlay.exists(), f"{name} failed to boot ({failure}) and left its overlay behind: {overlay}"


def test_a_qemu_that_ignores_sigterm_is_killed_and_its_overlay_deleted(rig: _Rig) -> None:
    rig.qemu_mode = "ignore-term"
    fixture = rig.start("smoke_vm")
    overlay = rig.only_overlay()

    fixture.close()

    assert rig.started[0].returncode == -signal.SIGKILL, "a SIGTERM-proof qemu must be escalated to SIGKILL"
    assert not overlay.exists(), f"SIGKILLed VM left its overlay behind: {overlay}"


def test_stopping_a_vm_whose_overlay_is_already_gone_is_not_an_error(rig: _Rig) -> None:
    fixture = rig.start("smoke_vm")
    rig.only_overlay().unlink()

    fixture.close()  # raises if the teardown trips over the missing file


def test_stopping_the_same_vm_twice_is_harmless(rig: _Rig) -> None:
    real_kill = smoke_conftest._kill
    stops: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def spy(*args: Any, **kwargs: Any) -> None:
        stops.append((args, kwargs))
        real_kill(*args, **kwargs)

    rig.monkeypatch.setattr(smoke_conftest, "_kill", spy)
    fixture = rig.start("smoke_vm")
    overlay = rig.only_overlay()
    fixture.close()
    assert not overlay.exists(), f"stopped VM left its overlay behind: {overlay}"

    real_kill(*stops[0][0], **stops[0][1])  # the second stop has nothing left to remove
