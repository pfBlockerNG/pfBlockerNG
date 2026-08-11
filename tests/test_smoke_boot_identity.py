"""Issue #2297: every live-VM boot reports guest identity before deployment."""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from tests.smoke import conftest as smoke_conftest


def test_log_guest_identity_reports_observed_and_expected_facts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeVM:
        def __init__(self) -> None:
            self.calls: list[tuple[tuple[str, ...], float]] = []

        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            self.calls.append((remote, timeout))
            return subprocess.CompletedProcess(
                remote,
                0,
                "etc_version=2.8.1-RELEASE\nversionpatch=0\nkernel=15.0-CURRENT\nabi=FreeBSD:15:amd64\n",
                "",
            )

    monkeypatch.setenv("SMOKE_IMAGE_REF", "registry.example/pfsense-ce:2.8")
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    fake_vm = FakeVM()

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, fake_vm))

    assert fake_vm.calls == [((smoke_conftest.GUEST_IDENTITY_COMMAND,), 30.0)]
    assert capsys.readouterr().out.splitlines() == [
        "PFB_GUEST_IDENTITY image_ref=registry.example/pfsense-ce:2.8 expected_abi=FreeBSD:15:amd64",
        "PFB_GUEST_IDENTITY etc_version=2.8.1-RELEASE",
        "PFB_GUEST_IDENTITY versionpatch=0",
        "PFB_GUEST_IDENTITY kernel=15.0-CURRENT",
        "PFB_GUEST_IDENTITY abi=FreeBSD:15:amd64",
    ]


def test_boot_and_probe_logs_identity_after_boot_completion(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    events: list[str] = []
    live_helpers = importlib.import_module("tests.smoke.helpers")

    class FakeProcess:
        pid = 1234

        def poll(self) -> None:
            return None

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert argv[0:2] == ["sh", str(smoke_conftest.WAIT_READY_SH)]
        return subprocess.CompletedProcess(argv, 0, "boot-to-ready: 1 second\n", "")

    monkeypatch.setattr(smoke_conftest.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    monkeypatch.setattr(smoke_conftest.subprocess, "run", fake_run)
    monkeypatch.setattr(live_helpers, "wait_boot_complete", lambda vm: events.append("boot-complete"))
    monkeypatch.setattr(smoke_conftest, "_log_guest_identity", lambda vm: events.append("identity"), raising=False)

    handle = smoke_conftest.boot_and_probe(Path("base.qcow2"), "smoke-key", log_path=tmp_path / "vm.log")
    handle.log_file.close()

    assert events == ["boot-complete", "identity"]
