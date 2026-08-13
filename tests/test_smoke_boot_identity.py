"""Issue #2297: every live-VM boot reports guest identity before deployment."""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

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
                "etc_version=2.8.1-RELEASE\nversionpatch=0\n"
                "kernel_release=15.0-CURRENT\nkernel_version=FreeBSD 15 build\n"
                "abi=FreeBSD:15:amd64\n",
                "",
            )

    monkeypatch.setenv("SMOKE_IMAGE_REF", "registry.example/pfsense-ce:2.8")
    monkeypatch.setenv("SMOKE_PFSENSE_VERSION", "2.8")
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    fake_vm = FakeVM()

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, fake_vm))

    assert fake_vm.calls == [((smoke_conftest.GUEST_IDENTITY_COMMAND,), 30.0)]
    assert capsys.readouterr().out.splitlines() == [
        "PFB_GUEST_IDENTITY image_ref=registry.example/pfsense-ce:2.8 "
        "expected_version=2.8 expected_abi=FreeBSD:15:amd64",
        "PFB_GUEST_IDENTITY etc_version=2.8.1-RELEASE",
        "PFB_GUEST_IDENTITY versionpatch=0",
        "PFB_GUEST_IDENTITY kernel_release=15.0-CURRENT",
        "PFB_GUEST_IDENTITY kernel_version=FreeBSD 15 build",
        "PFB_GUEST_IDENTITY abi=FreeBSD:15:amd64",
    ]
    assert "/bin/cat /etc/version" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/bin/cat /etc/versionpatch" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/usr/bin/uname -r" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/usr/bin/uname -v" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/usr/local/sbin/pkg config ABI" in smoke_conftest.GUEST_IDENTITY_COMMAND


def test_log_guest_identity_failure_is_loud_and_read_only() -> None:
    class FailingVM:
        def __init__(self) -> None:
            self.calls: list[tuple[tuple[str, ...], float]] = []

        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            self.calls.append((remote, timeout))
            return subprocess.CompletedProcess(remote, 7, "partial-fact\n", "probe-failed\n")

    fake_vm = FailingVM()
    with pytest.raises(RuntimeError, match=r"guest identity probe failed \(rc=7\)") as exc_info:
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, fake_vm))

    assert "partial-fact" in str(exc_info.value)
    assert "probe-failed" in str(exc_info.value)
    assert fake_vm.calls == [((smoke_conftest.GUEST_IDENTITY_COMMAND,), 30.0)]


def test_log_guest_identity_empty_output_is_loud() -> None:
    class EmptyVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(remote, 0, "", "")

    with pytest.raises(RuntimeError, match=r"guest identity probe failed \(rc=0\)"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, EmptyVM()))


def test_successful_deploy_emits_installer_diagnostics(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    live_helpers = importlib.import_module("tests.smoke.helpers")
    pkg = tmp_path / "package.pkg"
    pkg.write_bytes(b"pkg")

    class FakeVM:
        ssh_target = "root@127.0.0.1"
        ssh_port = 2222
        ssh_key_path = "smoke-key"

        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(remote, 0, "", "")

    monkeypatch.setattr(
        live_helpers.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "PFB_PKG_CONTEXT absolute_abi=FreeBSD:15:amd64\n", "installer-warning\n"
        ),
    )
    monkeypatch.setattr(
        live_helpers,
        "php_eval",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "OK", ""),
    )

    live_helpers.deploy(cast(Any, FakeVM()), str(pkg))

    captured = capsys.readouterr()
    assert "PFB_PKG_CONTEXT absolute_abi=FreeBSD:15:amd64" in captured.out
    assert "installer-warning" in captured.err


@pytest.mark.parametrize(
    ("workflow", "job", "expected_version", "expected_abi"),
    [
        ("ui-tests.yml", "ui", "${{ matrix.version }}", "FreeBSD:${{ matrix.freebsd_major }}:amd64"),
        ("smoke-single.yml", "smoke", "${{ inputs.pfsense_version }}", "${{ inputs.abi }}"),
    ],
)
def test_live_workflows_export_expected_guest_identity(
    workflow: str, job: str, expected_version: str, expected_abi: str
) -> None:
    doc = yaml.safe_load((Path(__file__).parents[1] / ".github" / "workflows" / workflow).read_text())
    step = next(item for item in doc["jobs"][job]["steps"] if str(item.get("name", "")).startswith("Run the "))
    assert step["env"]["SMOKE_PFSENSE_VERSION"] == expected_version
    assert step["env"]["SMOKE_ABI"] == expected_abi


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
    monkeypatch.setattr(live_helpers, "_write_cron_disable_flag", lambda vm: events.append("cron-disabled"))
    monkeypatch.setattr(smoke_conftest, "_log_guest_identity", lambda vm: events.append("identity"), raising=False)

    handle = smoke_conftest.boot_and_probe(Path("base.qcow2"), "smoke-key", log_path=tmp_path / "vm.log")
    handle.log_file.close()

    assert events == ["boot-complete", "cron-disabled", "identity"]


def test_smoke_vm_refuses_cron_disable_sentinel_removal(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(smoke_conftest.subprocess, "run", fake_run)
    vm = smoke_conftest.SmokeVM("smoke-key", "127.0.0.1", 2222, 8080, 5353)

    with pytest.raises(RuntimeError, match="scheduled ticks must stay disabled"):
        vm.ssh("rm", "-f", "/var/db/pfblockerng/.pfb_cron_disable")

    assert not called, "the forbidden removal must be rejected before SSH runs"


def test_cron_disable_guard_persists_across_guest_reboots(monkeypatch: pytest.MonkeyPatch) -> None:
    live_helpers = importlib.import_module("tests.smoke.helpers")
    snippets: list[str] = []

    class FakeVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(remote, 0, "", "")

    def fake_php_eval(vm: object, snippet: str, *, timeout: float) -> subprocess.CompletedProcess[str]:
        snippets.append(snippet)
        return subprocess.CompletedProcess(snippet, 0, "OK", "")

    monkeypatch.setattr(live_helpers, "php_eval", fake_php_eval)
    live_helpers._write_cron_disable_flag(cast(Any, FakeVM()))

    assert len(snippets) == 1
    assert "system/earlyshellcmd" in snippets[0]
    assert "/var/db/pfblockerng/.pfb_cron_disable" in snippets[0]
