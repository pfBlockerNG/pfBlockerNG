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
                "abi=FreeBSD:15:amd64\nfreebsd_version=15.0-CURRENT\n"
                "pkg_client=1.21.3\npkg_pkg=1.21.3_8\n",
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
        "PFB_GUEST_IDENTITY freebsd_version=15.0-CURRENT",
        "PFB_GUEST_IDENTITY pkg_client=1.21.3",
        "PFB_GUEST_IDENTITY pkg_pkg=1.21.3_8",
    ]
    assert "/bin/cat /etc/version" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/bin/cat /etc/versionpatch" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/usr/bin/uname -r" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/usr/bin/uname -v" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/usr/local/sbin/pkg config ABI" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/bin/freebsd-version" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/usr/local/sbin/pkg -v" in smoke_conftest.GUEST_IDENTITY_COMMAND
    assert "/usr/local/sbin/pkg query %v pkg" in smoke_conftest.GUEST_IDENTITY_COMMAND


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


class _IdentityVM:
    """A guest whose ssh(...) always returns the given identity probe stdout."""

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        self.calls.append((remote, timeout))
        return subprocess.CompletedProcess(remote, 0, self._stdout, "")


def _identity_stdout(
    abi_line: str | None,
    *,
    freebsd_version_line: str = "freebsd_version=15.0-CURRENT",
    kernel_release_line: str = "kernel_release=15.0-CURRENT",
    pkg_client_line: str = "pkg_client=1.21.3",
    pkg_pkg_line: str = "pkg_pkg=1.21.3_8",
) -> str:
    """Row-2/row-3 fields default to values consistent with the SMOKE_ABI major most
    tests here use (15), so an abi-focused fixture doesn't accidentally trip rows 2/3."""
    lines = [
        "etc_version=2.8.1-RELEASE",
        "versionpatch=0",
        kernel_release_line,
        "kernel_version=FreeBSD 15 build",
    ]
    if abi_line is not None:
        lines.append(abi_line)
    lines += [freebsd_version_line, pkg_client_line, pkg_pkg_line]
    return "\n".join(lines) + "\n"


def test_log_guest_identity_allows_pkg_abi_drift_when_userland_major_matches(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """issue #2730: rc.update_pkg_metadata can flip `pkg config ABI` to 16
    on a CE 2.8 guest whose kernel and freebsd-version stay 15.0-CURRENT.

    Row 2 (userland major) is the wrong-image abort. A parseable pkg-ABI drift
    with a matching userland must not refuse the boot — install-pkg.sh then
    adds with ``pkg -o ABI=$SMOKE_ABI``.
    """
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:16:amd64"))

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))  # must not raise

    printed = capsys.readouterr().out
    assert "PFB_GUEST_IDENTITY abi=FreeBSD:16:amd64" in printed
    assert "PFB_GUEST_IDENTITY freebsd_version=15.0-CURRENT" in printed
    assert "forcing_add_abi=FreeBSD:15:amd64" in printed


def test_log_guest_identity_refuses_when_userland_major_moved_with_pkg_abi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """issue #2730 escalation: a 16 userland plus a 16 pkg ABI is not agreement.

    Drift-allow is only when freebsd-version stays on the matrix major. Row 2
    still refuses a real OS upgrade, even if pkg config ABI matches that upgrade.
    """
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:16:amd64", freebsd_version_line="freebsd_version=16.0-CURRENT"))

    with pytest.raises(RuntimeError, match=r"freebsd-version") as exc_info:
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))

    assert "16.0-CURRENT" in str(exc_info.value)
    assert "FreeBSD:15:amd64" in str(exc_info.value)


@pytest.mark.parametrize("abi_line", ["abi=Linux:16:amd64", "abi=Debian:16:amd64"])
def test_log_guest_identity_refuses_foreign_os_name(monkeypatch: pytest.MonkeyPatch, abi_line: str) -> None:
    """issue #2730: drift-allow is FreeBSD major only, not a foreign OS name."""
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout(abi_line))

    with pytest.raises(RuntimeError, match=r"OS name"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


def test_log_guest_identity_refuses_kernel_major_mismatch_even_when_userland_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """issue #2730: a 16 kernel is not config-ABI drift, even if freebsd-version stays 15."""
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(
        _identity_stdout(
            "abi=FreeBSD:16:amd64",
            kernel_release_line="kernel_release=16.0-CURRENT",
        )
    )

    with pytest.raises(RuntimeError, match=r"kernel"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


@pytest.mark.parametrize(
    "abi_line",
    [
        "abi=",
        "abi= ",
        "abi=?",
        "abi=FreeBSD:",
        "abi=FreeBSD:x:amd64",
        "abi=not-an-abi",
        "abi=FreeBSD",
    ],
)
def test_log_guest_identity_refuses_unreadable_pkg_abi(monkeypatch: pytest.MonkeyPatch, abi_line: str) -> None:
    """issue #2730: unreadable/placeholder pkg ABI fails closed, not as drift."""
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout(abi_line))

    with pytest.raises(RuntimeError, match=r"unreadable pkg ABI"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


def test_log_guest_identity_allows_matching_abi_os_major(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:15:amd64"))

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))  # must not raise


def test_log_guest_identity_skips_check_when_smoke_abi_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SMOKE_ABI", raising=False)
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:16:amd64"))

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))  # must not raise


def test_log_guest_identity_treats_empty_smoke_abi_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:16:amd64"))

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))  # must not raise


def test_log_guest_identity_raises_on_abi_fallback_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=?"))

    with pytest.raises(RuntimeError, match=r"FreeBSD:15:amd64"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


def test_log_guest_identity_allows_arch_only_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    # arch is not compared; OS name and numeric major still must match (issue #2730)
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:15:aarch64"))

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))  # must not raise


def test_log_guest_identity_raises_when_abi_line_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout(None))

    with pytest.raises(RuntimeError, match=r"FreeBSD:15:amd64"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


def test_log_guest_identity_raises_on_garbage_smoke_abi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "garbage")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:15:amd64"))

    with pytest.raises(RuntimeError, match=r"garbage"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


# --- row 2: /bin/freebsd-version major vs SMOKE_ABI major (owner residual table) ---


def test_log_guest_identity_raises_on_freebsd_version_major_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:15:amd64", freebsd_version_line="freebsd_version=16.0-CURRENT"))

    with pytest.raises(RuntimeError, match=r"freebsd-version") as exc_info:
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))

    assert "16.0-CURRENT" in str(exc_info.value)
    assert "FreeBSD:15:amd64" in str(exc_info.value)


def test_log_guest_identity_raises_on_freebsd_version_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:15:amd64", freebsd_version_line="freebsd_version=?"))

    with pytest.raises(RuntimeError, match=r"freebsd-version"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


def test_log_guest_identity_allows_matching_freebsd_version_major(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    # a patch-level difference on the same major must not raise
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:15:amd64", freebsd_version_line="freebsd_version=15.1-RELEASE"))

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))  # must not raise


# --- row 3: pkg client major vs the installed pkg package's own major ---


def test_log_guest_identity_raises_on_pkg_client_major_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(
        _identity_stdout("abi=FreeBSD:15:amd64", pkg_client_line="pkg_client=2.7.5", pkg_pkg_line="pkg_pkg=1.21.3_8")
    )

    with pytest.raises(
        RuntimeError,
        match=r"pkg client 2\.7\.5 does not match the installed pkg package 1\.21\.3_8",
    ):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


def test_log_guest_identity_allows_matching_pkg_client_major(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    # a patch-level difference on the same major must not raise
    vm = _IdentityVM(
        _identity_stdout("abi=FreeBSD:15:amd64", pkg_client_line="pkg_client=1.21.3", pkg_pkg_line="pkg_pkg=1.21.4_1")
    )

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))  # must not raise


def test_log_guest_identity_raises_on_pkg_client_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:15:amd64", pkg_client_line="pkg_client=?"))

    with pytest.raises(RuntimeError, match=r"pkg client"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


def test_log_guest_identity_raises_on_pkg_pkg_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_ABI", "FreeBSD:15:amd64")
    vm = _IdentityVM(_identity_stdout("abi=FreeBSD:15:amd64", pkg_pkg_line="pkg_pkg=?"))

    with pytest.raises(RuntimeError, match=r"pkg client"):
        smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))


def test_log_guest_identity_skips_rows_2_and_3_when_smoke_abi_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SMOKE_ABI", raising=False)
    vm = _IdentityVM(
        _identity_stdout(
            "abi=FreeBSD:16:amd64",
            freebsd_version_line="freebsd_version=99.0-CURRENT",
            pkg_client_line="pkg_client=9.9.9",
            pkg_pkg_line="pkg_pkg=1.1.1",
        )
    )

    smoke_conftest._log_guest_identity(cast(smoke_conftest.SmokeVM, vm))  # must not raise


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
