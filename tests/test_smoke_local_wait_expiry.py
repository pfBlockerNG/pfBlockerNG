from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from tests.smoke import test_hook_stream_visibility as hook
from tests.smoke import test_smoke_upstream_block as upstream
from tests.smoke import test_syslog_export as syslog


def test_upstream_lines_expiry_reports_expected_and_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upstream, "_read_dnsbl_log", lambda _vm: "tail line")
    with pytest.raises(RuntimeError, match=r"salvage cap expired / stuck or environment.*nonempty.*tail line"):
        upstream._wait_for_upstream_block_lines(
            cast(upstream.SmokeVM, object()), "example.invalid", timeout_s=0, poll_s=0
        )


def test_upstream_counter_expiry_reports_expected_and_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upstream, "_read_upstream_counter", lambda _vm: (3, "counter stayed at baseline"))
    with pytest.raises(RuntimeError, match=r"salvage cap expired / stuck or environment.*counter > 3.*3"):
        upstream._wait_for_counter_above(cast(upstream.SmokeVM, object()), 3, timeout_s=0, poll_s=0)


def test_syslog_event_expiry_reports_expected_and_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(syslog, "_pfb_event_lines", lambda _vm: ["new event line"])
    with pytest.raises(
        RuntimeError, match=r"salvage cap expired / stuck or environment.*want.*missing.*new event line"
    ):
        syslog._wait_for_event(
            cast(syslog.SmokeVM, object()),
            baseline_len=0,
            want=("missing",),
            any_of=("act=block",),
            timeout=0,
            interval=0,
        )


def test_guest_file_expiry_reports_command_result() -> None:
    vm = SimpleNamespace(
        ssh=lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="no file", stderr="not found")
    )
    with pytest.raises(
        RuntimeError, match=r"salvage cap expired / stuck or environment.*guest file.*example.*rc=1.*no file.*not found"
    ):
        hook._wait_for_guest_file(cast(hook.SmokeVM, vm), "/tmp/example", deadline_s=0, poll_s=0)


def test_upgrade_expiry_reports_expected_and_observed() -> None:
    vm = SimpleNamespace(ssh=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="pid 123", stderr=""))
    with pytest.raises(RuntimeError, match=r"salvage cap expired / stuck or environment.*pgrep.*rc=0.*pid 123"):
        hook._wait_upgrade_gone(cast(hook.SmokeVM, vm), deadline_s=0, poll_s=0)


def test_upgrade_wait_rejects_transport_status_as_gone() -> None:
    vm = SimpleNamespace(ssh=lambda *_args, **_kwargs: SimpleNamespace(returncode=255, stdout="", stderr="ssh failed"))

    with pytest.raises(
        RuntimeError,
        match=r"salvage cap expired / stuck or environment.*pgrep.*rc=255.*ssh failed",
    ):
        hook._wait_upgrade_gone(cast(hook.SmokeVM, vm), deadline_s=0, poll_s=0)


def test_hook_cleanup_preserves_primary_failure_and_finishes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def ssh(*args: str, **_kwargs: object) -> SimpleNamespace:
        calls.append(args[0])
        return SimpleNamespace(returncode=0)

    vm = SimpleNamespace(ssh=ssh)

    def expire(*_args: object, **_kwargs: object) -> None:
        calls.append("wait")
        raise RuntimeError("salvage cap expired / stuck or environment: upgrade still running")

    monkeypatch.setattr(hook, "_wait_upgrade_gone", expire)
    monkeypatch.setattr(hook.h, "clear_update_hooks", lambda _vm: calls.append("clear"))
    monkeypatch.setattr(hook, "pkg_delete", lambda _vm: calls.append("delete"))
    monkeypatch.setattr(hook, "repo_priority", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(hook, "write_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hook, "pkg_update", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hook, "pkg_installed_version", lambda *_args, **_kwargs: "already installed")

    with pytest.raises(AssertionError, match="unexpectedly present") as caught:
        hook.test_hook_output_streams_to_gui_while_running(cast(hook.SmokeVM, vm))

    assert calls == ["delete", "/usr/bin/touch", "wait", "clear", "/bin/rm"]
    assert any("salvage cap expired" in note for note in getattr(caught.value, "__notes__", ()))


def test_hook_cleanup_expiry_is_loud_after_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def ssh(*args: str, **_kwargs: object) -> SimpleNamespace:
        calls.append(args[0])
        return SimpleNamespace(returncode=0)

    vm = SimpleNamespace(ssh=ssh)

    def expire(*_args: object, **_kwargs: object) -> None:
        calls.append("wait")
        raise RuntimeError("salvage cap expired / stuck or environment: upgrade still running")

    monkeypatch.setattr(hook, "_wait_upgrade_gone", expire)
    monkeypatch.setattr(hook.h, "clear_update_hooks", lambda _vm: calls.append("clear"))
    monkeypatch.setattr(hook, "pkg_delete", lambda _vm: calls.append("delete"))

    with pytest.raises(RuntimeError, match="salvage cap expired / stuck or environment"):
        hook._cleanup_hook_run(cast(hook.SmokeVM, vm))

    assert calls == ["/usr/bin/touch", "wait", "clear", "/bin/rm"]


def test_hook_cleanup_preserves_primary_when_hook_reset_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def ssh(*args: str, **_kwargs: object) -> SimpleNamespace:
        calls.append(args[0])
        return SimpleNamespace(returncode=0)

    vm = SimpleNamespace(ssh=ssh)
    monkeypatch.setattr(hook, "_wait_upgrade_gone", lambda *_args, **_kwargs: calls.append("wait"))

    def fail_clear(_vm: object) -> None:
        calls.append("clear")
        raise RuntimeError("hook reset failed")

    monkeypatch.setattr(hook.h, "clear_update_hooks", fail_clear)
    monkeypatch.setattr(hook, "pkg_delete", lambda _vm: calls.append("delete"))
    monkeypatch.setattr(hook, "repo_priority", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(hook, "write_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hook, "pkg_update", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hook, "pkg_installed_version", lambda *_args, **_kwargs: "already installed")

    with pytest.raises(AssertionError, match="unexpectedly present") as caught:
        hook.test_hook_output_streams_to_gui_while_running(cast(hook.SmokeVM, vm))

    assert calls == ["delete", "/usr/bin/touch", "wait", "clear", "/bin/rm", "delete"]
    assert any("hook reset failed" in note for note in getattr(caught.value, "__notes__", ()))


@pytest.mark.parametrize("failure_stage", ["touch", "wait"])
def test_hook_cleanup_preserves_primary_on_transport_failure(
    monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    calls: list[str] = []

    def ssh(*args: str, **_kwargs: object) -> SimpleNamespace:
        calls.append(args[0])
        if failure_stage == "touch" and args[0] == "/usr/bin/touch":
            raise OSError("touch transport failed")
        return SimpleNamespace(returncode=0)

    def wait(*_args: object, **_kwargs: object) -> None:
        calls.append("wait")
        if failure_stage == "wait":
            raise TimeoutError("wait transport failed")

    vm = SimpleNamespace(ssh=ssh)
    monkeypatch.setattr(hook, "_wait_upgrade_gone", wait)
    monkeypatch.setattr(hook.h, "clear_update_hooks", lambda _vm: calls.append("clear"))
    monkeypatch.setattr(hook, "pkg_delete", lambda _vm: calls.append("delete"))

    with pytest.raises(AssertionError, match="primary failure") as caught:
        try:
            raise AssertionError("primary failure")
        finally:
            hook._cleanup_hook_run(cast(hook.SmokeVM, vm))

    expected = ["/usr/bin/touch", "clear", "/bin/rm"]
    if failure_stage == "wait":
        expected.insert(1, "wait")
    assert calls == expected
    assert any(f"{failure_stage} transport failed" in note for note in getattr(caught.value, "__notes__", ()))
