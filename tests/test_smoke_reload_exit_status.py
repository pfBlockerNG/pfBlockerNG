"""Hermetic contract tests for ``tests.smoke.helpers.reload`` CLI status handling."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

import pytest

from tests.smoke import helpers


@dataclass
class _FakeResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class _FakeVM:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    commands: list[tuple[str, ...]] = field(default_factory=list)
    vm_pid: int | None = 123
    host: str = "127.0.0.1"

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        self.commands.append(remote)
        if remote and remote[0] == helpers.PHP_BIN:
            return _FakeResult(self.returncode, self.stdout, self.stderr)
        raise AssertionError(f"reload performed unexpected guest I/O: {remote!r}")


def _reload(
    vm: _FakeVM,
    scope: str = "update",
    *,
    timeout: float = 600.0,
    retry_deferred: float = 0.0,
) -> None:
    helpers.reload(
        cast(helpers.SmokeVM, vm),
        scope,
        wait_unbound=False,
        timeout=timeout,
        retry_deferred=retry_deferred,
    )


@pytest.fixture(autouse=True)
def _exclusive_core(monkeypatch: pytest.MonkeyPatch) -> None:
    def view(vm: _FakeVM, *_args: object, **_kwargs: object) -> dict[str, object]:
        scope = "both"
        force = "none"
        if vm.commands:
            command = vm.commands[-1]
            if "scope=ip" in command or "updateip" in command:
                scope, force = "ip", "download"
            elif "scope=dnsbl" in command or "updatednsbl" in command:
                scope, force = "dnsbl", "download"
        return _view(scope=scope, force=force)

    monkeypatch.setattr(helpers, "core_update_view", view)
    monkeypatch.setattr(helpers, "_php_read_scalar", lambda *_args, **_kwargs: "[null, null]")


def _view(
    *,
    running: bool = False,
    result: str = "success",
    scope: str = "both",
    force: str = "none",
    trigger: str = "manual",
) -> dict[str, object]:
    return {
        "running": running,
        "update": {
            "trigger": trigger,
            "scope": scope,
            "force": force,
            "result": result,
            "startedAt": 1,
            "finishedAt": 1,
        },
        "next": "opaque",
        "log": "",
    }


def test_clean_exit_is_accepted_without_pass_marker_log_scraping() -> None:
    vm = _FakeVM(returncode=0)

    _reload(vm)

    assert vm.commands == [
        (helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", "scope=both", "force=false", "trigger=manual")
    ]


@pytest.mark.parametrize("reason", ["dispatcher lock is held", "feed-pass lock is held"])
def test_lock_deferral_fails_immediately_with_precise_stderr_reason(reason: str) -> None:
    stderr = f"pfBlockerNG feed pass deferred: {reason}\n"
    vm = _FakeVM(returncode=75, stderr=stderr)

    with pytest.raises(RuntimeError) as excinfo:
        helpers.reload(cast(helpers.SmokeVM, vm), "update")

    assert str(excinfo.value) == f"reload(update) deferred (rc=75): {stderr.strip()}"
    assert vm.commands == [
        (helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", "scope=both", "force=false", "trigger=manual")
    ]


def test_lock_deferral_does_not_wait_for_swap_or_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    counted_markers: list[str | tuple[str, ...]] = []

    def count_marker(_vm: object, _path: str, marker: str | tuple[str, ...]) -> int:
        counted_markers.append(marker)
        return 0

    monkeypatch.setattr(helpers, "count_log_marker", count_marker)
    monkeypatch.setattr(
        helpers,
        "wait_zero_downtime_swap",
        lambda *_args, **_kwargs: pytest.fail("rc=75 must fail before the zero-downtime swap wait"),
    )
    monkeypatch.setattr(
        helpers,
        "wait_unbound_ready",
        lambda *_args, **_kwargs: pytest.fail("rc=75 must fail before the resolver readiness wait"),
    )
    vm = _FakeVM(returncode=75, stderr="pfBlockerNG feed pass deferred: feed-pass lock is held\n")

    with pytest.raises(RuntimeError, match=r"^reload\(update\) deferred \(rc=75\): .*feed-pass lock is held$"):
        helpers.reload(cast(helpers.SmokeVM, vm), "update", data_path=True, timeout=30.0)

    assert counted_markers == [helpers.SWAP_LOG_MARKER]


def test_real_failure_preserves_generic_diagnostic() -> None:
    vm = _FakeVM(returncode=1, stdout="fatal output", stderr="real failure\n")

    with pytest.raises(RuntimeError) as excinfo:
        _reload(vm, "updateip")

    assert str(excinfo.value) == "reload(updateip) failed: rc=1 stdout='fatal output' stderr='real failure\\n'"
    assert vm.commands == [(helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", "scope=ip", "force=true", "trigger=force")]


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("update", ("scope=both", "force=false", "trigger=manual")),
        ("updateip", ("scope=ip", "force=true", "trigger=force")),
        ("updatednsbl", ("scope=dnsbl", "force=true", "trigger=force")),
    ],
)
def test_trigger_shape_is_unchanged(scope: str, expected: tuple[str, ...]) -> None:
    vm = _FakeVM(returncode=0)

    _reload(vm, scope)

    assert vm.commands == [(helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", *expected)]


@pytest.mark.parametrize("scope", ["scheduled", "cron", "retry", "both", ""])
def test_unsupported_scope_never_reaches_guest_transport(scope: str, monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _FakeVM()
    monkeypatch.setattr(helpers, "core_update_view", lambda *_a, **_k: pytest.fail("invalid scope read Core"))
    monkeypatch.setattr(helpers, "count_log_marker", lambda *_a, **_k: pytest.fail("invalid scope read a log"))

    with pytest.raises(ValueError, match="reload scope"):
        helpers.reload(cast(helpers.SmokeVM, vm), scope, data_path=True)

    assert vm.commands == []


@pytest.mark.parametrize("scope", ["scheduled", "update", "tick"])
def test_retired_feeds_argument_never_reaches_guest_transport(scope: str) -> None:
    vm = _FakeVM()
    request: dict[str, Any] = {"feeds": ["dnsbl:smokefeed"]}
    with pytest.raises(TypeError, match="feeds"):
        helpers.reload(cast(helpers.SmokeVM, vm), scope, **request)
    assert vm.commands == []


@pytest.mark.parametrize("result", ["failed", "skipped"])
def test_terminal_non_success_is_not_cli_success(monkeypatch: pytest.MonkeyPatch, result: str) -> None:
    vm = _FakeVM()
    views = iter([_view(), _view(result=result)])
    monkeypatch.setattr(helpers, "core_update_view", lambda *_a, **_k: next(views))
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda *_a, **_k: pytest.fail("not completed"))
    with pytest.raises(RuntimeError, match=result):
        helpers.reload(cast(helpers.SmokeVM, vm))


@pytest.mark.parametrize("kwargs", [{}, {"wait_unbound": False}, {"data_path": True}])
def test_completion_precedes_readiness_and_pf_only_return(monkeypatch: pytest.MonkeyPatch, kwargs: dict) -> None:
    vm = _FakeVM()
    events: list[str] = []
    views = iter([_view(), _view(running=True), _view()])

    def view(*_a: object, **_k: object) -> dict[str, object]:
        value = next(views)
        events.append("running" if value["running"] else "terminal")
        return value

    monkeypatch.setattr(helpers, "core_update_view", view)
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a: None)
    monkeypatch.setattr(helpers, "count_log_marker", lambda *_a: 4)
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda *_a, **_k: events.append("ready"))
    monkeypatch.setattr(helpers, "wait_zero_downtime_swap", lambda *_a, **_k: events.append("swap"))
    monkeypatch.setattr(helpers, "_require_pfb_dns_serving", lambda *_a: events.append("proxy"))
    helpers.reload(cast(helpers.SmokeVM, vm), **kwargs)
    assert events[:3] == ["terminal", "running", "terminal"]
    assert events[3:] == (
        ["swap", "proxy"]
        if kwargs.get("data_path")
        else []
        if kwargs.get("wait_unbound") is False
        else ["ready", "proxy"]
    )


@pytest.mark.parametrize("change", [{"scope": "ip"}, {"force": "download"}, {"trigger": "apply"}])
def test_competing_request_fails(monkeypatch: pytest.MonkeyPatch, change: dict) -> None:
    views = iter([_view(), _view(**change)])
    monkeypatch.setattr(helpers, "core_update_view", lambda *_a, **_k: next(views))
    with pytest.raises(RuntimeError, match="exclusive|unexpected"):
        _reload(_FakeVM())


def test_busy_preflight_never_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _FakeVM()
    monkeypatch.setattr(helpers, "core_update_view", lambda *_a, **_k: _view(running=True))
    with pytest.raises(RuntimeError, match="running|busy"):
        _reload(vm)
    assert vm.commands == []


def test_same_second_equal_status_is_valid_after_admission() -> None:
    _reload(_FakeVM())


def test_expired_watchdog_never_dispatches() -> None:
    vm = _FakeVM()
    with pytest.raises(RuntimeError, match="STUCK|timeout|budget"):
        _reload(vm, timeout=0)
    assert vm.commands == []


@pytest.mark.parametrize("verb", ["update", "updateip", "updatednsbl"])
@pytest.mark.parametrize("result", ["success", "failed", "skipped"])
def test_deprecated_waits_for_terminal(monkeypatch: pytest.MonkeyPatch, verb: str, result: str) -> None:
    vm = _FakeVM()
    scope = {"update": "both", "updateip": "ip", "updatednsbl": "dnsbl"}[verb]
    views = iter([_view(), _view(scope=scope, force="none" if verb == "update" else "download", result=result)])
    events: list[str] = []
    monkeypatch.setattr(helpers, "core_update_view", lambda *_a, **_k: next(views))
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda *_a, **_k: events.append("ready"))
    if result == "success":
        helpers.reload_deprecated_verb(cast(helpers.SmokeVM, vm), verb)
        assert events == ["ready"]
    else:
        with pytest.raises(RuntimeError, match=result):
            helpers.reload_deprecated_verb(cast(helpers.SmokeVM, vm), verb)
        assert events == []
    assert vm.commands == [(helpers.PHP_BIN, helpers.PFB_CLI, verb)]


def test_idle_tick_does_not_wait_for_nonexistent_admission() -> None:
    vm = _FakeVM()
    _reload(vm, "tick")
    assert vm.commands == [(helpers.PHP_BIN, helpers.PFB_CLI, "tick")]


def test_pending_saved_version_must_settle_before_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "_php_read_scalar", lambda *_a, **_k: '["saved", "older"]')
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda *_a, **_k: pytest.fail("pending saved state"))
    with pytest.raises(RuntimeError, match="pending|settled"):
        helpers.reload(cast(helpers.SmokeVM, _FakeVM()))


@pytest.mark.parametrize("kind", ["cli", "skipped"])
def test_deferral_retry_is_bounded_and_can_succeed(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    vm = _FakeVM(returncode=75 if kind == "cli" else 0)
    commands = vm.ssh

    def ssh(*args: str, **kwargs: float) -> _FakeResult:
        reply = commands(*args, **kwargs)
        vm.returncode = 0
        return reply

    monkeypatch.setattr(vm, "ssh", ssh)
    views = iter([_view(), _view(result="skipped"), _view(), _view()]) if kind == "skipped" else None
    if views is not None:
        monkeypatch.setattr(helpers, "core_update_view", lambda *_a, **_k: next(views))
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a: None)
    _reload(vm, retry_deferred=5)
    assert len(vm.commands) == 2


@pytest.mark.parametrize("result", ["skipped", "cli"])
def test_deferral_retry_exhaustion_remains_loud(monkeypatch: pytest.MonkeyPatch, result: str) -> None:
    vm = _FakeVM(returncode=75 if result == "cli" else 0)
    views = iter([_view(), _view(result="skipped"), _view(), _view(result="skipped")])
    monkeypatch.setattr(helpers, "core_update_view", lambda *_a, **_k: next(views))
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a: None)
    with pytest.raises(RuntimeError, match="deferred|skipped"):
        _reload(vm, retry_deferred=5)
    assert len(vm.commands) == 2


@pytest.mark.parametrize("owned", [False, True])
def test_only_owned_loopback_disposable_vm_is_accepted(owned: bool) -> None:
    vm = _FakeVM()
    if owned:
        vm.host = "firewall"
    else:
        vm.vm_pid = None
    with pytest.raises(RuntimeError, match="disposable|exclusive|loopback"):
        _reload(vm)
    assert vm.commands == []


def test_saved_version_is_observed_settled(monkeypatch: pytest.MonkeyPatch) -> None:
    states = iter(['["saved", "older"]', '["saved", "saved"]'])
    monkeypatch.setattr(helpers, "_php_read_scalar", lambda *_a, **_k: next(states))
    _reload(_FakeVM())


@pytest.mark.parametrize("mode", ["ready", "swap", "update", "updateip", "updatednsbl"])
def test_remaining_budget_reaches_external_boundaries(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    vm = _FakeVM()
    now = [0.0]
    budgets: list[tuple[str, float]] = []
    scope = {"updateip": "ip", "updatednsbl": "dnsbl"}.get(mode, "both")
    force = "download" if scope != "both" else "none"

    def record(name: str, timeout: float) -> None:
        budgets.append((name, timeout))
        now[0] += 1

    def core(_vm: object, *, timeout: float = 60) -> dict[str, object]:
        record("core", timeout)
        return _view(scope=scope, force=force)

    def marker(_vm: object, _pre: str, _expr: str, *, timeout: float = 60) -> str:
        record("marker", timeout)
        return '["saved", "saved"]'

    def ssh(*_args: str, timeout: float = 60) -> _FakeResult:
        record("cli", timeout)
        return _FakeResult(0)

    def ready(_vm: object, *, timeout: float = 120) -> None:
        record("ready", timeout)

    def swap(_vm: object, *, since: int, timeout: float = 60) -> None:
        assert since == 4
        record("swap", timeout)

    monkeypatch.setattr(helpers.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(helpers, "core_update_view", core)
    monkeypatch.setattr(helpers, "_php_read_scalar", marker)
    monkeypatch.setattr(vm, "ssh", ssh)
    monkeypatch.setattr(helpers, "count_log_marker", lambda *_a: 4)
    monkeypatch.setattr(helpers, "wait_unbound_ready", ready)
    monkeypatch.setattr(helpers, "wait_zero_downtime_swap", swap)
    monkeypatch.setattr(helpers, "_require_pfb_dns_serving", lambda *_a: None)
    if mode in ("ready", "swap"):
        helpers.reload(cast(helpers.SmokeVM, vm), timeout=20, data_path=mode == "swap")
    else:
        helpers.reload_deprecated_verb(cast(helpers.SmokeVM, vm), mode, timeout=20)
    names = ["core", "marker", "cli", "core", "marker"] if scope == "both" else ["core", "cli", "core"]
    names.append("swap" if mode == "swap" else "ready")
    assert budgets == [(name, 20 - index) for index, name in enumerate(names)]


@pytest.mark.parametrize("mode", ["ready", "swap", "deprecated"])
def test_completion_spending_remaining_budget_fails_before_readiness(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    now = [0.0]
    budgets: list[float] = []
    vm = _FakeVM()

    def core(_vm: object, *, timeout: float = 60) -> dict[str, object]:
        budgets.append(timeout)
        now[0] += 1 if len(budgets) == 1 else 9
        return _view(scope="ip", force="download")

    def ssh(*_args: str, timeout: float = 60) -> _FakeResult:
        assert timeout == 9
        return _FakeResult(0)

    monkeypatch.setattr(helpers.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(helpers, "core_update_view", core)
    monkeypatch.setattr(vm, "ssh", ssh)
    monkeypatch.setattr(helpers, "count_log_marker", lambda *_a: 4)
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda *_a, **_k: pytest.fail("expired before readiness"))
    monkeypatch.setattr(helpers, "wait_zero_downtime_swap", lambda *_a, **_k: pytest.fail("expired before swap"))
    monkeypatch.setattr(helpers, "_require_pfb_dns_serving", lambda *_a: pytest.fail("expired before proxy"))
    with pytest.raises(RuntimeError, match="STUCK: reload timeout budget exhausted"):
        if mode == "deprecated":
            helpers.reload_deprecated_verb(cast(helpers.SmokeVM, vm), "updateip", timeout=10)
        else:
            helpers.reload(cast(helpers.SmokeVM, vm), "updateip", timeout=10, data_path=mode == "swap")
    assert budgets == [10, 9]
