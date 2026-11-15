"""Owned, exclusive-client Update capture through the real smoke helper/API adapters."""

from __future__ import annotations

from collections import deque
from typing import Any, cast

import pytest

from tests.smoke import test_core_update as capture


def status(**changes: Any) -> dict[str, Any]:
    return {
        "trigger": "manual",
        "scope": "both",
        "force": "none",
        "startedAt": 100,
        "finishedAt": 100,
        "result": "success",
        **changes,
    }


def view(update: dict[str, Any], log: str = "", next_: str = "opaque end", *, running: bool = False) -> dict[str, Any]:
    return {"running": running, "update": update, "log": log, "next": next_}


class UpdateAPI:
    """An ordered external API transcript; cursor strings have no interpreted structure."""

    def __init__(
        self,
        pages: list[tuple[str | None, dict[str, Any]]],
        *,
        before: dict[str, Any] | None = None,
        trigger: str = "manual",
        scope: str = "both",
        busy: bool = False,
    ) -> None:
        self.pages = deque(pages)
        self.before = before if before is not None else status(startedAt=99, finishedAt=99)
        self.params = (
            {"trigger": trigger, "scope": scope, "force": "none"} if trigger == "manual" else {"trigger": trigger}
        )
        self.events: list[str] = []
        self.started = False
        self.busy = busy

    def calls(
        self, vm: capture.SmokeVM, calls: list[tuple[str, dict[str, Any] | None]], *, timeout: float = 60.0
    ) -> list[dict[str, Any]]:
        assert timeout == 60.0, "keep the bounded Core HTTP request timeout"
        replies = []
        for method, params in calls:
            self.events.append(method)
            if method == "StartUpdate":
                assert not self.started and not self.busy, "admit only after await_idle drained activity"
                assert params == self.params
                self.started = True
                body: Any = {}
            else:
                assert method == "GetUpdate"
                if not self.started:
                    body = view(self.before, running=self.busy)
                    self.busy = False
                else:
                    assert self.pages, "GetUpdate fetched separately/latest after the owned capture drained"
                    after, body = self.pages.popleft()
                    assert params == ({} if after is None else {"after": after}), "pass next unchanged"
            replies.append({"status": 200, "body": body})
        return replies

    def install(self, monkeypatch: pytest.MonkeyPatch) -> capture.SmokeVM:
        monkeypatch.setattr(capture.h, "core_calls", self.calls)
        monkeypatch.setattr(capture.time, "sleep", lambda _: None)
        return cast(capture.SmokeVM, object())


def test_capture_keeps_running_chunks_native_line_and_terminal_tail(monkeypatch: pytest.MonkeyPatch) -> None:
    active = status()
    del active["finishedAt"], active["result"]
    terminal = status()
    api = UpdateAPI(
        [
            (None, view(active, "UPDATE PROCESS START\n", "first opaque page", running=True)),
            ("first opaque page", view(active, "feed dnsbl:owned: changed\n", "native opaque page", running=True)),
            ("native opaque page", view(terminal, "UPDATE PROCESS ENDED\n", "terminal opaque page")),
            ("terminal opaque page", view(terminal, "terminal tail\n", "tail opaque page")),
            ("tail opaque page", view(terminal)),
        ],
        busy=True,
    )
    update, log = capture._run_update(api.install(monkeypatch))
    assert update == terminal
    assert log == "UPDATE PROCESS START\nfeed dnsbl:owned: changed\nUPDATE PROCESS ENDED\nterminal tail\n"
    assert not api.pages
    assert api.events[:3] == ["GetUpdate", "GetUpdate", "StartUpdate"]


@pytest.mark.parametrize("result", ["success", "failed"])
def test_same_second_identical_before_record_is_valid_after_admission(
    monkeypatch: pytest.MonkeyPatch,
    result: str,
) -> None:
    terminal = status(result=result)
    api = UpdateAPI(
        [
            (None, view(terminal, "feed ipv4:owned_v4: failed\n", "terminal")),
            ("terminal", view(terminal)),
        ],
        before=terminal,
    )
    update, log = capture._run_update(api.install(monkeypatch))
    assert update == terminal  # Failed results belong to the caller, not the capture loop.
    assert log == "feed ipv4:owned_v4: failed\n"
    assert not api.pages


@pytest.mark.parametrize("field,value", [("trigger", "scheduled"), ("scope", "ip"), ("force", "download")])
@pytest.mark.parametrize("during_drain", [False, True])
def test_unexpected_request_is_rejected_on_every_view(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    during_drain: bool,
) -> None:
    pages: list[tuple[str | None, dict[str, Any]]] = [(None, view(status(**{field: value}), "competing log\n"))]
    if during_drain:
        pages = [
            (None, view(status(), "owned log\n", "owned")),
            ("owned", view(status(**{field: value}), "competing log\n")),
        ]
    api = UpdateAPI(pages)
    with pytest.raises(AssertionError, match="(?i)unexpected.*Update|Update.*unexpected"):
        capture._run_update(api.install(monkeypatch))


@pytest.mark.parametrize(
    "replacement", [view(status(startedAt=101)), view(status(result="failed")), view(status(), running=True)]
)
def test_terminal_drain_rejects_replaced_or_changed_status(
    monkeypatch: pytest.MonkeyPatch,
    replacement: dict[str, Any],
) -> None:
    api = UpdateAPI([(None, view(status(), "owned\n", "owned")), ("owned", replacement)])
    with pytest.raises(AssertionError, match="Update was replaced"):
        capture._run_update(api.install(monkeypatch))


def test_running_capture_rejects_changed_start_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    active = status()
    del active["finishedAt"], active["result"]
    api = UpdateAPI([(None, view(active, "owned\n", "owned", running=True)), ("owned", view(status(startedAt=101)))])
    with pytest.raises(AssertionError, match="Update was replaced"):
        capture._run_update(api.install(monkeypatch))


def test_retry_checks_cores_actual_default_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = status(trigger="retry")
    api = UpdateAPI([(None, view(terminal, "retry\n", "retry page")), ("retry page", view(terminal))], trigger="retry")
    update, log = capture._run_update(api.install(monkeypatch), "retry", "ip")
    assert update == terminal and log == "retry\n"
    assert not api.pages


def test_watchdog_expiry_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    active = status()
    del active["finishedAt"], active["result"]
    api = UpdateAPI([(None, view(active, running=True))])
    vm = api.install(monkeypatch)
    ticks = iter([0.0, 0.0, capture.UPDATE_WATCHDOG + 1.0])
    monkeypatch.setattr(capture.time, "monotonic", lambda: next(ticks))
    with pytest.raises(RuntimeError, match="STUCK.*Update"):
        capture._run_update(vm)
