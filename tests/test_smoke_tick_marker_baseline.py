"""Off-appliance regression test for tick marker attribution."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from tests.smoke import test_smoke_tick as tick


def _tick_fixture(monkeypatch: pytest.MonkeyPatch, *, emit_tick_marker: bool) -> tuple[dict[str, int], tick.SmokeVM]:
    state = {"drains": 0, "marker": 0, "next_due": 0, "pins": 0}

    class VM(tick.SmokeVM):
        def ssh(self, *args: str, timeout: float = 60.0) -> Any:
            if args == ("date +%s",):
                return SimpleNamespace(returncode=0, stdout="100\n", stderr="")
            if args == (tick._PHP, tick._PFB_PHP, "tick"):
                state["next_due"] = 101
                if emit_tick_marker:
                    state["marker"] += 1
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(args)

    # issue #2506: due-ness now rides h.pin_cron_due's durable schedule-state reservation,
    # not a hand-seeded ledger row — stub it (it would otherwise reach for a real box).
    def pin_cron_due(_vm: Any) -> int:
        state["pins"] += 1
        return 0

    def read_ledger(_vm: Any) -> dict[str, dict[str, int]]:
        return {"cron": {"next_due": state["next_due"]}}

    def drain(_vm: Any) -> None:
        state["drains"] += 1
        if state["drains"] == 1:
            state["marker"] += 1

    monkeypatch.setattr(tick, "_read_ledger", read_ledger)
    monkeypatch.setattr(tick.h, "pin_cron_due", pin_cron_due)
    monkeypatch.setattr(tick.h, "wait_no_active_pfb_task", drain)
    monkeypatch.setattr(tick.h, "count_log_marker", lambda *_args: state["marker"])
    monkeypatch.setattr(tick.h, "wait_until", lambda predicate, **_kwargs: bool(predicate()))

    return state, VM("")


def test_due_marker_baseline_drains_before_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _tick_fixture(monkeypatch, emit_tick_marker=False)

    with pytest.raises(AssertionError, match="marker count did not increase"):
        tick.test_tick_dispatches_due_feed(vm)


def test_due_marker_after_baseline_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    state, vm = _tick_fixture(monkeypatch, emit_tick_marker=True)

    tick.test_tick_dispatches_due_feed(vm)

    assert state == {"drains": 2, "marker": 2, "next_due": 101, "pins": 1}
