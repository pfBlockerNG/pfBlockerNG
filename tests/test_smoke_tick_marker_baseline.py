"""Off-appliance regression test for tick marker attribution."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from tests.smoke import test_smoke_tick as tick


def test_due_marker_baseline_drains_before_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {"drains": 0, "marker": 0, "next_due": 0}

    class VM(tick.SmokeVM):
        def ssh(self, *args: str, timeout: float = 60.0) -> Any:
            if args == ("date +%s",):
                return SimpleNamespace(returncode=0, stdout="100\n", stderr="")
            if args == (tick._PHP, tick._PFB_PHP, "tick"):
                state["next_due"] = 101
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(args)

    def write_ledger(_vm: Any, _key: str, _last: int, next_due: int) -> None:
        state["next_due"] = next_due

    def read_ledger(_vm: Any) -> dict[str, dict[str, int]]:
        return {"cron": {"next_due": state["next_due"]}}

    def drain(_vm: Any) -> None:
        state["drains"] += 1
        if state["drains"] == 1:
            state["marker"] += 1

    monkeypatch.setattr(tick, "_write_ledger_entry", write_ledger)
    monkeypatch.setattr(tick, "_read_ledger", read_ledger)
    monkeypatch.setattr(tick.h, "wait_no_active_pfb_task", drain)
    monkeypatch.setattr(tick.h, "count_log_marker", lambda *_args: state["marker"])
    monkeypatch.setattr(tick.h, "wait_until", lambda predicate, **_kwargs: bool(predicate()))

    with pytest.raises(AssertionError, match="marker count did not increase"):
        tick.test_tick_dispatches_due_feed(VM(""))
