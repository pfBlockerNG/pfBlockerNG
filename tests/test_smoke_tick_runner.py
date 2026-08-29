"""Off-appliance contract tests for the tick smoke runner."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from tests.smoke import test_smoke_tick as tick


def test_run_tick_drains_before_dispatch_and_returns_ssh_result(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[tuple[Any, ...]] = []
    vm: Any = SimpleNamespace()
    ssh_result: Any = SimpleNamespace(returncode=0, stdout="tick output", stderr="")

    def wait_no_active_pfb_task(received_vm: Any) -> None:
        events.append(("drain", received_vm))

    def ssh(*args: Any, timeout: float = 60.0) -> Any:
        events.append(("ssh", args, timeout))
        return ssh_result

    vm.ssh = ssh
    monkeypatch.setattr(tick.h, "wait_no_active_pfb_task", wait_no_active_pfb_task)

    result = tick._run_tick(vm)

    # issue #2506: the tick dispatches feed/apply passes inline, so the runner widens the
    # per-call SSH budget past SmokeVM.ssh's 60s default — the widened value is part of the
    # runner's contract.
    assert events == [("drain", vm), ("ssh", (tick._PHP, tick._PFB_PHP, "tick"), 180.0)], (
        f"expected drain before tick dispatch with the widened 180s budget, got events={events!r}"
    )
    assert result is ssh_result, f"runner must preserve SSH result object, got {result!r}"
