"""Off-appliance regression test for tick marker attribution."""

from __future__ import annotations

from copy import deepcopy
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


def _reboot_ledger_fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    preserve_probe: bool = True,
    regenerate_cron: bool = True,
) -> tuple[dict[str, Any], tick.SmokeVM]:
    state: dict[str, Any] = {
        "archive": None,
        "ledger": {},
        "sentinel": False,
        "tick_calls": 0,
    }

    class VM(tick.SmokeVM):
        def ssh(self, *args: str, timeout: float = 60.0) -> Any:
            if args == ("date +%s",):
                return SimpleNamespace(returncode=0, stdout="100\n", stderr="")
            if args[:3] == ("rm", "-f", tick.h.ALIASARCHIVE + ".zst"):
                state["archive"] = None
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if args == ("/usr/bin/touch", tick._VAR_WIPE_SENTINEL):
                state["sentinel"] = True
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if args == ("test", "-e", tick._VAR_WIPE_SENTINEL):
                return SimpleNamespace(returncode=0 if state["sentinel"] else 1, stdout="", stderr="")
            if args == ("/sbin/mount",):
                return SimpleNamespace(returncode=0, stdout="tmpfs on /var (rw)\n", stderr="")
            if args == (tick._PHP, tick._PFB_PHP, "tick"):
                state["tick_calls"] += 1
                if regenerate_cron:
                    state["ledger"]["cron"] = {"last_run": 100, "next_due": 100, "jitter": 0}
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(args)

    def write_entry(_vm: Any, job_key: str, last_run: int, next_due: int, jitter: int = 0) -> None:
        state["ledger"][job_key] = {"last_run": last_run, "next_due": next_due, "jitter": jitter}

    def php_eval(_vm: Any, _snippet: str) -> Any:
        state["archive"] = deepcopy(state["ledger"])
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    def reboot(_vm: Any) -> None:
        state["ledger"] = deepcopy(state["archive"])
        state["sentinel"] = False
        if not preserve_probe:
            state["ledger"].pop(tick._REBOOT_LEDGER_PROBE, None)

    monkeypatch.setattr(tick, "_read_ledger", lambda _vm: deepcopy(state["ledger"]))
    monkeypatch.setattr(tick, "_write_ledger_entry", write_entry)
    monkeypatch.setattr(tick.h, "archive_exists", lambda *_args: state["archive"] is not None)
    monkeypatch.setattr(tick.h, "php_eval", php_eval)
    monkeypatch.setattr(tick.h, "reboot_vm", reboot)
    monkeypatch.setattr(tick.h, "wait_no_active_pfb_task", lambda _vm: None)
    return state, VM("")


def test_reboot_ledger_oracle_accepts_file_persistence_with_cron_regeneration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, vm = _reboot_ledger_fixture(monkeypatch)

    tick.test_tick_reboot_persists_ledger(vm)

    assert state["tick_calls"] == 1
    assert tick._REBOOT_LEDGER_PROBE in state["ledger"]


def test_reboot_ledger_oracle_rejects_lost_persistence_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _reboot_ledger_fixture(monkeypatch, preserve_probe=False)

    with pytest.raises(AssertionError, match="persistence probe missing after reboot"):
        tick.test_tick_reboot_persists_ledger(vm)


def test_reboot_ledger_oracle_rejects_byte_stable_derived_cron(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _reboot_ledger_fixture(monkeypatch, regenerate_cron=False)

    with pytest.raises(AssertionError, match="derived cron row was not regenerated"):
        tick.test_tick_reboot_persists_ledger(vm)
