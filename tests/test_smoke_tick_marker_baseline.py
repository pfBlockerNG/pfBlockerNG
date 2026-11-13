"""Off-appliance regression tests for the oracles of the tick smoke tests (issue #3941).

The retry test's feed-pass marker baseline must be taken after the box is drained, and it must demand a `retry`
Update that logged the pass; the reboot test must see the ledger's probe survive, the tick's own row regrow and no
retired schedule row come back.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest

from tests.smoke import test_smoke_tick as tick

_BEFORE = {"trigger": "apply", "startedAt": 90, "finishedAt": 91, "result": "success"}


def _retry_fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    emit_marker: bool = True,
    trigger: str = "retry",
    log: str = f" {tick._FEED_PASS_MARKER} [ 1 ]\n",
) -> tuple[dict[str, Any], tick.SmokeVM]:
    state: dict[str, Any] = {"drains": 0, "marker": 0, "ssh": [], "ticks": 0}

    class VM(tick.SmokeVM):
        def ssh(self, *args: str, timeout: float = 60.0) -> Any:
            state["ssh"].append(args)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    @contextlib.contextmanager
    def scheduled_on(_vm: Any) -> Iterator[None]:
        yield

    def drain(_vm: Any) -> None:
        state["drains"] += 1
        if state["drains"] == 1:
            state["marker"] += 1  # a task that was still ending writes its line before the box is quiet

    def run_tick(_vm: Any) -> SimpleNamespace:
        state["ticks"] += 1
        if emit_marker:
            state["marker"] += 1
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tick, "_drain_pending_apply", lambda _vm: None)
    monkeypatch.setattr(tick, "_run_tick", run_tick)
    monkeypatch.setattr(tick.h, "scheduled_updates_on", scheduled_on)
    monkeypatch.setattr(tick.h, "core_update_view", lambda _vm: {"update": _BEFORE})
    monkeypatch.setattr(
        tick.h,
        "await_core_update_end",
        lambda _vm, *, before, watchdog: {"running": False, "update": {**_BEFORE, "trigger": trigger, "startedAt": 99}},
    )
    monkeypatch.setattr(tick.h, "core_update_log", lambda _vm: log)
    monkeypatch.setattr(tick.h, "wait_no_active_pfb_task", drain)
    monkeypatch.setattr(tick.h, "count_log_marker", lambda *_args: state["marker"])
    return state, VM("")


def test_feed_pass_marker_baseline_drains_before_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _retry_fixture(monkeypatch, emit_marker=False)

    with pytest.raises(AssertionError, match="did not reach"):
        tick.test_tick_asks_core_to_retry_a_failed_feed(vm)


def test_retry_with_the_feed_pass_is_accepted_and_the_fail_marker_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    state, vm = _retry_fixture(monkeypatch)

    tick.test_tick_asks_core_to_retry_a_failed_feed(vm)

    assert state["ticks"] == 1 and state["drains"] == 1
    assert state["ssh"][-1] == ("rm", "-f", tick._FAIL_MARKER), "the planted .fail marker must be removed again"


def test_an_update_that_is_not_a_retry_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _retry_fixture(monkeypatch, trigger="apply")

    with pytest.raises(AssertionError, match="must ask Core for a retry"):
        tick.test_tick_asks_core_to_retry_a_failed_feed(vm)


def test_a_retry_whose_log_has_no_feed_pass_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _retry_fixture(monkeypatch, log="Dispatching pending apply.\n")

    with pytest.raises(AssertionError, match="feed pass did not run"):
        tick.test_tick_asks_core_to_retry_a_failed_feed(vm)


def _reboot_ledger_fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    preserve_probe: bool = True,
    own_row: bool = True,
    derived_cache: bool = False,
) -> tuple[dict[str, Any], tick.SmokeVM]:
    state: dict[str, Any] = {"archive": None, "ledger": {}, "sentinel": False, "tick_calls": 0}

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
                if own_row:
                    state["ledger"]["ss_refresh"] = {"last_run": 100, "next_due": 1000, "jitter": 0}
                if derived_cache:
                    state["ledger"]["_meta"] = {"schema": 1}
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


def test_reboot_ledger_oracle_accepts_file_persistence_with_the_ticks_own_row(monkeypatch: pytest.MonkeyPatch) -> None:
    state, vm = _reboot_ledger_fixture(monkeypatch)

    tick.test_tick_reboot_persists_ledger(vm)

    assert state["tick_calls"] == 1
    assert tick._REBOOT_LEDGER_PROBE in state["ledger"]


def test_reboot_ledger_oracle_rejects_lost_persistence_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _reboot_ledger_fixture(monkeypatch, preserve_probe=False)

    with pytest.raises(AssertionError, match="persistence probe missing after reboot"):
        tick.test_tick_reboot_persists_ledger(vm)


def test_reboot_ledger_oracle_rejects_a_tick_that_wrote_no_row_of_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _reboot_ledger_fixture(monkeypatch, own_row=False)

    with pytest.raises(AssertionError, match="did not write its own 'ss_refresh' row"):
        tick.test_tick_reboot_persists_ledger(vm)


def test_reboot_ledger_oracle_rejects_the_retired_derived_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    _state, vm = _reboot_ledger_fixture(monkeypatch, derived_cache=True)

    with pytest.raises(AssertionError, match="derived cache"):
        tick.test_tick_reboot_persists_ledger(vm)
