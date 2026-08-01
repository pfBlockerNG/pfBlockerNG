"""Distinct failure contracts for PFBL-03 test-harness salvage caps."""

from __future__ import annotations

import threading
from typing import Any

import pytest

from tests import test_pfbl03_control_channel as channel


def test_control_timer_stop_expiry_is_distinct(monkeypatch: Any) -> None:
    monkeypatch.setattr(channel.P, "python_control_thread", lambda _name: True)

    with pytest.raises(RuntimeError, match="salvage cap expired / stuck or environment.*timer thread 'sleep' to stop"):
        channel._await_control_thread_stopped("sleep", timeout=0)


def test_watcher_start_expiry_is_distinct(monkeypatch: Any) -> None:
    harness = object.__new__(channel._ControlHarness)
    monkeypatch.setattr(harness, "read_applied", lambda: None)

    with pytest.raises(RuntimeError, match="salvage cap expired / stuck or environment.*startup baseline"):
        harness.wait_started(timeout=0)


def test_applied_marker_expiry_is_distinct(monkeypatch: Any) -> None:
    harness = object.__new__(channel._ControlHarness)
    monkeypatch.setattr(harness, "read_applied", lambda: None)

    with pytest.raises(RuntimeError, match="salvage cap expired / stuck or environment.*applied marker.*sequence 7"):
        harness.wait_applied(7, timeout=0)


def test_record_read_expiry_is_distinct() -> None:
    harness = object.__new__(channel._ControlHarness)
    harness.read_condition = threading.Condition()
    harness.read_seqs = []

    with pytest.raises(
        RuntimeError,
        match=r"salvage cap expired / stuck or environment.*record read.*sequence 7.*observed \[\]",
    ):
        harness.wait_read(7, timeout=0)
