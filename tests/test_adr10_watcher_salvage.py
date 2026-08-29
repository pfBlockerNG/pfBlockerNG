"""Distinct failure contracts for ADR-10 watcher salvage caps."""

from __future__ import annotations

import threading
from typing import Any

import pytest

from tests import test_adr10_watcher as watcher


def test_builder_gate_expiry_is_distinct(tmp_path: Any, monkeypatch: Any) -> None:
    harness = watcher._Harness(tmp_path, monkeypatch)
    monkeypatch.setattr(harness._gate, "wait", lambda _timeout: False)

    with pytest.raises(
        RuntimeError,
        match=r"salvage cap expired / stuck or environment.*gated reload-builder release.*observed generation 0",
    ):
        harness.builder()


def test_watcher_stop_expiry_is_distinct(monkeypatch: Any) -> None:
    class StuckWatcher:
        name = "pfb_reload_watcher_test"

        def join(self, timeout: float) -> None:
            pass

        def is_alive(self) -> bool:
            return True

    harness = object.__new__(watcher._Harness)
    harness._gate = threading.Event()
    harness.thread = StuckWatcher()
    monkeypatch.setattr(watcher.P, "pfb_reload_stop", threading.Event(), raising=False)

    with pytest.raises(
        RuntimeError,
        match=r"salvage cap expired / stuck or environment.*watcher thread 'pfb_reload_watcher_test' still alive",
    ):
        harness.stop_join(timeout=0)
