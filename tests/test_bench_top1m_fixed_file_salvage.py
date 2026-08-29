"""Distinct failure contract for TOP1M worker-start salvage expiry."""

from __future__ import annotations

from typing import Any

import pytest

from tests import test_bench_top1m_fixed_file as bench


def test_worker_start_cap_reports_marker_state(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    waits: list[float] = []

    class FakeDriver:
        pid = 4242

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def wait(self, timeout: float) -> int:
            waits.append(timeout)
            return 0

    monkeypatch.setattr(bench.subprocess, "Popen", FakeDriver)
    monotonic_values = iter((0, 11))
    monkeypatch.setattr(bench.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(bench.time, "sleep", lambda _seconds: None)

    def no_process(*_args: object) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(bench.os, "kill", no_process)

    with pytest.raises(RuntimeError) as raised:
        bench.test_timed_parent_signal_kills_worker_process_group(tmp_path)

    message = str(raised.value)
    assert message.startswith("salvage cap expired / stuck or environment:")
    assert "timed worker startup marker" in message
    assert str(tmp_path / "signal-worker.pid") in message
    assert "observed exists=False" in message
    assert waits == [2]
