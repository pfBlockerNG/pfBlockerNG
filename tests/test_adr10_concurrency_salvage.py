"""Distinct failure contract for ADR-10 query-worker salvage."""

from __future__ import annotations

import re
from typing import Any

import pytest

from tests import test_adr10_concurrency as concurrency


def test_atomic_swap_reports_every_live_query_worker(tmp_path: Any, monkeypatch: Any) -> None:
    created: list[Any] = []

    class FakeThread:
        def __init__(self, *, target: Any, args: tuple[Any, ...] = (), name: str | None = None, daemon: bool = False):
            query_index = sum(thread.name != "pfb_reload_watcher_test" for thread in created)
            self.name = name or "fake-query-{}".format(query_index)
            self.target = target
            self.args = args
            self.daemon = daemon
            self.query_index = query_index
            self.joined = False
            created.append(self)

        def start(self) -> None:
            pass

        def join(self, timeout: float) -> None:
            self.joined = True

        def is_alive(self) -> bool:
            return self.name in {"adr10-query-1", "adr10-query-4"} or (
                self.name.startswith("fake-query-") and self.query_index in {1, 4}
            )

    monkeypatch.setattr(concurrency.threading, "Thread", FakeThread)
    monkeypatch.setattr(concurrency.threading.Condition, "wait_for", lambda _self, _predicate, timeout: True)

    with pytest.raises(RuntimeError) as raised:
        concurrency.test_atomic_swap_no_torn_across_every_matcher_mechanism(tmp_path, monkeypatch)

    message = str(raised.value)
    assert re.match(r"^salvage cap expired / stuck or environment", message)
    assert "adr10-query-1" in message
    assert "adr10-query-4" in message
    assert created[0].name == "pfb_reload_watcher_test"
    assert created[0].joined is True
    assert concurrency.P.pfb_reload_stop.is_set()
