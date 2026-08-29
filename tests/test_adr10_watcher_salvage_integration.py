"""Integrated ADR-10 watcher salvage-cap regression."""

from __future__ import annotations

from typing import Any

import pytest

from tests import test_adr10_watcher as watcher


def test_real_watcher_surfaces_builder_cap_after_cleanup(tmp_path: Any, monkeypatch: Any) -> None:
    harness = watcher._Harness(tmp_path, monkeypatch)
    monkeypatch.setattr(harness._gate, "wait", lambda _timeout: False)

    harness.start()
    harness.publish(1)
    harness.wait_builds(1)

    with pytest.raises(
        RuntimeError,
        match=r"salvage cap expired / stuck or environment.*gated reload-builder release.*observed generation 1",
    ):
        harness.stop_join()

    assert not harness.thread.is_alive()
