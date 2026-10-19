"""The stuck-run watchdog (frontend_helpers.watched / watchdog): a WATCHDOG expiry is reported as STUCK/ENVIRONMENT with
the timeout chained, so an environment stall is never read as a product failure. The expiry is forced with a zero
limit, so the test needs no clock."""

from __future__ import annotations

import asyncio
import subprocess

import frontend_helpers
import pytest
from frontend_constants import LogFeed


def test_an_async_wait_that_expires_is_stuck_and_chains_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(frontend_helpers, "WATCHDOG", 0)

    async def never_finishes() -> None:
        await asyncio.Event().wait()

    with pytest.raises(
        AssertionError, match=r"^STUCK/ENVIRONMENT: the probe wait did not finish within 0 s$"
    ) as raised:
        asyncio.run(frontend_helpers.watchdog(never_finishes(), "the probe wait"))
    assert isinstance(raised.value.__cause__, TimeoutError)


def test_a_sync_wait_that_expires_is_stuck_for_a_child_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(frontend_helpers, "WATCHDOG", 2.5)
    message = r"^STUCK/ENVIRONMENT: the decider to exit did not finish within 2.5 s$"
    with pytest.raises(AssertionError, match=message) as raised:
        with frontend_helpers.watched("the decider to exit"):
            raise subprocess.TimeoutExpired(["decider"], 2.5)
    assert isinstance(raised.value.__cause__, subprocess.TimeoutExpired)


def test_a_wait_that_finishes_in_time_returns_its_value() -> None:
    async def finished() -> str:
        return "answer"

    assert asyncio.run(frontend_helpers.watchdog(finished(), "the probe wait")) == "answer"


def test_a_log_line_that_never_comes_is_stuck_not_a_verdict() -> None:
    with pytest.raises(AssertionError, match=r"^STUCK/ENVIRONMENT: no expected log line within 0 s") as raised:
        LogFeed().wait_for(lambda _log: False, timeout=0)
    assert "saw []" in str(raised.value)
