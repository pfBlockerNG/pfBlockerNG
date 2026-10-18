"""Which UDP query goes when an address is over its limit (test_hostile.py has the limits and when work may go)."""

from __future__ import annotations

import asyncio

import pfb_dns_proxy
import pytest
from frontend_helpers import ManualClock, drained


def test_an_address_over_its_udp_limit_loses_its_own_oldest_query_not_the_oldest_of_all(
    clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_UDP_PER_SOURCE", 2)

    async def scenario() -> list[str]:
        release = asyncio.Event()
        cancelled: list[str] = []

        async def query(name: str) -> None:
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.append(name)
                raise

        frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9), timeout=4.0)
        frontend.spawn_udp_query(query("bystander"), "192.0.2.3")  # the oldest of all
        clock.advance(1.0)
        frontend.spawn_udp_query(query("own first"), "192.0.2.2")
        clock.advance(1.0)
        frontend.spawn_udp_query(query("own second"), "192.0.2.2")
        await asyncio.sleep(0)  # they are all waiting for Unbound now
        clock.advance(2.0)  # each has waited half the 4 s timeout or more
        frontend.spawn_udp_query(query("own third"), "192.0.2.2")
        await asyncio.sleep(0)
        gone = list(cancelled)
        release.set()
        await drained(frontend)
        return gone

    assert asyncio.run(scenario()) == ["own first"]
