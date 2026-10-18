"""Which UDP query goes when the table or an address is full (test_hostile.py has the limits and when work may go)."""

from __future__ import annotations

import asyncio

import pfb_dns_proxy
import pytest
from frontend_helpers import ManualClock, drained


class _Queries:
    """Queries for Frontend.spawn_udp_query that wait on one event: `started` lists the ones that ran, `cancelled` the
    ones dropped while they waited."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.started: list[str] = []
        self.cancelled: list[str] = []

    async def query(self, name: str) -> None:
        self.started.append(name)
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.append(name)
            raise


BUSIEST, OTHER = "192.0.2.1", "192.0.2.2"


def _full_table(frontend: pfb_dns_proxy.Frontend, queries: _Queries, clock: ManualClock) -> None:
    """Three queries in a table of three: `other` is the oldest overall, and the busiest address holds `busy1` and
    `busy2`, each younger than it."""
    frontend.spawn_udp_query(queries.query("other"), OTHER)
    clock.advance(0.5)
    frontend.spawn_udp_query(queries.query("busy1"), BUSIEST)
    clock.advance(0.5)
    frontend.spawn_udp_query(queries.query("busy2"), BUSIEST)


@pytest.mark.parametrize(
    ("newcomer", "displaced"),
    [
        pytest.param("192.0.2.9", ["busy1"], id="an-address-with-nothing-in-flight"),
        pytest.param(OTHER, ["busy1"], id="an-address-with-fewer-than-the-busiest"),
        pytest.param(BUSIEST, [], id="the-busiest-address-itself-is-not-lighter-so-it-is-dropped"),
    ],
)
def test_at_the_global_udp_limit_a_lighter_address_takes_the_place_of_the_busiest_addresss_oldest_query(
    newcomer: str, displaced: list[str], clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The oldest query of the table belongs to a lighter address and is left alone: the one that goes is the oldest of
    the address that holds most, however young it still is."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_UDP_INFLIGHT", 3)

    async def scenario() -> tuple[list[str], list[str], dict[str, int]]:
        queries = _Queries()
        frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9), timeout=4.0)
        _full_table(frontend, queries, clock)
        await asyncio.sleep(0)  # all three are waiting for Unbound now
        clock.advance(0.25)  # nothing has waited half the 4 s timeout
        frontend.spawn_udp_query(queries.query("new"), newcomer)
        await asyncio.sleep(0)
        outcome = (list(queries.started), list(queries.cancelled), dict(frontend._per_source))
        queries.release.set()
        await drained(frontend)
        return outcome

    started, cancelled, shares = asyncio.run(scenario())
    assert cancelled == displaced
    assert ("new" in started) == bool(displaced)
    assert sum(shares.values()) == 3  # the table never holds more than its limit


def test_a_newcomer_that_is_not_lighter_takes_the_place_of_its_own_stalled_query_not_another_addresss(
    clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At the global limit an address that holds as much as the busiest one is dropped for, never another address's
    work, and only its own queries that have waited half the timeout can make room for it."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_UDP_INFLIGHT", 3)

    async def scenario() -> list[str]:
        queries = _Queries()
        frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9), timeout=4.0)
        _full_table(frontend, queries, clock)  # `other` has waited 1 s, `busy1` 0.5 s
        await asyncio.sleep(0)  # all three are waiting for Unbound now
        clock.advance(1.5)  # `other` has waited 2.5 s and `busy1` 2 s: both are half the timeout or more
        frontend.spawn_udp_query(queries.query("new"), BUSIEST)
        await asyncio.sleep(0)
        gone = list(queries.cancelled)
        queries.release.set()
        await drained(frontend)
        return gone

    assert asyncio.run(scenario()) == ["busy1"]  # the oldest of the address, not the table's oldest query


def test_an_address_over_its_udp_limit_loses_its_own_oldest_query_not_the_oldest_of_all(
    clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_UDP_PER_SOURCE", 2)

    async def scenario() -> list[str]:
        queries = _Queries()
        frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9), timeout=4.0)
        frontend.spawn_udp_query(queries.query("bystander"), "192.0.2.3")  # the oldest of all
        clock.advance(1.0)
        frontend.spawn_udp_query(queries.query("own first"), "192.0.2.2")
        clock.advance(1.0)
        frontend.spawn_udp_query(queries.query("own second"), "192.0.2.2")
        await asyncio.sleep(0)  # they are all waiting for Unbound now
        clock.advance(2.0)  # each has waited half the 4 s timeout or more
        frontend.spawn_udp_query(queries.query("own third"), "192.0.2.2")
        await asyncio.sleep(0)
        gone = list(queries.cancelled)
        queries.release.set()
        await drained(frontend)
        return gone

    assert asyncio.run(scenario()) == ["own first"]


def test_a_newcomer_as_heavy_as_the_busiest_never_takes_another_addresss_query_even_a_stalled_one(
    clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two addresses hold one query each. The one of the older has waited half the timeout, the newcomer's own has not:
    the newcomer is dropped, since only its own address's stalled work makes room for it."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_UDP_INFLIGHT", 2)

    async def scenario() -> tuple[list[str], list[str]]:
        queries = _Queries()
        frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9), timeout=4.0)
        frontend.spawn_udp_query(queries.query("busiest"), BUSIEST)
        clock.advance(1.9)
        frontend.spawn_udp_query(queries.query("other"), OTHER)
        await asyncio.sleep(0)
        clock.advance(0.1)  # `busiest` has waited 2 s of the 4 s timeout, `other` 0.1 s
        frontend.spawn_udp_query(queries.query("new"), OTHER)
        await asyncio.sleep(0)
        outcome = (list(queries.started), list(queries.cancelled))
        queries.release.set()
        await drained(frontend)
        return outcome

    assert asyncio.run(scenario()) == (["busiest", "other"], [])
