"""Client connection limits of the TCP and DoT listeners, and the DoT handshake deadline.

A connection over the cap is closed at accept without being read and without opening an upstream connection; on a DoT
listener that is before the first TLS handshake byte, and a client still in its handshake holds a slot. The connections
already served keep working, a freed slot is reusable, and an overload burst costs one log line (as for UDP). The cap
scenarios run against the plain TCP listener and the DoT listener, which share one cap.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import struct
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import dnswire
import pfb_dns_proxy
import pfsense_dot
import pytest
import unbound_shim as shim
from dot_helpers import dot_exchange, open_dot
from frontend_constants import ALLOWED, BLOCKED, Booted
from frontend_helpers import (
    WATCHDOG,
    FakeProxyUpstream,
    FakeUnbound,
    ManualClock,
    build_query,
    serve_dot,
    serve_plain,
    udp_exchange,
)

ZONE = {(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]}
Connection = tuple[asyncio.StreamReader, asyncio.StreamWriter]


class WatchedFrontend(pfb_dns_proxy.Frontend):
    """A Frontend that reports each finished TCP/DoT client handler, so a test waits for a slot to free, not polls, and
    keeps the server side of each client connection."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.finished: asyncio.Queue[None] = asyncio.Queue()
        self.writers: list[asyncio.StreamWriter] = []

    async def _tcp_client(self, *args: Any, **kwargs: Any) -> None:
        self.writers.append(args[1])
        try:
            await super()._tcp_client(*args, **kwargs)
        finally:
            self.finished.put_nowait(None)


@dataclass
class Listener:
    tls: bool
    trust: Path
    context: ssl.SSLContext

    async def start(self, frontend: pfb_dns_proxy.Frontend) -> tuple[str, int]:
        if self.tls:
            [server] = await serve_dot(frontend, ["127.0.0.1"], 0, self.context)
        else:
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
        return server

    async def connect(self, server: tuple[str, int], source: str = "127.0.0.1") -> Connection:
        if self.tls:
            return await open_dot(server, self.trust, source=source)
        return await asyncio.wait_for(asyncio.open_connection(*server, local_addr=(source, 0)), WATCHDOG)


def _listener(tls: bool, directory: Path, certificate: tuple[bytes, bytes]) -> Listener:
    crt, key = certificate
    trust = directory / "trust.pem"
    trust.write_bytes(crt)
    return Listener(tls, trust, pfsense_dot.server_context(pfsense_dot.DotSettings(853, crt, key)))


@pytest.fixture(params=[False, True], ids=["tcp", "dot"])
def listener(request: pytest.FixtureRequest, tmp_path: Path, certificate: tuple[bytes, bytes]) -> Listener:
    return _listener(request.param, tmp_path, certificate)


@pytest.fixture
def dot_listener(tmp_path: Path, certificate: tuple[bytes, bytes]) -> Listener:
    return _listener(True, tmp_path, certificate)


def _framed(wire: bytes) -> bytes:
    return struct.pack("!H", len(wire)) + wire


async def _read_reply(connection: Connection) -> dnswire.Message:
    reader, _ = connection
    size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), WATCHDOG))[0]
    return dnswire.parse(await asyncio.wait_for(reader.readexactly(size), WATCHDOG))


async def _ask(connection: Connection, qid: int, name: str = ALLOWED) -> dnswire.Message:
    _, writer = connection
    writer.write(_framed(build_query(name, qid=qid)))
    await writer.drain()
    return await _read_reply(connection)


async def _until_closed(reader: asyncio.StreamReader) -> bytes:
    """What the server sent before it closed the connection; a reset or a TLS abort is a close too."""
    sent = b""
    try:
        while chunk := await asyncio.wait_for(reader.read(65536), WATCHDOG):
            sent += chunk
    except TimeoutError:
        pytest.fail(f"the server left the connection open; it had sent {len(sent)} bytes: {sent[:32]!r}")
    except (ConnectionError, ssl.SSLError):
        pass
    return sent


async def _served(listener: Listener, server: tuple[str, int], qid: int, source: str = "127.0.0.1") -> Connection:
    """A connection that is accepted and answered, so its slot is taken before the next client connects."""
    connection = await listener.connect(server, source)
    reply = await _ask(connection, qid)
    assert (reply.id, reply.rcode) == (qid, 0)
    return connection


async def _slot_freed(frontend: WatchedFrontend) -> None:
    """Wait for one client handler to finish; one that never ran or never finished fails at the watchdog."""
    try:
        await asyncio.wait_for(frontend.finished.get(), WATCHDOG)
    except TimeoutError:
        pytest.fail("no TCP/DoT client handler finished: a slot was never freed, or the handler never ran")


TRACEBACK_HEADER = "Traceback (most recent call last)"


def _tracebacks_logged(caplog: pytest.LogCaptureFixture, stderr: str) -> list[str]:
    """What carries a traceback: log records with exc_info or a traceback in their text, and stderr lines of one."""
    records = [r.getMessage() for r in caplog.records if r.exc_info or TRACEBACK_HEADER in r.getMessage()]
    return records + [line for line in stderr.splitlines() if TRACEBACK_HEADER in line]


def _overload_lines(warnings: list[object]) -> list[str]:
    return [str(line) for line in warnings if "TCP client limit" in str(line)]


# --- the cap -------------------------------------------------------------------------------------


def test_the_connection_limits_default_to_128_in_all_and_64_per_source() -> None:
    assert (pfb_dns_proxy.MAX_TCP_CLIENTS, pfb_dns_proxy.MAX_TCP_PER_SOURCE) == (128, 64)


async def _refused(listener: Listener, server: tuple[str, int], source: str = "127.0.0.1") -> None:
    """A connection the proxy turns away: it is closed without a reply, whatever the client asks (on DoT before the
    handshake, so the client's own handshake fails)."""
    try:
        reader, writer = await listener.connect(server, source)
    except (ConnectionError, ssl.SSLError, EOFError):
        return
    try:
        writer.write(_framed(build_query(ALLOWED)))
        try:
            reply = await asyncio.wait_for(reader.read(65536), WATCHDOG)
        except (ConnectionError, ssl.SSLError):
            return
        assert reply == b"", f"the connection was served: {reply[:32]!r}"
    finally:
        writer.close()


HELD = "held.example."
HELD_ZONE = ZONE | {(HELD, dnswire.TYPE_A): [f"{HELD} 300 IN A 192.0.2.78"]}


class HoldingFrontend(WatchedFrontend):
    """A WatchedFrontend that keeps the query for HELD inside resolve() until `release` is set: a client whose query is
    with Unbound and has not been answered yet."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def resolve(self, wire: bytes, client_ip: str, forward: Any, **kwargs: Any) -> bytes | None:
        if dnswire.parse(wire).questions[0].name == HELD:
            self.entered.set()
            await self.release.wait()
        return await super().resolve(wire, client_ip, forward, **kwargs)


def test_40_persistent_connections_behind_one_address_are_all_kept_and_all_answered(
    booted: Booted, listener: Listener, clock: ManualClock
) -> None:
    """Issue #3515 gate: 40 clients behind one NAT address, each asking every half second, were closed and reconnected
    331 times in 8 s, because one address could hold 16 connections and each newcomer closed the longest idle one."""

    async def scenario() -> tuple[list[int], int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            held: list[Connection] = []
            try:
                for qid in range(40):
                    held.append(await _served(listener, server, qid, "127.0.0.2"))
                rcodes = []
                for round_number in (1, 2, 3):
                    clock.advance(0.5)
                    rcodes += [(await _ask(c, 100 * round_number + n)).rcode for n, c in enumerate(held)]
                return rcodes, len(frontend.writers)
            finally:
                for _, writer in held:
                    writer.close()
                await frontend.stop()

    rcodes, connections = asyncio.run(scenario())
    assert (rcodes, connections) == ([0] * 120, 40)  # every one of them answered three times on its first connection


def test_a_connection_over_the_cap_is_refused_while_every_client_is_active(
    booted: Booted, listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #3515 gate: each newcomer over the cap closed the client idle longest, so clients that were using their
    connections were closed and had to reconnect, again and again. A client heard from within the last half of the idle
    timeout keeps its slot; the newcomer is the one turned away."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 2)
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)

    async def scenario() -> list[int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            held: list[Connection] = []
            try:
                held += [await _served(listener, server, 1), await _served(listener, server, 2)]
                clock.advance(14.5)  # half of the 30 s idle timeout is 15 s
                await _refused(listener, server)
                return [(await _ask(connection, 3 + n)).rcode for n, connection in enumerate(held)]
            finally:
                for _, writer in held:
                    writer.close()
                await frontend.stop()

    assert asyncio.run(scenario()) == [0, 0]
    assert len(_overload_lines(warnings)) == 1


def test_a_client_idle_for_half_the_idle_timeout_is_closed_for_a_newcomer_and_only_that_one(
    booted: Booted, listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #3517 review: idle connections held every slot, so a new client was refused for as long as they stayed.
    One that has said nothing for half the idle timeout is the one that goes, not the one that connected first."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 2)

    async def scenario() -> tuple[int, bytes]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            held: list[Connection] = []
            try:
                first = await _served(listener, server, 1)
                clock.advance(1.0)
                second = await _served(listener, server, 2)
                clock.advance(1.0)
                await _ask(first, 3)  # `first` connected before `second`, but has been heard from since
                held += [first, second]
                clock.advance(13.5)  # `second` has been silent 14.5 s, `first` 13.5 s
                await _refused(listener, server)
                clock.advance(0.5)  # `second` has now been silent for exactly half the idle timeout
                held.append(await _served(listener, server, 4))
                closed = await _until_closed(second[0])
                return (await _ask(first, 5)).rcode, closed
            finally:
                for _, writer in held:
                    writer.close()
                await frontend.stop()

    assert asyncio.run(scenario()) == (0, b"")


def test_the_client_closed_for_a_newcomer_is_the_one_idle_longest_not_the_one_that_connected_first(
    booted: Booted, listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 2)

    async def scenario() -> tuple[bytes, int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            held: list[Connection] = []
            try:
                first = await _served(listener, server, 1)
                clock.advance(1.0)
                second = await _served(listener, server, 2)
                clock.advance(1.0)
                await _ask(first, 3)  # `first` is the older connection, but `second` has now been idle the longer
                held += [first, second]
                clock.advance(30.0)  # both are well past half the idle timeout
                held.append(await _served(listener, server, 4))
                return await _until_closed(second[0]), (await _ask(first, 5)).rcode
            finally:
                for _, writer in held:
                    writer.close()
                await frontend.stop()

    assert asyncio.run(scenario()) == (b"", 0)


def test_a_connection_that_sent_nothing_is_idle_from_the_moment_it_connected(
    booted: Booted, listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 1)

    async def scenario() -> tuple[bytes, int]:
        frontend = WatchedFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        server = await listener.start(frontend)
        # Accepted before the next client connects, so asyncio runs its handler (and takes the slot) first.
        silent_reader, silent = await asyncio.wait_for(asyncio.open_connection(*server), WATCHDOG)
        try:
            clock.advance(14.5)
            await _refused(listener, server)
            clock.advance(0.5)
            newcomer = await listener.connect(server)
            reply = await _ask(newcomer, 5, BLOCKED)
            newcomer[1].close()
            return await _until_closed(silent_reader), reply.rcode
        finally:
            silent.close()
            await frontend.stop()

    assert asyncio.run(scenario()) == (b"", 0)


@pytest.mark.parametrize(
    ("phase", "neighbours"),
    [("waiting", 1), ("waiting", 0), ("answered", 1)],
    ids=["waiting-an-idle-neighbour-goes", "waiting-nobody-idle-newcomer-refused", "answered-an-idle-neighbour-goes"],
)
def test_a_client_that_has_a_query_at_unbound_or_was_just_answered_is_never_the_one_closed_as_idle(
    booted: Booted, listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch, phase: str, neighbours: int
) -> None:
    """Issue #3515 gate: a client whose query had been with Unbound for a second counted as idle since its frame came,
    and was the one closed for 135 newcomers, just before its answer. Waiting is not idling, and the answer is activity
    however long it took."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 1 + neighbours)

    async def scenario() -> tuple[int, int, list[bytes]]:
        async with FakeProxyUpstream(FakeUnbound(HELD_ZONE)) as upstream:
            frontend = HoldingFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            held: list[Connection] = []
            try:
                waiting = await listener.connect(server)
                held.append(waiting)
                waiting[1].write(_framed(build_query(HELD, qid=1)))
                await asyncio.wait_for(frontend.entered.wait(), WATCHDOG)
                clock.advance(1.0)
                idle = [await _served(listener, server, 10 + n) for n in range(neighbours)]
                held += idle
                clock.advance(100.0)  # everyone has been silent for far longer than half the idle timeout
                if phase == "answered":
                    frontend.release.set()
                    reply = await _read_reply(waiting)
                if neighbours:
                    held.append(await _served(listener, server, 20))
                else:
                    await _refused(listener, server)
                if phase == "waiting":
                    frontend.release.set()
                    reply = await _read_reply(waiting)
                return reply.id, reply.rcode, [await _until_closed(connection[0]) for connection in idle]
            finally:
                for _, writer in held:
                    writer.close()
                await frontend.stop()

    assert asyncio.run(scenario()) == (1, 0, [b""] * neighbours)


def test_a_source_at_its_connection_limit_has_its_newcomers_refused_and_no_other_source_is_affected(
    booted: Booted, listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #3517 review: 128 idle connections from one host locked every other client out of TCP and DoT."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_PER_SOURCE", 2)
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)

    async def scenario() -> list[int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            held: list[Connection] = []
            try:
                a1 = await _served(listener, server, 1, "127.0.0.2")
                a2 = await _served(listener, server, 2, "127.0.0.2")
                bystander = await _served(listener, server, 3, "127.0.0.3")
                await _refused(listener, server, "127.0.0.2")  # the third from one source
                await _refused(listener, server, "127.0.0.2")
                other = await _served(listener, server, 4, "127.0.0.3")  # another source is not affected
                held += [a1, a2, bystander, other]
                return [(await _ask(c, 10 + n)).rcode for n, c in enumerate(held)]
            finally:
                for _, writer in held:
                    writer.close()
                await frontend.stop()

    assert asyncio.run(scenario()) == [0, 0, 0, 0]
    assert len([line for line in warnings if "127.0.0.2" in str(line)]) == 1  # two refusals, one burst, one line


def test_a_source_over_its_connection_limit_loses_its_own_longest_idle_client_not_another_sources(
    booted: Booted, listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_PER_SOURCE", 2)

    async def scenario() -> tuple[bytes, list[int]]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            held: list[Connection] = []
            try:
                bystander = await _served(listener, server, 1, "127.0.0.3")  # idle the longest of all
                clock.advance(1.0)
                a1 = await _served(listener, server, 2, "127.0.0.2")
                clock.advance(1.0)
                a2 = await _served(listener, server, 3, "127.0.0.2")
                clock.advance(30.0)  # all of them are well past half the idle timeout
                a3 = await _served(listener, server, 4, "127.0.0.2")
                held += [bystander, a1, a2, a3]
                closed = await _until_closed(a1[0])
                return closed, [(await _ask(c, 10 + n)).rcode for n, c in enumerate([bystander, a2, a3])]
            finally:
                for _, writer in held:
                    writer.close()
                await frontend.stop()

    assert asyncio.run(scenario()) == (b"", [0, 0, 0])


def test_a_cap_overload_is_logged_once_per_burst(
    booted: Booted, listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 1)
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)

    async def scenario() -> list[int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            lines_after_burst = []
            for qid in (1, 2):
                served = await _served(listener, server, qid)  # takes the one slot
                await _refused(listener, server)
                await _refused(listener, server)  # two turned away: one line
                lines_after_burst.append(len(_overload_lines(warnings)))
                served[1].close()
                for _ in range(3):
                    await frontend.finished.get()  # no client left: the burst is over
            await frontend.stop()
            return lines_after_burst

    assert asyncio.run(scenario()) == [1, 2]


def test_the_default_idle_timeout_is_30_seconds() -> None:
    """Unbound's tcp-idle-timeout default. The tests around it shorten the timeout, so nothing else pins this value."""
    assert pfb_dns_proxy.TCP_IDLE_TIMEOUT == 30.0


def test_a_client_that_sends_nothing_is_closed_at_the_idle_timeout_and_its_slot_is_freed(
    booted: Booted, listener: Listener, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "TCP_IDLE_TIMEOUT", 0.2)

    async def scenario() -> tuple[bytes, tuple[int, int]]:
        frontend = WatchedFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        server = await listener.start(frontend)
        silent_reader, silent_writer = await listener.connect(server)  # says nothing
        try:
            silent_sent = await _until_closed(silent_reader)  # the idle timeout closes it
            await frontend.finished.get()
            later = await listener.connect(server)
            reply = await _ask(later, 5, BLOCKED)
            later[1].close()
            return silent_sent, (reply.id, reply.rcode)
        finally:
            silent_writer.close()
            await frontend.stop()

    assert asyncio.run(scenario()) == (b"", (5, 0))


def test_the_tcp_cap_does_not_limit_udp(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 1)

    async def scenario() -> bytes:
        frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
        _, writer = await asyncio.open_connection(*server)  # the only TCP slot is taken
        try:
            return (await udp_exchange(server, build_query(BLOCKED, qid=6)))[0]
        finally:
            writer.close()
            await frontend.stop()

    reply = dnswire.parse(asyncio.run(scenario()))
    assert (reply.id, reply.rcode, len(reply.answers)) == (6, 0, 1)


def test_the_upstream_connection_of_a_tcp_or_dot_client_is_closed_with_it(
    booted: Booted, listener: Listener, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A leaked one would hold an Unbound TCP connection (pfSense allows few per thread) for each client that came."""
    opened: list[asyncio.StreamWriter] = []
    upstream_port = 0
    real_open = asyncio.open_connection

    async def open_and_keep_upstream_writers(host: Any, port: Any, **kwargs: Any) -> Connection:
        reader, writer = await real_open(host, port, **kwargs)
        if (host, port) == ("127.0.0.1", upstream_port):
            opened.append(writer)
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", open_and_keep_upstream_writers)

    async def scenario() -> None:
        nonlocal upstream_port
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            upstream_port = upstream.port
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            server = await listener.start(frontend)
            _, writer = await _served(listener, server, 1)
            assert [w.is_closing() for w in opened] == [False]  # while the client is there it is in use
            writer.close()
            await frontend.finished.get()
            await frontend.stop()

    asyncio.run(scenario())
    assert [w.is_closing() for w in opened] == [True]


class _ResetBeforeTheHandlerRan:
    """The StreamWriter of a connection whose peer reset it before the handler started: no addresses any more."""

    def __init__(self) -> None:
        self.closed = False

    def get_extra_info(self, name: str, default: object = None) -> object:
        return default

    def close(self) -> None:
        self.closed = True


def test_a_connection_that_is_gone_before_its_handler_runs_does_not_keep_a_slot(
    booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 1)
    frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
    writers = [_ResetBeforeTheHandlerRan() for _ in range(3)]  # three would fill a cap of one for good if they leaked

    async def scenario() -> None:
        for writer in writers:
            await frontend._tcp_client(asyncio.StreamReader(), writer)  # type: ignore[arg-type]

    asyncio.run(scenario())
    assert [writer.closed for writer in writers] == [True, True, True]
    assert not frontend._clients


# --- the cap comes before the DoT handshake ------------------------------------------------------


def test_a_dot_client_still_in_its_handshake_holds_its_slot_and_the_newcomer_is_refused_before_its_own(
    booted: Booted, dot_listener: Listener, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #3517 review: a peer that opened connections and sent nothing held every slot for the handshake timeout.
    The cap is applied before the handshake, so a refused newcomer costs no TLS work; and a client is silent only from
    its connection on, so the stalled one is not closed for it before it has been silent for half the idle timeout."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 1)

    async def scenario() -> int:
        frontend = WatchedFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        server = await dot_listener.start(frontend)
        # Accepted before the next client connects, so asyncio runs its handler (and takes the slot) first.
        _, stalled = await asyncio.wait_for(asyncio.open_connection(*server), WATCHDOG)  # no ClientHello
        try:
            await _refused(dot_listener, server)
            return len(frontend._clients)
        finally:
            stalled.close()
            await frontend.stop()

    assert asyncio.run(scenario()) == 1


# --- the DoT handshake ---------------------------------------------------------------------------


def test_the_default_handshake_deadline_is_10_seconds() -> None:
    assert pfb_dns_proxy.TLS_HANDSHAKE_TIMEOUT == 10.0


def test_the_default_dot_shutdown_timeout_is_2_seconds() -> None:
    assert pfb_dns_proxy.TLS_SHUTDOWN_TIMEOUT == 2.0


def test_a_dot_client_that_ignores_the_close_does_not_keep_its_connection_past_the_shutdown_timeout(
    booted: Booted, dot_listener: Listener, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #3517 review: with asyncio's 30 s default the connection outlived the slot freed for it, so the open
    descriptors could reach twice the cap."""
    monkeypatch.setattr(pfb_dns_proxy, "TCP_IDLE_TIMEOUT", 0.2)
    monkeypatch.setattr(pfb_dns_proxy, "TLS_SHUTDOWN_TIMEOUT", 0.2)

    async def scenario() -> bool:
        frontend = WatchedFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        server = await dot_listener.start(frontend)
        _, writer = await dot_listener.connect(server)
        cast(asyncio.Transport, writer.transport).pause_reading()  # the server's close_notify is never answered
        try:
            await frontend.finished.get()  # the idle timeout ended the handler and freed its slot
            closed = asyncio.ensure_future(frontend.writers[0].wait_closed())
            done, _ = await asyncio.wait({closed}, timeout=WATCHDOG)
            if done:
                closed.exception()  # a forced close ends wait_closed() with the TimeoutError; retrieve it
            else:
                closed.cancel()
            return bool(done)
        finally:
            writer.close()
            await frontend.stop()

    assert asyncio.run(scenario()), "the TLS connection of the departed client was still open at the watchdog"


def test_a_dot_client_that_never_sends_a_hello_is_disconnected_at_the_handshake_timeout_and_its_slot_is_freed(
    booted: Booted, dot_listener: Listener, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "TLS_HANDSHAKE_TIMEOUT", 0.2)

    async def scenario() -> tuple[bytes, tuple[int, int]]:
        frontend = WatchedFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        server = await dot_listener.start(frontend)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*server), WATCHDOG)  # no TLS, no bytes
        try:
            sent = await _until_closed(reader)  # a server without a deadline holds this until the watchdog
            await _slot_freed(frontend)
            reply = await _ask(await dot_listener.connect(server), 5, BLOCKED)  # the only slot is usable again
            return sent, (reply.id, reply.rcode)
        finally:
            writer.close()
            await frontend.stop()

    assert asyncio.run(scenario()) == (b"", (5, 0))


def test_a_non_tls_client_is_dropped_without_a_traceback_and_the_next_client_is_served(
    booted: Booted,
    certificate: tuple[bytes, bytes],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    trust = tmp_path / "trust.pem"
    trust.write_bytes(certificate[0])

    async def scenario() -> tuple[bytes, bytes]:
        frontend = WatchedFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        context = pfsense_dot.server_context(pfsense_dot.DotSettings(853, *certificate))
        [server] = await serve_dot(frontend, ["127.0.0.1"], 0, context)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*server), WATCHDOG)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: dns.example\r\n\r\n")
            sent = await _until_closed(reader)
            reply, _, _ = await dot_exchange(server, build_query(BLOCKED, qid=8), trust)
            return sent, reply
        finally:
            writer.close()
            await frontend.stop()

    sent, reply = asyncio.run(scenario())
    assert sent == b"" or sent[0] == 0x15  # nothing, or a TLS alert record: never an HTTP or DNS answer
    assert dnswire.parse(reply).id == 8  # the garbage client did not take the listener down
    assert _tracebacks_logged(caplog, capfd.readouterr().err) == []


# --- the traceback predicate is not vacuous ------------------------------------------------------


def _a_real_traceback() -> str:
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        return traceback.format_exc()


@pytest.mark.parametrize("channel", ["log-text", "log-exc-info", "stderr-via-shim"])
def test_the_traceback_predicate_flags_a_log_that_has_one(
    channel: str, caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    text = _a_real_traceback()
    assert TRACEBACK_HEADER in text  # the fixture is a real traceback, not a stand-in for one
    if channel == "log-text":
        logging.getLogger("asyncio").error(text)
    elif channel == "log-exc-info":
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            logging.getLogger("asyncio").exception("Fatal error on SSL transport")
    else:
        shim.log_err(text)  # how the proxy prints a query task that failed
    assert _tracebacks_logged(caplog, capfd.readouterr().err) != []


def test_the_traceback_predicate_passes_a_log_without_one(
    caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger("asyncio").info("SSL handshake failed")
    shim.log_warn("TCP client limit of 2 reached: closing new connections until the clients drain")
    assert _tracebacks_logged(caplog, capfd.readouterr().err) == []
