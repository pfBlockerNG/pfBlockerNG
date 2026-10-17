"""Client connection limits of the TCP and DoT listeners, and the DoT handshake deadline.

A connection over the cap is closed at accept without being read and without opening an upstream connection; the
connections already served keep working, a freed slot is reusable, and an overload burst costs one log line (as for
UDP). Every cap scenario runs against the plain TCP listener and the DoT listener, which share one cap.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import dnswire
import pfb_dns_proxy
import pfsense_dot
import pytest
import unbound_shim as shim
from dot_helpers import dot_exchange, open_dot
from frontend_constants import ALLOWED, BLOCKED, Booted
from frontend_helpers import WATCHDOG, FakeProxyUpstream, FakeUnbound, build_query, udp_exchange

ZONE = {(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]}
Connection = tuple[asyncio.StreamReader, asyncio.StreamWriter]


class WatchedFrontend(pfb_dns_proxy.Frontend):
    """A Frontend that reports each finished TCP/DoT client handler, so a test waits for a slot to free, not polls."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.finished: asyncio.Queue[None] = asyncio.Queue()

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await super()._tcp_client(reader, writer)
        finally:
            self.finished.put_nowait(None)


@dataclass
class Listener:
    tls: bool
    trust: Path
    context: ssl.SSLContext

    async def start(self, frontend: pfb_dns_proxy.Frontend) -> tuple[str, int]:
        if self.tls:
            [server] = await frontend.start_dot(["127.0.0.1"], 0, self.context)
        else:
            [server] = await frontend.start(["127.0.0.1"], 0)
        return server

    async def connect(self, server: tuple[str, int]) -> Connection:
        if self.tls:
            return await open_dot(server, self.trust)
        return await asyncio.wait_for(asyncio.open_connection(*server), WATCHDOG)


@pytest.fixture(params=[False, True], ids=["tcp", "dot"])
def listener(request: pytest.FixtureRequest, tmp_path: Path, certificate: tuple[bytes, bytes]) -> Listener:
    crt, key = certificate
    trust = tmp_path / "trust.pem"
    trust.write_bytes(crt)
    return Listener(request.param, trust, pfsense_dot.server_context(pfsense_dot.DotSettings(853, crt, key)))


def _framed(wire: bytes) -> bytes:
    return struct.pack("!H", len(wire)) + wire


async def _ask(connection: Connection, qid: int, name: str = ALLOWED) -> dnswire.Message:
    reader, writer = connection
    writer.write(_framed(build_query(name, qid=qid)))
    await writer.drain()
    size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), WATCHDOG))[0]
    return dnswire.parse(await asyncio.wait_for(reader.readexactly(size), WATCHDOG))


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


async def _served(listener: Listener, server: tuple[str, int], qid: int) -> Connection:
    """A connection that is accepted and answered, so its slot is taken before the next client connects."""
    connection = await listener.connect(server)
    reply = await _ask(connection, qid)
    assert (reply.id, reply.rcode) == (qid, 0)
    return connection


async def _turned_away(listener: Listener, server: tuple[str, int], frontend: WatchedFrontend) -> bytes:
    """Connect over the cap and send a query; returns what the server sent back before closing (nothing)."""
    reader, writer = await listener.connect(server)
    try:
        writer.write(_framed(build_query(ALLOWED, qid=0x0BAD)))
        sent = await _until_closed(reader)
        await frontend.finished.get()  # the handler has returned: nothing of this connection is left to happen
        return sent
    finally:
        writer.close()


def _overload_lines(warnings: list[object]) -> list[str]:
    return [str(line) for line in warnings if "TCP client limit" in str(line)]


# --- the cap -------------------------------------------------------------------------------------


def test_connections_beyond_the_cap_are_closed_unread_and_the_others_keep_working(
    booted: Booted, listener: Listener, monkeypatch: pytest.MonkeyPatch
) -> None:
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)

    async def scenario() -> tuple[list[bytes], int, tuple[int, int]]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG, max_tcp_clients=2)
            server = await listener.start(frontend)
            held = [await _served(listener, server, qid) for qid in (1, 2)]
            try:
                turned_away = [await _turned_away(listener, server, frontend) for _ in range(2)]
                upstream_connections = len(upstream.headers)
                kept = await _ask(held[0], 3)
                held[0][1].close()
                await frontend.finished.get()  # the first client left: its slot is free
                reused = await _served(listener, server, 4)  # asserts it was answered
                reused[1].close()
                return turned_away, upstream_connections, (kept.id, kept.rcode)
            finally:
                for _, writer in held:
                    writer.close()
                await frontend.stop()

    turned_away, upstream_connections, kept = asyncio.run(scenario())
    assert turned_away == [b"", b""]  # closed unread: not a byte of reply to the query each one sent
    assert upstream_connections == 2  # only the two served clients ever reached Unbound
    assert kept == (3, 0)  # a client that was in before the cap was hit is unaffected by it
    assert len(_overload_lines(warnings)) == 1  # two turned-away clients, one burst, one line
    assert "TCP client limit of 2" in _overload_lines(warnings)[0]


def test_a_new_overload_after_the_clients_drained_is_logged_again(
    booted: Booted, listener: Listener, monkeypatch: pytest.MonkeyPatch
) -> None:
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)

    async def scenario() -> list[int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = WatchedFrontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG, max_tcp_clients=1)
            server = await listener.start(frontend)
            lines_after_burst = []
            for burst in (1, 2):
                held = await _served(listener, server, burst)
                await _turned_away(listener, server, frontend)
                await _turned_away(listener, server, frontend)
                lines_after_burst.append(len(_overload_lines(warnings)))
                held[1].close()
                await frontend.finished.get()  # no client left: the burst is over
            await frontend.stop()
            return lines_after_burst

    assert asyncio.run(scenario()) == [1, 2]


def test_a_client_that_sends_nothing_holds_its_slot_only_until_the_idle_timeout(
    booted: Booted, listener: Listener, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "TCP_IDLE_TIMEOUT", 0.2)

    async def scenario() -> tuple[bytes, bytes, tuple[int, int]]:
        frontend = WatchedFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG, max_tcp_clients=1)
        server = await listener.start(frontend)
        silent_reader, silent_writer = await listener.connect(server)  # takes the only slot and says nothing
        try:
            over_cap = await _turned_away(listener, server, frontend)
            silent_sent = await _until_closed(silent_reader)  # the idle timeout closes it
            await frontend.finished.get()
            reply = await _ask(await listener.connect(server), 5, BLOCKED)  # the slot is back
            return over_cap, silent_sent, (reply.id, reply.rcode)
        finally:
            silent_writer.close()
            await frontend.stop()

    over_cap, silent_sent, reply = asyncio.run(scenario())
    assert (over_cap, silent_sent) == (b"", b"")
    assert reply == (5, 0)  # answered locally: the slot was free again


def test_the_tcp_cap_does_not_limit_udp(booted: Booted) -> None:
    async def scenario() -> bytes:
        frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG, max_tcp_clients=0)
        [server] = await frontend.start(["127.0.0.1"], 0)
        try:
            return (await udp_exchange(server, build_query(BLOCKED, qid=6)))[0]
        finally:
            await frontend.stop()

    reply = dnswire.parse(asyncio.run(scenario()))
    assert (reply.id, reply.rcode, len(reply.answers)) == (6, 0, 1)


class _ResetBeforeTheHandlerRan:
    """The StreamWriter of a connection whose peer reset it before the handler started: no addresses any more."""

    def __init__(self) -> None:
        self.closed = False

    def get_extra_info(self, name: str, default: object = None) -> object:
        return default

    def close(self) -> None:
        self.closed = True


def test_a_connection_that_is_gone_before_its_handler_runs_does_not_keep_a_slot(booted: Booted) -> None:
    frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG, max_tcp_clients=1)
    writers = [_ResetBeforeTheHandlerRan() for _ in range(3)]  # three would fill a cap of one for good if they leaked

    async def scenario() -> None:
        for writer in writers:
            await frontend._tcp_client(asyncio.StreamReader(), writer)  # type: ignore[arg-type]

    asyncio.run(scenario())
    assert [writer.closed for writer in writers] == [True, True, True]
    assert frontend._clients == set()


# --- the DoT handshake ---------------------------------------------------------------------------


def test_the_default_handshake_deadline_is_10_seconds() -> None:
    assert pfb_dns_proxy.TLS_HANDSHAKE_TIMEOUT == 10.0


def test_a_dot_client_that_never_sends_a_hello_is_disconnected_at_the_handshake_timeout(
    booted: Booted, certificate: tuple[bytes, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "TLS_HANDSHAKE_TIMEOUT", 0.2)

    async def scenario() -> tuple[bytes, bool]:
        frontend = WatchedFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        context = pfsense_dot.server_context(pfsense_dot.DotSettings(853, *certificate))
        [server] = await frontend.start_dot(["127.0.0.1"], 0, context)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*server), WATCHDOG)  # no TLS, no bytes
        try:
            sent = await _until_closed(reader)  # a server without a deadline holds this until the watchdog
            return sent, frontend.finished.empty()
        finally:
            writer.close()
            await frontend.stop()

    sent, never_reached_the_handler = asyncio.run(scenario())
    assert sent == b"" and never_reached_the_handler


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
        [server] = await frontend.start_dot(["127.0.0.1"], 0, context)
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
    assert [record.getMessage() for record in caplog.records if record.exc_info] == []
    assert "Traceback" not in capfd.readouterr().err
