"""Wire builders and a fake PROXYv2-speaking Unbound shared by the DNS proxy tests."""

from __future__ import annotations

import asyncio
import contextlib
import re
import selectors
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Self

import dnswire
import pfb_dns_proxy
from frontend_constants import PROTO_DIR

WATCHDOG = 10.0  # stuck-run guard for socket waits; never asserted on
PROXY_FIXED = 16  # 12-byte signature + ver/cmd + family + 2-byte length


def build_query(
    name: str,
    qtype: int = dnswire.TYPE_A,
    *,
    qid: int = 0x1234,
    rd: bool = True,
    cd: bool = False,
    edns: bool = False,
    do: bool = False,
    udp_size: int = 1232,
    options: bytes = b"",
) -> bytes:
    """A one-question query; `edns` adds an OPT advertising `udp_size`, `do` one with the DNSSEC-OK bit set, `options`
    (already encoded EDNS options) one that carries them."""
    opt = dnswire.RR(".", dnswire.TYPE_OPT, udp_size, 0x8000 if do else 0, options)
    flags = (dnswire.RD if rd else 0) | (dnswire.CD if cd else 0)
    message = dnswire.Message(
        qid, flags, [dnswire.Question(name, qtype)], additional=[opt] if edns or do or options else []
    )
    return dnswire.encode(message)


def _bind_strict(listen: Sequence[str], port: int, *, udp: bool) -> list[pfb_dns_proxy.Listener]:
    """pfb_dns_proxy.bind() on each address; the first ListenError propagates once the ones already bound are closed."""
    bound: list[pfb_dns_proxy.Listener] = []
    try:
        for host in listen:
            bound.append(pfb_dns_proxy.bind(host, port, udp=udp))
    except BaseException:
        for listener in bound:
            listener.close()
        raise
    return bound


async def serve_plain(frontend: pfb_dns_proxy.Frontend, listen: Sequence[str], port: int) -> list[tuple[str, int]]:
    """Serve UDP and TCP on each address (port 0 picks one port per address); returns the bound (host, port)s."""
    return await frontend.serve_listeners(_bind_strict(listen, port, udp=True))


async def serve_dot(
    frontend: pfb_dns_proxy.Frontend, listen: Sequence[str], port: int, context: ssl.SSLContext
) -> list[tuple[str, int]]:
    """Serve DNS over TLS on each address; returns the bound (host, port)s."""
    return await frontend.serve_listeners(_bind_strict(listen, port, udp=False), context)


EDNS_OPTION_EDE = 15  # RFC 8914 Extended DNS Error
UPSTREAM_SOA = "example. 60 IN SOA ns.example. hostmaster.example. 1 2 3 4 60"


@dataclass(frozen=True)
class UpstreamVerdict:
    """The raw reply an upstream resolver gives for one name, whatever Unbound makes of it on the way to its client:
    RCODE, the RA and AA header bits, RFC 8914 (info code, extra text) pairs and answer records (`{name}` is the
    queried name)."""

    rcode: int
    ra: bool = True
    aa: bool = False
    ede: tuple[tuple[int, str], ...] = ()
    answers: tuple[str, ...] = ()


def _upstream_reply(query: dnswire.Message, verdict: UpstreamVerdict) -> bytes:
    flags = dnswire.QR | (query.flags & dnswire.RD) | verdict.rcode
    flags |= (dnswire.RA if verdict.ra else 0) | (dnswire.AA if verdict.aa else 0)
    options = b"".join(
        struct.pack("!HHH", EDNS_OPTION_EDE, 2 + len(text.encode()), code) + text.encode() for code, text in verdict.ede
    )
    has_opt = any(rr.rtype == dnswire.TYPE_OPT for rr in query.additional)
    additional = [dnswire.RR(".", dnswire.TYPE_OPT, 1232, 0, options)] if options or has_opt else []
    authority = [] if verdict.answers else [dnswire.rr_from_text(UPSTREAM_SOA)]
    answers = [dnswire.rr_from_text(text.replace("{name}", query.questions[0].name)) for text in verdict.answers]
    return dnswire.encode(dnswire.Message(query.id, flags, query.questions, answers, authority, additional))


class FakeUnbound:
    """Stands in for Unbound behind the proxy: answers from a table, records every query it is sent.

    A name in `verdicts` (lower case, trailing dot) is answered with that raw reply instead of the table's, which is how
    a test makes the upstream behind a REAL Unbound say NXRA, an Extended DNS Error, a null address and so on.
    """

    def __init__(self, zone: dict[tuple[str, int], list[str]]) -> None:
        self.zone = zone
        self.verdicts: dict[str, UpstreamVerdict] = {}
        self.queries: list[bytes] = []

    def answer(self, wire: bytes) -> bytes:
        self.queries.append(wire)
        query = dnswire.parse(wire)
        question = query.questions[0]
        verdict = self.verdicts.get(question.name.lower())
        if verdict is not None:
            return _upstream_reply(query, verdict)
        rrs = self.zone.get((question.name.lower(), question.qtype))
        flags = dnswire.QR | dnswire.RA | (query.flags & dnswire.RD) | (0 if rrs is not None else 3)
        reply = dnswire.Message(query.id, flags, query.questions, [dnswire.rr_from_text(t) for t in rrs or []])
        return dnswire.encode(reply)

    async def __call__(self, wire: bytes) -> bytes | None:
        return self.answer(wire)


class FakeAuthoritative:
    """UDP responder on a loopback port served from a thread (a real Unbound forwards a zone to it).

    `delay` (seconds, settable between queries) holds each reply back on its own timer, so queries that arrive
    together are all in flight together instead of being answered one after the other.
    """

    def __init__(self, unbound: FakeUnbound, *, delay: float = 0.0) -> None:
        self.unbound = unbound
        self.delay = delay
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port: int = self.sock.getsockname()[1]
        self._timers: list[threading.Timer] = []
        self._wake_read, self._wake_write = socket.socketpair()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        with selectors.DefaultSelector() as selector:
            selector.register(self.sock, selectors.EVENT_READ)
            selector.register(self._wake_read, selectors.EVENT_READ)
            while True:
                for key, _ in selector.select():
                    if key.fileobj is self._wake_read:
                        return
                    data, client = self.sock.recvfrom(4096)
                    reply = self.unbound.answer(data)
                    if self.delay:
                        timer = threading.Timer(self.delay, self.sock.sendto, (reply, client))
                        self._timers.append(timer)
                        timer.start()
                    else:
                        self.sock.sendto(reply, client)

    def close(self) -> None:
        self._wake_write.send(b"x")
        self._thread.join()
        for timer in self._timers:
            timer.cancel()
            timer.join()
        for resource in (self.sock, self._wake_read, self._wake_write):
            resource.close()


def split_proxy_header(data: bytes) -> tuple[bytes, bytes]:
    """(PROXYv2 header, the rest) of a buffer that starts with one."""
    length = struct.unpack("!H", data[14:16])[0]
    return data[: PROXY_FIXED + length], data[PROXY_FIXED + length :]


class FakeProxyUpstream:
    """UDP+TCP listener on one loopback port that records each PROXYv2 header and answers via FakeUnbound."""

    def __init__(self, unbound: FakeUnbound, *, silent: bool = False) -> None:
        self.unbound = unbound
        self.silent = silent
        self.headers: list[bytes] = []
        self.port = 0
        self._tcp: asyncio.Server | None = None
        self._udp: asyncio.DatagramTransport | None = None

    async def __aenter__(self) -> Self:
        loop = asyncio.get_running_loop()
        self._tcp = await asyncio.start_server(self._tcp_client, "127.0.0.1", 0)
        self.port = self._tcp.sockets[0].getsockname()[1]
        udp, _ = await loop.create_datagram_endpoint(lambda: _UdpUpstream(self), local_addr=("127.0.0.1", self.port))
        self._udp = udp
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._tcp is not None and self._udp is not None
        self._udp.close()
        self._tcp.close()
        await self._tcp.wait_closed()

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            fixed = await reader.readexactly(PROXY_FIXED)
            header = fixed + await reader.readexactly(struct.unpack("!H", fixed[14:16])[0])
            self.headers.append(header)
            while True:
                size = struct.unpack("!H", await reader.readexactly(2))[0]
                reply = self.unbound.answer(await reader.readexactly(size))
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()


class _UdpUpstream(asyncio.DatagramProtocol):
    def __init__(self, owner: FakeProxyUpstream) -> None:
        self.owner = owner
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        header, wire = split_proxy_header(data)
        self.owner.headers.append(header)
        if not self.owner.silent and self.transport is not None:
            self.transport.sendto(self.owner.unbound.answer(wire), addr)


class _OneReply(asyncio.DatagramProtocol):
    def __init__(self, result: asyncio.Future[bytes]) -> None:
        self.result = result

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.result.done():
            self.result.set_result(data)


async def udp_exchange(
    server: tuple[str, int], wire: bytes, *, source: str = "127.0.0.1"
) -> tuple[bytes, tuple[str, int]]:
    """Send one datagram from `source`; return (reply, client socket address). A stuck run fails at the watchdog."""
    loop = asyncio.get_running_loop()
    result: asyncio.Future[bytes] = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _OneReply(result), remote_addr=server, local_addr=(source, 0)
    )
    try:
        transport.sendto(wire)
        return await asyncio.wait_for(result, WATCHDOG), transport.get_extra_info("sockname")[:2]
    finally:
        transport.close()


async def tcp_exchange(
    server: tuple[str, int], wire: bytes, *, source: str = "127.0.0.1"
) -> tuple[bytes, tuple[str, int]]:
    """One length-framed query over a fresh TCP connection from `source`; return (reply, client socket address)."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(*server, local_addr=(source, 0)), WATCHDOG)
    try:
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), WATCHDOG))[0]
        reply = await asyncio.wait_for(reader.readexactly(size), WATCHDOG)
        return reply, writer.get_extra_info("sockname")[:2]
    finally:
        writer.close()


async def udp_concurrent(server: tuple[str, int], queries: list[tuple[str, bytes]]) -> list[bytes]:
    """One datagram per (source, wire), sent back to back in list order once every socket exists; replies in list order.

    Nothing awaits between the sends, so the first query is on the wire, in order, before the second one starts.
    """
    loop = asyncio.get_running_loop()
    results: list[asyncio.Future[bytes]] = [loop.create_future() for _ in queries]
    transports = [
        (await loop.create_datagram_endpoint(partial(_OneReply, result), remote_addr=server, local_addr=(source, 0)))[0]
        for (source, _), result in zip(queries, results, strict=True)
    ]
    try:
        for transport, (_, wire) in zip(transports, queries, strict=True):
            transport.sendto(wire)
        return list(await asyncio.wait_for(asyncio.gather(*results), WATCHDOG))
    finally:
        for transport in transports:
            transport.close()


async def tcp_concurrent(server: tuple[str, int], queries: list[tuple[str, bytes]]) -> list[bytes]:
    """One length-framed query per (source, wire) on its own connection; all written before any reply is read.

    The queries are written in list order, but the proxy may service the connections in either order.
    """
    connections = [
        await asyncio.wait_for(asyncio.open_connection(*server, local_addr=(source, 0)), WATCHDOG)
        for source, _ in queries
    ]

    async def read_reply(reader: asyncio.StreamReader) -> bytes:
        size = struct.unpack("!H", await reader.readexactly(2))[0]
        return await reader.readexactly(size)

    try:
        for (_, writer), (_, wire) in zip(connections, queries, strict=True):
            writer.write(struct.pack("!H", len(wire)) + wire)
        return list(
            await asyncio.wait_for(asyncio.gather(*(read_reply(reader) for reader, _ in connections)), WATCHDOG)
        )
    finally:
        for _, writer in connections:
            writer.close()


@contextlib.contextmanager
def running_proxy(
    argv: Sequence[str], *, interpreter: str = sys.executable, cwd: Path | None = None
) -> Iterator[tuple[subprocess.Popen[str], int]]:
    """The real pfb_dns_proxy.py as a child process, once it says it listens: (child, its first UDP+TCP port).

    Leaving the block cleanly stops it with SIGTERM and requires exit status 0; leaving it by an exception just
    reaps it. A proxy that never says it listens fails at EOF of its stderr (the watchdog kills it), with what it said.
    """
    command = [interpreter, str(PROTO_DIR / "pfb_dns_proxy.py"), *argv]
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, cwd=cwd)
    watchdog = threading.Timer(WATCHDOG, child.kill)
    watchdog.start()
    try:
        assert child.stderr is not None
        seen: list[str] = []
        port = None
        for line in child.stderr:
            seen.append(line)
            if match := re.search(r"listening on 127\.0\.0\.1:(\d+)", line):
                port = int(match.group(1))
                break
        assert port is not None, f"the proxy never listened; it printed:\n{''.join(seen)}"
        yield child, port
        child.send_signal(signal.SIGTERM)
        assert child.wait(timeout=WATCHDOG) == 0
    finally:
        watchdog.cancel()
        if child.poll() is None:
            child.kill()
        child.wait()
        if child.stderr is not None:
            child.stderr.close()
