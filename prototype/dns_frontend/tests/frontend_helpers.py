"""Wire builders and a fake PROXYv2-speaking Unbound shared by the prototype tests."""

from __future__ import annotations

import asyncio
import selectors
import socket
import struct
import threading
from typing import Self

import dnswire

WATCHDOG = 10.0  # stuck-run guard for socket waits; never asserted on
PROXY_FIXED = 16  # 12-byte signature + ver/cmd + family + 2-byte length


def build_query(
    name: str, qtype: int = dnswire.TYPE_A, *, qid: int = 0x1234, rd: bool = True, edns: bool = False
) -> bytes:
    additional = [dnswire.make_opt()] if edns else []
    message = dnswire.Message(qid, dnswire.RD if rd else 0, [dnswire.Question(name, qtype)], additional=additional)
    return dnswire.encode(message)


class FakeUnbound:
    """Stands in for Unbound behind the front end: answers from a table, records every query it is sent."""

    def __init__(self, zone: dict[tuple[str, int], list[str]]) -> None:
        self.zone = zone
        self.queries: list[bytes] = []

    def answer(self, wire: bytes) -> bytes:
        self.queries.append(wire)
        query = dnswire.parse(wire)
        question = query.questions[0]
        rrs = self.zone.get((question.name.lower(), question.qtype))
        flags = dnswire.QR | dnswire.RA | (query.flags & dnswire.RD) | (0 if rrs is not None else 3)
        reply = dnswire.Message(query.id, flags, query.questions, [dnswire.rr_from_text(t) for t in rrs or []])
        return dnswire.encode(reply)

    async def __call__(self, wire: bytes) -> bytes | None:
        return self.answer(wire)


class FakeAuthoritative:
    """UDP responder on a loopback port served from a thread (a real Unbound forwards a zone to it)."""

    def __init__(self, unbound: FakeUnbound) -> None:
        self.unbound = unbound
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port: int = self.sock.getsockname()[1]
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
                    self.sock.sendto(self.unbound.answer(data), client)

    def close(self) -> None:
        self._wake_write.send(b"x")
        self._thread.join()
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
