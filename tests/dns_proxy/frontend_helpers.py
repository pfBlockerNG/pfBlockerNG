"""Wire builders, a fake Unbound, client exchanges and the decision socket's gateway end, shared by the DNS tests."""

from __future__ import annotations

import asyncio
import contextlib
import selectors
import socket
import struct
import threading
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from functools import partial

import dnswire

WATCHDOG = 10.0  # stuck-run guard for socket waits; never asserted on


class ManualClock:
    """Stands in for pfb_dns_proxy.monotonic: it reads the same every time until a test moves it. The decider's log
    window runs on that clock, so a test ages a silence by `advance`, never by waiting. The tests use steps that are
    exact in binary (0.5, 1, 2...), so a boundary is hit exactly."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


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


EDNS_OPTION_EDE = 15  # RFC 8914 Extended DNS Error
AD = 0x0020  # DNSSEC authenticated data: dnswire does not name it, and the proxy never sets it on its own answers
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

    `gate` (an Event, settable between queries) holds each reply back until it is set, so a test can release the
    replies once it has seen the queries it wants in flight together; None answers at once.
    """

    def __init__(self, unbound: FakeUnbound) -> None:
        self.unbound = unbound
        self.gate: threading.Event | None = None
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
                    reply = self.unbound.answer(data)
                    if self.gate is None:
                        self.sock.sendto(reply, client)
                    else:
                        threading.Thread(
                            target=self._send_when_open, args=(self.gate, reply, client), daemon=True
                        ).start()

    def _send_when_open(self, gate: threading.Event, reply: bytes, client: tuple[str, int]) -> None:
        if gate.wait(WATCHDOG):  # a gate never opened is a stuck test: the reply is dropped and the test fails
            with contextlib.suppress(OSError):  # the socket is closed when the test is over
                self.sock.sendto(reply, client)

    def close(self) -> None:
        self._wake_write.send(b"x")
        self._thread.join()
        for resource in (self.sock, self._wake_read, self._wake_write):
            resource.close()


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


# --- the gateway end of the decision socket, for tests that run the decider in this process ---------------------

QUERY, FORWARD, REPLY, ANSWER, READY = 1, 2, 3, 4, 6  # the frame types of docs/misc/dns-gateway-protocol.md
STREAM, DATAGRAM = 0, 1  # the QUERY's transport byte


class DecisionGateway:
    """The Go gateway's end of the decision socket, played in the test's event loop; frames are packed here."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer

    async def send(self, ftype: int, fid: int, payload: bytes = b"") -> None:
        self.writer.write(struct.pack("!IBI", 5 + len(payload), ftype, fid) + payload)
        await self.writer.drain()

    async def recv(self) -> tuple[int, int, bytes]:
        (size,) = struct.unpack("!I", await asyncio.wait_for(self.reader.readexactly(4), WATCHDOG))
        body = await asyncio.wait_for(self.reader.readexactly(size), WATCHDOG)
        ftype, fid = struct.unpack_from("!BI", body)
        return ftype, fid, body[5:]

    async def ask(
        self, wire: bytes, unbound: FakeUnbound, *, client: str = "127.0.0.2", datagram: bool = True, fid: int = 1
    ) -> bytes:
        """QUERY `wire` as `client`, answer every FORWARD from `unbound`, and return the final ANSWER's wire."""
        text = client.encode("ascii")
        await self.send(QUERY, fid, bytes([DATAGRAM if datagram else STREAM, len(text)]) + text + wire)
        while True:
            ftype, got, payload = await self.recv()
            assert got == fid
            if ftype == ANSWER:
                return payload
            assert ftype == FORWARD, f"frame type {ftype}: want FORWARD or ANSWER"
            await self.send(REPLY, fid, unbound.answer(payload))


@contextlib.asynccontextmanager
async def serving_decisions(argv: Sequence[str]) -> AsyncIterator[DecisionGateway]:
    """pfb_dns_proxy.serve_decisions() as a task of this process on one end of a socketpair, with `argv` after
    `--decision-fd`: yields the gateway end once READY has been read. Leaving ends the session by EOF, and a decider
    that failed raises here."""
    import pfb_dns_proxy  # the shipped decider: the tests' conftest puts its directory on sys.path

    gateway_end, decider_end = socket.socketpair()
    args = pfb_dns_proxy.parse_args(["--decision-fd", str(decider_end.detach()), *argv])
    task = asyncio.ensure_future(pfb_dns_proxy.serve_decisions(args))
    reader, writer = await asyncio.open_connection(sock=gateway_end)
    gateway = DecisionGateway(reader, writer)
    try:
        assert await gateway.recv() == (READY, 0, b"")
        yield gateway
    finally:
        writer.close()
        await asyncio.wait_for(task, WATCHDOG)
