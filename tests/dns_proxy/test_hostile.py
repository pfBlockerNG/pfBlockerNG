"""Hostile packets and misbehaving peers must cost bounded time and descriptors, and one log line.

Pointer bombs and header-only FORMERR; dropped responses; a UDP flood and descriptor exhaustion; a TCP client that
never reads; the per-test alarm; stale upstream TCP, qclass, 14-bit offsets.
"""

from __future__ import annotations

import asyncio
import errno
import os
import struct
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import dnswire
import pfb_dns_proxy
import pytest
import unbound_shim as shim
from frontend_constants import ALLOWED, BLOCKED, Booted
from frontend_helpers import (
    PROXY_FIXED,
    WATCHDOG,
    FakeProxyUpstream,
    FakeUnbound,
    build_query,
    serve_plain,
    split_proxy_header,
    udp_exchange,
)

QTC = b"\x00\x01\x00\x01"  # qtype A, qclass IN
ZONE = {(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]}
SLOW = 0.05  # seconds a hostile packet may cost; the bombs below cost the unfixed code seconds


def _hdr(qd: int = 0, an: int = 0, ns: int = 0, ar: int = 0, *, flags: int = 0x0100, qid: int = 0xABCD) -> bytes:
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)


def _null_rr(owner: bytes) -> bytes:
    return owner + struct.pack("!HHIH", 10, 1, 0, 0)  # type NULL, no rdata


def _chain_of_questions(count: int) -> bytes:
    """`count` questions, each name a pointer at the previous question's name: parsing all costs count^2/2 hops."""
    out = bytearray(_hdr(count) + b"\x01a\x00" + QTC)
    previous = 12
    for _ in range(count - 1):
        here = len(out)
        out += struct.pack("!H", 0xC000 | previous) + QTC
        previous = here
    return bytes(out)


def _wide_name_questions(count: int) -> bytes:
    """A 127-label name, then `count` questions that are each a pointer at it."""
    return _hdr(count) + b"\x01a" * 127 + b"\x00" + QTC + (b"\xc0\x0c" + QTC) * (count - 1)


def _pointer_chain_rrs(count: int) -> bytes:
    """One question, then `count` RRs whose owners each point at the previous owner: the last name has `count` hops."""
    out = bytearray(_hdr(1, count) + b"\x01a\x00" + QTC)
    previous = 12
    for _ in range(count):
        here = len(out)
        out += _null_rr(struct.pack("!H", 0xC000 | previous))
        previous = here
    return bytes(out)


def _resolve_timed(booted: Booted, wire: bytes, forward: Any = None) -> tuple[bytes | None, float]:
    async def scenario() -> tuple[bytes | None, float]:
        frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        started = time.perf_counter()
        reply = await frontend.resolve(wire, "192.0.2.10", forward or FakeUnbound(ZONE))
        return reply, time.perf_counter() - started

    return asyncio.run(scenario())


# --- pointer bombs and header-only FORMERR -----------------------------------------------


def test_a_chain_of_200_compression_pointers_is_rejected_in_milliseconds() -> None:
    started = time.perf_counter()
    with pytest.raises(dnswire.WireError, match="pointer"):
        dnswire.parse(_pointer_chain_rrs(200))
    assert time.perf_counter() - started < SLOW


def test_a_chain_of_100_compression_pointers_is_still_a_name() -> None:
    message = dnswire.parse(_pointer_chain_rrs(100))
    assert [rr.name for rr in message.answers] == ["a."] * 100


@pytest.mark.parametrize(
    "bomb",
    [_chain_of_questions(4000), _wide_name_questions(8000), _hdr(2) + b"\x01a\x00" + QTC + b"\xc0\x0c" + QTC],
    ids=["chain-of-questions", "wide-name-pointer-questions", "two-questions"],
)
def test_a_query_without_exactly_one_question_gets_a_header_only_formerr_without_being_parsed(
    booted: Booted, bomb: bytes
) -> None:
    reply, elapsed = _resolve_timed(booted, bomb)
    assert reply is not None and len(reply) == 12  # the header alone: no question echoed, nothing to amplify
    parsed = dnswire.parse(reply)
    assert (parsed.id, parsed.rcode, parsed.flags & (dnswire.QR | dnswire.RD)) == (0xABCD, 1, dnswire.QR | dnswire.RD)
    assert elapsed < SLOW


@pytest.mark.parametrize(("extra", "formerr"), [(8, False), (9, True)])
def test_a_query_carrying_more_than_8_other_records_gets_a_header_only_formerr(
    booted: Booted, extra: int, formerr: bool
) -> None:
    wire = _hdr(1, ar=extra) + dnswire.encode_name(BLOCKED) + QTC + _null_rr(b"\x00") * extra
    reply, _ = _resolve_timed(booted, wire)
    assert reply is not None
    assert (len(reply) == 12 and dnswire.parse(reply).rcode == 1) is formerr
    assert formerr or dnswire.parse(reply).answers  # eight records are a query like any other: the block answer


# --- a response is never answered ------------------------------------------------------------


def test_a_truncated_packet_with_qr_set_is_dropped_not_answered_with_formerr(booted: Booted) -> None:
    truncated_response = struct.pack("!HHHHHH", 7, 0x8100, 1, 0, 0, 0) + b"\xc0"
    assert _resolve_timed(booted, truncated_response)[0] is None


# --- a flood and an exhausted descriptor table -----------------------------------------------


class _Collector(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.replies: list[bytes] = []

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.replies.append(data)


def test_udp_queries_beyond_the_in_flight_limit_are_dropped_with_one_log_line(
    booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)

    async def scenario() -> tuple[int, int, list[bytes]]:
        async with FakeProxyUpstream(FakeUnbound(ZONE), silent=True) as upstream:
            frontend = pfb_dns_proxy.Frontend(
                booted.module, ("127.0.0.1", upstream.port), timeout=0.3, max_udp_inflight=4
            )
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            collector = _Collector()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: collector, remote_addr=server
            )
            try:
                for qid in range(10):
                    transport.sendto(build_query(ALLOWED, qid=qid))
                while len(collector.replies) < 4:
                    await asyncio.sleep(0.01)
                await asyncio.sleep(0.3)  # the dropped six must not trickle in late
                return len(upstream.headers), len(collector.replies), collector.replies
            finally:
                transport.close()
                await frontend.stop()

    forwarded, answered, replies = asyncio.run(scenario())
    assert (forwarded, answered) == (4, 4)  # four in flight, six dropped
    assert [dnswire.parse(reply).rcode for reply in replies] == [2, 2, 2, 2]  # the four time out: SERVFAIL
    assert len([w for w in warnings if "in flight" in str(w)]) == 1


def test_no_descriptor_for_an_upstream_socket_is_one_log_line_and_a_servfail(
    booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    warnings: list[object] = []
    errors: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)
    monkeypatch.setattr(shim, "log_err", errors.append)
    real = asyncio.BaseEventLoop.create_datagram_endpoint

    async def out_of_descriptors(self: Any, factory: Any, *args: Any, **kwargs: Any) -> Any:
        if kwargs.get("remote_addr") == ("127.0.0.1", 9):  # the upstream socket; clients and listeners work
            raise OSError(errno.EMFILE, "Too many open files")
        return await real(self, factory, *args, **kwargs)

    async def scenario() -> bytes:
        frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
        monkeypatch.setattr(asyncio.BaseEventLoop, "create_datagram_endpoint", out_of_descriptors)
        try:
            return (await udp_exchange(server, build_query(ALLOWED)))[0]
        finally:
            await frontend.stop()

    assert dnswire.parse(asyncio.run(scenario())).rcode == 2
    assert errors == [] and len(warnings) == 1  # no traceback for a condition the code expects


# --- a TCP client that never reads -----------------------------------------------------------


def test_a_tcp_client_that_stops_reading_loses_its_connection(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "TCP_IDLE_TIMEOUT", 0.2)
    real_drain = asyncio.StreamWriter.drain

    async def drain_that_never_finishes_on_the_server_side(self: asyncio.StreamWriter) -> None:
        if self.get_extra_info("sockname")[1] == server_port:  # a peer whose receive window is full
            await asyncio.sleep(3600)
        await real_drain(self)

    server_port = 0

    async def scenario() -> bytes:
        nonlocal server_port
        frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
        server_port = server[1]
        monkeypatch.setattr(asyncio.StreamWriter, "drain", drain_that_never_finishes_on_the_server_side)
        try:
            reader, writer = await asyncio.open_connection(*server)
            wire = build_query(BLOCKED)
            writer.write(struct.pack("!H", len(wire)) + wire)
            await asyncio.wait_for(reader.readexactly(2 + 12), WATCHDOG)  # the reply was written before the stall
            rest = await asyncio.wait_for(reader.read(), WATCHDOG)  # EOF once the server gives up on the drain
            writer.close()
            return rest
        finally:
            await frontend.stop()

    asyncio.run(scenario())  # a server that never closes fails at the watchdog


# --- the per-test alarm ----------------------------------------------------------------------


def test_a_hung_test_is_failed_by_the_alarm_instead_of_stalling_the_run(tmp_path: Path) -> None:
    (tmp_path / "test_spin.py").write_text("def test_spin():\n    while True:\n        pass\n", encoding="utf-8")
    env = {**os.environ, "PFB_TEST_TIMEOUT": "1", "PYTHONPATH": str(Path(__file__).parent)}
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "hang_guard", "-p", "no:cacheprovider", "-o", "addopts=", "-q"]
        + [str(tmp_path / "test_spin.py")],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        cwd=tmp_path,
        env=env,
    )
    assert run.returncode == 1 and "test exceeded 1 s" in run.stdout


# --- stale upstream TCP, qclass, 14-bit offsets -----------------------------------------------


class _AnswersOnceThenCloses(FakeProxyUpstream):
    """An upstream that drops each TCP connection after one reply, as Unbound does when a connection idles out."""

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            fixed = await reader.readexactly(PROXY_FIXED)
            self.headers.append(fixed + await reader.readexactly(struct.unpack("!H", fixed[14:16])[0]))
            size = struct.unpack("!H", await reader.readexactly(2))[0]
            reply = self.unbound.answer(await reader.readexactly(size))
            writer.write(struct.pack("!H", len(reply)) + reply)
            await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()


def test_an_upstream_tcp_connection_unbound_closed_while_idle_is_reopened_once(booted: Booted) -> None:
    async def scenario() -> tuple[list[bytes], int]:
        async with _AnswersOnceThenCloses(FakeUnbound(ZONE)) as upstream:
            frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            try:
                reader, writer = await asyncio.open_connection(*server)
                replies = []
                for qid in (1, 2):
                    wire = build_query(ALLOWED, qid=qid)
                    writer.write(struct.pack("!H", len(wire)) + wire)
                    size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), WATCHDOG))[0]
                    replies.append(await asyncio.wait_for(reader.readexactly(size), WATCHDOG))
                    await asyncio.sleep(0.1)  # let the upstream's close arrive
                writer.close()
                return replies, len(upstream.headers)
            finally:
                await frontend.stop()

    replies, connections = asyncio.run(scenario())
    assert [(dnswire.parse(r).id, dnswire.parse(r).rcode, len(dnswire.parse(r).answers)) for r in replies] == [
        (1, 0, 1),
        (2, 0, 1),
    ]
    assert connections == 2


def test_the_question_class_reaches_the_module(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []
    real = booted.module.operate

    def spy(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        seen.append(qstate.qinfo.qclass)
        return real(id, event, qstate, qdata)

    monkeypatch.setattr(booted.module, "operate", spy)
    chaos = dnswire.encode(dnswire.Message(5, dnswire.RD, [dnswire.Question("version.bind.", dnswire.TYPE_TXT, 3)]))
    _resolve_timed(booted, chaos)
    assert seen[0] == 3


def test_a_name_first_written_beyond_the_14_bit_pointer_range_is_never_a_pointer_target() -> None:
    filler = dnswire.RR("a.example.", dnswire.TYPE_TXT, 1, 60, b"\xff" + b"x" * 255 + (b"\xff" + b"x" * 255) * 65)
    late = [dnswire.RR(f"{label}.late.example.", dnswire.TYPE_A, 1, 60, bytes(4)) for label in ("x", "y")]
    wire = dnswire.encode(dnswire.Message(1, dnswire.QR, [], [filler, *late]))
    assert len(wire) > 0x4000 + 40  # the late names really start beyond what a pointer can reach
    assert [rr.name for rr in dnswire.parse(wire).answers] == ["a.example.", "x.late.example.", "y.late.example."]


# --- an upstream reply that is not for this query ------------------------------------------------

GENUINE, FORGED = "192.0.2.77", "192.0.2.66"


class _ScriptedUnbound(asyncio.DatagramProtocol):
    """A UDP Unbound that answers each query (PROXYv2 header stripped) with the datagrams `script` returns for it."""

    def __init__(self, script: Callable[[dnswire.Message], list[bytes]]) -> None:
        self.script = script
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        assert self.transport is not None
        for reply in self.script(dnswire.parse(split_proxy_header(data)[1])):
            self.transport.sendto(reply, addr)


def _reply_for(query: dnswire.Message, qid: int, address: str) -> bytes:
    flags = dnswire.QR | dnswire.RA | dnswire.RD
    return dnswire.encode(
        dnswire.Message(qid, flags, query.questions, [dnswire.rr_from_text(f"{ALLOWED} 300 IN A {address}")])
    )


def _asked_over_udp(booted: Booted, script: Callable[[dnswire.Message], list[bytes]]) -> dnswire.Message:
    """What a client gets for ALLOWED (qid 0x1234) over UDP when Unbound's datagrams are whatever `script` says."""

    async def scenario() -> bytes:
        upstream, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: _ScriptedUnbound(script), local_addr=("127.0.0.1", 0)
        )
        frontend = pfb_dns_proxy.Frontend(booted.module, upstream.get_extra_info("sockname")[:2], timeout=0.3)
        [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
        try:
            return (await udp_exchange(server, build_query(ALLOWED, qid=0x1234)))[0]
        finally:
            await frontend.stop()
            upstream.close()

    return dnswire.parse(asyncio.run(scenario()))


def test_upstream_replies_with_another_id_or_under_2_bytes_are_ignored_until_the_right_one_arrives(
    booted: Booted,
) -> None:
    def script(query: dnswire.Message) -> list[bytes]:
        forged = _reply_for(query, query.id ^ 0xFFFF, FORGED)
        return [forged, b"", b"\x12", _reply_for(query, query.id, GENUINE)]

    reply = _asked_over_udp(booted, script)
    assert (reply.id, reply.rcode) == (0x1234, 0)
    assert [rr.rdata for rr in reply.answers] == [bytes([192, 0, 2, 77])]  # the genuine address, not the forged one


@pytest.mark.parametrize("kind", ["another-id", "empty", "one-byte"])
def test_only_upstream_replies_that_are_not_for_this_query_give_servfail_after_the_timeout(
    booted: Booted, kind: str
) -> None:
    def script(query: dnswire.Message) -> list[bytes]:
        forged = {"another-id": _reply_for(query, query.id ^ 0xFFFF, FORGED), "empty": b"", "one-byte": b"\x12"}
        return [forged[kind]]

    reply = _asked_over_udp(booted, script)
    assert (reply.id, reply.rcode, reply.answers) == (0x1234, 2, [])
