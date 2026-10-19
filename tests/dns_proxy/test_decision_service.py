"""Decision protocol (issue #3513): `pfb_dns_proxy.py --decision-fd N` answers or forwards per query over one AF_UNIX
stream, the Go gateway doing the transport. The REAL shipped pfb_unbound.py decides; the test plays the gateway
(QUERY in, FORWARD answered with a REPLY from a fake Unbound) in the event loop, or in a real child process where the
exit status is the point. Frame bytes are packed here with struct, not with the code under test.
"""

from __future__ import annotations

import asyncio
import csv
import json
import select
import socket
import stat
import struct
import subprocess
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import decision_service
import dnswire
import pfb_dns_proxy
import pytest
from frontend_constants import (
    ALLOWED,
    BLOCKED,
    BYPASSED_CLIENT,
    DNSBL_IPV4,
    FILTERED_CLIENT,
    PROTO_DIR,
    Booted,
    LogFeed,
)
from frontend_helpers import WATCHDOG, FakeUnbound, ManualClock, build_query

QUERY, FORWARD, REPLY, ANSWER, DROP, READY = 1, 2, 3, 4, 5, 6
MAX_FRAME_LEN = 5 + 1 + 1 + 255 + 65535  # type + id + (transport + n + 255 IP text bytes + 65535 DNS wire bytes)
STREAM, DATAGRAM = 0, 1  # the QUERY's transport byte
CLIENT = "192.0.2.10"
VIP4 = bytes(int(octet) for octet in DNSBL_IPV4.split("."))
DUCK, TARGET = "duck.example.", "safe.duck.example."
ZONE = {
    (ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"],
    (BLOCKED, dnswire.TYPE_A): [f"{BLOCKED} 300 IN A 192.0.2.99"],
    ("alias.example.", dnswire.TYPE_A): [
        "alias.example. 300 IN CNAME blocked.example.",
        "blocked.example. 300 IN A 192.0.2.99",
    ],
    (DUCK, dnswire.TYPE_A): [f"{DUCK} 300 IN A 192.0.2.50"],
    (TARGET, dnswire.TYPE_A): [f"{TARGET} 300 IN A 192.0.2.88"],
}
Frame = tuple[int, int, bytes]
NOTIFY = struct.pack("!HHHHHH", 5, 4 << 11, 1, 0, 0, 0) + b"\x07blocked\x07example\x00\x00\x06\x00\x01"  # opcode 4


def frame(ftype: int, fid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!IBI", 5 + len(payload), ftype, fid) + payload


def query_frame(fid: int, wire: bytes, ip: str | bytes = CLIENT, transport: int = STREAM) -> bytes:
    text = ip.encode("ascii") if isinstance(ip, str) else ip
    return frame(QUERY, fid, bytes([transport, len(text)]) + text + wire)


def _answers(wire: bytes) -> list[tuple[str, int, bytes]]:
    return [(rr.name, rr.rtype, rr.rdata) for rr in dnswire.parse(wire).answers]


class Gateway:
    """The Go side of the socketpair, played in the test's event loop."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer

    @classmethod
    async def attach(cls, sock: socket.socket) -> Gateway:
        return cls(*await asyncio.open_connection(sock=sock))

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self) -> Frame:
        (size,) = struct.unpack("!I", await asyncio.wait_for(self.reader.readexactly(4), WATCHDOG))
        body = await asyncio.wait_for(self.reader.readexactly(size), WATCHDOG)
        ftype, fid = struct.unpack_from("!BI", body)
        return ftype, fid, body[5:]

    async def expect_eof(self) -> None:
        """The decider closed its end and sent nothing more (read() runs to EOF, so a stray frame shows up)."""
        assert await asyncio.wait_for(self.reader.read(), WATCHDOG) == b""

    def close(self) -> None:
        self.writer.close()


async def _start_with(
    resolve: decision_service.Resolve, timeout: float = WATCHDOG
) -> tuple[Gateway, asyncio.Task[None], list[str]]:
    """The decision service over `resolve` on one end of a socketpair; the gateway has read READY."""
    go, py = socket.socketpair()
    problems: list[str] = []
    service = asyncio.ensure_future(decision_service.serve(py, resolve, timeout, problems.append))
    gateway = await Gateway.attach(go)
    assert await gateway.recv() == (READY, 0, b"")
    return gateway, service, problems


async def _start(booted: Booted, timeout: float = WATCHDOG) -> tuple[Gateway, asyncio.Task[None], list[str]]:
    """The decision service over the booted module's resolve; the gateway has read READY."""
    frontend = pfb_dns_proxy.Frontend(booted.module)
    return await _start_with(frontend.resolve, timeout)


def _run(booted: Booted, scenario: Callable[[Gateway], Awaitable[None]], timeout: float = WATCHDOG) -> None:
    """Run `scenario` against a live service, then end the session by EOF and require a clean return."""

    async def main() -> None:
        gateway, service, problems = await _start(booted, timeout)
        try:
            await scenario(gateway)
        finally:
            gateway.close()
            await asyncio.wait_for(service, WATCHDOG)
        assert problems == []

    asyncio.run(main())


def _decider(module_dir: Path, sock_fd: int) -> subprocess.Popen[str]:
    """The real `pfb_dns_proxy.py --decision-fd` process, inheriting `sock_fd` as the gateway would pass fd 3."""
    command = [sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), "--decision-fd", str(sock_fd)]
    command += ["--module-dir", str(module_dir)]
    return subprocess.Popen(
        command,
        pass_fds=[sock_fd],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def _recv_exactly(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        assert chunk, f"the decider closed the socket after {len(data)} of {size} expected bytes"
        data += chunk
    return data


def _feed_real_process(module_dir: Path, payload: bytes, *, half_close: bool) -> tuple[int, str, bytes]:
    """Boot the real process, wait for its READY, write `payload`, then read to EOF.

    Returns (exit status, stderr, bytes sent after READY). `half_close` also shuts our write side, as a gateway that
    died mid-frame would; otherwise the decider alone must close the socket. A stuck decider fails at the watchdog.
    """
    go, py = socket.socketpair()
    go.settimeout(WATCHDOG)
    child = _decider(module_dir, py.fileno())
    py.close()
    try:
        assert _recv_exactly(go, 4 + 5) == struct.pack("!IBI", 5, READY, 0)
        go.sendall(payload)
        if half_close:
            go.shutdown(socket.SHUT_WR)
        tail = b""
        while chunk := go.recv(4096):
            tail += chunk
        _, stderr = child.communicate(timeout=WATCHDOG)
        return child.returncode, stderr, tail
    finally:
        go.close()
        if child.poll() is None:
            child.kill()
            child.communicate()


# --- the protocol, one query at a time -------------------------------------------------------------


def test_a_blocked_name_is_answered_with_the_block_answer_and_never_forwarded(booted: Booted) -> None:
    query = build_query(BLOCKED, qid=0xBEEF)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(7, query))
        ftype, fid, answer = await gateway.recv()  # the first frame after QUERY: a FORWARD would have come before it
        assert (ftype, fid) == (ANSWER, 7)
        reply = dnswire.parse(answer)
        assert (reply.id, reply.rcode, reply.questions) == (0xBEEF, 0, dnswire.parse(query).questions)
        assert _answers(answer) == [(BLOCKED, dnswire.TYPE_A, VIP4)]

    _run(booted, scenario)


def test_an_allowed_name_is_forwarded_as_the_clients_own_bytes_and_the_reply_passes_through(booted: Booted) -> None:
    query = build_query(ALLOWED, qid=0x0A0A)
    upstream_reply = FakeUnbound(ZONE).answer(query)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(7, query))
        assert await gateway.recv() == (FORWARD, 7, query)
        await gateway.send(frame(REPLY, 7, upstream_reply))
        assert await gateway.recv() == (ANSWER, 7, upstream_reply)

    _run(booted, scenario)


def test_an_empty_reply_means_unbound_gave_none_and_the_client_gets_servfail_for_its_own_query(booted: Booted) -> None:
    query = build_query(ALLOWED, qid=0x0B0B)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(2, query))
        assert (await gateway.recv())[:2] == (FORWARD, 2)
        await gateway.send(frame(REPLY, 2))
        ftype, fid, answer = await gateway.recv()
        assert (ftype, fid) == (ANSWER, 2)
        reply = dnswire.parse(answer)
        assert (reply.id, reply.rcode, reply.questions) == (0x0B0B, 2, dnswire.parse(query).questions)

    _run(booted, scenario)


def test_a_cname_chain_into_a_blocked_name_is_answered_with_the_block_answer(booted: Booted) -> None:
    query = build_query("alias.example.")
    upstream_reply = FakeUnbound(ZONE).answer(query)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(3, query))
        assert await gateway.recv() == (FORWARD, 3, query)
        await gateway.send(frame(REPLY, 3, upstream_reply))
        ftype, fid, answer = await gateway.recv()
        assert (ftype, fid) == (ANSWER, 3)
        assert answer != upstream_reply  # MODDONE ran on Unbound's reply
        assert _answers(answer) == [("alias.example.", dnswire.TYPE_A, VIP4)]

    _run(booted, scenario)


def test_the_safesearch_chase_is_a_second_forward_under_the_same_id_and_the_answer_carries_cname_and_target(
    ss_booted: Booted,
) -> None:
    query = build_query(DUCK, qid=0x4242)
    unbound = FakeUnbound(ZONE)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(9, query))
        assert await gateway.recv() == (FORWARD, 9, query)
        await gateway.send(frame(REPLY, 9, unbound.answer(query)))
        ftype, fid, chase = await gateway.recv()
        assert (ftype, fid) == (FORWARD, 9)
        assert [(q.name, q.qtype) for q in dnswire.parse(chase).questions] == [(TARGET, dnswire.TYPE_A)]
        await gateway.send(frame(REPLY, 9, unbound.answer(chase)))
        ftype, fid, answer = await gateway.recv()
        assert (ftype, fid) == (ANSWER, 9)
        assert _answers(answer) == [
            (DUCK, dnswire.TYPE_CNAME, dnswire.encode_name(TARGET)),
            (TARGET, dnswire.TYPE_A, bytes([192, 0, 2, 88])),
        ]

    _run(ss_booted, scenario)


def test_a_response_packet_sent_as_a_query_is_dropped(booted: Booted) -> None:
    response = FakeUnbound(ZONE).answer(build_query(ALLOWED))

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(4, response))
        assert await gateway.recv() == (DROP, 4, b"")

    _run(booted, scenario)


def test_two_questions_get_a_formerr_answer_without_any_forward(booted: Booted) -> None:
    question = dnswire.encode_name(ALLOWED) + struct.pack("!HH", dnswire.TYPE_A, dnswire.CLASS_IN)
    two_questions = struct.pack("!HHHHHH", 0x4242, dnswire.RD, 2, 0, 0, 0) + question + question

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(5, two_questions))
        ftype, fid, answer = await gateway.recv()
        assert (ftype, fid) == (ANSWER, 5)
        assert (dnswire.parse(answer).id, dnswire.parse(answer).rcode) == (0x4242, 1)

    _run(booted, scenario)


def test_a_non_query_opcode_is_forwarded_unchanged_and_its_reply_relayed(booted: Booted) -> None:
    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(6, NOTIFY))
        assert await gateway.recv() == (FORWARD, 6, NOTIFY)
        await gateway.send(frame(REPLY, 6, b"canned"))
        assert await gateway.recv() == (ANSWER, 6, b"canned")

    _run(booted, scenario)


def test_an_empty_reply_to_a_forwarded_non_query_opcode_is_a_drop(booted: Booted) -> None:
    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(6, NOTIFY))
        assert await gateway.recv() == (FORWARD, 6, NOTIFY)
        await gateway.send(frame(REPLY, 6))  # no reply from Unbound: nothing to relay, so nothing to send
        assert await gateway.recv() == (DROP, 6, b"")

    _run(booted, scenario)


def test_the_client_ip_in_the_query_decides_the_module_sees_the_client_not_the_gateway(gp_booted: Booted) -> None:
    query = build_query(BLOCKED)
    upstream_reply = FakeUnbound(ZONE).answer(query)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(1, query, FILTERED_CLIENT))
        ftype, fid, answer = await gateway.recv()
        assert (ftype, fid, _answers(answer)) == (ANSWER, 1, [(BLOCKED, dnswire.TYPE_A, VIP4)])
        await gateway.send(query_frame(2, query, BYPASSED_CLIENT))  # on the Group Policy bypass list: never blocked
        assert await gateway.recv() == (FORWARD, 2, query)
        await gateway.send(frame(REPLY, 2, upstream_reply))
        assert await gateway.recv() == (ANSWER, 2, upstream_reply)

    _run(gp_booted, scenario)


@pytest.mark.parametrize("ip", ["192.0.2.10", "2001:db8::1"])
def test_ipv4_and_ipv6_client_text_are_both_accepted(booted: Booted, ip: str) -> None:
    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(1, build_query(BLOCKED), ip))
        assert (await gateway.recv())[:2] == (ANSWER, 1)

    _run(booted, scenario)


# --- queries interleave ----------------------------------------------------------------------------


def test_a_blocked_query_is_answered_while_another_waits_for_its_reply_and_the_ids_never_cross(booted: Booted) -> None:
    waiting = build_query(ALLOWED, qid=0x00A1)
    upstream_reply = FakeUnbound(ZONE).answer(waiting)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(10, waiting))
        assert await gateway.recv() == (FORWARD, 10, waiting)  # A is out; its REPLY is withheld
        await gateway.send(query_frame(11, build_query(BLOCKED, qid=0x00B1)))
        ftype, fid, blocked = await gateway.recv()  # B completes while A still waits
        assert (ftype, fid, dnswire.parse(blocked).id) == (ANSWER, 11, 0x00B1)
        await gateway.send(frame(REPLY, 10, upstream_reply))
        assert await gateway.recv() == (ANSWER, 10, upstream_reply)

    _run(booted, scenario)


def test_300_concurrent_queries_each_get_their_own_answer_under_their_own_id(booted: Booted) -> None:
    count = 300
    wires = {1000 + i: build_query(BLOCKED if i % 3 == 0 else f"host{i}.example.", qid=i) for i in range(count)}
    expected_forward = {fid: wire for fid, wire in wires.items() if dnswire.parse(wire).questions[0].name != BLOCKED}
    unbound = FakeUnbound(ZONE)

    async def scenario(gateway: Gateway) -> None:
        for fid, wire in wires.items():
            await gateway.send(query_frame(fid, wire))
        first: list[Frame] = [await gateway.recv() for _ in range(count)]  # one first frame per query
        forwards = {fid: payload for ftype, fid, payload in first if ftype == FORWARD}
        answers = {fid: payload for ftype, fid, payload in first if ftype == ANSWER}
        assert forwards == expected_forward
        assert {fid: dnswire.parse(a).id for fid, a in answers.items()} == {
            fid: dnswire.parse(wires[fid]).id for fid in answers
        }
        for fid in reversed(list(forwards)):  # answered in the opposite order to arrival
            await gateway.send(frame(REPLY, fid, unbound.answer(forwards[fid])))
        for _ in forwards:
            ftype, fid, payload = await gateway.recv()
            assert ftype == ANSWER and fid in forwards
            answers[fid] = payload
        assert answers.keys() == wires.keys()
        for fid, wire in wires.items():
            if fid in forwards:
                assert answers[fid] == unbound.answer(wire), fid
            else:
                assert _answers(answers[fid]) == [(BLOCKED, dnswire.TYPE_A, VIP4)], fid

    _run(booted, scenario)


# --- no reply from Unbound -------------------------------------------------------------------------


def test_a_reply_that_never_comes_ends_in_servfail_and_a_late_reply_is_ignored(booted: Booted) -> None:
    query = build_query(ALLOWED, qid=0x0B0B)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(5, query))
        assert (await gateway.recv())[:2] == (FORWARD, 5)  # no REPLY is sent
        ftype, fid, answer = await gateway.recv()
        assert (ftype, fid) == (ANSWER, 5)
        assert (dnswire.parse(answer).id, dnswire.parse(answer).rcode) == (0x0B0B, 2)
        await gateway.send(frame(REPLY, 5, b"late"))  # id 5 is finished: ignored, and the next query still works
        await gateway.send(query_frame(6, build_query(BLOCKED)))
        assert (await gateway.recv())[:2] == (ANSWER, 6)

    _run(booted, scenario, timeout=0.01)  # the wait for a REPLY is twice this


def test_the_wait_for_a_reply_is_twice_the_timeout(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    waits: list[float | None] = []
    real_wait_for = asyncio.wait_for

    async def spy(awaitable: Awaitable[Any], timeout: float | None) -> Any:
        waits.append(timeout)
        return await real_wait_for(awaitable, timeout)

    monkeypatch.setattr(asyncio, "wait_for", spy)
    query = build_query(ALLOWED)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(1, query))
        assert await gateway.recv() == (FORWARD, 1, query)
        await gateway.send(frame(REPLY, 1, FakeUnbound(ZONE).answer(query)))
        assert (await gateway.recv())[:2] == (ANSWER, 1)

    _run(booted, scenario, timeout=3.0)
    assert [wait for wait in waits if wait != WATCHDOG] == [6.0]  # the gateway's own reads wait WATCHDOG


# --- hostile input that does not end the session ---------------------------------------------------


async def _still_serving(gateway: Gateway) -> None:
    """A blocked query after the hostile frame: its ANSWER is the next frame, so nothing else was sent in between."""
    await gateway.send(query_frame(900, build_query(BLOCKED)))
    ftype, fid, answer = await gateway.recv()
    assert (ftype, fid, _answers(answer)) == (ANSWER, 900, [(BLOCKED, dnswire.TYPE_A, VIP4)])


@pytest.mark.parametrize(
    "ip",
    [b"999.1.1.1", "１２７.0.0.1".encode(), b"\xff\xfe", b"not-an-ip", b"192.0.2.10/24", b" 192.0.2.10"],
    ids=["octet-over-255", "non-ascii-digits", "invalid-utf8", "text", "cidr", "leading-space"],
)
def test_a_client_ip_that_is_not_an_ip_gets_a_drop_and_the_session_continues(booted: Booted, ip: bytes) -> None:
    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(1, build_query(BLOCKED), ip))
        assert await gateway.recv() == (DROP, 1, b"")
        await _still_serving(gateway)

    _run(booted, scenario)


@pytest.mark.parametrize("wire", [b"", b"\x12\x34\x01", bytes(11)], ids=["empty", "3-bytes", "11-bytes"])
def test_a_dns_wire_shorter_than_a_header_gets_a_drop_and_the_session_continues(booted: Booted, wire: bytes) -> None:
    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(1, wire))
        assert await gateway.recv() == (DROP, 1, b"")
        await _still_serving(gateway)

    _run(booted, scenario)


@pytest.mark.parametrize("finished", [False, True], ids=["never-seen", "finished"])
def test_a_reply_for_an_unknown_or_finished_id_is_ignored(booted: Booted, finished: bool) -> None:
    async def scenario(gateway: Gateway) -> None:
        if finished:
            await gateway.send(query_frame(77, build_query(BLOCKED)))
            assert (await gateway.recv())[:2] == (ANSWER, 77)
        await gateway.send(frame(REPLY, 77, b"stray"))
        await gateway.send(frame(REPLY, 77))  # the minimum frame: len 5, empty payload
        await _still_serving(gateway)

    _run(booted, scenario)


def test_a_query_of_exactly_the_maximum_frame_length_is_read_whole(booted: Booted) -> None:
    payload = (
        bytes([STREAM, 255]) + b"9" * 255 + bytes(65535)
    )  # 255 IP text bytes (not an IP: a DROP) + a 65535 byte wire
    assert 5 + len(payload) == MAX_FRAME_LEN

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(frame(QUERY, 1, payload))
        assert await gateway.recv() == (DROP, 1, b"")
        await _still_serving(gateway)

    _run(booted, scenario)


def test_a_query_id_that_is_already_in_flight_is_a_protocol_error(booted: Booted) -> None:
    async def main() -> None:
        gateway, service, _ = await _start(booted)
        await gateway.send(query_frame(5, build_query(ALLOWED)))
        assert (await gateway.recv())[:2] == (FORWARD, 5)
        await gateway.send(query_frame(5, build_query(ALLOWED)))
        with pytest.raises(decision_service.ProtocolError, match="already in flight"):
            await asyncio.wait_for(service, WATCHDOG)
        await gateway.expect_eof()

    asyncio.run(main())


def test_an_id_is_free_again_once_its_answer_has_been_sent(booted: Booted) -> None:
    async def scenario(gateway: Gateway) -> None:
        for _ in range(2):
            await gateway.send(query_frame(5, build_query(BLOCKED)))
            assert (await gateway.recv())[:2] == (ANSWER, 5)

    _run(booted, scenario)


# --- the decider's own failures, and a gateway that cannot keep up ------------------------------------


async def _sock_frame(sock: socket.socket) -> Frame:
    """The next frame from a non-blocking socket read by hand: a StreamReader would read ahead of the test."""
    loop = asyncio.get_running_loop()

    async def read(size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = await asyncio.wait_for(loop.sock_recv(sock, size - len(data)), WATCHDOG)
            assert chunk, f"the decider closed the socket after {len(data)} of {size} expected bytes"
            data += chunk
        return data

    (size,) = struct.unpack("!I", await read(4))
    body = await read(size)
    ftype, fid = struct.unpack_from("!BI", body)
    return ftype, fid, body[5:]


async def _serve_raw(
    resolve: decision_service.Resolve, problems: list[str], buffer: int | None = None
) -> tuple[socket.socket, asyncio.Task[None]]:
    """serve() over `resolve` on one end of a socketpair; returns the other end (non-blocking, READY already read)."""
    go, py = socket.socketpair()
    if buffer is not None:
        for end in (go, py):
            end.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer)
            end.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer)
    go.setblocking(False)
    service = asyncio.ensure_future(decision_service.serve(py, resolve, WATCHDOG, problems.append))
    assert await _sock_frame(go) == (READY, 0, b"")
    return go, service


def test_a_resolve_that_raises_gets_a_drop_one_log_entry_and_the_session_goes_on() -> None:
    async def resolve(wire: bytes, ip: str, forward: decision_service.Forward, *, datagram: bool) -> bytes | None:
        if wire == b"explode":
            raise RuntimeError("module crashed")
        return b"fine"

    async def main() -> None:
        gateway, service, problems = await _start_with(resolve)
        try:
            await gateway.send(query_frame(7, b"explode"))
            assert await gateway.recv() == (DROP, 7, b"")
            await gateway.send(query_frame(7, b"fine"))  # the failed query's id is free again
            assert await gateway.recv() == (ANSWER, 7, b"fine")
        finally:
            gateway.close()
            await asyncio.wait_for(service, WATCHDOG)
        assert len(problems) == 1, problems
        assert "query 7" in problems[0] and "module crashed" in problems[0], problems

    asyncio.run(main())


def test_a_burst_of_failing_queries_writes_one_log_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every failed query is dropped, but one flood of failures must not fill the unrotated log: one line per window."""
    clock = ManualClock()
    monkeypatch.setattr(decision_service, "monotonic", clock, raising=False)

    async def resolve(wire: bytes, ip: str, forward: decision_service.Forward, *, datagram: bool) -> bytes | None:
        raise RuntimeError("module crashed")

    async def main() -> None:
        gateway, service, problems = await _start_with(resolve)
        try:
            for fid in range(100):
                await gateway.send(query_frame(fid, b"explode"))
                assert await gateway.recv() == (DROP, fid, b"")
        finally:
            gateway.close()
            await asyncio.wait_for(service, WATCHDOG)
        assert len(problems) == 1 and "query 0" in problems[0], problems

    asyncio.run(main())


def test_a_failure_after_the_thirty_second_window_is_logged_again(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = ManualClock()
    monkeypatch.setattr(decision_service, "monotonic", clock, raising=False)

    async def resolve(wire: bytes, ip: str, forward: decision_service.Forward, *, datagram: bool) -> bytes | None:
        raise RuntimeError("module crashed")

    async def main() -> None:
        gateway, service, problems = await _start_with(resolve)
        try:
            for fid in (0, 1):
                await gateway.send(query_frame(fid, b"explode"))
                assert await gateway.recv() == (DROP, fid, b"")
            clock.advance(30.0)  # the window ends exactly here
            await gateway.send(query_frame(2, b"explode"))
            assert await gateway.recv() == (DROP, 2, b"")
        finally:
            gateway.close()
            await asyncio.wait_for(service, WATCHDOG)
        assert [problem.split(":")[0] for problem in problems] == ["query 0 failed", "query 2 failed"], problems

    asyncio.run(main())


@pytest.mark.parametrize(("transport", "datagram"), [(STREAM, False), (DATAGRAM, True)], ids=["stream", "datagram"])
def test_the_clients_transport_byte_reaches_resolve_as_the_datagram_flag(transport: int, datagram: bool) -> None:
    seen: list[tuple[bytes, str, bool]] = []

    async def resolve(wire: bytes, ip: str, forward: decision_service.Forward, *, datagram: bool) -> bytes | None:
        seen.append((wire, ip, datagram))
        return b"fine"

    async def main() -> None:
        gateway, service, problems = await _start_with(resolve)
        try:
            await gateway.send(query_frame(7, b"query", transport=transport))
            assert await gateway.recv() == (ANSWER, 7, b"fine")
        finally:
            gateway.close()
            await asyncio.wait_for(service, WATCHDOG)
        assert problems == []

    asyncio.run(main())
    assert seen == [(b"query", CLIENT, datagram)]


def test_a_gateway_that_stops_reading_makes_the_senders_wait_and_every_frame_arrives_whole_under_its_id() -> None:
    count, size = 64, 60_000  # ~3.8 MB against ~16 KB of socket buffers and the transport's 64 KiB high-water mark

    def blob(qid: int) -> bytes:
        return struct.pack("!I", qid) + bytes([qid % 251]) * (size - 4)

    async def main() -> None:
        loop = asyncio.get_running_loop()
        tasks: list[asyncio.Task[Any]] = []
        problems: list[str] = []
        all_resolved = asyncio.Event()

        async def resolve(wire: bytes, ip: str, forward: decision_service.Forward, *, datagram: bool) -> bytes | None:
            task = asyncio.current_task()
            assert task is not None
            tasks.append(task)
            if len(tasks) == count:
                all_resolved.set()  # the answer is returned without a suspension: the send is the next thing it does
            return blob(struct.unpack("!H", wire[:2])[0])

        go, service = await _serve_raw(resolve, problems, buffer=4096)
        try:
            for qid in range(count):
                await loop.sock_sendall(go, query_frame(1000 + qid, build_query(ALLOWED, qid=qid)))
            await asyncio.wait_for(all_resolved.wait(), WATCHDOG)
            waiting = [task for task in tasks if not task.done()]
            # Nothing was read from the gateway's end: only ~2 answers fit in the buffers, the senders of the rest wait.
            assert len(waiting) > count // 2, f"{len(waiting)} of {count} senders were waiting for the gateway to read"

            seen: set[int] = set()
            for _ in range(count):
                ftype, fid, payload = await _sock_frame(go)
                assert ftype == ANSWER and fid not in seen, (ftype, fid)
                assert payload == blob(fid - 1000), f"the frame for id {fid} carries another payload"
                seen.add(fid)
            assert seen == {1000 + qid for qid in range(count)}
            await asyncio.wait_for(asyncio.gather(*tasks), WATCHDOG)  # raises if a query task failed
        finally:
            go.close()  # also on failure: serve() cannot finish closing while answers are buffered for the gateway
        await asyncio.wait_for(service, WATCHDOG)
        assert problems == []

    asyncio.run(main())


def test_a_gateway_that_resets_the_connection_ends_the_session_quietly(monkeypatch: pytest.MonkeyPatch) -> None:
    real_readexactly = asyncio.StreamReader.readexactly
    failures: list[OSError] = []

    async def spy(self: asyncio.StreamReader, n: int) -> bytes:
        try:
            return await real_readexactly(self, n)
        except OSError as exc:
            failures.append(exc)
            raise

    monkeypatch.setattr(asyncio.StreamReader, "readexactly", spy)

    async def resolve(wire: bytes, ip: str, forward: decision_service.Forward, *, datagram: bool) -> bytes | None:
        return await forward(wire)

    async def main() -> None:
        problems: list[str] = []
        loop = asyncio.get_running_loop()
        go, service = await _serve_raw(resolve, problems)
        await loop.sock_sendall(go, query_frame(1, build_query(ALLOWED)))
        unread = asyncio.Event()
        loop.add_reader(go, unread.set)  # the FORWARD is queued for the gateway, which never reads it
        try:
            await asyncio.wait_for(unread.wait(), WATCHDOG)
        finally:
            loop.remove_reader(go)
        go.close()  # closing with unread data is how an AF_UNIX peer is reset: its next read fails, it does not see EOF
        await asyncio.wait_for(service, WATCHDOG)  # raises if the reset escaped
        assert problems == []

    asyncio.run(main())
    assert [type(exc) for exc in failures] == [ConnectionResetError], failures


def test_an_answer_the_gateway_can_no_longer_receive_ends_its_query_without_an_error() -> None:
    tasks: list[asyncio.Task[Any]] = []

    async def main() -> None:
        problems: list[str] = []
        started = asyncio.Event()

        async def resolve(wire: bytes, ip: str, forward: decision_service.Forward, *, datagram: bool) -> bytes | None:
            task = asyncio.current_task()
            assert task is not None
            tasks.append(task)
            started.set()
            return b"answer"

        go, service = await _serve_raw(resolve, problems)
        go.shutdown(
            socket.SHUT_RD
        )  # the gateway still writes but reads nothing more: the decider's send fails with EPIPE
        await asyncio.get_running_loop().sock_sendall(go, query_frame(1, build_query(ALLOWED)))
        await asyncio.wait_for(started.wait(), WATCHDOG)
        _, pending = await asyncio.wait(tasks, timeout=WATCHDOG)
        assert not pending, "the query task never finished"
        go.close()
        await asyncio.wait_for(service, WATCHDOG)
        assert problems == []

    asyncio.run(main())
    [task] = tasks
    assert not task.cancelled() and task.exception() is None, f"the query task ended with {task!r}"


# --- hostile framing: the real process logs it, closes the socket and exits 1 -----------------------

WIRE = build_query(BLOCKED)
PROTOCOL_ERRORS = {
    "len-below-minimum": struct.pack("!I", 4),
    "len-zero": struct.pack("!I", 0),
    "len-over-maximum": struct.pack("!I", MAX_FRAME_LEN + 1),
    "unknown-type-0x07": frame(0x07, 1),
    "unknown-type-0x00": frame(0x00, 1),
    "forward-from-gateway": frame(FORWARD, 1, WIRE),
    "answer-from-gateway": frame(ANSWER, 1, WIRE),
    "drop-from-gateway": frame(DROP, 1),
    "ready-from-gateway": frame(READY, 0),
    "query-without-payload": frame(QUERY, 1),
    "query-with-a-transport-byte-only": frame(QUERY, 1, bytes([STREAM])),
    "query-with-an-unknown-transport": frame(QUERY, 1, bytes([2, 10]) + b"192.0.2.10" + WIRE),
    "query-ip-length-zero": frame(QUERY, 1, bytes([STREAM, 0]) + WIRE),
    "query-ip-length-beyond-payload": frame(QUERY, 1, bytes([STREAM, 10]) + b"1.2.3.4"),
    "query-ip-length-one-past-payload": frame(QUERY, 1, bytes([DATAGRAM, 8]) + b"1.2.3.4"),  # n = 8, 7 bytes follow
}


@pytest.mark.parametrize("payload", PROTOCOL_ERRORS.values(), ids=PROTOCOL_ERRORS.keys())
def test_malformed_framing_is_logged_the_socket_closed_and_the_process_exits_1(
    module_dir: Path, payload: bytes
) -> None:
    status, stderr, tail = _feed_real_process(module_dir, payload, half_close=False)
    assert (status, "decision protocol error" in stderr, tail) == (1, True, b""), stderr


@pytest.mark.parametrize(
    "payload",
    [b"", struct.pack("!I", 5)[:2], struct.pack("!IBI", 100, QUERY, 1) + b"\x04abcd"],
    ids=["after-ready", "mid-header", "mid-payload"],
)
def test_the_gateway_going_away_ends_the_process_cleanly_with_exit_0(module_dir: Path, payload: bytes) -> None:
    status, stderr, tail = _feed_real_process(module_dir, payload, half_close=True)
    assert (status, "protocol error" in stderr, tail) == (0, False, b""), stderr


# --- the command line and the lifecycle ----------------------------------------------------------


def _serve_decisions(
    module_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: Callable[[Gateway], Awaitable[None]],
    *extra: str,
) -> tuple[list[tuple[Any, ...]], bool]:
    """pfb_dns_proxy.serve_decisions over a socketpair with the real boot; returns (events in order, whether a frame was
    already waiting for the gateway when boot() began)."""
    events: list[tuple[Any, ...]] = []
    go, py = socket.socketpair()
    waiting_at_boot: list[bool] = []
    real_boot, real_shutdown = pfb_dns_proxy.boot, pfb_dns_proxy.shutdown

    def boot(directory: str) -> Any:
        waiting_at_boot.append(bool(select.select([go], [], [], 0)[0]))
        events.append(("boot",))
        return real_boot(directory)

    def shutdown(module: Any) -> None:
        events.append(("shutdown",))
        real_shutdown(module)

    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)  # boot() swaps it; keep monkeypatch's restore
    monkeypatch.setattr(pfb_dns_proxy, "boot", boot)
    monkeypatch.setattr(pfb_dns_proxy, "shutdown", shutdown)
    for name in ("setgroups", "setgid", "setuid"):  # a drop needs root; the order is what is pinned
        monkeypatch.setattr(pfb_dns_proxy.os, name, lambda *args, name=name: events.append((name, *args)))
    args = pfb_dns_proxy.parse_args(["--decision-fd", str(py.detach()), "--module-dir", str(module_dir), *extra])

    async def main() -> None:
        service = asyncio.ensure_future(pfb_dns_proxy.serve_decisions(args))
        gateway = await Gateway.attach(go)
        try:
            assert await gateway.recv() == (READY, 0, b"")
            await scenario(gateway)
        finally:
            gateway.close()
            await asyncio.wait_for(service, WATCHDOG)

    asyncio.run(main())
    return events, waiting_at_boot == [True]


async def _nothing(_gateway: Gateway) -> None:
    return None


def test_ready_is_sent_only_after_the_module_has_booted(module_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    events, waiting_at_boot = _serve_decisions(module_dir, monkeypatch, _nothing)
    assert (events, waiting_at_boot) == ([("boot",), ("shutdown",)], False)


async def _leave_a_query_waiting_for_its_reply(gateway: Gateway) -> None:
    await gateway.send(query_frame(5, build_query(ALLOWED)))
    assert (await gateway.recv())[:2] == (FORWARD, 5)  # no REPLY follows: EOF arrives first


def test_eof_with_a_query_waiting_for_its_reply_cancels_it_shuts_the_module_down_and_returns(
    module_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events, _ = _serve_decisions(module_dir, monkeypatch, _leave_a_query_waiting_for_its_reply)
    assert events == [("boot",), ("shutdown",)]


def test_privilege_is_dropped_before_the_module_boots(module_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    events, _ = _serve_decisions(module_dir, monkeypatch, _nothing, "--user", "root")
    assert [event[0] for event in events] == ["setgroups", "setgid", "setuid", "boot", "shutdown"]


def test_an_unknown_user_exits_1_before_the_socket_or_the_module_is_touched(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "boot", lambda *_a: pytest.fail("the module must not boot"))
    assert pfb_dns_proxy.main(["--decision-fd", "999", "--user", "pfb-no-such-user-3513"]) == 1
    assert capsys.readouterr().err == "pfb_dns_proxy: unknown user 'pfb-no-such-user-3513'\n"


# --- the upstream observer: the decider is the module host while the gateway fronts DNS ---------------------------
# Unbound's observer (pfb_upstream_observer.py) reports each raw upstream response to pfb_upstream.sock in the module
# dir. With the Go gateway there is no listening proxy, so the decider serves that socket itself when it is told to
# with --observer (DNSBL on, Resolver forwarding), or upstream blocks are no longer logged (issue #3513).

NXDOMAIN_RECURSIVE = 0x8183  # QR RD RA, NXDOMAIN: how a forwarding upstream answers a name it blocks
UPSTREAM_BLOCKED = "upstream-blocked.example"


def _observer_report() -> bytes:
    """The datagram the observer sends from inside Unbound for an upstream answer carrying EDE 15 (Blocked)."""
    ede15 = b"\x00\x0fBlocked by Quad9"
    return json.dumps(
        {
            "client": CLIENT,
            "qname": f"{UPSTREAM_BLOCKED}.",
            "qtype": dnswire.TYPE_A,
            "flags": NXDOMAIN_RECURSIVE,
            "opts": [[15, ede15.hex()]],
        }
    ).encode()


def _module_logs(monkeypatch: pytest.MonkeyPatch) -> LogFeed:
    """Send the log lines of whichever module boots next to a LogFeed instead of /var/log."""
    log = LogFeed()
    real_boot = pfb_dns_proxy.boot

    def boot(directory: str) -> Any:
        module = real_boot(directory)
        monkeypatch.setattr(module, "pfb_log", lambda name, line: log.append((name, line)))
        return module

    monkeypatch.setattr(pfb_dns_proxy, "boot", boot)
    return log


def _upstream_blocked_names(log: list[tuple[str, str]]) -> list[str]:
    rows = [next(csv.reader([line])) for name, line in log if name.endswith("dnsbl.log")]
    return [row[2] for row in rows if row[5] == "Upstream_Block"]


def test_an_upstream_report_sent_to_the_observer_socket_fires_the_modules_query_response(
    module_dir: Path, forwarding_ini: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = _module_logs(monkeypatch)
    socket_path = module_dir / pfb_dns_proxy.OBSERVER_SOCKET

    async def scenario(_gateway: Gateway) -> None:
        assert socket_path.exists(), f"the decider serves no observer socket at {socket_path}"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as observer:
            observer.sendto(_observer_report(), str(socket_path))
        await asyncio.to_thread(log.wait_for, lambda lines: _upstream_blocked_names(lines) == [UPSTREAM_BLOCKED])

    _serve_decisions(module_dir, monkeypatch, scenario, "--observer")
    assert _upstream_blocked_names(log) == [UPSTREAM_BLOCKED]


def test_the_observer_socket_is_private_while_the_decider_serves_and_gone_when_the_session_ends(
    module_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = module_dir / pfb_dns_proxy.OBSERVER_SOCKET
    modes: list[int] = []

    async def scenario(_gateway: Gateway) -> None:
        assert socket_path.exists(), f"the decider serves no observer socket at {socket_path}"
        modes.append(socket_path.stat().st_mode)

    _serve_decisions(module_dir, monkeypatch, scenario, "--observer")
    assert [(stat.S_ISSOCK(mode), stat.S_IMODE(mode)) for mode in modes] == [(True, 0o600)]
    assert not socket_path.exists()


def test_decisions_are_still_served_when_the_observer_socket_cannot_be_made(
    module_dir: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    socket_path = module_dir / pfb_dns_proxy.OBSERVER_SOCKET
    socket_path.write_text("in the way", encoding="utf-8")
    _module_logs(monkeypatch)

    async def scenario(gateway: Gateway) -> None:
        await gateway.send(query_frame(7, build_query(BLOCKED)))
        assert (await gateway.recv())[:2] == (ANSWER, 7)

    _serve_decisions(module_dir, monkeypatch, scenario, "--observer")
    assert "upstream-block detection is off" in capfd.readouterr().err
    assert socket_path.read_text(encoding="utf-8") == "in the way"
