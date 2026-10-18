"""Hostile packets and misbehaving peers must cost bounded time and descriptors, and one log line.

Pointer bombs and header-only FORMERR; dropped responses; a UDP flood and descriptor exhaustion; a TCP client that
never reads; the per-test alarm; stale upstream TCP, qclass, 14-bit offsets.
"""

from __future__ import annotations

import asyncio
import errno
import inspect
import os
import struct
import subprocess
import sys
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
    ManualClock,
    build_query,
    drained,
    serve_plain,
    split_proxy_header,
    tcp_exchange,
    udp_client,
    udp_exchange,
)

QTC = b"\x00\x01\x00\x01"  # qtype A, qclass IN
ZONE = {(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]}


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


def _resolve(booted: Booted, wire: bytes, forward: Any = None) -> bytes | None:
    async def scenario() -> bytes | None:
        frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        return await frontend.resolve(wire, "192.0.2.10", forward or FakeUnbound(ZONE))

    return asyncio.run(scenario())


# --- pointer bombs and header-only FORMERR -----------------------------------------------


def test_a_chain_of_200_compression_pointers_is_rejected() -> None:
    with pytest.raises(dnswire.WireError, match="pointer"):
        dnswire.parse(_pointer_chain_rrs(200))


def test_a_chain_of_100_compression_pointers_is_still_a_name() -> None:
    message = dnswire.parse(_pointer_chain_rrs(100))
    assert [rr.name for rr in message.answers] == ["a."] * 100


@pytest.mark.parametrize(
    "bomb",
    [_chain_of_questions(4000), _wide_name_questions(8000), _hdr(2) + b"\x01a\x00" + QTC + b"\xc0\x0c" + QTC],
    ids=["chain-of-questions", "wide-name-pointer-questions", "two-questions"],
)
def test_a_query_without_exactly_one_question_gets_a_header_only_formerr_without_being_parsed(
    booted: Booted, bomb: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(dnswire, "parse", lambda _wire: pytest.fail("the packet was parsed: its cost is not constant"))
        reply = _resolve(booted, bomb)
    assert reply is not None and len(reply) == 12  # the header alone: no question echoed, nothing to amplify
    msg_id, flags, *counts = struct.unpack("!HHHHHH", reply)
    assert (msg_id, flags & 0xF, flags & (dnswire.QR | dnswire.RD), counts) == (
        0xABCD,
        1,
        dnswire.QR | dnswire.RD,
        [0, 0, 0, 0],
    )


@pytest.mark.parametrize(("extra", "formerr"), [(8, False), (9, True)])
def test_a_query_carrying_more_than_8_other_records_gets_a_header_only_formerr(
    booted: Booted, extra: int, formerr: bool
) -> None:
    wire = _hdr(1, ar=extra) + dnswire.encode_name(BLOCKED) + QTC + _null_rr(b"\x00") * extra
    reply = _resolve(booted, wire)
    assert reply is not None
    assert (len(reply) == 12 and dnswire.parse(reply).rcode == 1) is formerr
    assert formerr or dnswire.parse(reply).answers  # eight records are a query like any other: the block answer


# --- a response is never answered ------------------------------------------------------------


def test_a_truncated_packet_with_qr_set_is_dropped_not_answered_with_formerr(booted: Booted) -> None:
    truncated_response = struct.pack("!HHHHHH", 7, 0x8100, 1, 0, 0, 0) + b"\xc0"
    assert _resolve(booted, truncated_response) is None


# --- a flood and an exhausted descriptor table -----------------------------------------------


def _ids(replies: list[bytes]) -> list[int]:
    return sorted(dnswire.parse(reply).id for reply in replies)


class _Hold:
    """Queries to hand Frontend.spawn_udp_query that wait on one event, and a record of who started and who was
    cancelled: what a query that Unbound has not answered yet looks like, without a socket."""

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


def test_the_in_flight_limits_default_to_512_in_all_and_256_per_source() -> None:
    assert (pfb_dns_proxy.MAX_UDP_INFLIGHT, pfb_dns_proxy.MAX_UDP_PER_SOURCE) == (512, 256)


def test_a_busy_address_with_120_queries_in_flight_has_every_one_of_them_answered(booted: Booted) -> None:
    """Issue #3515 gate: one address (a NAT'd network, a downstream forwarder, 127.0.0.1) at 400 qps against 0.3 s of
    Unbound latency keeps about 120 queries in flight. The per-source limit of 64 dropped the oldest for every newcomer,
    so each was cancelled just before its answer: 4% were answered."""
    count = 120

    class Holding(pfb_dns_proxy.Frontend):
        """Keeps every query inside resolve() until all of them have been received, so all 120 are in flight at once."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.received = 0
            self.all_received = asyncio.Event()
            self.release = asyncio.Event()
            self.answered: list[int] = []

        def spawn_udp_query(self, coro: Any, src: str) -> None:
            super().spawn_udp_query(coro, src)
            self.received += 1
            if self.received == count:
                self.all_received.set()

        async def resolve(self, wire: bytes, client_ip: str, forward: Any, **kwargs: Any) -> bytes | None:
            await self.release.wait()
            reply = await super().resolve(wire, client_ip, forward, **kwargs)
            self.answered.append(dnswire.parse(wire).id)  # not reached by a query cancelled while it waited
            return reply

    async def scenario() -> tuple[list[int], list[tuple[int, int, int]]]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = Holding(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            transport, client = await udp_client(server, "127.0.0.2")
            try:
                for qid in range(count):
                    transport.sendto(build_query(ALLOWED, qid=qid))
                await asyncio.wait_for(frontend.all_received.wait(), WATCHDOG)
                frontend.release.set()
                await drained(frontend)
                replies = [dnswire.parse(wire) for wire in await client.until(len(frontend.answered))]
                return sorted(frontend.answered), sorted((r.id, r.rcode, len(r.answers)) for r in replies)
            finally:
                transport.close()
                await frontend.stop()

    answered, replies = asyncio.run(scenario())
    assert answered == list(range(count))
    assert replies == [(qid, 0, 1) for qid in range(count)]


def test_a_source_at_its_udp_limit_has_its_newcomers_dropped_and_no_other_source_is_affected(
    booted: Booted, clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #3517 review: about 100 qps of names Unbound never answers from one host left every other host without
    DNS, because each held one of the shared slots for the whole timeout. What the limit protects is the queries
    already waiting, which may still be answered: over it, the newcomer is the one that is dropped."""
    monkeypatch.setattr(pfb_dns_proxy, "MAX_UDP_PER_SOURCE", 4)

    async def scenario() -> tuple[list[bytes], list[bytes]]:
        upstream = FakeProxyUpstream(FakeUnbound(ZONE), unanswered_prefix="slow")
        async with upstream:
            frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", upstream.port), timeout=0.3)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            flooder, flood = await udp_client(server, "127.0.0.2")
            bystander, other = await udp_client(server, "127.0.0.3")
            try:
                for qid in range(12):
                    flooder.sendto(build_query(f"slow{qid}.example.", qid=qid))
                bystander.sendto(build_query(ALLOWED, qid=0x77))
                await other.until(1)
                await flood.until(4)  # the flooder's four admitted queries time out
                await frontend.stop()  # every query task has ended: one that was dropped can never answer
                await asyncio.sleep(0)
                return flood.replies, other.replies
            finally:
                flooder.close()
                bystander.close()

    flood, other = asyncio.run(scenario())
    assert (_ids(flood), {dnswire.parse(reply).rcode for reply in flood}) == ([0, 1, 2, 3], {2})
    answered = dnswire.parse(other[0])
    assert (answered.id, answered.rcode, len(answered.answers)) == (0x77, 0, 1)


UDP_LIMITS = [
    pytest.param("MAX_UDP_PER_SOURCE", ["192.0.2.1"] * 4, id="source-limit"),
    pytest.param("MAX_UDP_INFLIGHT", ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"], id="global-limit"),
]


@pytest.mark.parametrize(("limit", "sources"), UDP_LIMITS)
def test_a_udp_query_at_a_limit_is_dropped_for_a_newcomer_only_once_it_has_waited_half_the_timeout(
    limit: str, sources: list[str], clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A query that is still young may be answered: the newcomer is dropped, not it. One that has waited half the
    timeout for Unbound will not be (an unanswered name holds its slot to the end): it is dropped for the newcomer, and
    at the global limit it may be another address's."""
    monkeypatch.setattr(pfb_dns_proxy, limit, 2)

    async def scenario() -> tuple[tuple[list[str], list[str], str], tuple[list[str], list[str]]]:
        hold = _Hold()
        frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9), timeout=4.0)
        first_source, second_source, third_source, fourth_source = sources
        frontend.spawn_udp_query(hold.query("first"), first_source)
        clock.advance(1.0)
        frontend.spawn_udp_query(hold.query("second"), second_source)
        clock.advance(0.5)
        young = hold.query("third")
        frontend.spawn_udp_query(young, third_source)  # `first` has waited 1.5 s of the 2 s: the newcomer is dropped
        await asyncio.sleep(0)
        before = (list(hold.started), list(hold.cancelled), inspect.getcoroutinestate(young))
        clock.advance(0.5)
        frontend.spawn_udp_query(hold.query("fourth"), fourth_source)  # `first` has now waited exactly 2 s: it goes
        await asyncio.sleep(0)
        after = (list(hold.started), list(hold.cancelled))
        hold.release.set()
        await drained(frontend)
        return before, after

    before, after = asyncio.run(scenario())
    assert before == (["first", "second"], [], inspect.CORO_CLOSED)  # closed: dropped, and never awaited
    assert after == (["first", "second", "fourth"], ["first"])


def test_an_overloaded_udp_table_is_logged_once_per_flood_and_again_for_the_next_one(
    clock: ManualClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)
    monkeypatch.setattr(pfb_dns_proxy, "MAX_UDP_PER_SOURCE", 2)

    async def scenario() -> list[list[str]]:
        frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9))
        started = []
        for _ in range(2):  # two floods, the queries of the first gone before the second starts
            hold = _Hold()
            for n in range(5):  # three of the five are over the limit: one line, not three
                frontend.spawn_udp_query(hold.query(f"q{n}"), "192.0.2.1")
            await asyncio.sleep(0)
            started.append(hold.started)
            hold.release.set()
            await drained(frontend)
        return started

    assert asyncio.run(scenario()) == [["q0", "q1"], ["q0", "q1"]]
    assert len([w for w in warnings if "in flight" in str(w)]) == 2


def test_the_per_source_counts_keep_nothing_for_a_source_with_no_query_left() -> None:
    """A flood from spoofed addresses would otherwise grow the table by one entry per address for the process's life."""

    async def scenario() -> tuple[int, dict[str, int], dict[Any, Any]]:
        frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9))

        async def finished() -> None:
            return None

        for index in range(50):
            frontend.spawn_udp_query(finished(), f"192.0.2.{index}")
        counted = len(frontend._per_source)
        await drained(frontend)
        return counted, frontend._per_source, frontend._queries

    assert asyncio.run(scenario()) == (50, {}, {})


# --- one client's pipelined frames do not stall everyone else ---------------------------------


def test_a_pipelined_burst_on_one_tcp_connection_does_not_hold_up_a_udp_query(booted: Booted) -> None:
    """Issue #3517 review: a client with 100k buffered frames delayed a UDP reply from 0.7 ms to 754 ms, because a read
    of buffered bytes and a write that is not blocked never yield. The burst is zero-length frames, which cost the
    proxy nothing but the loop turn; what is counted is how many were handled by the time the UDP query was."""
    frames = 20_000

    class CountingFrontend(pfb_dns_proxy.Frontend):
        handled = 0
        handled_when_the_udp_query_came: int | None = None

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.first_frame = asyncio.Event()

        async def resolve(self, wire: bytes, client_ip: str, forward: Any, **kwargs: Any) -> bytes | None:
            if wire:
                self.handled_when_the_udp_query_came = self.handled
            else:
                self.handled += 1
                self.first_frame.set()
            return await super().resolve(wire, client_ip, forward, **kwargs)

    async def scenario() -> int | None:
        frontend = CountingFrontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
        _, writer = await asyncio.open_connection(*server)
        try:
            writer.write(b"\x00\x00" * frames)  # all of it is in the proxy's receive buffer at once
            await asyncio.wait_for(frontend.first_frame.wait(), WATCHDOG)
            await udp_exchange(server, build_query(BLOCKED))
            return frontend.handled_when_the_udp_query_came
        finally:
            writer.close()
            await frontend.stop()

    handled = asyncio.run(scenario())
    assert handled is not None and handled < frames // 10, f"{handled} of {frames} frames were handled before it"


# --- Unbound's silence is logged once per window ---------------------------------------------


def _silence_lines(
    booted: Booted,
    clock: ManualClock,
    monkeypatch: pytest.MonkeyPatch,
    with_module: bool,
    steps: list[tuple[float, str]],
) -> list[str]:
    """The 'no reply from Unbound' lines logged while `steps` are resolved in order: (seconds to pass first, name).
    Unbound answers every name that does not start with 'silent'."""
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)
    answered = FakeUnbound(ZONE)

    async def forward(wire: bytes) -> bytes | None:
        return None if dnswire.parse(wire).questions[0].name.startswith("silent") else answered.answer(wire)

    async def scenario() -> None:
        frontend = pfb_dns_proxy.Frontend(booted.module if with_module else None, ("127.0.0.1", 9), timeout=WATCHDOG)
        for pause, name in steps:
            clock.advance(pause)
            await frontend.resolve(build_query(name), "192.0.2.10", forward)

    asyncio.run(scenario())
    return [str(line) for line in warnings if "no reply from Unbound" in str(line)]


@pytest.mark.parametrize("with_module", [True, False], ids=["module", "no-module"])
def test_unbound_not_answering_is_one_log_line_per_30_seconds_whatever_it_answers_in_between(
    booted: Booted, clock: ManualClock, monkeypatch: pytest.MonkeyPatch, with_module: bool
) -> None:
    """Issue #3517 review: one line per silent query, about 100 lines/s into an unrotated log under a flood."""
    steps = [
        (0, "silent0.example."),
        (0, ALLOWED),  # an answer in between does not re-arm the line
        (0, "silent1.example."),
        (29.5, "silent2.example."),  # 29.5 s into the window
        (0.5, "silent3.example."),  # exactly 30 s: the next window
    ]
    lines = _silence_lines(booted, clock, monkeypatch, with_module, steps)
    assert len(lines) == 2 and "silent0.example." in lines[0] and "silent3.example." in lines[1], lines


@pytest.mark.parametrize("with_module", [True, False], ids=["module", "no-module"])
def test_a_mixed_load_of_answered_and_unanswered_queries_logs_one_line_per_window(
    booted: Booted, clock: ManualClock, monkeypatch: pytest.MonkeyPatch, with_module: bool
) -> None:
    """Issue #3515 gate: one answer used to re-arm the line, so two silent queries per answered one logged about one
    line per second. Sixty seconds of that are two windows."""
    steps: list[tuple[float, str]] = []
    for second in range(60):
        steps += [(1.0 if second else 0, f"silent{second}a.example."), (0, f"silent{second}b.example.")]
        steps.append((0, ALLOWED))
    lines = _silence_lines(booted, clock, monkeypatch, with_module, steps)
    assert len(lines) == 2 and "silent0a.example." in lines[0] and "silent30a.example." in lines[1], lines


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


class _ClosesWithoutAnswering(FakeProxyUpstream):
    """An upstream that takes the query on each TCP connection and closes it without a word."""

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            fixed = await reader.readexactly(PROXY_FIXED)
            self.headers.append(fixed + await reader.readexactly(struct.unpack("!H", fixed[14:16])[0]))
            await reader.readexactly(struct.unpack("!H", await reader.readexactly(2))[0])
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()


def test_a_fresh_upstream_tcp_connection_that_fails_is_not_tried_again(booted: Booted) -> None:
    """Only a connection Unbound may have closed while it idled gets a second try; a new one that fails is final."""

    async def scenario() -> tuple[bytes, int]:
        async with _ClosesWithoutAnswering(FakeUnbound(ZONE)) as upstream:
            frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            try:
                return (await tcp_exchange(server, build_query(ALLOWED, qid=3)))[0], len(upstream.headers)
            finally:
                await frontend.stop()

    reply, connections = asyncio.run(scenario())
    assert (dnswire.parse(reply).rcode, connections) == (2, 1)


def test_the_upstream_socket_of_each_udp_query_is_closed_once_it_is_answered(
    booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An open one per query would use up the descriptors: asyncio keeps a transport registered until it is closed."""
    opened: list[asyncio.DatagramTransport] = []
    upstream_port = 0
    real = asyncio.BaseEventLoop.create_datagram_endpoint

    async def keep_upstream_transports(self: Any, factory: Any, *args: Any, **kwargs: Any) -> Any:
        transport, protocol = await real(self, factory, *args, **kwargs)
        if kwargs.get("remote_addr") == ("127.0.0.1", upstream_port):
            opened.append(transport)
        return transport, protocol

    monkeypatch.setattr(asyncio.BaseEventLoop, "create_datagram_endpoint", keep_upstream_transports)

    async def scenario() -> None:
        nonlocal upstream_port
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            upstream_port = upstream.port
            frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            try:
                for qid in (1, 2, 3):
                    await udp_exchange(server, build_query(ALLOWED, qid=qid))
            finally:
                await frontend.stop()

    asyncio.run(scenario())
    assert [transport.is_closing() for transport in opened] == [True, True, True]


def test_the_question_class_reaches_the_module(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []
    real = booted.module.operate

    def spy(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        seen.append(qstate.qinfo.qclass)
        return real(id, event, qstate, qdata)

    monkeypatch.setattr(booted.module, "operate", spy)
    chaos = dnswire.encode(dnswire.Message(5, dnswire.RD, [dnswire.Question("version.bind.", dnswire.TYPE_TXT, 3)]))
    _resolve(booted, chaos)
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
