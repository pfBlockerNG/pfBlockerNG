"""`--no-module` (pfB-DNS on, DNSBL off): the proxy boots no pfb_unbound.py and forwards every query to Unbound over
PROXYv2. There are no decisions, no MODDONE pass and no observer socket; UDP, TCP and DoT, the caps and the failure
shapes are the module mode's. test_integration_unbound.py runs the same against a real Unbound, and the privilege
drop of this mode is in test_privilege_drop.py.
"""

from __future__ import annotations

import asyncio
import os
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import dnswire
import pfb_dns_proxy
import pfsense_dot
import proxyv2
import pytest
from dot_helpers import dot_exchange, free_port
from frontend_constants import ALLOWED, BLOCKED, DNSBL_IPV4, Booted
from frontend_helpers import (
    WATCHDOG,
    FakeProxyUpstream,
    FakeUnbound,
    build_query,
    running_proxy,
    serve_dot,
    serve_plain,
    tcp_exchange,
    udp_client,
    udp_exchange,
)

CLIENT = "127.0.0.1"  # the module answers python_control only for localhost
VIP4 = bytes(int(octet) for octet in DNSBL_IPV4.split("."))
BLOCKED_ADDRESS = bytes([192, 0, 2, 99])
ZONE = {
    (BLOCKED, dnswire.TYPE_A): [f"{BLOCKED} 300 IN A 192.0.2.99"],
    (ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"],
}
# Queries the module answers by itself and never lets Unbound see: a feed-listed name, a python_control command, a
# noAAAA name (the fixture ini of frontend_constants.INI).
MODULE_ANSWERED = [
    pytest.param(build_query(BLOCKED), id="listed-name"),
    pytest.param(build_query("python_control.bogus.cmd.", dnswire.TYPE_TXT), id="control-name"),
    pytest.param(build_query("noaaaa.example.", dnswire.TYPE_AAAA), id="noaaaa-name"),
]


def _resolve(module: Any, wire: bytes, forward: Any) -> bytes | None:
    frontend = pfb_dns_proxy.Frontend(module, ("127.0.0.1", 9), timeout=WATCHDOG)
    return asyncio.run(frontend.resolve(wire, CLIENT, forward))


def _framed(wire: bytes) -> bytes:
    return struct.pack("!H", len(wire)) + wire


# --- the decision: there is none -------------------------------------------------------------------


@pytest.mark.parametrize("wire", MODULE_ANSWERED)
def test_a_query_the_module_would_answer_itself_goes_to_unbound_untouched_without_a_module(
    booted: Booted, wire: bytes
) -> None:
    asked = FakeUnbound(ZONE)
    _resolve(booted.module, wire, asked)
    assert asked.queries == []  # before: with the module, Unbound is never asked
    logged = list(booted.log)

    seen: list[bytes] = []

    async def forward(sent: bytes) -> bytes:
        seen.append(sent)
        return b"not even a DNS message"  # relayed as it is: no parse, no pass over the reply

    assert _resolve(None, wire, forward) == b"not even a DNS message"
    assert seen == [wire]
    assert list(booted.log) == logged  # and the module is not consulted: nothing new in its logs


def test_unbound_not_answering_is_a_servfail_for_the_query_with_one_warning_naming_it(
    capfd: pytest.CaptureFixture[str],
) -> None:
    async def silent(_wire: bytes) -> None:
        return None

    query = build_query(ALLOWED, qid=0x0B0B)
    reply = dnswire.parse(_resolve(None, query, silent) or b"")
    assert (reply.id, reply.rcode, reply.questions) == (0x0B0B, 2, dnswire.parse(query).questions)
    assert capfd.readouterr().err == "pfb_dns_proxy warning: no reply from Unbound for allowed.example. A\n"


def test_a_query_without_a_question_gets_formerr_and_never_reaches_unbound() -> None:
    asked = FakeUnbound(ZONE)
    wire = struct.pack("!HHHHHH", 0x4242, dnswire.RD, 0, 0, 0, 0)
    reply = dnswire.parse(_resolve(None, wire, asked) or b"")
    assert (reply.id, reply.rcode, reply.flags & dnswire.QR) == (0x4242, 1, dnswire.QR)
    assert asked.queries == []


def test_a_response_packet_is_dropped_and_never_reaches_unbound() -> None:
    asked = FakeUnbound(ZONE)
    response = FakeUnbound(ZONE).answer(build_query(ALLOWED))
    assert _resolve(None, response, asked) is None  # QR set: no reflection loops
    assert asked.queries == []


# --- the transports --------------------------------------------------------------------------------


def test_udp_and_tcp_forward_a_listed_name_with_the_real_client_in_the_proxyv2_header() -> None:
    query = build_query(BLOCKED)

    async def scenario() -> SimpleNamespace:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            try:
                out = SimpleNamespace(server=server)
                out.udp, out.udp_client = await udp_exchange(server, query, source="127.0.0.5")
                out.tcp, out.tcp_client = await tcp_exchange(server, query, source="127.0.0.6")
                out.headers = list(upstream.headers)
                return out
            finally:
                await frontend.stop()

    out = asyncio.run(scenario())
    expected = FakeUnbound(ZONE).answer(query)
    assert (out.udp, out.tcp) == (expected, expected)
    assert [(rr.rtype, rr.rdata) for rr in dnswire.parse(out.udp).answers] == [(dnswire.TYPE_A, BLOCKED_ADDRESS)]
    assert out.headers == [
        proxyv2.header(out.udp_client, out.server, tcp=False),
        proxyv2.header(out.tcp_client, out.server, tcp=True),
    ]
    assert (out.udp_client[0], out.tcp_client[0]) == ("127.0.0.5", "127.0.0.6")


def test_dot_forwards_a_listed_name_with_the_tls_client_in_the_proxyv2_header(
    tmp_path: Path, certificate: tuple[bytes, bytes]
) -> None:
    crt, key = certificate
    trust = tmp_path / "trust.pem"
    trust.write_bytes(crt)
    context = pfsense_dot.server_context(pfsense_dot.DotSettings(853, crt, key))
    query = build_query(BLOCKED)

    async def scenario() -> tuple[bytes, tuple[str, int], tuple[str, int], list[bytes]]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_dot(frontend, ["127.0.0.1"], 0, context)
            try:
                reply, client, _ = await dot_exchange(server, query, trust, source="127.0.0.7")
                return reply, client, server, list(upstream.headers)
            finally:
                await frontend.stop()

    reply, client, server, headers = asyncio.run(scenario())
    assert reply == FakeUnbound(ZONE).answer(query)
    assert headers == [proxyv2.header(client, server, tcp=True)]
    assert client[0] == "127.0.0.7"


def test_a_tcp_client_over_the_cap_closes_the_longest_idle_one_without_a_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_TCP_CLIENTS", 1)

    async def ask(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, qid: int) -> int:
        writer.write(_framed(build_query(ALLOWED, qid=qid)))
        size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), WATCHDOG))[0]
        return dnswire.parse(await asyncio.wait_for(reader.readexactly(size), WATCHDOG)).id

    async def scenario() -> tuple[int, int, bytes, int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            reader, writer = await asyncio.open_connection(*server)
            extra_reader, extra = None, None
            try:
                first = await ask(reader, writer, 1)  # served: its slot is taken
                extra_reader, extra = await asyncio.open_connection(*server)
                second = await ask(extra_reader, extra, 2)  # over the cap: served, the first one is closed for it
                try:
                    closed = await asyncio.wait_for(reader.read(), WATCHDOG)  # EOF
                except ConnectionError:
                    closed = b""
                return first, second, closed, len(upstream.headers)
            finally:
                writer.close()
                if extra is not None:
                    extra.close()
                await frontend.stop()

    assert asyncio.run(scenario()) == (1, 2, b"", 2)  # both were answered by Unbound, over a connection each


def test_a_udp_query_over_the_in_flight_cap_drops_the_oldest_one_without_a_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "MAX_UDP_INFLIGHT", 1)

    async def scenario() -> list[bytes]:
        async with FakeProxyUpstream(FakeUnbound(ZONE), silent=True) as upstream:
            frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", upstream.port), timeout=0.2)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            transport, client = await udp_client(server)
            try:
                transport.sendto(build_query(ALLOWED, qid=1))
                transport.sendto(build_query(ALLOWED, qid=2))
                await client.until(1)  # the newest times out: SERVFAIL
                await frontend.stop()  # every query task has ended: the dropped one can never answer
                await asyncio.sleep(0)
                return client.replies
            finally:
                transport.close()

    [reply] = asyncio.run(scenario())  # exactly one: the first was dropped
    assert (dnswire.parse(reply).id, dnswire.parse(reply).rcode) == (2, 2)


# --- starting up -----------------------------------------------------------------------------------


def test_no_module_is_off_unless_asked_for() -> None:
    assert pfb_dns_proxy.parse_args([]).no_module is False
    assert pfb_dns_proxy.parse_args(["--no-module"]).no_module is True


@pytest.fixture
def boots(module_dir: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The real module boots from `module_dir` without its /var/log files; the list holds every directory booted."""
    real_boot = pfb_dns_proxy.boot
    booted_from: list[str] = []

    def boot_without_log_files(directory: str) -> Any:
        booted_from.append(directory)
        module = real_boot(directory)
        monkeypatch.setattr(module, "pfb_log", lambda name, line: None)  # the module logs to /var/log/pfblockerng
        return module

    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)  # init_standard() replaces it; register the auto-restore
    monkeypatch.setattr(pfb_dns_proxy, "boot", boot_without_log_files)
    return booted_from


def _serve_and_ask(argv: list[str], wire: bytes) -> tuple[bytes, bool, int]:
    """Run serve() against a fake Unbound until ready and ask it `wire`: (reply, whether the observer socket exists
    in the working directory while it serves, how many queries Unbound was sent)."""

    async def scenario() -> tuple[bytes, bool, int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            args = pfb_dns_proxy.parse_args(["--listen", "127.0.0.1", "--port", "0", *argv])
            args.upstream = f"127.0.0.1:{upstream.port}"
            stop = asyncio.Event()
            ready: asyncio.Future[list[tuple[str, int]]] = asyncio.get_running_loop().create_future()
            task = asyncio.create_task(pfb_dns_proxy.serve(args, stop=stop, on_ready=ready.set_result))
            try:
                await asyncio.wait({ready, task}, timeout=WATCHDOG, return_when=asyncio.FIRST_COMPLETED)
                if task.done():
                    task.result()  # serve() ended before it was ready: raise the reason it gave
                if not ready.done():
                    pytest.fail("STUCK: serve() was not ready in time")
                [server] = ready.result()
                reply = (await udp_exchange(server, wire))[0]
                return reply, os.path.lexists(pfb_dns_proxy.OBSERVER_SOCKET), len(upstream.headers)
            finally:
                stop.set()
                await asyncio.wait_for(task, WATCHDOG)

    return asyncio.run(scenario())


@pytest.mark.parametrize(
    ("extra", "booted_from_module_dir", "observer", "forwarded", "answer"),
    [
        pytest.param([], True, False, 0, VIP4, id="module"),  # the module blocks it, Unbound is never asked
        pytest.param(["--observer"], True, True, 0, VIP4, id="module-and-observer"),
        pytest.param(["--no-module"], False, False, 1, BLOCKED_ADDRESS, id="no-module"),  # Unbound answers
    ],
)
def test_the_module_boots_with_a_module_and_the_observer_socket_exists_only_when_asked_for(
    extra: list[str],
    booted_from_module_dir: bool,
    observer: bool,
    forwarded: int,
    answer: bytes,
    module_dir: Path,
    boots: list[str],
) -> None:
    reply, observed, asked = _serve_and_ask(["--module-dir", str(module_dir), *extra], build_query(BLOCKED))
    assert boots == ([str(module_dir)] if booted_from_module_dir else [])
    assert (observed, asked, [rr.rdata for rr in dnswire.parse(reply).answers]) == (observer, forwarded, [answer])


@pytest.mark.parametrize("where", ["empty", "missing"])
def test_serve_starts_and_forwards_with_no_pfb_unbound_py_in_the_module_dir(
    where: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    module_dir = tmp_path / "unbound"
    if where == "empty":
        module_dir.mkdir()
    reply, observer, forwarded = _serve_and_ask(["--no-module", "--module-dir", str(module_dir)], build_query(BLOCKED))
    assert [rr.rdata for rr in dnswire.parse(reply).answers] == [BLOCKED_ADDRESS]
    assert (observer, forwarded) == (False, 1)


def test_the_real_process_starts_with_no_module_dir_forwards_and_stops_cleanly_on_sigterm(tmp_path: Path) -> None:
    dead_upstream = f"127.0.0.1:{free_port()}"  # nothing listens: the relay's own SERVFAIL, not a module's block
    argv = ["--no-module", "--listen", "127.0.0.1", "--port", "0", "--upstream", dead_upstream]
    argv += ["--module-dir", str(tmp_path / "absent")]
    with running_proxy(argv, cwd=tmp_path) as (_, port):
        reply = dnswire.parse(asyncio.run(udp_exchange(("127.0.0.1", port), build_query(BLOCKED, qid=0x3515)))[0])
        assert not (tmp_path / pfb_dns_proxy.OBSERVER_SOCKET).exists()  # while it runs: a started observer is here
    assert (reply.id, reply.rcode) == (0x3515, 2)
