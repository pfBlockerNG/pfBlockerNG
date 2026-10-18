"""DNS proxy end-to-end with the REAL shipped pfb_unbound.py booted through the shim.

Unbound is replaced by FakeUnbound (a table); test_integration_unbound.py runs the same flows against a real one.
"""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import logging
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import dnswire
import pfb_dns_proxy
import proxyv2
import pytest
import unbound_shim as shim
from frontend_constants import ALLOWED, BLOCKED, DNSBL_IPV4, DNSBL_IPV6, Booted
from frontend_helpers import (
    WATCHDOG,
    FakeProxyUpstream,
    FakeUnbound,
    build_query,
    serve_plain,
    tcp_exchange,
    udp_exchange,
)

CLIENT = "192.0.2.10"
VIP4 = bytes(int(octet) for octet in DNSBL_IPV4.split("."))
ZONE = {
    (ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"],
    ("alias.example.", dnswire.TYPE_A): [
        "alias.example. 300 IN CNAME blocked.example.",
        "blocked.example. 300 IN A 192.0.2.99",
    ],
    ("fine.example.", dnswire.TYPE_A): [
        "fine.example. 300 IN CNAME allowed.example.",
        "allowed.example. 300 IN A 192.0.2.77",
    ],
}


def _resolve(booted: Booted, wire: bytes, forward: Any, client: str = CLIENT) -> bytes | None:
    frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
    return asyncio.run(frontend.resolve(wire, client, forward))


def _answers(reply: dnswire.Message) -> list[tuple[str, int, bytes]]:
    return [(rr.name, rr.rtype, rr.rdata) for rr in reply.answers]


def _log_rows(booted: Booted, name: str) -> list[list[str]]:
    return [next(csv.reader([line])) for log, line in booted.log if log.endswith(name)]


# --- the module answers: DNSBL decisions never reach Unbound -------------------------------------


def test_blocked_name_gets_the_block_answer_and_never_reaches_unbound(booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)
    query = build_query(BLOCKED, qid=0xBEEF)
    reply = dnswire.parse(_resolve(booted, query, unbound) or b"")
    assert (reply.id, reply.rcode, reply.flags & (dnswire.QR | dnswire.RD | dnswire.RA)) == (
        0xBEEF,
        0,
        dnswire.QR | dnswire.RD | dnswire.RA,
    )
    assert reply.questions == dnswire.parse(query).questions
    assert _answers(reply) == [(BLOCKED, dnswire.TYPE_A, VIP4)]
    assert unbound.queries == []


def test_blocked_aaaa_gets_the_ipv6_block_address(booted: Booted) -> None:
    reply = dnswire.parse(_resolve(booted, build_query(BLOCKED, dnswire.TYPE_AAAA), FakeUnbound(ZONE)) or b"")
    assert [(rr.rtype, rr.rdata) for rr in reply.answers] == [
        (dnswire.TYPE_AAAA, ipaddress.IPv6Address(DNSBL_IPV6).packed)
    ]


def test_blocked_type_without_an_address_gets_nodata_with_soa(booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)
    reply = dnswire.parse(_resolve(booted, build_query(BLOCKED, dnswire.TYPE_MX), unbound) or b"")
    assert (reply.rcode, reply.answers) == (0, [])
    assert [(rr.name, rr.rtype) for rr in reply.authority] == [(BLOCKED, dnswire.TYPE_SOA)]
    assert reply.authority[0].rdata.startswith(b"\x03pfb\x07invalid\x00")
    assert unbound.queries == []


def test_block_answer_keeps_the_client_case_clears_rd_and_echoes_edns(booted: Booted) -> None:
    query = build_query("BlOcKeD.ExAmPlE.", rd=False, edns=True)
    reply = dnswire.parse(_resolve(booted, query, FakeUnbound(ZONE)) or b"")
    assert reply.flags & dnswire.RD == 0
    assert reply.questions[0].name == "BlOcKeD.ExAmPlE."
    assert reply.answers[0].name == "BlOcKeD.ExAmPlE."  # compressed against the question, so the case follows it
    assert [rr.rtype for rr in reply.additional] == [dnswire.TYPE_OPT]


def test_block_is_logged_with_the_feed_and_the_client_address(booted: Booted) -> None:
    _resolve(booted, build_query(BLOCKED), FakeUnbound(ZONE))
    [row] = _log_rows(booted, "dnsbl.log")
    assert (row[0], row[2], row[3], row[-1]) == ("DNSBL-python", "blocked.example", CLIENT, "A")
    assert "TestFeed" in row and "TestGroup" in row


def test_noaaaa_answer_is_nodata_and_fires_the_reply_callback(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, int, str]] = []
    real = shim.callbacks["reply"]

    def spy(qinfo: Any, qstate: Any, rep: Any, rcode: int, edns: Any, opts: Any, region: Any, **kwargs: Any) -> bool:
        calls.append((rep, rcode, kwargs["repinfo"].addr))
        return real(qinfo, qstate, rep, rcode, edns, opts, region, **kwargs)

    monkeypatch.setitem(shim.callbacks, "reply", spy)
    unbound = FakeUnbound(ZONE)
    reply = dnswire.parse(_resolve(booted, build_query("noaaaa.example.", dnswire.TYPE_AAAA), unbound) or b"")
    assert (reply.rcode, reply.answers, [rr.rtype for rr in reply.authority]) == (0, [], [dnswire.TYPE_SOA])
    assert unbound.queries == []
    assert [(rep is not None, rcode, addr) for rep, rcode, addr in calls] == [(True, 0, CLIENT)]


def test_python_control_txt_answer_round_trips_through_the_codec(booted: Booted) -> None:
    reply = dnswire.parse(
        _resolve(booted, build_query("python_control.bogus.cmd.", dnswire.TYPE_TXT), None, "127.0.0.1") or b""
    )
    [(name, rtype, rdata)] = _answers(reply)
    text = "Python_control: Command not authorized! [ python_control.bogus.cmd ]"
    assert (name, rtype, rdata) == ("python_control_fail.", dnswire.TYPE_TXT, bytes([len(text)]) + text.encode())


# --- the module defers: Unbound answers, the proxy relays ------------------------------------


def test_allowed_name_is_forwarded_and_the_reply_relayed_byte_for_byte(booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)
    query = build_query(ALLOWED, qid=0x0A0A)
    reply = _resolve(booted, query, unbound)
    assert unbound.queries == [query]
    assert reply == FakeUnbound(ZONE).answer(query)
    assert _answers(dnswire.parse(reply)) == [(ALLOWED, dnswire.TYPE_A, bytes([192, 0, 2, 77]))]
    assert _log_rows(booted, "dnsbl.log") == []


def test_unbound_reply_is_relayed_byte_for_byte_even_where_our_encoder_would_differ(booted: Booted) -> None:
    qname = b"\x07allowed\x07example\x00"
    upstream_reply = (
        struct.pack("!HHHHHH", 0x0C0C, dnswire.QR | dnswire.RD | dnswire.RA, 1, 1, 0, 1)
        + qname
        + b"\x00\x01\x00\x01"
        + qname  # owner written out in full: dnswire.encode would compress it
        + struct.pack("!HHIH", dnswire.TYPE_A, 1, 300, 4)
        + bytes([192, 0, 2, 77])
        + b"\x00"
        + struct.pack("!HHIH", dnswire.TYPE_OPT, 4096, 0, 4)  # an OPT with an EDE option code, which we never echo
        + b"\x00\x0f\x00\x00"
    )

    async def forward(_wire: bytes) -> bytes:
        return upstream_reply

    assert _resolve(booted, build_query(ALLOWED, qid=0x0C0C, edns=True), forward) == upstream_reply


def test_forwarded_reply_is_logged_against_the_client_not_the_proxy(booted: Booted) -> None:
    _resolve(booted, build_query(ALLOWED), FakeUnbound(ZONE))
    [row] = _log_rows(booted, "dns_reply.log")
    assert "allowed.example" in row and CLIENT in row and "192.0.2.77" in row
    assert "127.0.0.1" not in row


def test_cname_chain_reaching_a_blocked_name_gets_the_block_answer(booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)
    query = build_query("alias.example.")
    reply = _resolve(booted, query, unbound)
    assert unbound.queries == [query]  # alias.example. itself is not listed, so Unbound resolved it
    assert reply != FakeUnbound(ZONE).answer(query)
    assert _answers(dnswire.parse(reply or b"")) == [("alias.example.", dnswire.TYPE_A, VIP4)]
    [row] = _log_rows(booted, "dnsbl.log")
    assert (row[2], row[3]) == ("alias.example", CLIENT)


def test_cname_chain_to_an_allowed_name_is_relayed_unchanged(booted: Booted) -> None:
    query = build_query("fine.example.")
    assert _resolve(booted, query, FakeUnbound(ZONE)) == FakeUnbound(ZONE).answer(query)


def test_non_query_opcode_bypasses_the_module_and_goes_to_unbound(booted: Booted) -> None:
    seen: list[bytes] = []

    async def forward(wire: bytes) -> bytes:
        seen.append(wire)
        return b"canned"

    notify = struct.pack("!HHHHHH", 5, 4 << 11, 1, 0, 0, 0) + b"\x07blocked\x07example\x00\x00\x06\x00\x01"
    assert _resolve(booted, notify, forward) == b"canned"
    assert seen == [notify]
    assert booted.log == []


# --- failure and hostile-input shapes ------------------------------------------------------------


def test_header_only_query_without_a_question_gets_formerr(booted: Booted) -> None:
    wire = struct.pack("!HHHHHH", 0x4242, dnswire.RD, 0, 0, 0, 0)
    reply = dnswire.parse(_resolve(booted, wire, FakeUnbound(ZONE)) or b"")
    assert (reply.id, reply.rcode, reply.flags & dnswire.QR) == (0x4242, 1, dnswire.QR)


def test_query_with_a_broken_question_gets_formerr(booted: Booted) -> None:
    wire = struct.pack("!HHHHHH", 0x4243, 0, 1, 0, 0, 0) + b"\xc0"
    assert dnswire.parse(_resolve(booted, wire, FakeUnbound(ZONE)) or b"").rcode == 1


def test_packets_that_are_not_queries_are_dropped(booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)
    response = FakeUnbound(ZONE).answer(build_query(ALLOWED))
    assert _resolve(booted, response, unbound) is None  # QR set: never answer (no reflection loops)
    assert _resolve(booted, b"\x12\x34\x01", unbound) is None  # not even a header
    assert unbound.queries == []


def test_unbound_not_answering_gives_servfail(booted: Booted) -> None:
    async def silent(_wire: bytes) -> None:
        return None

    query = build_query(ALLOWED, qid=0x0B0B)
    reply = dnswire.parse(_resolve(booted, query, silent) or b"")
    assert (reply.id, reply.rcode, reply.questions) == (0x0B0B, 2, dnswire.parse(query).questions)


@pytest.mark.parametrize("cd", [False, True], ids=["cd-clear", "cd-set"])
@pytest.mark.parametrize("error", ["servfail", "formerr"])
def test_an_error_reply_copies_the_clients_cd_bit_as_unbound_does(booted: Booted, error: str, cd: bool) -> None:
    async def silent(_wire: bytes) -> None:
        return None

    query = build_query(ALLOWED, cd=cd)
    if error == "formerr":
        query = query[:4] + b"\x00\x02" + query[6:]  # two questions: refused before it is parsed
    reply = dnswire.parse(_resolve(booted, query, silent) or b"")
    assert (reply.rcode, bool(reply.flags & dnswire.CD), bool(reply.flags & dnswire.RD)) == (
        2 if error == "servfail" else 1,
        cd,
        True,
    )


def test_refused_reply_without_a_question_section_is_relayed_and_logged_as_refused(booted: Booted) -> None:
    # Unbound's access-control REFUSED carries no question section at all
    refused = struct.pack("!HHHHHH", 0x1234, dnswire.QR | dnswire.RD | dnswire.RA | 5, 0, 0, 0, 0)

    async def forward(_wire: bytes) -> bytes:
        return refused

    assert _resolve(booted, build_query(ALLOWED), forward) == refused
    [row] = _log_rows(booted, "dns_reply.log")
    assert "Refused" in row and CLIENT in row


def test_unparseable_unbound_reply_gives_servfail(booted: Booted) -> None:
    async def garbage(_wire: bytes) -> bytes:
        return b"\x00\x01"

    assert dnswire.parse(_resolve(booted, build_query(ALLOWED), garbage) or b"").rcode == 2


def test_module_exception_gives_servfail(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: Any) -> bool:
        raise RuntimeError("module crashed")

    monkeypatch.setattr(booted.module, "operate", explode)
    unbound = FakeUnbound(ZONE)
    assert dnswire.parse(_resolve(booted, build_query(ALLOWED), unbound) or b"").rcode == 2
    assert unbound.queries == []


def test_module_error_state_gives_servfail(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        qstate.ext_state[id] = shim.MODULE_ERROR
        return True

    monkeypatch.setattr(booted.module, "operate", fail)
    assert dnswire.parse(_resolve(booted, build_query(ALLOWED), FakeUnbound(ZONE)) or b"").rcode == 2


def test_restart_next_without_a_planted_cname_referral_gives_servfail(
    booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def restart(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        qstate.ext_state[id] = shim.MODULE_RESTART_NEXT
        return True

    monkeypatch.setattr(booted.module, "operate", restart)
    assert dnswire.parse(_resolve(booted, build_query(ALLOWED), FakeUnbound(ZONE)) or b"").rcode == 2


def test_nxdomain_return_rcode_is_a_bare_nxdomain_even_when_unbound_found_records(
    booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = booted.module.operate

    def nxdomain_block(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        if event != shim.MODULE_EVENT_MODDONE:
            return real(id, event, qstate, qdata)
        qstate.return_rcode = shim.RCODE_NXDOMAIN  # what the module does for an NXDOMAIN-shaped block
        qstate.ext_state[id] = shim.MODULE_FINISHED
        return True

    monkeypatch.setattr(booted.module, "operate", nxdomain_block)
    reply = dnswire.parse(_resolve(booted, build_query(ALLOWED), FakeUnbound(ZONE)) or b"")
    assert (reply.rcode, reply.answers, reply.authority) == (3, [], [])


def test_finished_without_any_message_is_servfail(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    def finish_empty(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        qstate.ext_state[id] = shim.MODULE_FINISHED
        return True

    monkeypatch.setattr(booted.module, "operate", finish_empty)
    assert dnswire.parse(_resolve(booted, build_query(ALLOWED), FakeUnbound(ZONE)) or b"").rcode == 2


def test_servfail_goes_to_the_servfail_callback_not_the_reply_callback(
    booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    kinds: list[str] = []

    def recorder(kind: str) -> Any:
        def record(*_args: Any, **_kwargs: Any) -> bool:
            kinds.append(kind)
            return True

        return record

    for kind in ("reply", "reply_servfail"):
        monkeypatch.setitem(shim.callbacks, kind, recorder(kind))

    async def silent(_wire: bytes) -> None:
        return None

    _resolve(booted, build_query(ALLOWED), silent)
    assert kinds == ["reply_servfail"]


# --- addressing and CLI --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("client", "local", "expected"),
    [
        (("::ffff:192.0.2.10", 1), ("::", 53), (("192.0.2.10", 1), ("0.0.0.0", 53))),
        (("::ffff:192.0.2.10", 1), ("::ffff:192.0.2.1", 53), (("192.0.2.10", 1), ("192.0.2.1", 53))),
        (("192.0.2.10", 1), ("0.0.0.0", 53), (("192.0.2.10", 1), ("0.0.0.0", 53))),
        (("2001:db8::1", 1), ("0.0.0.0", 53), (("2001:db8::1", 1), ("::", 53))),
        (("fe80::1%eth0", 1), ("::1", 53), (("fe80::1", 1), ("::1", 53))),
    ],
)
def test_proxy_endpoints_share_one_family_and_drop_scope_ids(
    client: tuple[str, int], local: tuple[str, int], expected: tuple[tuple[str, int], tuple[str, int]]
) -> None:
    assert pfb_dns_proxy.proxy_endpoints(client, local) == expected


def test_shutdown_gives_back_the_stderr_init_standard_replaced(
    module_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the module's logger-backed stderr has no flush(), so interpreter exit would complain through it
    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    before = sys.stderr
    module = pfb_dns_proxy.boot(str(module_dir))
    try:
        assert sys.stderr is not before
    finally:
        pfb_dns_proxy.shutdown(module)
    assert sys.stderr is before


def test_module_without_a_log_dir_gets_a_stderr_sink_instead_of_recursing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # init_standard() points sys.stderr at a logger; with no root handler that logger's last-resort handler
    # writes back into sys.stderr and recurses until the process dies (seen when /var/log/pfblockerng is absent).
    monkeypatch.setattr(pfb_dns_proxy, "LOG_DIR", str(tmp_path / "absent"))
    monkeypatch.setattr(logging.root, "handlers", [])
    pfb_dns_proxy.ensure_stderr_sink()
    [handler] = logging.root.handlers
    assert getattr(handler, "stream", None) is sys.__stderr__  # the real fd 2, not the replaced sys.stderr

    monkeypatch.setattr(logging.root, "handlers", [])
    monkeypatch.setattr(pfb_dns_proxy, "LOG_DIR", str(tmp_path))  # writable: init_standard() logs to py_error.log
    pfb_dns_proxy.ensure_stderr_sink()
    assert logging.root.handlers == []


def test_parse_hostport_handles_ipv4_ipv6_and_rejects_garbage() -> None:
    assert pfb_dns_proxy.parse_hostport("127.0.0.1:5353") == ("127.0.0.1", 5353)
    assert pfb_dns_proxy.parse_hostport("[::1]:5353") == ("::1", 5353)
    for bad in ("5353", "host:port", "127.0.0.1:99999"):
        with pytest.raises(ValueError):
            pfb_dns_proxy.parse_hostport(bad)


def test_cli_defaults_match_the_documented_contract() -> None:
    args = pfb_dns_proxy.parse_args([])
    assert (args.listen, args.port, args.upstream, args.module_dir) == (None, 53, "127.0.0.1:5353", "/var/unbound")
    args = pfb_dns_proxy.parse_args(["--listen", "127.0.0.1", "--listen", "::1", "--port", "5300"])
    assert (args.listen, args.port) == (["127.0.0.1", "::1"], 5300)


# --- real sockets --------------------------------------------------------------------------------


def test_udp_and_tcp_listeners_block_locally_and_forward_with_a_proxyv2_header(booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)

    async def scenario() -> SimpleNamespace:
        async with FakeProxyUpstream(unbound) as upstream:
            frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            try:
                out = SimpleNamespace(server=server)
                out.udp_blocked, _ = await udp_exchange(server, build_query(BLOCKED))
                out.tcp_blocked, _ = await tcp_exchange(server, build_query(BLOCKED))
                assert upstream.headers == []  # nothing forwarded yet
                out.udp_allowed, out.udp_client = await udp_exchange(server, build_query(ALLOWED), source="127.0.0.5")
                out.tcp_allowed, out.tcp_client = await tcp_exchange(server, build_query(ALLOWED), source="127.0.0.6")
                out.headers = list(upstream.headers)
                return out
            finally:
                await frontend.stop()

    out = asyncio.run(scenario())
    for blocked in (out.udp_blocked, out.tcp_blocked):
        assert _answers(dnswire.parse(blocked)) == [(BLOCKED, dnswire.TYPE_A, VIP4)]
    expected = FakeUnbound(ZONE).answer(build_query(ALLOWED))
    assert (out.udp_allowed, out.tcp_allowed) == (expected, expected)
    assert out.headers == [
        proxyv2.header(out.udp_client, out.server, tcp=False),
        proxyv2.header(out.tcp_client, out.server, tcp=True),
    ]
    assert out.udp_client[0] == "127.0.0.5" and out.tcp_client[0] == "127.0.0.6"


def test_tcp_client_connection_reuses_one_upstream_connection_and_header(booted: Booted) -> None:
    async def scenario() -> tuple[list[bytes], list[bytes]]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
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
                return replies, list(upstream.headers)
            finally:
                await frontend.stop()

    replies, headers = asyncio.run(scenario())
    assert [dnswire.parse(reply).id for reply in replies] == [1, 2]
    assert len(headers) == 1


def test_udp_query_unanswered_by_unbound_gets_servfail(booted: Booted) -> None:
    async def scenario() -> bytes:
        async with FakeProxyUpstream(FakeUnbound(ZONE), silent=True) as upstream:
            frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", upstream.port), timeout=0.05)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            try:
                return (await udp_exchange(server, build_query(ALLOWED, qid=9)))[0]
            finally:
                await frontend.stop()

    reply = dnswire.parse(asyncio.run(scenario()))
    assert (reply.id, reply.rcode) == (9, 2)


def test_serve_boots_the_module_from_the_module_dir_and_shuts_it_down(
    module_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    before = sys.modules.get("pfb_unbound")  # the repo-wide conftest has already imported its own copy
    real_boot = pfb_dns_proxy.boot
    booted_modules: list[Any] = []

    def boot_without_log_files(directory: str) -> Any:
        module = real_boot(directory)
        booted_modules.append(module)
        monkeypatch.setattr(module, "pfb_log", lambda name, line: None)  # the module logs to /var/log/pfblockerng
        return module

    monkeypatch.setattr(pfb_dns_proxy, "boot", boot_without_log_files)
    args = pfb_dns_proxy.parse_args(
        ["--listen", "127.0.0.1", "--port", "0", "--upstream", "127.0.0.1:9", "--module-dir", str(module_dir)]
    )

    async def scenario() -> bytes:
        stop = asyncio.Event()
        ready: asyncio.Future[list[tuple[str, int]]] = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(pfb_dns_proxy.serve(args, stop=stop, on_ready=ready.set_result))
        try:
            [server] = await asyncio.wait_for(ready, WATCHDOG)
            return (await udp_exchange(server, build_query(BLOCKED)))[0]
        finally:
            stop.set()
            await asyncio.wait_for(task, WATCHDOG)

    reply = asyncio.run(scenario())
    assert _answers(dnswire.parse(reply)) == [(BLOCKED, dnswire.TYPE_A, VIP4)]
    assert booted_modules[0] is not before  # serve() imported the module dir's pfb_unbound ...
    assert sys.modules.get("pfb_unbound") is before  # ... and shutdown() uninstalled the shim
