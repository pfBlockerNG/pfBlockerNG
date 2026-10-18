"""SafeSearch CNAME redirect (MODULE_RESTART_NEXT) through the DNS proxy, with the REAL shipped pfb_unbound.py.

The module plants `orig -> CNAME -> target` and asks for a restart so Unbound's iterator chases the target. The proxy
plays that iterator: it asks Unbound (as the same client) for the target and gives the module the combined message.
test_integration_unbound.py runs the same flows against a real Unbound.
"""

from __future__ import annotations

import asyncio
import builtins
import ipaddress
import struct
from typing import Any

import dnswire
import pfb_dns_proxy
import proxyv2
import pytest
import unbound_shim as shim
from frontend_constants import DNSBL_IPV4, Booted
from frontend_helpers import (
    AD,
    WATCHDOG,
    FakeProxyUpstream,
    FakeUnbound,
    build_query,
    serve_plain,
    tcp_exchange,
    udp_exchange,
)

CLIENT = "192.0.2.10"
DUCK = "duck.example."
TARGET = "safe.duck.example."
VIP4 = bytes(int(octet) for octet in DNSBL_IPV4.split("."))
CNAME_TO_TARGET = (DUCK, dnswire.TYPE_CNAME, dnswire.encode_name(TARGET))
TARGET_A = bytes([192, 0, 2, 88])
TARGET_AAAA = ipaddress.IPv6Address("2001:db8::88").packed
ZONE = {
    (DUCK, dnswire.TYPE_A): [f"{DUCK} 300 IN A 192.0.2.50"],
    (DUCK, dnswire.TYPE_AAAA): [f"{DUCK} 300 IN AAAA 2001:db8::50"],
    ("www.duck.example.", dnswire.TYPE_A): ["www.duck.example. 300 IN A 192.0.2.50"],
    (TARGET, dnswire.TYPE_A): [f"{TARGET} 300 IN A 192.0.2.88"],
    (TARGET, dnswire.TYPE_AAAA): [f"{TARGET} 300 IN AAAA 2001:db8::88"],
    ("nodata.example.", dnswire.TYPE_A): ["nodata.example. 300 IN A 192.0.2.51"],
    ("nodata.example.", dnswire.TYPE_AAAA): ["nodata.example. 300 IN AAAA 2001:db8::51"],
    ("nodata-target.example.", dnswire.TYPE_A): [],
    ("nodata-target.example.", dnswire.TYPE_AAAA): [],
    ("nx.example.", dnswire.TYPE_A): ["nx.example. 300 IN A 192.0.2.52"],
    ("nx.example.", dnswire.TYPE_AAAA): ["nx.example. 300 IN AAAA 2001:db8::52"],
    ("servfail.example.", dnswire.TYPE_A): ["servfail.example. 300 IN A 192.0.2.53"],
    ("silent.example.", dnswire.TYPE_A): ["silent.example. 300 IN A 192.0.2.54"],
    ("nobaked.example.", dnswire.TYPE_A): ["nobaked.example. 300 IN A 192.0.2.55"],
    ("trap.example.", dnswire.TYPE_A): ["trap.example. 300 IN A 192.0.2.56"],
    ("blocked.example.", dnswire.TYPE_A): ["blocked.example. 300 IN A 192.0.2.99"],
    (DUCK, dnswire.TYPE_TXT): [],
    ("chain.example.", dnswire.TYPE_A): [
        "chain.example. 300 IN CNAME other.example.",
        "other.example. 300 IN A 192.0.2.60",
    ],
}


class TargetTroubles(FakeUnbound):
    """FakeUnbound whose chase of one target ends in SERVFAIL or in silence, as a broken upstream would."""

    def answer(self, wire: bytes) -> bytes:
        reply = super().answer(wire)
        query = dnswire.parse(wire)
        if query.questions[0].name == "servfail-target.example.":
            return dnswire.encode(dnswire.Message(query.id, dnswire.QR | dnswire.RA | 2, query.questions))
        return reply

    async def __call__(self, wire: bytes) -> bytes | None:
        if dnswire.parse(wire).questions[0].name == "silent-target.example.":
            self.queries.append(wire)
            return None
        return self.answer(wire)


@pytest.fixture
def cache_calls(ss_booted: Booted) -> list[tuple[Any, ...]]:
    """What the module asked Unbound's message cache to store or drop, in order. The shim's own calls are no-ops, so
    the names the module looks up in builtins are swapped for recorders; uninstall() puts the originals back, and this
    fixture depends on ss_booted so that runs after the test."""
    calls: list[tuple[Any, ...]] = []

    def store(qstate: Any, qinfo: Any, msgrep: Any, is_referral: int) -> bool:
        calls.append(("store", qinfo.qname_str, is_referral))
        return True

    def invalidate(qstate: Any, qinfo: Any) -> None:
        calls.append(("invalidate", qinfo.qname_str))

    builtins.storeQueryInCache = store  # type: ignore[attr-defined]
    builtins.invalidateQueryInCache = invalidate  # type: ignore[attr-defined]
    return calls


def _resolve_wire(
    booted: Booted, wire: bytes, forward: Any, client: str = CLIENT, over_tcp: Any = None
) -> bytes | None:
    """What the client is sent; `over_tcp` makes the client a UDP one (see Frontend.resolve)."""
    frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
    extra = {} if over_tcp is None else {"over_tcp": over_tcp}
    return asyncio.run(frontend.resolve(wire, client, forward, **extra))


def _resolve(booted: Booted, wire: bytes, forward: Any, client: str = CLIENT, over_tcp: Any = None) -> dnswire.Message:
    return dnswire.parse(_resolve_wire(booted, wire, forward, client, over_tcp) or b"")


def _answers(reply: dnswire.Message) -> list[tuple[str, int, bytes]]:
    return [(rr.name, rr.rtype, rr.rdata) for rr in reply.answers]


def _asked(unbound: FakeUnbound) -> list[tuple[str, int]]:
    return [(q.name, q.qtype) for wire in unbound.queries for q in dnswire.parse(wire).questions]


# --- the chase -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("qtype", "address"), [(dnswire.TYPE_A, TARGET_A), (dnswire.TYPE_AAAA, TARGET_AAAA)], ids=["A", "AAAA"]
)
def test_cname_is_chased_and_the_client_gets_the_cname_plus_the_targets_address(
    ss_booted: Booted, cache_calls: list[tuple[Any, ...]], qtype: int, address: bytes
) -> None:
    unbound = FakeUnbound(ZONE)
    reply = _resolve(ss_booted, build_query(DUCK, qtype, qid=0xBEEF), unbound)
    assert (reply.id, reply.rcode, reply.flags & (dnswire.QR | dnswire.RA | dnswire.RD)) == (
        0xBEEF,
        0,
        dnswire.QR | dnswire.RA | dnswire.RD,
    )
    assert [(q.name, q.qtype) for q in reply.questions] == [(DUCK, qtype)]
    assert _answers(reply) == [CNAME_TO_TARGET, (TARGET, qtype, address)]
    assert _asked(unbound) == [(DUCK, qtype), (TARGET, qtype)]  # the original name first, then the chase
    # The module itself ran both passes: plant + restart, then the post-chase re-cache.
    assert cache_calls == [("invalidate", DUCK), ("store", DUCK, 1), ("invalidate", DUCK), ("store", DUCK, 0)]


@pytest.mark.parametrize(("do", "cd"), [(True, False), (False, True), (True, True)], ids=["do", "cd", "do-and-cd"])
def test_a_safesearch_answer_never_claims_dnssec_authentication_whatever_the_client_asks(
    ss_booted: Booted, do: bool, cd: bool
) -> None:
    reply = _resolve(ss_booted, build_query(DUCK, do=do, cd=cd, edns=True), FakeUnbound(ZONE))
    assert _answers(reply) == [CNAME_TO_TARGET, (TARGET, dnswire.TYPE_A, TARGET_A)]
    assert reply.flags & AD == 0  # the proxy synthesised this answer, so it cannot vouch for it


def test_the_www_variant_of_a_safesearch_name_is_redirected_too(ss_booted: Booted) -> None:
    reply = _resolve(ss_booted, build_query("www.duck.example."), FakeUnbound(ZONE))
    assert _answers(reply) == [
        ("www.duck.example.", dnswire.TYPE_CNAME, dnswire.encode_name(TARGET)),
        (TARGET, 1, TARGET_A),
    ]


def test_the_first_upstream_query_is_the_clients_own_bytes_and_the_chase_is_a_fresh_recursive_one(
    ss_booted: Booted,
) -> None:
    unbound = FakeUnbound(ZONE)
    client_wire = build_query(DUCK, qid=0x4242, edns=True)
    _resolve(ss_booted, client_wire, unbound)
    chase = dnswire.parse(unbound.queries[1])
    assert unbound.queries[0] == client_wire
    assert (chase.flags & ~dnswire.RD, chase.flags & dnswire.RD) == (0, dnswire.RD)
    assert [(q.name, q.qtype, q.qclass) for q in chase.questions] == [(TARGET, dnswire.TYPE_A, dnswire.CLASS_IN)]
    assert [rr.rtype for rr in chase.additional] == [dnswire.TYPE_OPT]  # the client speaks EDNS, so the chase does


def test_the_chase_has_no_edns_when_the_client_has_none(ss_booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)
    _resolve(ss_booted, build_query(DUCK), unbound)
    assert dnswire.parse(unbound.queries[1]).additional == []


def _dnssec_ok_bits(wire: bytes) -> list[bool]:
    """The DNSSEC-OK bit of each OPT record in the wire message: [] without EDNS, one entry with it."""
    return [bool(rr.ttl & 0x8000) for rr in dnswire.parse(wire).additional if rr.rtype == dnswire.TYPE_OPT]


@pytest.mark.parametrize(
    ("client_edns", "client_do", "chase"),
    [(True, True, [True]), (True, False, [False]), (False, False, [])],
    ids=["do-1", "do-0", "no-opt"],
)
def test_the_chase_carries_the_clients_dnssec_ok_bit_or_no_opt_at_all(
    ss_booted: Booted, client_edns: bool, client_do: bool, chase: list[bool]
) -> None:
    unbound = FakeUnbound(ZONE)
    _resolve(ss_booted, build_query(DUCK, edns=client_edns, do=client_do), unbound)
    assert _dnssec_ok_bits(unbound.queries[0]) == ([client_do] if client_edns else [])  # what the client sent
    assert _dnssec_ok_bits(unbound.queries[1]) == chase  # what the chase sends Unbound for the target


def test_other_query_types_for_a_safesearch_name_are_relayed_untouched(ss_booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)
    wire = build_query(DUCK, dnswire.TYPE_TXT)
    reply = _resolve(ss_booted, wire, unbound)
    assert reply == dnswire.parse(FakeUnbound(ZONE).answer(wire))
    assert _asked(unbound) == [(DUCK, dnswire.TYPE_TXT)]


def test_a_target_the_dnsbl_blocks_gets_the_block_answer_for_the_safesearch_name(ss_booted: Booted) -> None:
    """The module's CNAME validation runs on the chased message, as it does behind the real iterator."""
    reply = _resolve(ss_booted, build_query("trap.example."), FakeUnbound(ZONE))
    assert _answers(reply) == [("trap.example.", dnswire.TYPE_A, VIP4)]


# --- a chase answer that does not fit a datagram -------------------------------------------------


def _target_zone(count: int) -> dict[tuple[str, int], list[str]]:
    """ZONE with `count` addresses for the SafeSearch target, each an A record of its own."""
    addresses = [f"{TARGET} 300 IN A 10.0.{n // 250}.{n % 250 + 1}" for n in range(count)]
    return ZONE | {(TARGET, dnswire.TYPE_A): addresses}


class TruncatesTarget(FakeUnbound):
    """Unbound over UDP for a target whose addresses do not fit a datagram: TC set and no answer, as Unbound does."""

    def answer(self, wire: bytes) -> bytes:
        query = dnswire.parse(wire)
        if query.questions[0].name != TARGET:
            return super().answer(wire)
        self.queries.append(wire)
        flags = dnswire.QR | dnswire.RA | dnswire.TC | (query.flags & dnswire.RD)
        return dnswire.encode(dnswire.Message(query.id, flags, query.questions))


BAKED_V4 = ipaddress.IPv4Address("198.51.100.7").packed


def test_a_chase_truncated_over_udp_is_repeated_over_tcp_and_the_client_gets_the_targets_real_addresses(
    ss_booted: Booted,
) -> None:
    """Issue #3517 review: a TC reply with no answers read as 'the target has no address' and served the baked one."""
    udp, tcp = TruncatesTarget(_target_zone(3)), FakeUnbound(_target_zone(3))
    reply = _resolve(ss_booted, build_query(DUCK, edns=True), udp, over_tcp=tcp)
    assert reply.flags & dnswire.TC == 0
    assert [(rr.name, rr.rtype) for rr in reply.answers] == [(DUCK, dnswire.TYPE_CNAME)] + [
        (TARGET, dnswire.TYPE_A)
    ] * 3
    assert [rr.rdata for rr in reply.answers[1:]] == [bytes([10, 0, 0, n]) for n in (1, 2, 3)]
    assert BAKED_V4 not in [rr.rdata for rr in reply.answers]
    assert _asked(udp) == [(DUCK, dnswire.TYPE_A), (TARGET, dnswire.TYPE_A)]
    assert _asked(tcp) == [(TARGET, dnswire.TYPE_A)]  # the chase, once, as the same query that was truncated
    assert tcp.queries == [udp.queries[1]]


def test_a_chase_that_was_not_truncated_is_not_repeated_over_tcp(ss_booted: Booted) -> None:
    udp, tcp = FakeUnbound(ZONE), FakeUnbound(ZONE)
    reply = _resolve(ss_booted, build_query(DUCK, edns=True), udp, over_tcp=tcp)
    assert _answers(reply) == [CNAME_TO_TARGET, (TARGET, dnswire.TYPE_A, TARGET_A)]
    assert tcp.queries == []


def test_a_chase_truncated_over_udp_and_unanswered_over_tcp_gets_the_baked_address(ss_booted: Booted) -> None:
    async def silent(_wire: bytes) -> None:
        return None

    reply = _resolve(ss_booted, build_query(DUCK, edns=True), TruncatesTarget(ZONE), over_tcp=silent)
    assert _answers(reply) == [(DUCK, dnswire.TYPE_A, BAKED_V4)]  # as for any chase that gets no reply


# --- the client's UDP size is kept -----------------------------------------------------------------

# (client's EDNS size or None, target addresses, whether the reply has to be truncated). The reply holds the CNAME and
# every address: 92 + 16 per further address bytes without an OPT, 11 more with the proxy's own OPT.
UDP_SIZES = [
    pytest.param(None, 40, True, id="no-edns-limit-512"),
    pytest.param(512, 40, True, id="edns-512"),
    pytest.param(100, 26, False, id="edns-below-512-counts-as-512"),
    pytest.param(1232, 60, False, id="edns-1232-fits"),
    pytest.param(4096, 94, True, id="edns-4096-is-held-to-the-1232-the-proxy-advertises"),
    pytest.param(65535, 94, True, id="edns-65535-is-held-to-1232-too"),
]


def _udp_query(size: int | None) -> bytes:
    return build_query(DUCK) if size is None else build_query(DUCK, edns=True, udp_size=size)


@pytest.mark.parametrize(("size", "count", "truncated"), UDP_SIZES)
def test_a_reply_the_proxy_builds_is_cut_to_the_udp_size_the_client_advertised(
    ss_booted: Booted, size: int | None, count: int, truncated: bool
) -> None:
    """Issue #3517 review: a no-EDNS client was sent 530 bytes and one advertising 512 was sent 796, TC clear."""
    wire = _resolve_wire(ss_booted, _udp_query(size), FakeUnbound(_target_zone(count)), over_tcp=FakeUnbound(ZONE))
    assert wire is not None
    reply = dnswire.parse(wire)
    limit = min(max(size or 512, 512), 1232)
    assert (reply.id, reply.rcode, reply.flags & dnswire.RD, reply.questions) == (
        0x1234,
        0,
        dnswire.RD,
        [dnswire.Question(DUCK, dnswire.TYPE_A)],
    )
    if truncated:
        assert (reply.flags & dnswire.TC, reply.answers, reply.authority) == (dnswire.TC, [], [])
        assert len(wire) <= limit
    else:
        assert (reply.flags & dnswire.TC, len(reply.answers)) == (0, 1 + count)
        assert len(wire) <= limit
    assert [(rr.rtype, rr.rclass) for rr in reply.additional] == ([] if size is None else [(dnswire.TYPE_OPT, 1232)])


def test_a_reply_exactly_as_big_as_the_clients_udp_size_is_not_truncated(ss_booted: Booted) -> None:
    zone = _target_zone(45)
    full = _resolve_wire(ss_booted, build_query(DUCK, edns=True, udp_size=4096), FakeUnbound(zone))  # TCP: no limit
    assert full is not None and 512 < len(full) < 1232
    for size, truncated in ((len(full), False), (len(full) - 1, True)):
        reply = _resolve(
            ss_booted, build_query(DUCK, edns=True, udp_size=size), FakeUnbound(zone), over_tcp=FakeUnbound(zone)
        )
        assert (size, bool(reply.flags & dnswire.TC)) == (size, truncated)


def test_over_tcp_a_reply_larger_than_any_udp_size_is_sent_whole(ss_booted: Booted) -> None:
    wire = _resolve_wire(
        ss_booted, build_query(DUCK), FakeUnbound(_target_zone(94))
    )  # no over_tcp: a TCP or DoT client
    assert wire is not None and len(wire) > 1232
    reply = dnswire.parse(wire)
    assert (reply.flags & dnswire.TC, len(reply.answers)) == (0, 95)


def test_a_message_the_module_flags_truncated_or_authoritative_keeps_both_flags(
    ss_booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def plant(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        if event == shim.MODULE_EVENT_NEW:
            qstate.ext_state[id] = shim.MODULE_WAIT_MODULE
            return True
        flags = shim.PKT_QR | shim.PKT_RA | shim.PKT_AA | shim.PKT_TC
        planted = shim.DNSMessage(qstate.qinfo.qname_str, qstate.qinfo.qtype, shim.RR_CLASS_IN, flags)
        planted.answer.append(f"{qstate.qinfo.qname_str} 60 IN A 192.0.2.1")
        planted.set_return_msg(qstate)
        qstate.ext_state[id] = shim.MODULE_FINISHED
        return True

    monkeypatch.setattr(ss_booted.module, "operate", plant)
    reply = _resolve(ss_booted, build_query(DUCK), FakeUnbound(ZONE))
    assert reply.flags & (dnswire.AA | dnswire.TC) == dnswire.AA | dnswire.TC


# --- the chase carries the client's context --------------------------------------------------------

ECS = struct.pack("!HHHBB", 8, 7, 1, 24, 0) + bytes([192, 0, 2])  # EDNS Client Subnet: 192.0.2.0/24


def test_the_chase_carries_the_clients_cd_bit_and_edns_options_and_advertises_1232(ss_booted: Booted) -> None:
    """Issue #3517 review: the chase dropped CD and ECS, so a CD client's bogus target was SERVFAIL, not an answer."""
    unbound = FakeUnbound(ZONE)
    _resolve(ss_booted, build_query(DUCK, cd=True, do=True, udp_size=4096, options=ECS), unbound)
    chase = dnswire.parse(unbound.queries[1])
    assert chase.flags & (dnswire.RD | dnswire.CD) == dnswire.RD | dnswire.CD
    [opt] = chase.additional
    assert (opt.rtype, opt.rclass, bool(opt.ttl & 0x8000), opt.rdata) == (dnswire.TYPE_OPT, 1232, True, ECS)


def test_the_chase_has_no_cd_bit_when_the_client_sent_none(ss_booted: Booted) -> None:
    unbound = FakeUnbound(ZONE)
    _resolve(ss_booted, build_query(DUCK, edns=True), unbound)
    assert dnswire.parse(unbound.queries[1]).flags & dnswire.CD == 0


def test_the_reply_advertises_1232_and_echoes_none_of_the_clients_edns_options(ss_booted: Booted) -> None:
    reply = _resolve(ss_booted, build_query(DUCK, do=True, udp_size=4096, options=ECS), FakeUnbound(ZONE))
    [opt] = reply.additional
    assert (opt.rtype, opt.rclass, bool(opt.ttl & 0x8000), opt.rdata) == (dnswire.TYPE_OPT, 1232, True, b"")


# --- the chase yields no address: the module's own baked fallback --------------------------------


@pytest.mark.parametrize("name", ["nodata.example.", "nx.example.", "servfail.example.", "silent.example."])
def test_a_chase_without_an_address_gets_the_baked_address(ss_booted: Booted, name: str) -> None:
    unbound = TargetTroubles(ZONE)
    reply = _resolve(ss_booted, build_query(name), unbound)
    baked = {
        "nodata.example.": "198.51.100.8",
        "nx.example.": "198.51.100.10",
        "servfail.example.": "198.51.100.11",
        "silent.example.": "198.51.100.12",
    }[name]
    assert (reply.rcode, _answers(reply)) == (0, [(name, dnswire.TYPE_A, ipaddress.IPv4Address(baked).packed)])
    assert len(_asked(unbound)) == 2  # the original name and exactly one chase


def test_aaaa_without_an_address_gets_the_baked_v6(ss_booted: Booted) -> None:
    reply = _resolve(ss_booted, build_query("nodata.example.", dnswire.TYPE_AAAA), FakeUnbound(ZONE))
    assert _answers(reply) == [("nodata.example.", dnswire.TYPE_AAAA, ipaddress.IPv6Address("2001:db8::8").packed)]


def test_no_chased_address_and_no_baked_address_leaves_the_client_the_lone_cname(ss_booted: Booted) -> None:
    """The module declines (no baked address for the type) and finishes with what the chase gave it: the CNAME."""
    reply = _resolve(ss_booted, build_query("nobaked.example."), FakeUnbound(ZONE))
    assert (reply.rcode, _answers(reply)) == (
        0,
        [("nobaked.example.", dnswire.TYPE_CNAME, dnswire.encode_name("nodata-target.example."))],
    )


# --- guards --------------------------------------------------------------------------------------


def test_a_module_that_keeps_asking_for_restarts_gets_one_chase_then_servfail(
    ss_booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def restart_forever(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        if event == shim.MODULE_EVENT_NEW:
            qstate.ext_state[id] = shim.MODULE_WAIT_MODULE
            return True
        planted = shim.DNSMessage(qstate.qinfo.qname_str, qstate.qinfo.qtype, shim.RR_CLASS_IN, shim.PKT_QR)
        planted.answer.append(f"{qstate.qinfo.qname_str} 3600 IN CNAME {TARGET}")
        planted.set_return_msg(qstate)
        qstate.ext_state[id] = shim.MODULE_RESTART_NEXT
        return True

    monkeypatch.setattr(ss_booted.module, "operate", restart_forever)
    unbound = FakeUnbound(ZONE)
    assert _resolve(ss_booted, build_query(DUCK), unbound).rcode == 2
    assert _asked(unbound) == [(DUCK, dnswire.TYPE_A), (TARGET, dnswire.TYPE_A)]


@pytest.mark.parametrize("name", [DUCK, "chain.example."], ids=["address-answer", "unrelated-cname-chain"])
def test_a_restart_with_nothing_planted_is_servfail_without_a_chase(
    ss_booted: Booted, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    def restart(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        qstate.ext_state[id] = shim.MODULE_WAIT_MODULE if event == shim.MODULE_EVENT_NEW else shim.MODULE_RESTART_NEXT
        return True

    monkeypatch.setattr(ss_booted.module, "operate", restart)
    unbound = FakeUnbound(ZONE)
    assert _resolve(ss_booted, build_query(name), unbound).rcode == 2
    assert _asked(unbound) == [(name, dnswire.TYPE_A)]


# --- real sockets: the chase is made as the client -----------------------------------------------


def test_the_chase_reaches_unbound_behind_the_same_proxyv2_header_as_the_clients_query(ss_booted: Booted) -> None:
    async def scenario() -> tuple[Any, ...]:
        unbound = FakeUnbound(ZONE)
        async with FakeProxyUpstream(unbound) as upstream:
            frontend = pfb_dns_proxy.Frontend(ss_booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            try:
                udp, udp_client = await udp_exchange(server, build_query(DUCK), source="127.0.0.5")
                udp_headers = list(upstream.headers)
                upstream.headers.clear()
                tcp, tcp_client = await tcp_exchange(server, build_query(DUCK), source="127.0.0.6")
                return server, udp, udp_client, udp_headers, tcp, tcp_client, list(upstream.headers), _asked(unbound)
            finally:
                await frontend.stop()

    server, udp, udp_client, udp_headers, tcp, tcp_client, tcp_headers, asked = asyncio.run(scenario())
    for reply in (udp, tcp):
        assert _answers(dnswire.parse(reply)) == [CNAME_TO_TARGET, (TARGET, dnswire.TYPE_A, TARGET_A)]
    udp_header = proxyv2.header(udp_client, server, tcp=False)
    assert udp_headers == [udp_header, udp_header]  # the query and its chase, one client
    assert tcp_headers == [proxyv2.header(tcp_client, server, tcp=True)]  # both over the client's one connection
    assert asked == [(DUCK, 1), (TARGET, 1)] * 2
    assert struct.unpack("!H", udp[:2])[0] == 0x1234  # the client's id, not the chase's


def test_a_chase_repeated_over_tcp_opens_the_connection_to_unbound_with_a_stream_header_for_the_same_client(
    ss_booted: Booted,
) -> None:
    async def scenario() -> tuple[tuple[str, int], tuple[str, int], list[bytes]]:
        async with FakeProxyUpstream(TruncatesTarget(_target_zone(3))) as upstream:
            frontend = pfb_dns_proxy.Frontend(ss_booted.module, ("127.0.0.1", upstream.port), timeout=WATCHDOG)
            [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
            try:
                _, client = await udp_exchange(server, build_query(DUCK, edns=True), source="127.0.0.5")
                return server, client, list(upstream.headers)
            finally:
                await frontend.stop()

    server, client, headers = asyncio.run(scenario())
    datagram = proxyv2.header(client, server, tcp=False)
    assert headers == [datagram, datagram, proxyv2.header(client, server, tcp=True)]  # query, chase, chase over TCP
