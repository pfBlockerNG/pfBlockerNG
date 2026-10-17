"""SafeSearch CNAME redirect (MODULE_RESTART_NEXT) through the DNS proxy, with the REAL shipped pfb_unbound.py.

The module plants `orig -> CNAME -> target` and asks for a restart so Unbound's iterator chases the target. The proxy
plays that iterator: it asks Unbound (as the same client) for the target and gives the module the combined message.
test_integration_unbound.py runs the same flows against a real Unbound.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct
from typing import Any

import dnswire
import pfb_dns_proxy
import proxyv2
import pytest
import unbound_shim as shim
from frontend_constants import DNSBL_IPV4, Booted
from frontend_helpers import WATCHDOG, FakeProxyUpstream, FakeUnbound, build_query, tcp_exchange, udp_exchange

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


def _resolve(booted: Booted, wire: bytes, forward: Any, client: str = CLIENT) -> dnswire.Message:
    frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
    return dnswire.parse(asyncio.run(frontend.resolve(wire, client, forward)) or b"")


def _answers(reply: dnswire.Message) -> list[tuple[str, int, bytes]]:
    return [(rr.name, rr.rtype, rr.rdata) for rr in reply.answers]


def _asked(unbound: FakeUnbound) -> list[tuple[str, int]]:
    return [(q.name, q.qtype) for wire in unbound.queries for q in dnswire.parse(wire).questions]


# --- the chase -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("qtype", "address"), [(dnswire.TYPE_A, TARGET_A), (dnswire.TYPE_AAAA, TARGET_AAAA)], ids=["A", "AAAA"]
)
def test_cname_is_chased_and_the_client_gets_the_cname_plus_the_targets_address(
    ss_booted: Booted, qtype: int, address: bytes
) -> None:
    unbound = FakeUnbound(ZONE)
    shim.cache_calls.clear()
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
    assert shim.cache_calls == [("invalidate", DUCK), ("store", DUCK, 1), ("invalidate", DUCK), ("store", DUCK, 0)]


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
            [server] = await frontend.start(["127.0.0.1"], 0)
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
