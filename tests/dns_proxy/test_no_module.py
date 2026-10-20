"""`--no-module` (pfB-DNS on, DNSBL off): the decider boots no pfb_unbound.py and has every query forwarded to Unbound.
There are no decisions, no MODDONE pass and no observer socket; the failure shapes are the module mode's.
test_gateway_modes.py runs the same through the real gateway against a real Unbound, and the privilege drop of this
mode is in test_privilege_drop.py.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any

import dnswire
import pfb_dns_proxy
import pytest
from frontend_constants import ALLOWED, BLOCKED, DNSBL_IPV4, Booted
from frontend_helpers import (
    FakeUnbound,
    build_query,
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
    frontend = pfb_dns_proxy.Frontend(module)
    return asyncio.run(frontend.resolve(wire, CLIENT, forward))


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


@pytest.mark.parametrize("short", [b"", b"\x0b\x0b", bytes(11)], ids=["zero-length", "id-only", "11-bytes"])
def test_a_reply_from_unbound_too_short_to_have_a_header_is_a_servfail_not_relayed(short: bytes) -> None:
    async def forward(_wire: bytes) -> bytes:
        return short

    reply = dnswire.parse(_resolve(None, build_query(ALLOWED, qid=0x0B0B), forward) or b"")
    assert (reply.id, reply.rcode) == (0x0B0B, 2)


def test_a_reply_from_unbound_of_a_header_alone_is_relayed_as_it_is() -> None:
    refused = struct.pack("!HHHHHH", 0x0B0B, dnswire.QR | dnswire.RD | dnswire.RA | 5, 0, 0, 0, 0)  # 12 bytes: REFUSED

    async def forward(_wire: bytes) -> bytes:
        return refused

    assert _resolve(None, build_query(ALLOWED, qid=0x0B0B), forward) == refused


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


# --- starting up -----------------------------------------------------------------------------------
