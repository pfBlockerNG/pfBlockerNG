"""Issue #3517: SafeSearch's chase through the REAL Go gateway, the REAL decider and a real Unbound (Docker).

A target with 94 addresses does not fit a datagram: Unbound truncates the chase it is asked over UDP. The gateway asks
a plain-UDP client's chase again over TCP, so the decider sees the target's real addresses, builds the answer, and
holds it to the client's UDP size; a TCP client's answer is not held to one.
"""

from __future__ import annotations

import asyncio

import dnswire
import pytest
from frontend_helpers import build_query, tcp_exchange, udp_exchange
from test_gateway_e2e import Running, _answers, acl_text, gateway, gateway_binary  # noqa: F401  (fixtures)
from test_integration_unbound import (  # noqa: F401
    ALLOWED_CLIENT,
    ALLOWED_CLIENT_TCP,
    BIG_ADDRESSES,
    RunningUnbound,
    unbound,
)


@pytest.mark.parametrize(("edns_size", "limit"), [(None, 512), (1232, 1232)], ids=["no-edns", "edns-1232"])
def test_a_udp_client_is_sent_tc_when_the_safesearch_target_is_too_big_for_a_datagram_not_the_baked_address(
    safesearch_csv: None,
    gateway: Running,
    edns_size: int | None,
    limit: int,
) -> None:
    """Issue #3517 review: Unbound truncated the chase over UDP (TC, no answers), the decider read that as 'no
    address' and answered with the baked 198.51.100.13, TC clear."""
    query = (
        build_query("big.example.") if edns_size is None else build_query("big.example.", edns=True, udp_size=edns_size)
    )
    wire = asyncio.run(udp_exchange(gateway.server, query, source=ALLOWED_CLIENT))[0]
    reply = dnswire.parse(wire)
    assert (reply.rcode, reply.flags & dnswire.TC, reply.answers) == (0, dnswire.TC, [])
    assert len(wire) <= limit


def test_a_tcp_client_is_sent_every_real_address_of_the_big_safesearch_target(
    safesearch_csv: None,
    gateway: Running,  # noqa: F811
) -> None:
    wire = asyncio.run(tcp_exchange(gateway.server, build_query("big.example."), source=ALLOWED_CLIENT_TCP))[0]
    assert dnswire.parse(wire).flags & dnswire.TC == 0
    answers = _answers(wire)  # Unbound rotates the address set, so only the CNAME has a place
    assert answers[0] == ("big.example.", dnswire.TYPE_CNAME, dnswire.encode_name("big-target.example."))
    assert sorted(answers[1:]) == [("big-target.example.", dnswire.TYPE_A, address) for address in BIG_ADDRESSES]
