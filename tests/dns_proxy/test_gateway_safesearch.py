"""SafeSearch's chase through the REAL Go gateway, the REAL decider and a real Unbound (Docker): a target the chase
finds no address for gives the client the module's baked address, over either transport. test_gateway_chase.py has
the target that is too big for a datagram; test_gateway_e2e.py the redirect itself.
"""

from __future__ import annotations

import asyncio

import dnswire
import pytest
from frontend_helpers import build_query, tcp_exchange, udp_exchange
from test_gateway_e2e import Running, _answers, acl_text, gateway, gateway_binary  # noqa: F401  (fixtures)
from test_integration_unbound import ALLOWED_CLIENT, ALLOWED_CLIENT_TCP, RunningUnbound, unbound  # noqa: F401


@pytest.mark.parametrize("transport", ["udp", "tcp"])
@pytest.mark.parametrize(
    ("name", "target", "baked"),
    [
        ("nodata.example.", "nodata-target.example.", "198.51.100.8"),
        ("nx.example.", "nx-target.example.", "198.51.100.10"),
    ],
    ids=["target-has-no-data", "target-does-not-exist"],
)
def test_a_safesearch_target_without_an_address_gives_the_client_the_modules_baked_address(
    safesearch_csv: None, gateway: Running, unbound: RunningUnbound, transport: str, name: str, target: str, baked: str
) -> None:
    mark = unbound.tail.mark()
    client = ALLOWED_CLIENT if transport == "udp" else ALLOWED_CLIENT_TCP
    exchange = udp_exchange if transport == "udp" else tcp_exchange

    reply = asyncio.run(exchange(gateway.server, build_query(name), source=client))[0]

    assert _answers(reply) == [(name, dnswire.TYPE_A, bytes(int(octet) for octet in baked.split(".")))]
    unbound.tail.wait_for(f"{client} {target} A IN", since=mark)  # the chase happened, as the client, and found nothing
