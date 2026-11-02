"""Real Unbound must answer legal labels as sent, even when a label contains a literal dot (RFC 2181 section 11)."""

from __future__ import annotations

import struct
from collections.abc import Callable, Coroutine
from typing import Any

import pytest
from frontend_helpers import tcp_exchange, udp_exchange
from test_gateway_e2e import (  # noqa: F401 (shared real gateway and Unbound fixtures)
    ALLOWED_CLIENT,
    ALLOWED_CLIENT_TCP,
    Running,
    _ask,
    acl_text,
    gateway,
    gateway_binary,
    unbound,
)


@pytest.mark.parametrize(
    ("exchange", "source"), [(udp_exchange, ALLOWED_CLIENT), (tcp_exchange, ALLOWED_CLIENT_TCP)], ids=["udp", "tcp"]
)
@pytest.mark.parametrize(
    ("label", "qtype", "edns", "rcode", "answers", "authority"),
    [
        (b"a.b", 1, False, 0, 1, 0),
        (b"a.b", 1, True, 0, 1, 0),
        (b"a.b", 16, False, 0, 1, 0),
        (b"q.r", 1, False, 3, 0, 1),
        (b"q.r", 1, True, 3, 0, 1),
        (b"a.b.c", 1, False, 0, 1, 0),
        (b".", 1, False, 0, 1, 0),
    ],
    ids=["A", "A-EDNS", "TXT", "NXDOMAIN-SOA", "NXDOMAIN-SOA-EDNS", "several-dots", "dot-only"],
)
def test_unbounds_actual_answer_to_a_dot_inside_a_label_reaches_the_client(
    gateway: Running,  # noqa: F811 (pytest fixture imported above)
    exchange: Callable[..., Coroutine[Any, Any, Any]],
    source: str,
    label: bytes,
    qtype: int,
    edns: bool,
    rcode: int,
    answers: int,
    authority: int,
) -> None:
    name = bytes([len(label)]) + label + b"\x0dbinary-labels\x07example\x00"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, int(edns)) + name + struct.pack("!HH", qtype, 1)
    if edns:
        query += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    reply = _ask(exchange, gateway.server, query, source)
    msg_id, flags, qd, an, ns, _ = struct.unpack("!HHHHHH", reply[:12])
    assert (msg_id, flags & 0xF, qd, an, ns) == (0x1234, rcode, 1, answers, authority), reply.hex()
    assert reply[12 : 12 + len(name) + 4] == name + struct.pack("!HH", qtype, 1), reply.hex()
