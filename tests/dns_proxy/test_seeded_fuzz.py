"""A seeded random and mutation loop over the decider's wire code (issue #3517, maintainer fuzz note).

Every input is a mutation of a well-formed message. The seed is fixed, so a failure reproduces exactly: each assertion
names the seed and the step. Two properties: dnswire.parse raises only WireError, and a message it accepts encodes and
parses again; Frontend.resolve never raises, and its reply is None or a message dnswire.parse accepts.
"""

from __future__ import annotations

import asyncio
import random
import struct

import dnswire
import pfb_dns_proxy
from frontend_constants import ALLOWED, BLOCKED, Booted
from frontend_helpers import FakeUnbound, build_query

SEED = 3517
ITERATIONS = 3000
MIN_ITERATIONS = 100  # a shorter run says nothing: its verdict would be the seed's choice, not the code's
CLIENT = "192.0.2.10"
ZONE = {(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]}


def _seeds() -> list[bytes]:
    """Well-formed messages of the shapes the decider meets: queries with and without EDNS, a DNSSEC query, a blocked
    name, a reply with every section filled."""
    reply = dnswire.Message(
        0x1234,
        dnswire.QR | dnswire.RD | dnswire.RA,
        [dnswire.Question(ALLOWED, dnswire.TYPE_A)],
        [
            dnswire.rr_from_text(f"{ALLOWED} 300 IN CNAME target.example."),
            dnswire.rr_from_text("target.example. 60 IN A 192.0.2.1"),
        ],
        [dnswire.rr_from_text("example. 60 IN SOA ns.example. hostmaster.example. 1 2 3 4 60")],
        [dnswire.make_opt(1232, do=True)],
    )
    return [
        build_query(BLOCKED),
        build_query(ALLOWED, edns=True, udp_size=512),
        build_query(ALLOWED, do=True, cd=True),
        build_query("long.label.example.", edns=True, options=struct.pack("!HH", 15, 3) + b"abc"),
        dnswire.encode(reply),
    ]


def _mutate(rng: random.Random, wire: bytes) -> bytes:
    """Between one and four random edits: bit and byte changes, truncation, insertion, header fields, pointers."""
    data = bytearray(wire)
    for _ in range(rng.randint(1, 4)):
        edit = rng.randrange(6)
        if edit == 0 and data:
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        elif edit == 1 and data:
            data[rng.randrange(len(data))] = rng.randrange(256)
        elif edit == 2:
            del data[rng.randrange(len(data) + 1) :]
        elif edit == 3:
            at = rng.randrange(len(data) + 1)
            data[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        elif edit == 4 and len(data) >= 12:
            count = 4 + 2 * rng.randrange(4)  # QDCOUNT, ANCOUNT, NSCOUNT or ARCOUNT
            struct.pack_into("!H", data, count, rng.choice([0, 1, 2, 8, 9, 0xFFFF, rng.randrange(0x10000)]))
        else:
            at = rng.randrange(len(data) + 1)
            data[at:at] = bytes([0xC0, rng.randrange(256)])  # a compression pointer, maybe forward or into a loop
    return bytes(data)


def test_parse_raises_only_wire_error_and_an_accepted_message_encodes_and_parses_again() -> None:
    assert ITERATIONS >= MIN_ITERATIONS, f"ran {ITERATIONS} iterations; the parse property needs {MIN_ITERATIONS}"
    rng = random.Random(SEED)
    seeds = _seeds()
    ran = accepted = 0
    for step in range(ITERATIONS):
        ran += 1
        wire = _mutate(rng, rng.choice(seeds))
        try:
            message = dnswire.parse(wire)
        except dnswire.WireError:
            continue
        except Exception as exc:
            raise AssertionError(f"seed {SEED} step {step}: parse raised {exc!r} on {wire!r}") from exc
        accepted += 1
        try:
            dnswire.parse(dnswire.encode(message))
        except Exception as exc:
            raise AssertionError(f"seed {SEED} step {step}: re-encoding failed {exc!r} for {wire!r}") from exc
    minimum = max(1, ITERATIONS // 10)
    assert (ran, accepted >= minimum) == (ITERATIONS, True), (
        f"ran {ran} of {ITERATIONS} iterations; {accepted} parsed, at least {minimum} needed"
    )


def test_resolve_never_raises_and_its_reply_is_none_or_a_message(booted: Booted) -> None:
    assert ITERATIONS >= MIN_ITERATIONS, f"ran {ITERATIONS} iterations; the resolve property needs {MIN_ITERATIONS}"
    rng = random.Random(SEED)
    seeds = _seeds()
    frontend = pfb_dns_proxy.Frontend(booted.module)
    unbound = FakeUnbound(ZONE)

    async def forward(wire: bytes) -> bytes | None:
        # the gateway's forward gives no reply to a query Unbound cannot read; the stand-in does the same
        try:
            return unbound.answer(wire)
        except (dnswire.WireError, IndexError):
            return None

    async def run() -> int:
        replies = 0
        for step in range(ITERATIONS):
            wire = _mutate(rng, rng.choice(seeds))
            try:
                reply = await frontend.resolve(wire, CLIENT, forward, datagram=rng.random() < 0.5)
            except Exception as exc:
                raise AssertionError(f"seed {SEED} step {step}: resolve raised {exc!r} on {wire!r}") from exc
            if reply is not None:
                try:
                    dnswire.parse(reply)
                except Exception as exc:
                    raise AssertionError(f"seed {SEED} step {step}: unparseable reply {exc!r} for {wire!r}") from exc
                replies += 1
        return replies

    replies = asyncio.run(run())
    assert replies >= max(1, ITERATIONS // 10), f"{replies} of {ITERATIONS} iterations got a reply"
