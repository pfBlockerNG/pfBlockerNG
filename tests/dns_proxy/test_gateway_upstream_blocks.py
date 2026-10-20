"""Upstream blocks (issue #267) through the REAL Go gateway, the REAL decider and a real Unbound (Docker).

Unbound rewrites every reply it sends (RA set, AA clear, the upstream's EDNS options dropped), so the decider cannot
classify the reply it relays. In forwarding mode Unbound therefore runs pfb_upstream_observer.py, which reports each RAW
upstream response to the decider's socket (`--observer`); the decider logs it as the module logs one inside Unbound,
for the client the gateway named in its PROXYv2 header.

One gateway and one Unbound serve the module; each test asks for names of its own and reads the rows of those names.
"""

from __future__ import annotations

import asyncio
import csv
import struct
import sys
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import dnswire
import pytest
from frontend_constants import write_module_dir
from frontend_helpers import WATCHDOG, UpstreamVerdict, build_query, tcp_exchange, udp_exchange
from test_gateway_e2e import (  # noqa: F401  (fixtures)
    ACL_FILE,
    Running,
    _gateway_process,
    acl_text,
    gateway,
    gateway_binary,
)
from test_integration_unbound import (  # noqa: F401  (fixtures: the Docker Unbound with and without the observer)
    ALLOWED_CLIENT,
    ALLOWED_CLIENT_TCP,
    EDE_BLOCKED,
    EDE_CENSORED,
    EDE_FILTERED,
    NXDOMAIN,
    REFUSED,
    SERVFAIL,
    RunningUnbound,
    observed_unbound,
    unbound,
)

NULL_ADDRESS = ("{name} 60 IN A 0.0.0.0",)
REAL_ADDRESS = ("{name} 60 IN A 192.0.2.1",)
SENTINEL = UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "sentinel"),))


@dataclass(frozen=True)
class Signature:
    verdict: UpstreamVerdict  # what the upstream answers
    block: tuple[str, str] | None  # the (label, feed) the log row carries; None: not an upstream block
    retried: bool = False  # Unbound asks again after a SERVFAIL/REFUSED and the callback fires, and logs, per try


# Pinned from the module's own verdict on the raw response, observed inside the same Unbound 1.26.1 (not computed here).
SIGNATURES = {
    "nxra": Signature(UpstreamVerdict(NXDOMAIN, ra=False), ("NXRA", "External")),
    "nxdomain-recursive": Signature(UpstreamVerdict(NXDOMAIN), None),
    "nxdomain-authoritative": Signature(UpstreamVerdict(NXDOMAIN, ra=False, aa=True), None),
    "nxdomain-authoritative-and-recursive": Signature(UpstreamVerdict(NXDOMAIN, aa=True), None),
    "ede15-nxdomain": Signature(
        UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked by Quad9"),)), ("EDE15 (Blocked)", "Blocked by Quad9")
    ),
    "ede15-nxdomain-no-text": Signature(
        UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, ""),)), ("EDE15 (Blocked)", "External")
    ),
    "ede15-null-address": Signature(
        UpstreamVerdict(0, ede=((EDE_BLOCKED, "Blocked"),), answers=NULL_ADDRESS), ("EDE15 (Blocked)", "Blocked")
    ),
    "ede15-nodata": Signature(UpstreamVerdict(0, ede=((EDE_BLOCKED, "Blocked"),)), ("EDE15 (Blocked)", "Blocked")),
    "ede17-nxdomain": Signature(
        UpstreamVerdict(NXDOMAIN, ede=((EDE_FILTERED, "Filtered by X"),)), ("EDE17 (Filtered)", "Filtered by X")
    ),
    "ede17-null-address": Signature(
        UpstreamVerdict(0, ede=((EDE_FILTERED, ""),), answers=NULL_ADDRESS), ("EDE17 (Filtered)", "External")
    ),
    "ede15-and-ede17": Signature(
        UpstreamVerdict(NXDOMAIN, ede=((EDE_FILTERED, "second"), (EDE_BLOCKED, "first"))), ("EDE15 (Blocked)", "first")
    ),
    "ede15-on-nxra": Signature(
        UpstreamVerdict(NXDOMAIN, ra=False, ede=((EDE_BLOCKED, "Blocked nxra"),)), ("EDE15 (Blocked)", "Blocked nxra")
    ),
    "unrecognised-ede-on-nxra": Signature(
        UpstreamVerdict(NXDOMAIN, ra=False, ede=((EDE_CENSORED, "Censored"),)), ("NXRA", "External")
    ),
    "unrecognised-ede-on-an-answer": Signature(
        UpstreamVerdict(0, ede=((EDE_CENSORED, "Censored"),), answers=REAL_ADDRESS), None
    ),
    "null-address-without-ede": Signature(UpstreamVerdict(0, answers=NULL_ADDRESS), None),
    "answer-with-ra-clear-without-ede": Signature(UpstreamVerdict(0, ra=False, answers=REAL_ADDRESS), None),
    "ede15-refused": Signature(
        UpstreamVerdict(REFUSED, ede=((EDE_BLOCKED, "Blocked refused"),)), ("EDE15 (Blocked)", "Blocked refused"), True
    ),
    "ede15-servfail": Signature(
        UpstreamVerdict(SERVFAIL, ede=((EDE_BLOCKED, "Blocked servfail"),)),
        ("EDE15 (Blocked)", "Blocked servfail"),
        True,
    ),
}


@pytest.fixture(scope="module")
def observed_gateway(
    tmp_path_factory: pytest.TempPathFactory, gateway_binary: Path, observed_unbound: RunningUnbound
) -> Iterator[Running]:
    """The gateway with `--observer` in front of the observed Unbound; its decider hosts the module in forwarding mode.
    Unbound's working directory hosts the module and the observer's socket, as /var/unbound does."""
    write_module_dir(observed_unbound.conf_dir, forwarding=True)
    with _gateway_process(
        gateway_binary, observed_unbound.conf_dir, observed_unbound, tmp_path_factory.mktemp("observed"), ACL_FILE,
        ["--observer"],
    ) as (process, log_dir):  # fmt: skip
        yield Running(process, process.server(), log_dir)


def _fresh(prefix: str) -> str:
    """A name nothing has asked for yet (Unbound's cache would answer a repeat without asking upstream)."""
    return f"{prefix}-{uuid.uuid4().hex[:10]}.example."


def _rows(running: Running) -> list[list[str]]:
    path = running.log_dir / "dnsbl.log"
    return [next(csv.reader([line])) for line in path.read_text().splitlines()] if path.exists() else []


def _upstream_blocks(running: Running, name: str) -> list[tuple[str, str, str, str, str]]:
    """(b_type, label, feed, client, query type) of each upstream-block row logged for `name`."""
    rows = _rows(running)
    return [(r[5], r[7], r[8], r[3], r[10]) for r in rows if r[5] == "Upstream_Block" and r[2] == name.rstrip(".")]


def _logged_through(running: Running, name: str) -> None:
    """Return once `name`'s upstream-block row is logged: the observer's reports reach the decider in the order Unbound
    made them, so every report of a query answered BEFORE `name` was asked is logged by then. The module logs from a
    thread of its own into a file, so the wait polls it; the watchdog bounds the loop."""
    deadline = time.monotonic() + WATCHDOG
    while not _upstream_blocks(running, name):
        assert time.monotonic() < deadline, (
            f"STUCK/ENVIRONMENT: no upstream-block row for {name}; rows: {_rows(running)}"
        )
        time.sleep(0.02)


def _ask(server: tuple[str, int], name: str, source: str, *, edns: bool = False, tcp: bool = False) -> bytes:
    exchange = tcp_exchange if tcp else udp_exchange
    return asyncio.run(exchange(server, build_query(name, edns=edns), source=source))[0]


@pytest.mark.parametrize("edns", [False, True], ids=["client-without-edns", "client-with-edns"])
@pytest.mark.parametrize("signature", SIGNATURES.values(), ids=SIGNATURES.keys())
def test_each_upstream_signature_is_logged_as_the_module_logs_it_inside_unbound(
    observed_gateway: Running, observed_unbound: RunningUnbound, signature: Signature, edns: bool
) -> None:
    name, sentinel = _fresh("signature"), _fresh("sentinel")
    observed_unbound.verdicts[name] = signature.verdict
    observed_unbound.verdicts[sentinel] = SENTINEL

    _ask(observed_gateway.server, name, ALLOWED_CLIENT, edns=edns)
    _ask(observed_gateway.server, sentinel, ALLOWED_CLIENT)
    _logged_through(observed_gateway, sentinel)

    rows = _upstream_blocks(observed_gateway, name)
    if signature.block is None:
        assert rows == []
        return
    label, feed = signature.block
    assert set(rows) == {("Upstream_Block", label, feed, ALLOWED_CLIENT, "A")}
    assert signature.retried or len(rows) == 1


def test_an_upstream_block_is_logged_for_the_client_that_asked_over_udp_and_over_tcp(
    observed_gateway: Running, observed_unbound: RunningUnbound
) -> None:
    udp_name, tcp_name, sentinel = _fresh("udp"), _fresh("tcp"), _fresh("sentinel")
    for name in (udp_name, tcp_name):
        observed_unbound.verdicts[name] = UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked"),))
    observed_unbound.verdicts[sentinel] = SENTINEL

    _ask(observed_gateway.server, udp_name, ALLOWED_CLIENT)
    _ask(observed_gateway.server, tcp_name, ALLOWED_CLIENT_TCP, tcp=True)
    _ask(observed_gateway.server, sentinel, ALLOWED_CLIENT)
    _logged_through(observed_gateway, sentinel)

    block = ("Upstream_Block", "EDE15 (Blocked)", "Blocked")
    assert _upstream_blocks(observed_gateway, udp_name) == [
        (*block, ALLOWED_CLIENT, "A")
    ]  # not the gateway's 127.0.0.1
    assert _upstream_blocks(observed_gateway, tcp_name) == [(*block, ALLOWED_CLIENT_TCP, "A")]


def test_an_upstream_block_is_logged_once_when_unbound_fetched_it_not_for_each_client_it_answers(
    observed_gateway: Running, observed_unbound: RunningUnbound
) -> None:
    """As inside Unbound: the callback fires per upstream fetch, so a repeat answered from the cache logs nothing."""
    name, sentinel = _fresh("cached"), _fresh("sentinel")
    observed_unbound.verdicts[name] = UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked"),))
    observed_unbound.verdicts[sentinel] = SENTINEL
    upstream = observed_unbound.authoritative.unbound

    def asked_upstream() -> int:
        return [dnswire.parse(wire).questions[0].name.lower() for wire in upstream.queries].count(name)

    _ask(observed_gateway.server, name, ALLOWED_CLIENT)
    fetched = asked_upstream()
    _ask(observed_gateway.server, name, ALLOWED_CLIENT_TCP)
    _ask(observed_gateway.server, sentinel, ALLOWED_CLIENT)
    _logged_through(observed_gateway, sentinel)

    assert (fetched, asked_upstream()) == (1, 1)  # the second client was answered from Unbound's cache
    assert _upstream_blocks(observed_gateway, name) == [
        ("Upstream_Block", "EDE15 (Blocked)", "Blocked", ALLOWED_CLIENT, "A")
    ]


def _ede_codes(message: dnswire.Message) -> list[int]:
    codes = []
    for rr in message.additional:
        data = rr.rdata if rr.rtype == dnswire.TYPE_OPT else b""
        while len(data) >= 4:
            code, size = struct.unpack("!HH", data[:4])
            if code == 15:
                codes.append(struct.unpack("!H", data[4:6])[0])
            data = data[4 + size :]
    return codes


@pytest.mark.parametrize(
    "verdict",
    [UpstreamVerdict(NXDOMAIN, ra=False), UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked"),))],
    ids=["nxra", "ede15"],
)
def test_unbound_hides_the_upstream_signals_from_the_gateway_which_is_why_the_observer_exists(
    gateway: Running,
    unbound: RunningUnbound,
    verdict: UpstreamVerdict,  # noqa: F811
) -> None:
    """The probe result the design rests on, pinned: a reply Unbound builds from an upstream block carries RA set, AA
    clear and no Extended DNS Error, even to a client that sent EDNS, so nothing in front of it can classify what it
    relays. If an Unbound release starts passing them on, this fails and the observer can go."""
    name = _fresh("hidden")
    unbound.verdicts[name] = verdict

    reply = dnswire.parse(_ask(gateway.server, name, ALLOWED_CLIENT, edns=True))

    assert (reply.rcode, bool(reply.flags & dnswire.RA), bool(reply.flags & dnswire.AA), _ede_codes(reply)) == (
        NXDOMAIN,
        True,
        False,
        [],
    )


def test_a_row_that_never_gets_logged_is_stuck_not_a_failed_row_assertion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys.modules[__name__], "WATCHDOG", 0)
    running = Running(cast(Any, None), ("127.0.0.1", 1), tmp_path)  # _logged_through reads only the log dir
    with pytest.raises(
        AssertionError, match=r"^STUCK/ENVIRONMENT: no upstream-block row for blocked\.example\."
    ) as raised:
        _logged_through(running, "blocked.example.")
    assert "rows: []" in str(raised.value)
