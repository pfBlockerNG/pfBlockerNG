"""Hostile packets must cost bounded time, and a silent Unbound one log line a window (the gateway's own limits, its
flood and stalled-client handling are in go/pfb_dns_gateway: caps_test.go, hostile_test.go, upstream_test.go).

Pointer bombs and header-only FORMERR; dropped responses; Unbound's silence; the per-test alarm; qclass, 14-bit offsets.
"""

from __future__ import annotations

import asyncio
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

import dnswire
import pfb_dns_proxy
import pytest
import unbound_shim as shim
from frontend_constants import ALLOWED, BLOCKED, Booted
from frontend_helpers import (
    FakeUnbound,
    ManualClock,
    build_query,
)

QTC = b"\x00\x01\x00\x01"  # qtype A, qclass IN
ZONE = {(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]}


def _hdr(qd: int = 0, an: int = 0, ns: int = 0, ar: int = 0, *, flags: int = 0x0100, qid: int = 0xABCD) -> bytes:
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)


def _null_rr(owner: bytes) -> bytes:
    return owner + struct.pack("!HHIH", 10, 1, 0, 0)  # type NULL, no rdata


def _chain_of_questions(count: int) -> bytes:
    """`count` questions, each name a pointer at the previous question's name: parsing all costs count^2/2 hops."""
    out = bytearray(_hdr(count) + b"\x01a\x00" + QTC)
    previous = 12
    for _ in range(count - 1):
        here = len(out)
        out += struct.pack("!H", 0xC000 | previous) + QTC
        previous = here
    return bytes(out)


def _wide_name_questions(count: int) -> bytes:
    """A 127-label name, then `count` questions that are each a pointer at it."""
    return _hdr(count) + b"\x01a" * 127 + b"\x00" + QTC + (b"\xc0\x0c" + QTC) * (count - 1)


def _pointer_chain_rrs(count: int) -> bytes:
    """One question, then `count` RRs whose owners each point at the previous owner: the last name has `count` hops."""
    out = bytearray(_hdr(1, count) + b"\x01a\x00" + QTC)
    previous = 12
    for _ in range(count):
        here = len(out)
        out += _null_rr(struct.pack("!H", 0xC000 | previous))
        previous = here
    return bytes(out)


def _resolve(booted: Booted, wire: bytes, forward: Any = None) -> bytes | None:
    async def scenario() -> bytes | None:
        frontend = pfb_dns_proxy.Frontend(booted.module)
        return await frontend.resolve(wire, "192.0.2.10", forward or FakeUnbound(ZONE))

    return asyncio.run(scenario())


# --- pointer bombs and header-only FORMERR -----------------------------------------------


def test_a_chain_of_200_compression_pointers_is_rejected() -> None:
    with pytest.raises(dnswire.WireError, match="pointer"):
        dnswire.parse(_pointer_chain_rrs(200))


def test_a_chain_of_100_compression_pointers_is_still_a_name() -> None:
    message = dnswire.parse(_pointer_chain_rrs(100))
    assert [rr.name for rr in message.answers] == ["a."] * 100


@pytest.mark.parametrize(
    "bomb",
    [_chain_of_questions(4000), _wide_name_questions(8000), _hdr(2) + b"\x01a\x00" + QTC + b"\xc0\x0c" + QTC],
    ids=["chain-of-questions", "wide-name-pointer-questions", "two-questions"],
)
def test_a_query_without_exactly_one_question_gets_a_header_only_formerr_without_being_parsed(
    booted: Booted, bomb: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(dnswire, "parse", lambda _wire: pytest.fail("the packet was parsed: its cost is not constant"))
        reply = _resolve(booted, bomb)
    assert reply is not None and len(reply) == 12  # the header alone: no question echoed, nothing to amplify
    msg_id, flags, *counts = struct.unpack("!HHHHHH", reply)
    assert (msg_id, flags & 0xF, flags & (dnswire.QR | dnswire.RD), counts) == (
        0xABCD,
        1,
        dnswire.QR | dnswire.RD,
        [0, 0, 0, 0],
    )


# --- what Unbound answers without resolving is Unbound's: forwarded unchanged, the module not asked ------

UNBOUND_SAID = b"Unbound's reply, not a DNS message"  # comes back exactly as forwarded: the test sees who answered
ANSWER = dnswire.RR(BLOCKED, dnswire.TYPE_A, dnswire.CLASS_IN, 60, bytes([192, 0, 2, 1]))
NULL_RR = dnswire.RR(".", 10, dnswire.CLASS_IN, 0, b"")


def _opt(version: int = 0, owner: str = ".") -> dnswire.RR:
    return dnswire.RR(owner, dnswire.TYPE_OPT, 1232, version << 16, b"")


def _query(
    *,
    flags: int = dnswire.RD,
    qclass: int = dnswire.CLASS_IN,
    answers: list[dnswire.RR] | None = None,
    authority: list[dnswire.RR] | None = None,
    additional: list[dnswire.RR] | None = None,
) -> bytes:
    question = dnswire.Question(BLOCKED, dnswire.TYPE_A, qclass)
    return dnswire.encode(dnswire.Message(0x4242, flags, [question], answers or [], authority or [], additional or []))


FORWARDED = {
    "TC set": _query(flags=dnswire.RD | dnswire.TC),
    "an answer record": _query(answers=[ANSWER]),
    "an authority record": _query(authority=[ANSWER]),
    "two additional records": _query(additional=[_opt(), NULL_RR]),
    "two OPT records": _query(additional=[_opt(), _opt()]),
    "nine additional records": _query(additional=[NULL_RR] * 9),
    "one additional record that is not an OPT": _query(additional=[NULL_RR]),
    "an OPT of EDNS version 1": _query(additional=[_opt(version=1)]),
    "an OPT not owned by the root": _query(additional=[_opt(owner="example.")]),
    "class CH": _query(qclass=3),
    "class HS": _query(qclass=4),
    "opcode UPDATE": _query(flags=dnswire.RD | (5 << 11)),
    "opcode IQUERY": _query(flags=dnswire.RD | (1 << 11)),
    "opcode STATUS": _query(flags=dnswire.RD | (2 << 11)),
    "an answer section the parser cannot read": _hdr(1, an=1) + dnswire.encode_name(BLOCKED) + QTC + b"\xff",
}
DECIDED = {
    "a plain query": _query(),
    "an EDNS version 0 OPT of the root": _query(additional=[_opt()]),
    "class ANY": _query(qclass=255),  # not a class Unbound answers without resolving: it stays with the module
}


def _decide(booted: Booted, monkeypatch: pytest.MonkeyPatch, wire: bytes) -> tuple[bytes | None, list[bytes], int]:
    """(the reply, the wires forwarded to Unbound, how many times the module was asked) for one client query."""
    forwarded: list[bytes] = []
    asked: list[int] = []
    real = booted.module.operate

    def spy(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        asked.append(event)
        return real(id, event, qstate, qdata)

    async def forward(unbound_wire: bytes) -> bytes | None:
        forwarded.append(unbound_wire)
        return UNBOUND_SAID

    monkeypatch.setattr(booted.module, "operate", spy)
    return _resolve(booted, wire, forward), forwarded, len(asked)


@pytest.mark.parametrize("wire", FORWARDED.values(), ids=FORWARDED.keys())
def test_a_query_unbound_answers_without_resolving_goes_to_unbound_unchanged(
    booted: Booted, monkeypatch: pytest.MonkeyPatch, wire: bytes
) -> None:
    """Unbound rejects or answers these before it resolves a name, so its reply is the exact answer and the module does
    not decide them."""
    assert _decide(booted, monkeypatch, wire) == (UNBOUND_SAID, [wire], 0)


@pytest.mark.parametrize("wire", DECIDED.values(), ids=DECIDED.keys())
def test_a_query_the_module_decides_is_not_forwarded(
    booted: Booted, monkeypatch: pytest.MonkeyPatch, wire: bytes
) -> None:
    reply, forwarded, asked = _decide(booted, monkeypatch, wire)
    assert (reply != UNBOUND_SAID, forwarded, asked > 0) == (True, [], True)


def test_a_packet_the_parser_cannot_read_gets_a_header_only_formerr_and_is_not_forwarded(
    booted: Booted, monkeypatch: pytest.MonkeyPatch
) -> None:
    reply, forwarded, asked = _decide(booted, monkeypatch, _hdr(1) + b"\x05ab")  # a 5-octet label, 2 octets present
    assert reply is not None
    assert (len(reply), dnswire.parse(reply).rcode, forwarded, asked) == (12, 1, [], 0)


@pytest.mark.parametrize("wire", [FORWARDED["TC set"], FORWARDED["class CH"]], ids=["truncated", "class CH"])
def test_a_query_unbound_answers_itself_that_gets_no_reply_is_a_servfail(booted: Booted, wire: bytes) -> None:
    async def silent(_wire: bytes) -> bytes | None:
        return None

    reply = _resolve(booted, wire, silent)
    assert reply is not None
    assert dnswire.parse(reply).rcode == 2  # SERVFAIL, as a module-decided query gets when Unbound is silent


@pytest.mark.parametrize(
    "wire",
    [FORWARDED["opcode UPDATE"], FORWARDED["opcode IQUERY"], FORWARDED["opcode STATUS"]],
    ids=["update", "iquery", "status"],
)
def test_an_opcode_query_unbound_gives_no_reply_to_gets_a_header_only_servfail_with_its_id_and_opcode(
    booted: Booted, wire: bytes
) -> None:
    """An opcode the decider forwards unchanged is answered like every other forwarded query when Unbound is silent: a
    SERVFAIL that keeps the id and the opcode, header only, as the decider builds for a query it does not parse."""

    async def silent(_wire: bytes) -> bytes | None:
        return None

    reply = _resolve(booted, wire, silent)
    assert reply is not None
    query, message = dnswire.parse(wire), dnswire.parse(reply)
    assert (
        len(reply),
        message.id,
        message.flags & 0x7800,
        message.flags & dnswire.QR,
        message.rcode,
        message.questions,
    ) == (
        12,
        query.id,
        query.flags & 0x7800,
        dnswire.QR,
        2,
        [],
    )


# --- a response is never answered ------------------------------------------------------------


def test_a_truncated_packet_with_qr_set_is_dropped_not_answered_with_formerr(booted: Booted) -> None:
    truncated_response = struct.pack("!HHHHHH", 7, 0x8100, 1, 0, 0, 0) + b"\xc0"
    assert _resolve(booted, truncated_response) is None


# --- Unbound's silence is logged once per window ---------------------------------------------


def _silence_lines(
    booted: Booted,
    clock: ManualClock,
    monkeypatch: pytest.MonkeyPatch,
    with_module: bool,
    steps: list[tuple[float, str]],
) -> list[str]:
    """The 'no reply from Unbound' lines logged while `steps` are resolved in order: (seconds to pass first, name).
    Unbound answers every name that does not start with 'silent'."""
    warnings: list[object] = []
    monkeypatch.setattr(shim, "log_warn", warnings.append)
    answered = FakeUnbound(ZONE)

    async def forward(wire: bytes) -> bytes | None:
        return None if dnswire.parse(wire).questions[0].name.startswith("silent") else answered.answer(wire)

    async def scenario() -> None:
        frontend = pfb_dns_proxy.Frontend(booted.module if with_module else None)
        for pause, name in steps:
            clock.advance(pause)
            await frontend.resolve(build_query(name), "192.0.2.10", forward)

    asyncio.run(scenario())
    return [str(line) for line in warnings if "no reply from Unbound" in str(line)]


@pytest.mark.parametrize("with_module", [True, False], ids=["module", "no-module"])
def test_unbound_not_answering_is_one_log_line_per_30_seconds_whatever_it_answers_in_between(
    booted: Booted, clock: ManualClock, monkeypatch: pytest.MonkeyPatch, with_module: bool
) -> None:
    """Issue #3517 review: one line per silent query, about 100 lines/s into an unrotated log under a flood."""
    steps = [
        (0, "silent0.example."),
        (0, ALLOWED),  # an answer in between does not re-arm the line
        (0, "silent1.example."),
        (29.5, "silent2.example."),  # 29.5 s into the window
        (0.5, "silent3.example."),  # exactly 30 s: the next window
    ]
    lines = _silence_lines(booted, clock, monkeypatch, with_module, steps)
    assert len(lines) == 2 and "silent0.example." in lines[0] and "silent3.example." in lines[1], lines


@pytest.mark.parametrize("with_module", [True, False], ids=["module", "no-module"])
def test_a_mixed_load_of_answered_and_unanswered_queries_logs_one_line_per_window(
    booted: Booted, clock: ManualClock, monkeypatch: pytest.MonkeyPatch, with_module: bool
) -> None:
    """Issue #3515 gate: one answer used to re-arm the line, so two silent queries per answered one logged about one
    line per second. Sixty seconds of that are two windows."""
    steps: list[tuple[float, str]] = []
    for second in range(60):
        steps += [(1.0 if second else 0, f"silent{second}a.example."), (0, f"silent{second}b.example.")]
        steps.append((0, ALLOWED))
    lines = _silence_lines(booted, clock, monkeypatch, with_module, steps)
    assert len(lines) == 2 and "silent0a.example." in lines[0] and "silent30a.example." in lines[1], lines


# --- the per-test alarm ----------------------------------------------------------------------


def test_a_hung_test_is_failed_by_the_alarm_instead_of_stalling_the_run(tmp_path: Path) -> None:
    (tmp_path / "test_spin.py").write_text("def test_spin():\n    while True:\n        pass\n", encoding="utf-8")
    env = {**os.environ, "PFB_TEST_TIMEOUT": "1", "PYTHONPATH": str(Path(__file__).parent)}
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "hang_guard", "-p", "no:cacheprovider", "-o", "addopts=", "-q"]
        + [str(tmp_path / "test_spin.py")],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        cwd=tmp_path,
        env=env,
    )
    assert run.returncode == 1 and "test exceeded 1 s" in run.stdout


# --- qclass, 14-bit offsets -------------------------------------------------------------------


def test_the_question_class_reaches_the_module(booted: Booted, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []
    real = booted.module.operate

    def spy(id: int, event: int, qstate: Any, qdata: Any) -> bool:
        seen.append(qstate.qinfo.qclass)
        return real(id, event, qstate, qdata)

    monkeypatch.setattr(booted.module, "operate", spy)
    any_class = dnswire.encode(
        dnswire.Message(5, dnswire.RD, [dnswire.Question("version.bind.", dnswire.TYPE_TXT, 255)])
    )
    _resolve(booted, any_class)
    assert seen[0] == 255


def test_a_name_first_written_beyond_the_14_bit_pointer_range_is_never_a_pointer_target() -> None:
    filler = dnswire.RR("a.example.", dnswire.TYPE_TXT, 1, 60, b"\xff" + b"x" * 255 + (b"\xff" + b"x" * 255) * 65)
    late = [dnswire.RR(f"{label}.late.example.", dnswire.TYPE_A, 1, 60, bytes(4)) for label in ("x", "y")]
    wire = dnswire.encode(dnswire.Message(1, dnswire.QR, [], [filler, *late]))
    assert len(wire) > 0x4000 + 40  # the late names really start beyond what a pointer can reach
    assert [rr.name for rr in dnswire.parse(wire).answers] == ["a.example.", "x.late.example.", "y.late.example."]
