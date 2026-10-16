"""dnswire: the stdlib DNS codec. Packets are hand-built so the codec is not graded against itself."""

from __future__ import annotations

import struct

import dnswire
import pytest
from dnswire import RR, Message, Question, WireError

WWW = b"\x03www\x07example\x03com\x00"
IN = dnswire.CLASS_IN


def _hdr(qd: int = 0, an: int = 0, ns: int = 0, ar: int = 0, *, flags: int = 0x8180, qid: int = 0xABCD) -> bytes:
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)


def _rr(owner: bytes, rtype: int, rdata: bytes, ttl: int = 60) -> bytes:
    return owner + struct.pack("!HHIH", rtype, IN, ttl, len(rdata)) + rdata


def _response() -> bytes:
    """A response with one RR of every supported type, owners equal to the question name."""
    owner = "www.example.com."
    message = Message(
        0xABCD,
        dnswire.QR | dnswire.RD | dnswire.RA,
        [Question(owner, dnswire.TYPE_A)],
        answers=[
            dnswire.rr_from_text(f"{owner} 300 IN A 192.0.2.1"),
            dnswire.rr_from_text(f"{owner} 300 IN AAAA 2001:db8::1"),
            dnswire.rr_from_text(f"{owner} 300 IN CNAME target.example.com."),
            dnswire.rr_from_text(f'{owner} 300 IN TXT "hello world"'),
        ],
        authority=[dnswire.rr_from_text("example.com. 300 IN SOA ns.example.com. admin.example.com. 1 2 3 4 5")],
    )
    return dnswire.encode(message)


# --- happy path ----------------------------------------------------------------------------------


def test_encode_query_matches_hand_built_bytes() -> None:
    message = Message(0xABCD, dnswire.RD, [Question("www.example.com.", dnswire.TYPE_A)])
    assert dnswire.encode(message) == _hdr(1, flags=0x0100) + WWW + b"\x00\x01\x00\x01"


def test_parse_hand_built_query() -> None:
    message = dnswire.parse(_hdr(1, flags=0x0100) + WWW + b"\x00\x1c\x00\x01")
    assert (message.id, message.flags, message.rcode, message.opcode) == (0xABCD, 0x0100, 0, 0)
    assert message.questions == [Question("www.example.com.", dnswire.TYPE_AAAA, IN)]
    assert message.answers == message.authority == message.additional == []


def test_response_round_trips_and_compresses_owner_names() -> None:
    wire = _response()
    # owner == question name -> pointer to offset 12; the SOA owner example.com. -> pointer into the question
    assert wire.count(b"\xc0\x0c") == 4
    assert b"\xc0\x10" in wire
    message = dnswire.parse(wire)
    assert [rr.rtype for rr in message.answers] == [
        dnswire.TYPE_A,
        dnswire.TYPE_AAAA,
        dnswire.TYPE_CNAME,
        dnswire.TYPE_TXT,
    ]
    assert message.answers[0] == RR("www.example.com.", dnswire.TYPE_A, IN, 300, bytes([192, 0, 2, 1]))
    assert message.answers[2].rdata == b"\x06target\x07example\x03com\x00"
    assert message.answers[3].rdata == b"\x0bhello world"
    assert message.authority[0].rtype == dnswire.TYPE_SOA
    assert dnswire.encode(message) == wire  # re-encoding the parsed message is stable


def test_parse_expands_compression_pointers_inside_rdata() -> None:
    question = b"\x01a\x07example\x00" + struct.pack("!HH", dnswire.TYPE_CNAME, IN)  # "example." label at offset 14
    owner = b"\xc0\x0c"
    cname = _rr(owner, dnswire.TYPE_CNAME, b"\x03www\xc0\x0e")
    mx = _rr(owner, dnswire.TYPE_MX, struct.pack("!H", 10) + b"\x04mail\xc0\x0e")
    soa = _rr(owner, dnswire.TYPE_SOA, b"\x02ns\xc0\x0e\x05admin\xc0\x0e" + struct.pack("!IIIII", 1, 2, 3, 4, 5))
    message = dnswire.parse(_hdr(1, 3) + question + cname + mx + soa)
    assert [rr.rdata for rr in message.answers] == [
        b"\x03www\x07example\x00",
        struct.pack("!H", 10) + b"\x04mail\x07example\x00",
        b"\x02ns\x07example\x00\x05admin\x07example\x00" + struct.pack("!IIIII", 1, 2, 3, 4, 5),
    ]


def test_parse_keeps_rdata_of_types_that_may_not_be_compressed() -> None:
    srv = struct.pack("!HHH", 1, 2, 3) + b"\x03srv\x07example\x00"
    message = dnswire.parse(_hdr(1, 1) + WWW + b"\x00\x01\x00\x01" + _rr(b"\xc0\x0c", dnswire.TYPE_SRV, srv))
    assert message.answers[0].rdata == srv


def test_parse_ignores_bytes_after_the_last_record() -> None:
    message = dnswire.parse(_hdr(1, flags=0x0100) + WWW + b"\x00\x01\x00\x01" + b"trailing")
    assert len(message.questions) == 1


def test_names_round_trip_escaped_labels() -> None:
    wire = b"\x03a.b\x07example\x00"
    assert dnswire.encode_name("a\\.b.example.") == wire
    message = dnswire.parse(_hdr(1) + wire + b"\x00\x01\x00\x01")
    assert message.questions[0].name == "a\\.b.example."
    nonprintable = dnswire.parse(_hdr(1) + b"\x01\x01\x00" + b"\x00\x01\x00\x01")
    assert nonprintable.questions[0].name == "\\001."


def test_opt_record_marks_edns_and_carries_the_do_bit() -> None:
    opt = dnswire.make_opt(1232, do=True)
    assert (opt.name, opt.rtype, opt.rclass, opt.ttl, opt.rdata) == (".", dnswire.TYPE_OPT, 1232, 0x8000, b"")
    wire = dnswire.encode(Message(1, 0, [Question("example.", dnswire.TYPE_A)], additional=[opt]))
    assert dnswire.parse(wire).additional == [opt]


# --- text RRs as written by pfb_unbound.py (DNSMessage.answer/authority) -------------------------


@pytest.mark.parametrize(
    ("text", "rtype", "rdata"),
    [
        ("x.example. 3600 IN A 10.10.10.1", dnswire.TYPE_A, bytes([10, 10, 10, 1])),
        ("x.example. 3600 IN AAAA ::1", dnswire.TYPE_AAAA, bytes(15) + b"\x01"),
        ("x.example. 3600 IN CNAME y.example.", dnswire.TYPE_CNAME, b"\x01y\x07example\x00"),
        ('python_control. 0 IN TXT "Not authorized! [ a b ]"', dnswire.TYPE_TXT, b"\x17Not authorized! [ a b ]"),
        (
            "blocked.example. 3600 IN SOA pfb.invalid. nobody.invalid. 1 3600 1200 604800 3600",
            dnswire.TYPE_SOA,
            b"\x03pfb\x07invalid\x00\x06nobody\x07invalid\x00" + struct.pack("!IIIII", 1, 3600, 1200, 604800, 3600),
        ),
    ],
)
def test_rr_from_text_builds_the_wire_rdata(text: str, rtype: int, rdata: bytes) -> None:
    rr = dnswire.rr_from_text(text)
    assert (rr.name, rr.rtype, rr.rclass, rr.rdata) == (text.split()[0], rtype, IN, rdata)
    assert rr.ttl == int(text.split()[1])


@pytest.mark.parametrize(
    "text",
    [
        "x.example. 60 IN MX 10 mail.example.",  # type the module never writes
        "x.example. 60 IN A",  # rdata missing
        "x.example. 60 IN A 999.1.1.1",
        "x.example. 60 IN AAAA 10.0.0.1",
        "x.example. 60 CH A 10.0.0.1",
        "x.example. sixty IN A 10.0.0.1",
        'x.example. 60 IN TXT "unterminated',
        "x.example. 60 IN TXT " + '"' + "a" * 256 + '"',
        "x.example. 60 IN SOA only.three. fields.here.",
    ],
)
def test_rr_from_text_rejects_what_it_cannot_encode(text: str) -> None:
    with pytest.raises(ValueError):
        dnswire.rr_from_text(text)


# --- hostile input -------------------------------------------------------------------------------


@pytest.mark.parametrize("cut", range(len(_response())))
def test_every_truncation_of_a_valid_response_is_rejected(cut: int) -> None:
    with pytest.raises(WireError):
        dnswire.parse(_response()[:cut])


def test_pointer_to_itself_is_rejected() -> None:
    with pytest.raises(WireError, match="backwards"):
        dnswire.parse(_hdr(1) + b"\xc0\x0c" + b"\x00\x01\x00\x01")


def test_forward_pointer_is_rejected() -> None:
    with pytest.raises(WireError, match="backwards"):
        dnswire.parse(_hdr(1) + b"\xc0\x14" + b"\x00\x01\x00\x01" + WWW)


def test_two_pointers_aimed_at_each_other_are_rejected() -> None:
    # offset 12 points at 16 and offset 16 points back at 12: a cycle needs one non-backward hop
    packet = _hdr(1) + b"\xc0\x10" + b"\x00\x01" + b"\xc0\x0c" + b"\x00\x01"
    with pytest.raises(WireError):
        dnswire.parse(packet)


def test_truncated_pointer_is_rejected() -> None:
    with pytest.raises(WireError):
        dnswire.parse(_hdr(1) + b"\xc0")


@pytest.mark.parametrize("length_octet", [0x40, 0x41, 0x80, 0xBF])
def test_label_longer_than_63_or_reserved_type_is_rejected(length_octet: int) -> None:
    packet = _hdr(1) + bytes([length_octet]) + b"a" * 200 + b"\x00\x00\x01\x00\x01"
    with pytest.raises(WireError, match="label"):
        dnswire.parse(packet)


def test_encoding_a_label_longer_than_63_is_rejected() -> None:
    with pytest.raises(ValueError, match="label"):
        dnswire.encode_name("a" * 64 + ".example.")


def test_name_of_255_octets_is_accepted_and_256_is_not() -> None:
    longest = b"\x01a" * 127 + b"\x00"  # 255 octets on the wire
    assert dnswire.parse(_hdr(1) + longest + b"\x00\x01\x00\x01").questions[0].name == "a." * 127
    with pytest.raises(WireError, match="255"):
        dnswire.parse(_hdr(1) + b"\x01a" * 128 + b"\x00\x00\x01\x00\x01")
    with pytest.raises(ValueError, match="255"):
        dnswire.encode_name("a." * 128)


def test_empty_label_in_the_middle_of_a_name_is_rejected() -> None:
    with pytest.raises(ValueError):
        dnswire.encode_name("a..example.")


def test_question_count_zero_parses_to_no_questions() -> None:
    message = dnswire.parse(_hdr(0, flags=0x0100))
    assert message.questions == []


def test_header_counts_larger_than_the_packet_are_rejected_before_parsing() -> None:
    with pytest.raises(WireError, match="count"):
        dnswire.parse(_hdr(65535, 65535, 65535, 65535))


def test_header_shorter_than_twelve_bytes_is_rejected() -> None:
    with pytest.raises(WireError, match="header"):
        dnswire.parse(b"\x12\x34\x01")


def test_rdlength_beyond_the_packet_is_rejected() -> None:
    packet = _hdr(1, 1) + WWW + b"\x00\x01\x00\x01" + b"\xc0\x0c" + struct.pack("!HHIH", 1, IN, 60, 4) + b"\x01\x02"
    with pytest.raises(WireError, match="rdata"):
        dnswire.parse(packet)


def test_name_inside_rdata_that_runs_past_rdlength_is_rejected() -> None:
    # CNAME rdlength 2 covers "\x01a" only; the name's root octet sits OUTSIDE the declared rdata
    packet = _hdr(1, 1) + WWW + b"\x00\x05\x00\x01" + b"\xc0\x0c" + struct.pack("!HHIH", 5, IN, 60, 2) + b"\x01a\x00"
    with pytest.raises(WireError, match="rdata"):
        dnswire.parse(packet)
