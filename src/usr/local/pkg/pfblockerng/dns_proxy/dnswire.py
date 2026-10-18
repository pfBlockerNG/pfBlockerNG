"""Standard-library DNS wire codec (RFC 1035 with the RFC 6891 OPT record) for the pfBlockerNG DNS proxy.

Names are absolute presentation strings ("example.com.", root "."); `\\.`, `\\\\` and `\\DDD` escape the bytes a
label may carry. RR rdata is kept canonical: names inside RFC 1035 rdata types are expanded (never compressed),
which is also how Unbound stores them. `encode` compresses owner names only.
"""

from __future__ import annotations

import ipaddress
import shlex
import struct
from dataclasses import dataclass, field

QR = 0x8000
AA = 0x0400
TC = 0x0200
RD = 0x0100
RA = 0x0080
CD = 0x0010

CLASS_IN = 1
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_OPT = 41
TYPE_RRSIG = 46

_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    24: "SIG",
    28: "AAAA",
    33: "SRV",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}

# rdata layouts of the RFC 1035 types, the only ones whose names may be compressed on the wire:
# a number is a run of fixed octets, None is a domain name.
_NAME_LAYOUTS: dict[int, tuple[int | None, ...]] = {
    TYPE_NS: (None,),
    3: (None,),  # MD
    4: (None,),  # MF
    TYPE_CNAME: (None,),
    TYPE_SOA: (None, None, 20),
    7: (None,),  # MB
    8: (None,),  # MG
    9: (None,),  # MR
    TYPE_PTR: (None,),
    14: (None, None),  # MINFO
    TYPE_MX: (2, None),
}

_MAX_NAME = 255
_MAX_LABEL = 63
_MAX_HOPS = 127  # a name has at most 127 labels, so a longer pointer chain is not a compressed name
_HEADER = struct.Struct("!HHHHHH")


class WireError(ValueError):
    """The packet is not a well-formed DNS message."""


def type_str(rtype: int) -> str:
    return _TYPE_NAMES.get(rtype, f"TYPE{rtype}")


@dataclass(frozen=True, slots=True)
class Question:
    name: str
    qtype: int
    qclass: int = CLASS_IN


@dataclass(frozen=True, slots=True)
class RR:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes


@dataclass(slots=True)
class Message:
    id: int = 0
    flags: int = 0
    questions: list[Question] = field(default_factory=list)
    answers: list[RR] = field(default_factory=list)
    authority: list[RR] = field(default_factory=list)
    additional: list[RR] = field(default_factory=list)

    @property
    def rcode(self) -> int:
        return self.flags & 0xF

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF


EDNS_UDP_SIZE = 1232  # the UDP size the proxy advertises: Unbound's edns-buffer-size default


def make_opt(udp_size: int = EDNS_UDP_SIZE, *, do: bool = False, options: bytes = b"") -> RR:
    """An EDNS OPT pseudo-RR: the class field carries the UDP size, the TTL field the DO bit, the rdata `options`
    (already encoded)."""
    return RR(".", TYPE_OPT, udp_size, 0x8000 if do else 0, options)


# --- names ---------------------------------------------------------------------------------------


def _label_text(label: bytes) -> str:
    out = []
    for octet in label:
        if octet in (0x2E, 0x5C):
            out.append("\\" + chr(octet))
        elif 0x21 <= octet <= 0x7E:
            out.append(chr(octet))
        else:
            out.append(f"\\{octet:03d}")
    return "".join(out)


def labels_to_text(labels: list[bytes]) -> str:
    return "".join(_label_text(label) + "." for label in labels) or "."


def name_to_labels(name: str) -> list[bytes]:
    """Presentation name -> labels (no root label). Raises ValueError for what cannot go on the wire."""
    if name == ".":
        return []
    if not name:
        raise ValueError("empty name")
    labels: list[bytes] = []
    current = bytearray()
    i = 0
    while i < len(name):
        char = name[i]
        if char == "\\":
            i += 1
            if i >= len(name):
                raise ValueError(f"dangling escape in {name!r}")
            digits = name[i : i + 3]
            if name[i].isdigit():
                if len(digits) != 3 or not digits.isdigit() or int(digits) > 255:
                    raise ValueError(f"bad \\DDD escape in {name!r}")
                current.append(int(digits))
                i += 3
            else:
                current += name[i].encode()
                i += 1
            continue
        if char == ".":
            if not current:
                raise ValueError(f"empty label in {name!r}")
            labels.append(bytes(current))
            current = bytearray()
        else:
            current += char.encode()
        i += 1
    if current:
        labels.append(bytes(current))
    if any(len(label) > _MAX_LABEL for label in labels):
        raise ValueError(f"label longer than {_MAX_LABEL} octets in {name!r}")
    if sum(len(label) + 1 for label in labels) + 1 > _MAX_NAME:
        raise ValueError(f"name longer than {_MAX_NAME} octets")
    return labels


def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label for label in name_to_labels(name)) + b"\x00"


def name_from_rdata(rdata: bytes) -> str:
    """The name an uncompressed domain-name rdata (CNAME, NS, PTR) holds, in presentation form."""
    return labels_to_text(_read_labels(rdata, 0)[0])


def _read_labels(data: bytes, pos: int) -> tuple[list[bytes], int]:
    """Labels of the name at `pos` (following compression pointers) and the offset just past it in the stream.

    A pointer must point strictly backwards, so a loop is impossible by construction; at most _MAX_HOPS pointers are
    followed, because a chain of pointers aimed at the previous pointer costs a hop per link on every read.
    """
    labels: list[bytes] = []
    wire_len = 1  # root octet
    end: int | None = None
    hops = 0
    cur = pos
    while True:
        if cur >= len(data):
            raise WireError("truncated name")
        octet = data[cur]
        if octet == 0:
            return labels, (end if end is not None else cur + 1)
        if octet & 0xC0 == 0xC0:
            if cur + 1 >= len(data):
                raise WireError("truncated compression pointer")
            target = ((octet & 0x3F) << 8) | data[cur + 1]
            if end is None:
                end = cur + 2
            if target >= cur:
                raise WireError("compression pointer does not point backwards")
            hops += 1
            if hops > _MAX_HOPS:
                raise WireError(f"more than {_MAX_HOPS} compression pointers in one name")
            cur = target
            continue
        if octet & 0xC0:
            raise WireError("reserved label type or label longer than 63 octets")
        if cur + 1 + octet > len(data):
            raise WireError("truncated label")
        wire_len += 1 + octet
        if wire_len > _MAX_NAME:
            raise WireError(f"name longer than {_MAX_NAME} octets")
        labels.append(data[cur + 1 : cur + 1 + octet])
        cur += 1 + octet


# --- parse ---------------------------------------------------------------------------------------


def _expand_rdata(data: bytes, rtype: int, start: int, end: int) -> bytes:
    layout = _NAME_LAYOUTS.get(rtype)
    if layout is None:
        return data[start:end]
    out = bytearray()
    cur = start
    for part in layout:
        if part is None:
            labels, cur = _read_labels(data, cur)
            if cur > end:
                raise WireError("name overruns rdata")
            out += b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
        else:
            if cur + part > end:
                raise WireError("fixed rdata field overruns rdata")
            out += data[cur : cur + part]
            cur += part
    if cur != end:
        raise WireError("rdata length mismatch")
    return bytes(out)


def parse(data: bytes) -> Message:
    """Parse a DNS message. Bytes after the last declared record are ignored."""
    if len(data) < _HEADER.size:
        raise WireError("short header")
    msg_id, flags, qdcount, ancount, nscount, arcount = _HEADER.unpack_from(data)
    if qdcount * 5 + (ancount + nscount + arcount) * 11 > len(data) - _HEADER.size:
        raise WireError("record counts exceed packet size")
    pos = _HEADER.size
    message = Message(msg_id, flags)
    for _ in range(qdcount):
        labels, pos = _read_labels(data, pos)
        if pos + 4 > len(data):
            raise WireError("truncated question")
        qtype, qclass = struct.unpack_from("!HH", data, pos)
        pos += 4
        message.questions.append(Question(labels_to_text(labels), qtype, qclass))
    for section, count in ((message.answers, ancount), (message.authority, nscount), (message.additional, arcount)):
        for _ in range(count):
            labels, pos = _read_labels(data, pos)
            if pos + 10 > len(data):
                raise WireError("truncated record")
            rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            if pos + rdlength > len(data):
                raise WireError("rdata overruns packet")
            section.append(
                RR(labels_to_text(labels), rtype, rclass, ttl, _expand_rdata(data, rtype, pos, pos + rdlength))
            )
            pos += rdlength
    return message


# --- encode --------------------------------------------------------------------------------------


def encode(message: Message) -> bytes:
    """Serialise a message, compressing owner names against everything already written."""
    out = bytearray(
        _HEADER.pack(
            message.id,
            message.flags,
            len(message.questions),
            len(message.answers),
            len(message.authority),
            len(message.additional),
        )
    )
    seen: dict[tuple[bytes, ...], int] = {}

    def put_name(name: str) -> None:
        labels = name_to_labels(name)
        folded = [label.lower() for label in labels]
        for i, label in enumerate(labels):
            suffix = tuple(folded[i:])
            if suffix in seen:
                out.extend(struct.pack("!H", 0xC000 | seen[suffix]))
                return
            if len(out) < 0x4000:
                seen[suffix] = len(out)
            out.append(len(label))
            out.extend(label)
        out.append(0)

    for question in message.questions:
        put_name(question.name)
        out.extend(struct.pack("!HH", question.qtype, question.qclass))
    for rr in (*message.answers, *message.authority, *message.additional):
        put_name(rr.name)
        out.extend(struct.pack("!HHIH", rr.rtype, rr.rclass, rr.ttl, len(rr.rdata)))
        out.extend(rr.rdata)
    return bytes(out)


# --- text RRs (what pfb_unbound.py hands DNSMessage.answer/authority) ----------------------------


def _txt_rdata(rest: str) -> bytes:
    strings = [token.encode() for token in shlex.split(rest)]
    if not strings or any(len(s) > 255 for s in strings):
        raise ValueError("TXT needs at least one character-string of at most 255 octets")
    return b"".join(bytes([len(s)]) + s for s in strings)


def _soa_rdata(rest: str) -> bytes:
    fields = rest.split()
    if len(fields) != 7:
        raise ValueError("SOA rdata is: mname rname serial refresh retry expire minimum")
    numbers = [int(value) for value in fields[2:]]
    if any(not 0 <= number <= 0xFFFFFFFF for number in numbers):
        raise ValueError("SOA counter out of range")
    return encode_name(fields[0]) + encode_name(fields[1]) + struct.pack("!IIIII", *numbers)


_TEXT_RDATA = {
    "A": (TYPE_A, lambda rest: ipaddress.IPv4Address(rest.strip()).packed),
    "AAAA": (TYPE_AAAA, lambda rest: ipaddress.IPv6Address(rest.strip()).packed),
    "CNAME": (TYPE_CNAME, lambda rest: encode_name(rest.strip())),
    "TXT": (TYPE_TXT, _txt_rdata),
    "SOA": (TYPE_SOA, _soa_rdata),
}


def rr_from_text(line: str) -> RR:
    """Build an RR from `name ttl IN type rdata` (A, AAAA, CNAME, TXT, SOA); ValueError for anything else."""
    parts = line.split(None, 4)
    if len(parts) < 5:
        raise ValueError(f"expected 'name ttl IN type rdata': {line!r}")
    name, ttl, rclass, rtype, rest = parts
    if not ttl.isdigit() or int(ttl) > 0xFFFFFFFF:
        raise ValueError(f"bad ttl {ttl!r}")
    if rclass.upper() != "IN":
        raise ValueError(f"unsupported class {rclass!r}")
    if rtype.upper() not in _TEXT_RDATA:
        raise ValueError(f"unsupported RR type {rtype!r}")
    code, build = _TEXT_RDATA[rtype.upper()]
    name_to_labels(name)  # reject a name that cannot be encoded now, not when the reply is serialised
    return RR(name, code, CLASS_IN, int(ttl), build(rest))
