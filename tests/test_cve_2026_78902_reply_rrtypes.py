"""DNS Reply log escaping across every record type the reply writer handles.

``get_details_reply()`` builds the reply column per rrset type: A and AAAA become
addresses, DNSKEY and DS become ``DNSSEC``, and every other type goes through
``convert_other()`` (an RFC 1035 name walk, latin-1). CNAME, NS, PTR, DNAME, SOA,
HINFO and TXT therefore carry third-party bytes straight into ``dns_reply.log``.
CVE-2026-78902 used TXT; the same bytes fit in any of those targets.

These cases drive the writer itself, so on unpatched code they fail on the logged
value, not on a missing helper. "All types" means every branch that builds the
column, not every IANA type code: any other type falls into the same name walk.

Real Unbound renders ``qname_str`` with ``dname_str()``, which turns every byte outside
``[A-Za-z0-9-_*]`` into ``?``, so a live query name never carries ``<>`` (the live smoke
pins ``a?b?``). The raw-``<`` query-name cases below feed the writer input Unbound does
not produce; they pin the writer's own escaping as defence in depth only.

The MX-class (``Unknown``), DNSSEC and post-walk overwrite rows are preservation
pins. They show those values stay literal; they are not proof that rdata from those
types is escaped, because that rdata never reaches the column.
"""

from __future__ import annotations

import csv
import types
from typing import Any

import pytest

import pfb_unbound

HTML_CHARS = set("<>\"'&")
HOSTILE = b'we"ird<x>'
HOSTILE_LOGGED = "we\\034ird\\060x\\062"
MIXED = b"a'b&c\x1b"
MIXED_LOGGED = "a\\039b\\038c\\027"


def _dname(*labels: bytes) -> bytes:
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def _strings(*strings: bytes) -> bytes:
    return b"".join(bytes([len(s)]) + s for s in strings)


def _rr(body: bytes) -> bytes:
    # unbound rr_data: 2-byte RDATA length, then the RDATA.
    return len(body).to_bytes(2, "big") + body


def _reply(rrsets: list[tuple[str, list[bytes]]]) -> Any:
    sets = [
        types.SimpleNamespace(
            rk=types.SimpleNamespace(type_str=rtype),
            entry=types.SimpleNamespace(data=types.SimpleNamespace(count=len(rdata), rr_data=rdata)),
        )
        for rtype, rdata in rrsets
    ]
    return types.SimpleNamespace(an_numrrsets=len(sets), rrsets=sets, ttl=300)


def _log_reply(
    monkeypatch: pytest.MonkeyPatch,
    qname: str,
    qtype: str,
    rep: Any,
    *,
    rcode: int = 0,
    mod_ipaddress: bool = True,
) -> tuple[str, list[str]]:
    monkeypatch.setitem(pfb_unbound.pfb, "python_reply", True)
    monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
    monkeypatch.setitem(pfb_unbound.pfb, "python_maxmind", False)
    monkeypatch.setitem(pfb_unbound.pfb, "mod_ipaddress", mod_ipaddress)
    lines: list[tuple[str, str]] = []
    monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append((path, line)))
    qstate = types.SimpleNamespace(
        qinfo=types.SimpleNamespace(qname_str=qname, qtype_str=qtype), return_msg=None, return_rcode=rcode
    )

    pfb_unbound.get_details_reply("reply", None, qstate, rep, {"pfb_addr": "192.0.2.7"})

    (raw,) = [line for path, line in lines if path.endswith("dns_reply.log")]
    fields = next(csv.reader([raw]))
    assert len(fields) == 10, fields
    return raw, fields


# Third-party bytes the reply walk decodes: (type, RDATA with a hostile label, logged value).
HOSTILE_CASES = [
    ("CNAME", _dname(HOSTILE, b"example"), f"{HOSTILE_LOGGED}.example"),
    ("NS", _dname(b"ns1", HOSTILE, b"example"), f"ns1.{HOSTILE_LOGGED}.example"),
    ("PTR", _dname(HOSTILE, b"example"), f"{HOSTILE_LOGGED}.example"),
    ("DNAME", _dname(HOSTILE, b"example"), f"{HOSTILE_LOGGED}.example"),
    # SOA: the walk stops at MNAME's root label; RNAME and the counters are never read.
    ("SOA", _dname(HOSTILE, b"example") + _dname(b"admin", b"example") + bytes(20), f"{HOSTILE_LOGGED}.example"),
    ("HINFO", _strings(HOSTILE, MIXED), f"{HOSTILE_LOGGED}.{MIXED_LOGGED}"),
    ("TXT", _strings(MIXED), MIXED_LOGGED),
]


@pytest.mark.parametrize(("rtype", "rdata", "logged"), HOSTILE_CASES, ids=[c[0] for c in HOSTILE_CASES])
def test_hostile_reply_data_is_escaped_for_every_decoded_type(
    monkeypatch: pytest.MonkeyPatch, rtype: str, rdata: bytes, logged: str
) -> None:
    raw, fields = _log_reply(monkeypatch, "q.example.", rtype, _reply([(rtype, [_rr(rdata)])]))

    assert fields[8] == logged
    assert not HTML_CHARS & set(raw), raw
    assert "\x1b" not in raw, raw


BENIGN_CASES = [
    ("CNAME", _dname(b"cdn", b"example", b"net"), "cdn.example.net"),
    ("NS", _dname(b"ns1", b"example", b"net"), "ns1.example.net"),
    ("PTR", _dname(b"host-1", b"example", b"net"), "host-1.example.net"),
    ("DNAME", _dname(b"other", b"example"), "other.example"),
    ("SOA", _dname(b"ns1", b"example", b"com") + _dname(b"admin", b"example", b"com") + bytes(20), "ns1.example.com"),
    ("HINFO", _strings(b"INTEL", b"Linux"), "INTEL.Linux"),
    ("TXT", _strings(b"v=spf1 include:_spf.google.com ~all"), "v=spf1 include:_spf.google.com ~all"),
    ("TXT", _strings(b"v=DMARC1; p=none; rua=mailto:d@example.com"), "v=DMARC1; p=none; rua=mailto:d@example.com"),
    ("A", bytes([192, 0, 2, 41]), "192.0.2.41"),
    ("AAAA", bytes.fromhex("20010db8000000000000000000000041"), "2001:db8::41"),
    ("DNSKEY", b"\x01\x01\x03\x08" + b"k" * 8, "DNSSEC"),
    ("DS", b"\x30\x39\x08\x02" + b"d" * 32, "DNSSEC"),
]


@pytest.mark.parametrize(
    ("rtype", "rdata", "logged"), BENIGN_CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(BENIGN_CASES)]
)
def test_ordinary_reply_data_is_logged_unchanged(
    monkeypatch: pytest.MonkeyPatch, rtype: str, rdata: bytes, logged: str
) -> None:
    _, fields = _log_reply(monkeypatch, "q.example.", rtype, _reply([(rtype, [_rr(rdata)])]))

    assert fields[8] == logged


# Types whose RDATA opens with a fixed numeric field: the name walk reads its zero octet
# as the root label and logs "Unknown" (#717), so no third-party text reaches the log.
PREFIXED_CASES = [
    ("MX", b"\x00\x0a" + _dname(HOSTILE, b"example")),
    ("SRV", b"\x00\x00\x00\x05\x13\xc4" + _dname(HOSTILE, b"example")),
    ("CAA", b"\x00\x05issue" + HOSTILE),
    ("HTTPS", b"\x00\x01" + _dname(HOSTILE, b"example")),
    ("SVCB", b"\x00\x01" + _dname(HOSTILE, b"example")),
    ("NAPTR", b"\x00\x64\x00\x0a" + _strings(b"u", b"E2U+sip", HOSTILE) + b"\x00"),
]


@pytest.mark.parametrize(("rtype", "rdata"), PREFIXED_CASES, ids=[c[0] for c in PREFIXED_CASES])
def test_prefixed_types_log_unknown_without_third_party_text(
    monkeypatch: pytest.MonkeyPatch, rtype: str, rdata: bytes
) -> None:
    raw, fields = _log_reply(monkeypatch, "q.example.", rtype, _reply([(rtype, [_rr(rdata)])]))

    assert fields[8] == "Unknown"
    assert not HTML_CHARS & set(raw), raw


def test_multiple_records_are_joined_and_each_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    rep = _reply([("TXT", [_rr(_strings(b"v=spf1 -all")), _rr(_strings(HOSTILE))])])

    raw, fields = _log_reply(monkeypatch, "q.example.", "TXT", rep)

    assert fields[8] == f"v=spf1 -all|{HOSTILE_LOGGED}"
    assert not HTML_CHARS & set(raw), raw


def test_cname_chain_logs_the_final_address(monkeypatch: pytest.MonkeyPatch) -> None:
    # A CNAME + A answer logs the address; the (hostile) CNAME target never reaches the row.
    rep = _reply([("CNAME", [_rr(_dname(HOSTILE, b"example"))]), ("A", [_rr(bytes([203, 0, 113, 8]))])])

    raw, fields = _log_reply(monkeypatch, "q.example.", "A", rep)

    assert fields[8] == "203.0.113.8"
    assert not HTML_CHARS & set(raw), raw


@pytest.mark.parametrize("rtype", ["CNAME", "NS", "PTR", "MX"])
def test_hostile_query_name_is_escaped_for_every_type(monkeypatch: pytest.MonkeyPatch, rtype: str) -> None:
    raw, fields = _log_reply(monkeypatch, "a<b>.example.", rtype, None)

    assert fields[6] == "a\\060b\\062.example"
    assert not HTML_CHARS & set(raw), raw


def test_character_string_over_63_bytes_logs_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    # A length octet above 63 is malformed for the name walk: the payload never reaches the row.
    raw, fields = _log_reply(monkeypatch, "q.example.", "TXT", _reply([("TXT", [_rr(_strings(b"<" * 64))])]))

    assert fields[8] == "Unknown"
    assert not HTML_CHARS & set(raw), raw


def test_only_the_first_a_record_is_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    rep = _reply([("A", [_rr(bytes([192, 0, 2, 1])), _rr(bytes([192, 0, 2, 2]))])])

    _, fields = _log_reply(monkeypatch, "q.example.", "A", rep)

    assert fields[8] == "192.0.2.1"


def test_aaaa_without_ipaddress_module_logs_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    rep = _reply([("AAAA", [_rr(bytes.fromhex("20010db8000000000000000000000041"))])])

    _, fields = _log_reply(monkeypatch, "q.example.", "AAAA", rep, mod_ipaddress=False)

    assert fields[8] == "Unknown"


@pytest.mark.parametrize("rtype", ["DNSKEY", "DS"])
def test_dnssec_rdata_is_discarded_not_logged(monkeypatch: pytest.MonkeyPatch, rtype: str) -> None:
    raw, fields = _log_reply(monkeypatch, "q.example.", rtype, _reply([(rtype, [_rr(HOSTILE)])]))

    assert fields[8] == "DNSSEC"
    assert not HTML_CHARS & set(raw), raw


def test_skipped_multi_record_cname_rrset_never_reaches_the_row(monkeypatch: pytest.MonkeyPatch) -> None:
    hostile = _rr(_dname(HOSTILE, b"example"))
    rep = _reply([("CNAME", [hostile, hostile]), ("A", [_rr(bytes([203, 0, 113, 9]))])])

    raw, fields = _log_reply(monkeypatch, "q.example.", "A", rep)

    assert fields[8] == "203.0.113.9"
    assert not HTML_CHARS & set(raw), raw


def test_hostile_query_name_on_an_a_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    rep = _reply([("A", [_rr(bytes([192, 0, 2, 41]))])])

    raw, fields = _log_reply(monkeypatch, "a<b>.example.", "A", rep)

    assert fields[6] == "a\\060b\\062.example"
    assert fields[8] == "192.0.2.41"
    assert not HTML_CHARS & set(raw), raw


def test_comma_in_a_name_target_stays_one_csv_field(monkeypatch: pytest.MonkeyPatch) -> None:
    raw, fields = _log_reply(monkeypatch, "q.example.", "CNAME", _reply([("CNAME", [_rr(_dname(b"a,b", b"example"))])]))

    assert fields[8] == "a,b.example"


def test_line_breaks_and_escape_in_a_string_stay_one_physical_line(monkeypatch: pytest.MonkeyPatch) -> None:
    raw, fields = _log_reply(monkeypatch, "q.example.", "TXT", _reply([("TXT", [_rr(_strings(b"a\r\nb\x1bc"))])]))

    assert "\n" not in raw and "\r" not in raw and "\x1b" not in raw, raw
    assert fields[8] == "a b\\027c"


# Values the writer substitutes after the record walk. They must stay literal.
def test_empty_answer_logs_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    _, fields = _log_reply(monkeypatch, "q.example.", "A", _reply([]))

    assert fields[8] == "NXDOMAIN"


def test_nonzero_rcode_replaces_the_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pfb_unbound, "rcodeDB", {2: "ServFail"}, raising=False)
    rep = _reply([("TXT", [_rr(_strings(HOSTILE))])])

    raw, fields = _log_reply(monkeypatch, "q.example.", "TXT", rep, rcode=2)

    assert fields[8] == "ServFail"
    assert not HTML_CHARS & set(raw), raw


@pytest.mark.parametrize("qtype", ["SOA", "NSEC3"])
def test_nxdomain_for_soa_and_nsec3_logs_the_type(monkeypatch: pytest.MonkeyPatch, qtype: str) -> None:
    _, fields = _log_reply(monkeypatch, "q.example.", qtype, _reply([]))

    assert fields[8] == qtype


def test_noaaaa_nxdomain_logs_noaaaa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pfb_unbound, "noAAAADB", {"q.example": "0"})

    _, fields = _log_reply(monkeypatch, "q.example.", "AAAA", _reply([]))

    assert fields[8] == "noAAAA"


def test_unbound_sanitised_query_name_is_logged_as_is(monkeypatch: pytest.MonkeyPatch) -> None:
    # The form Unbound's dname_str() actually hands the module for a name with brackets.
    rep = _reply([("A", [_rr(bytes([192, 0, 2, 41]))])])

    _, fields = _log_reply(monkeypatch, "a?b?.example.", "A", rep)

    assert fields[6] == "a?b?.example"
