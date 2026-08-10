from __future__ import annotations

import ipaddress
from types import SimpleNamespace

import pytest

import pfb_unbound


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        (bytes([0, 0, 192, 168, 1, 1]), "192.168.1.1"),
        (bytes([0, 0, 255, 255, 255, 255]), "255.255.255.255"),
        (b"", "Unknown"),
        (None, "Unknown"),
    ],
)
def test_convert_ipv4_uses_python3_byte_values(wire: bytes | None, expected: str) -> None:
    assert pfb_unbound.convert_ipv4(wire) == expected


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        (bytes([0, 0] + [0] * 15 + [1]), "0000:0000:0000:0000:0000:0000:0000:0001"),
        (
            bytes([0, 0, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001:0db8:0000:0000:0000:0000:0000:0001",
        ),
        (b"", "Unknown"),
        (None, "Unknown"),
    ],
)
def test_convert_ipv6_uses_python3_byte_values(wire: bytes | None, expected: str) -> None:
    assert pfb_unbound.convert_ipv6(wire) == expected


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ([ord("A"), 0, ord("B")], "A|B"),
        ([ord("A"), 1, ord("B")], "A.B"),
        ([ord("A"), 13, ord("B")], "A"),
        ([ord("A"), 32, ord("B")], "A B"),
        ([ord("h"), 58, ord("1")], "h:1"),
        ([ord("A"), 14, 200, ord("B")], "AB"),
        ([], "Unknown"),
    ],
)
def test_convert_other_uses_python3_byte_values(payload: list[int], expected: str) -> None:
    assert pfb_unbound.convert_other(bytes([0, 0, 0, *payload])) == expected


@pytest.mark.parametrize(
    ("duration", "expected"),
    [("abc", False), ("0", False), ("1", 1), ("3600", 3600), ("3601", False)],
)
def test_python_control_duration_enforces_numeric_bounds(duration: str, expected: int | bool) -> None:
    assert pfb_unbound.python_control_duration(duration) == expected


class _MaxMind:
    def __init__(self) -> None:
        self.addresses: list[str] = []

    def get(self, address: str) -> dict[str, dict[str, str]]:
        self.addresses.append(address)
        return {"country": {"iso_code": "US"}}


def test_reply_ipv6_is_compressed_before_maxmind_classification(monkeypatch: pytest.MonkeyPatch) -> None:
    address = "2001:4860:4860::8888"
    wire = bytes([0, 0, *ipaddress.ip_address(address).packed])
    data = SimpleNamespace(count=1, rr_data=[wire])
    rrset = SimpleNamespace(rk=SimpleNamespace(type_str="AAAA"), entry=SimpleNamespace(data=data))
    rep = SimpleNamespace(an_numrrsets=1, rrsets=[rrset], ttl=300)
    qinfo = SimpleNamespace(qname_str="example.test.", qtype_str="AAAA")
    qstate = SimpleNamespace(qinfo=qinfo, return_msg=None, return_rcode=0)
    reader = _MaxMind()
    lines: list[str] = []
    pfb_unbound.pfb.update(
        sqlite3_resolver_con=False,
        python_reply=True,
        mod_ipaddress=True,
        python_maxmind=True,
    )
    pfb_unbound.noAAAADB = {}
    pfb_unbound.rcodeDB = {}
    pfb_unbound.maxmindReader = reader
    monkeypatch.setattr(pfb_unbound, "log_entry", lambda line, _path: lines.append(line))

    assert pfb_unbound.get_details_reply("reply", None, qstate, rep, {"pfb_addr": "192.0.2.1"})
    fields = lines[0].split(",")
    assert fields[8:] == [address, "US"]
    assert reader.addresses == [address]


def _control_qstate(command: str) -> SimpleNamespace:
    reply = SimpleNamespace(query_reply=SimpleNamespace(addr="127.0.0.1"), next=None)
    return SimpleNamespace(
        qinfo=SimpleNamespace(qtype=16, qtype_str="TXT", qname_str=f"{command}."),
        mesh_info=SimpleNamespace(reply_list=reply),
        return_msg=SimpleNamespace(rep=SimpleNamespace(security=0)),
        return_rcode=None,
        ext_state={},
    )


@pytest.mark.parametrize(("encoded", "address"), [("192-0-2-1", "192.0.2.1"), ("2001:db8::1", "2001:db8::1")])
def test_python_control_addbypass_and_removebypass_parse_ip_addresses(encoded: str, address: str) -> None:
    pfb_unbound.pfb.update(
        noAAAADB=False,
        safeSearchDB=False,
        python_control=True,
        mod_threading=False,
        gpListDB=False,
    )
    pfb_unbound.gpListDB = {}

    add = _control_qstate(f"python_control.addbypass.{encoded}")
    assert pfb_unbound.operate(0, 0, add, None)
    assert pfb_unbound.gpListDB == {address: 0}

    remove = _control_qstate(f"python_control.removebypass.{encoded}")
    assert pfb_unbound.operate(0, 0, remove, None)
    assert pfb_unbound.gpListDB == {}
