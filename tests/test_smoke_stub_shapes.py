"""Off-box tests pinning the stub DNS server's wire flag shapes for issue #267.

These exercise the REAL ``_StubDnsServer._build_response`` (imported from the smoke
conftest) so a regression in the stub's RA/AA/EDE handling is caught here, off-box,
without a VM — not a re-implementation that could silently drift from it. Each shape's
full 16-bit flags field is pinned by exact equality to the live-VM-validated value
(run #159): unrelated bits cannot change without failing.

  * block (Quad9 NXDOMAIN):        flags 0x8103  rcode=3, RA=0, AA=0  -> DETECT
  * block + EDE 15/17:             flags 0x8103  + EDE option         -> DETECT
  * authoritative NXDOMAIN (AA=1): flags 0x8503  rcode=3, RA=0, AA=1  -> EXCLUDE
  * forwarder-natural NXDOMAIN:    flags 0x8183  rcode=3, RA=1, AA=0  -> EXCLUDE
  * normal answer:                 flags 0x8180  rcode=0, RA=1, AA=0  -> EXCLUDE
"""

from __future__ import annotations

from collections.abc import Iterator

import dns.edns
import dns.message
import dns.rdatatype
import pytest

from tests.smoke.conftest import _StubDnsServer


@pytest.fixture
def stub() -> Iterator[_StubDnsServer]:
    """A real stub server (ephemeral port) whose ``_build_response`` we drive directly."""
    srv = _StubDnsServer(port=0)
    try:
        yield srv
    finally:
        srv.stop()


def _response(stub: _StubDnsServer, name: str, rtype: str = "A") -> dns.message.Message:
    """Drive the REAL ``_StubDnsServer._build_response`` and parse its wire answer."""
    query = dns.message.make_query(name, getattr(dns.rdatatype, rtype), use_edns=0)
    wire = stub._build_response(query.to_wire(), "127.0.0.1")
    assert wire is not None, f"stub returned no response for {name}"
    return dns.message.from_wire(wire)


def _ede_options(resp: dns.message.Message) -> list[dns.edns.EDEOption]:
    return [o for o in resp.options if isinstance(o, dns.edns.EDEOption)]


class TestStubBlockShape:
    """Block NXDOMAIN (RA=0, AA=0): wire flags exactly 0x8103, no EDE."""

    def test_block_nxdomain_wire_flags(self, stub: _StubDnsServer) -> None:
        stub.register_nxdomain("block-267.example.")
        resp = _response(stub, "block-267.example.")
        # QR + RD + rcode=3, RA=0, AA=0 -> exactly 0x8103.
        assert resp.flags == 0x8103

    def test_block_nxdomain_has_no_ede(self, stub: _StubDnsServer) -> None:
        stub.register_nxdomain("block-267.example.")
        resp = _response(stub, "block-267.example.")
        assert not _ede_options(resp)


class TestStubBlockEDEShape:
    """Block NXDOMAIN + EDE: same 0x8103 flags, EDE option carries info-code + provider."""

    def test_block_ede15_flags_and_option(self, stub: _StubDnsServer) -> None:
        stub.register_nxdomain("ede15-267.example.", ede_info_code=15, ede_text="Quad9")
        resp = _response(stub, "ede15-267.example.")
        assert resp.flags == 0x8103  # EDE rides in EDNS; header flags unchanged.
        ede = _ede_options(resp)
        assert ede, "EDE option not present in block+EDE response"
        assert ede[0].code == 15
        assert ede[0].text == "Quad9"

    def test_block_ede17_info_code(self, stub: _StubDnsServer) -> None:
        stub.register_nxdomain("ede17-267.example.", ede_info_code=17, ede_text="Quad9")
        resp = _response(stub, "ede17-267.example.")
        assert resp.flags == 0x8103
        ede = _ede_options(resp)
        assert ede and ede[0].code == 17
        assert ede[0].text == "Quad9"


class TestStubAuthoritativeShape:
    """Authoritative NXDOMAIN (AA=1, RA=0): wire flags exactly 0x8503 — AA distinguishes it."""

    def test_authoritative_wire_flags(self, stub: _StubDnsServer) -> None:
        stub.register_nxdomain("auth-267.example.", authoritative=True)
        resp = _response(stub, "auth-267.example.")
        # QR + AA + RD + rcode=3 -> exactly 0x8503 (AA set, RA clear).
        assert resp.flags == 0x8503


class TestStubForwarderNaturalShape:
    """Forwarder-natural NXDOMAIN (RA=1, AA=0): wire flags exactly 0x8183 — RA distinguishes it."""

    def test_fwdnat_wire_flags(self, stub: _StubDnsServer) -> None:
        stub.register_nxdomain("fwdnat-267.example.", recursion_available=True)
        resp = _response(stub, "fwdnat-267.example.")
        # QR + RA + RD + rcode=3 -> exactly 0x8183 (RA set, AA clear).
        assert resp.flags == 0x8183


class TestStubNormalAnswerShape:
    """Normal answer (unregistered name): NOERROR, RA=1, AA=0 — wire flags exactly 0x8180."""

    def test_normal_answer_wire_flags(self, stub: _StubDnsServer) -> None:
        # Unregistered name -> stub sentinel NOERROR answer.
        resp = _response(stub, "normal-267.example.")
        # QR + RD + RA + rcode=0 -> exactly 0x8180.
        assert resp.flags == 0x8180
