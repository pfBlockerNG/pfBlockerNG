"""Pin the stub upstream's wire flag shapes for issue #267 — off-box, no VM.

These exercise the SHARED ``stub_responses`` builder (the same code the live
``_StubDnsServer`` runs), so a regression in the stub's RA/AA/EDE handling fails here
rather than only in a VM run. Each shape's full 16-bit flags field is pinned by exact
equality to the live-VM-validated value (run #159) — unrelated bits cannot drift.

  * block (Quad9 NXDOMAIN):        flags 0x8103  rcode=3, RA=0, AA=0  -> DETECT
  * block + EDE 15/17:             flags 0x8103  + EDE option         -> DETECT
  * authoritative NXDOMAIN (AA=1): flags 0x8503  rcode=3, RA=0, AA=1  -> EXCLUDE
  * forwarder-natural NXDOMAIN:    flags 0x8183  rcode=3, RA=1, AA=0  -> EXCLUDE
  * normal answer:                 flags 0x8180  rcode=0, RA=1, AA=0  -> EXCLUDE

Lives under tests/smoke/ (not the default unit suite) because it needs dnspython, a
smoke-only dependency. It needs no VM, so it runs fast in the smoke job; marked
``smoke``/``upstream`` so the #267 dispatch and the smoke fan-out both pick it up.
"""

from __future__ import annotations

import dns.edns
import dns.message
import dns.rdatatype
import pytest

from . import stub_responses

pytestmark = [pytest.mark.smoke, pytest.mark.upstream]


def _response(records: dict[str, dict[str, object]], name: str, rtype: str = "A") -> dns.message.Message:
    """Drive the SHARED ``stub_responses.build_response`` and parse its wire answer."""
    query = dns.message.make_query(name, getattr(dns.rdatatype, rtype), use_edns=0)
    wire, _ = stub_responses.build_response(records, query.to_wire())
    assert wire is not None, f"stub returned no response for {name}"
    return dns.message.from_wire(wire)


def _ede_options(resp: dns.message.Message) -> list[dns.edns.EDEOption]:
    return [o for o in resp.options if isinstance(o, dns.edns.EDEOption)]


class TestStubBlockShape:
    """Block NXDOMAIN (RA=0, AA=0): wire flags exactly 0x8103, no EDE."""

    def test_block_nxdomain_wire_flags(self) -> None:
        records = {"block-267.example.": stub_responses.nxdomain_record()}
        resp = _response(records, "block-267.example.")
        # QR + RD + rcode=3, RA=0, AA=0 -> exactly 0x8103.
        assert resp.flags == 0x8103

    def test_block_nxdomain_has_no_ede(self) -> None:
        records = {"block-267.example.": stub_responses.nxdomain_record()}
        resp = _response(records, "block-267.example.")
        assert not _ede_options(resp)


class TestStubBlockEDEShape:
    """Block NXDOMAIN + EDE: same 0x8103 flags, EDE option carries info-code + provider."""

    def test_block_ede15_flags_and_option(self) -> None:
        records = {"ede15-267.example.": stub_responses.nxdomain_record(ede_info_code=15, ede_text="Quad9")}
        resp = _response(records, "ede15-267.example.")
        assert resp.flags == 0x8103  # EDE rides in EDNS; header flags unchanged.
        ede = _ede_options(resp)
        assert ede, "EDE option not present in block+EDE response"
        assert ede[0].code == 15
        assert ede[0].text == "Quad9"

    def test_block_ede17_info_code(self) -> None:
        records = {"ede17-267.example.": stub_responses.nxdomain_record(ede_info_code=17, ede_text="Quad9")}
        resp = _response(records, "ede17-267.example.")
        assert resp.flags == 0x8103
        ede = _ede_options(resp)
        assert ede and ede[0].code == 17
        assert ede[0].text == "Quad9"


class TestStubAuthoritativeShape:
    """Authoritative NXDOMAIN (AA=1, RA=0): wire flags exactly 0x8503 — AA distinguishes it."""

    def test_authoritative_wire_flags(self) -> None:
        records = {"auth-267.example.": stub_responses.nxdomain_record(authoritative=True)}
        resp = _response(records, "auth-267.example.")
        # QR + AA + RD + rcode=3 -> exactly 0x8503 (AA set, RA clear).
        assert resp.flags == 0x8503


class TestStubForwarderNaturalShape:
    """Forwarder-natural NXDOMAIN (RA=1, AA=0): wire flags exactly 0x8183 — RA distinguishes it."""

    def test_fwdnat_wire_flags(self) -> None:
        records = {"fwdnat-267.example.": stub_responses.nxdomain_record(recursion_available=True)}
        resp = _response(records, "fwdnat-267.example.")
        # QR + RA + RD + rcode=3 -> exactly 0x8183 (RA set, AA clear).
        assert resp.flags == 0x8183


class TestStubNormalAnswerShape:
    """Normal answer (unregistered name): NOERROR, RA=1, AA=0 — wire flags exactly 0x8180."""

    def test_normal_answer_wire_flags(self) -> None:
        # Empty record map -> stub sentinel NOERROR answer.
        resp = _response({}, "normal-267.example.")
        # QR + RD + RA + rcode=0 -> exactly 0x8180.
        assert resp.flags == 0x8180


class TestStubResolvingBranches:
    """The non-block builder branches (pre-existing stub behaviour, now in the shared
    ``build_response``): registered A/AAAA, NODATA, CNAME chain, and non-address qtype.
    All are recursive-upstream NOERROR answers (flags 0x8180); they differ in the answer
    section. Pinned off-box so an extraction regression fails without a booted VM.
    """

    @staticmethod
    def _a_addrs(resp: dns.message.Message) -> list[str]:
        return [item.address for rrset in resp.answer if rrset.rdtype == dns.rdatatype.A for item in rrset]

    def test_registered_a_record(self) -> None:
        resp = _response({"host-267.example.": {"a": ("203.0.113.7",)}}, "host-267.example.", "A")
        assert resp.flags == 0x8180  # NOERROR, RA=1
        assert self._a_addrs(resp) == ["203.0.113.7"]

    def test_registered_aaaa_record(self) -> None:
        resp = _response({"host6-267.example.": {"aaaa": ("2001:db8::7",)}}, "host6-267.example.", "AAAA")
        assert resp.flags == 0x8180
        aaaa = [item.address for rrset in resp.answer if rrset.rdtype == dns.rdatatype.AAAA for item in rrset]
        assert aaaa == ["2001:db8::7"]

    def test_nodata_missing_family(self) -> None:
        # Registered with A only -> an AAAA query is NODATA: NOERROR with NO answer rrset.
        resp = _response({"v4only-267.example.": {"a": ("203.0.113.7",)}}, "v4only-267.example.", "AAAA")
        assert resp.flags == 0x8180
        assert len(resp.answer) == 0

    def test_cname_chain_resolves_to_target(self) -> None:
        records = {
            "alias-267.example.": {"cname": "canon-267.example."},
            "canon-267.example.": {"a": ("203.0.113.8",)},
        }
        resp = _response(records, "alias-267.example.", "A")
        assert resp.flags == 0x8180
        # Two-rrset answer: the CNAME plus the target's A (what pfb_unbound's CNAME walk reads).
        assert any(rrset.rdtype == dns.rdatatype.CNAME for rrset in resp.answer)
        assert self._a_addrs(resp) == ["203.0.113.8"]

    def test_non_address_qtype_is_empty_noerror(self) -> None:
        # A non-A/AAAA qtype (MX) -> empty NOERROR, no answer.
        resp = _response({}, "mx-267.example.", "MX")
        assert resp.flags == 0x8180
        assert len(resp.answer) == 0
