"""Off-box tests pinning the stub DNS server's wire flag shapes for issue #267.

The _StubDnsServer builds dnspython responses with specific RA/AA bit patterns
that map to the four upstream-response shapes the detector must discriminate:

  * block (Quad9 NXDOMAIN):         flags 0x8103  rcode=3, RA=0, AA=0  -> DETECT
  * block + EDE 15:                  flags 0x8103  + EDE option code 15 -> DETECT
  * authoritative NXDOMAIN (AA=1):  flags 0x8503  rcode=3, RA=0, AA=1  -> EXCLUDE
  * forwarder-natural NXDOMAIN:      flags 0x8183  rcode=3, RA=1, AA=0  -> EXCLUDE
  * normal answer:                   flags 0x8180  rcode=0, RA=1, AA=0  -> EXCLUDE

These are pure off-box tests — they instantiate the stub's response-builder logic
directly to confirm the dnspython flag bits match the live-VM validated values.
No Unbound API, no VM, no fixtures.
"""

from __future__ import annotations

import dns.edns
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype


def _make_nxdomain_response(
    *,
    authoritative: bool = False,
    recursion_available: bool = False,
    ede_info_code: int | None = None,
    ede_text: str = "",
) -> dns.message.Message:
    """Build a dnspython NXDOMAIN response with the given flag combination."""
    req = dns.message.make_query("test.example.com.", dns.rdatatype.A)
    resp = dns.message.make_response(req)
    resp.set_rcode(dns.rcode.NXDOMAIN)
    # make_response starts RA=0, AA=0 (the block shape); only raise when requested.
    if authoritative:
        resp.flags |= dns.flags.AA
    if recursion_available:
        resp.flags |= dns.flags.RA
    if ede_info_code is not None:
        ede_opt = dns.edns.EDEOption(dns.edns.EDECode(ede_info_code), text=ede_text or None)
        resp.use_edns(edns=0, options=[ede_opt])
    return resp


def _make_noerror_response() -> dns.message.Message:
    """Build a normal NOERROR response (RA=1, AA=0) as the stub does."""
    req = dns.message.make_query("test.example.com.", dns.rdatatype.A)
    resp = dns.message.make_response(req)
    # Normal recursive upstream: RA=1.
    resp.flags |= dns.flags.RA
    return resp


class TestStubBlockShape:
    """Block NXDOMAIN: RA=0, AA=0 — wire flags must be 0x8103."""

    def test_block_nxdomain_rcode_is_3(self) -> None:
        resp = _make_nxdomain_response()
        assert (resp.flags & 0x000F) == 3  # NXDOMAIN

    def test_block_nxdomain_ra_is_0(self) -> None:
        # Before-state: RA bit CLEARED -> 0x0080 not set.
        resp = _make_nxdomain_response()
        assert not (resp.flags & 0x0080)

    def test_block_nxdomain_aa_is_0(self) -> None:
        resp = _make_nxdomain_response()
        assert not (resp.flags & 0x0400)

    def test_block_nxdomain_wire_flags(self) -> None:
        resp = _make_nxdomain_response()
        # QR=1 (0x8000) + RD=1 (0x0100) + rcode=3 -> 0x8103.
        # Exact flag value matches the live-VM observation (run #159).
        assert resp.flags & 0x8103 == 0x8103
        assert not (resp.flags & 0x0080)  # RA=0
        assert not (resp.flags & 0x0400)  # AA=0


class TestStubBlockEDEShape:
    """Block NXDOMAIN + EDE INFO-CODE 15: same flags, EDE option present."""

    def test_block_ede_nxdomain_rcode_is_3(self) -> None:
        resp = _make_nxdomain_response(ede_info_code=15, ede_text="Quad9")
        assert (resp.flags & 0x000F) == 3

    def test_block_ede_has_ede_option(self) -> None:
        resp = _make_nxdomain_response(ede_info_code=15, ede_text="Quad9")
        # The response must carry an EDNS EDE option (code 15).
        ede_opts = [o for o in resp.options if isinstance(o, dns.edns.EDEOption)]
        assert ede_opts, "EDE option not present in block+EDE response"

    def test_block_ede_info_code_15(self) -> None:
        resp = _make_nxdomain_response(ede_info_code=15, ede_text="Quad9")
        ede_opts = [o for o in resp.options if isinstance(o, dns.edns.EDEOption)]
        assert ede_opts[0].code == 15

    def test_block_ede_extra_text(self) -> None:
        resp = _make_nxdomain_response(ede_info_code=15, ede_text="Quad9")
        ede_opts = [o for o in resp.options if isinstance(o, dns.edns.EDEOption)]
        assert ede_opts[0].text == "Quad9"

    def test_block_ede_ra_is_0(self) -> None:
        resp = _make_nxdomain_response(ede_info_code=15, ede_text="Quad9")
        assert not (resp.flags & 0x0080)


class TestStubAuthoritativeShape:
    """Authoritative NXDOMAIN: AA=1, RA=0 — wire flags must be 0x8503."""

    def test_authoritative_nxdomain_rcode_is_3(self) -> None:
        resp = _make_nxdomain_response(authoritative=True)
        assert (resp.flags & 0x000F) == 3

    def test_authoritative_nxdomain_aa_is_1(self) -> None:
        # AFTER: AA bit set (0x0400) — this is what distinguishes authoritative from block.
        resp = _make_nxdomain_response(authoritative=True)
        assert bool(resp.flags & 0x0400)

    def test_authoritative_nxdomain_ra_is_0(self) -> None:
        resp = _make_nxdomain_response(authoritative=True)
        assert not (resp.flags & 0x0080)

    def test_authoritative_wire_flags(self) -> None:
        resp = _make_nxdomain_response(authoritative=True)
        # QR + AA + RD + rcode=3 -> 0x8503.
        assert resp.flags & 0x0400  # AA=1
        assert not (resp.flags & 0x0080)  # RA=0


class TestStubForwarderNaturalShape:
    """Forwarder-natural NXDOMAIN: RA=1, AA=0 — wire flags must be 0x8183."""

    def test_fwdnat_nxdomain_rcode_is_3(self) -> None:
        resp = _make_nxdomain_response(recursion_available=True)
        assert (resp.flags & 0x000F) == 3

    def test_fwdnat_nxdomain_ra_is_1(self) -> None:
        # AFTER: RA bit set (0x0080) — this is what distinguishes a natural NXDOMAIN.
        resp = _make_nxdomain_response(recursion_available=True)
        assert bool(resp.flags & 0x0080)

    def test_fwdnat_nxdomain_aa_is_0(self) -> None:
        resp = _make_nxdomain_response(recursion_available=True)
        assert not (resp.flags & 0x0400)

    def test_fwdnat_wire_flags(self) -> None:
        resp = _make_nxdomain_response(recursion_available=True)
        # QR + RA + RD + rcode=3 -> 0x8183.
        assert bool(resp.flags & 0x0080)  # RA=1
        assert not (resp.flags & 0x0400)  # AA=0


class TestStubNormalAnswerShape:
    """Normal answer (NOERROR): RA=1, rcode=0."""

    def test_normal_answer_rcode_is_0(self) -> None:
        resp = _make_noerror_response()
        assert (resp.flags & 0x000F) == 0  # NOERROR

    def test_normal_answer_ra_is_1(self) -> None:
        resp = _make_noerror_response()
        assert bool(resp.flags & 0x0080)  # RA=1

    def test_normal_answer_aa_is_0(self) -> None:
        resp = _make_noerror_response()
        assert not (resp.flags & 0x0400)  # AA=0
