"""Shared DNS response builder for the stub upstream (issue #267).

Single source of truth for the wire shapes the smoke ``_StubDnsServer`` emits. Imported
by BOTH ``tests/smoke/conftest.py`` (the live stub server) and ``test_stub_shapes.py``
(the off-box shape pins), so neither duplicates the RA/AA/EDE flag logic and the default
unit suite never reaches into the smoke server.

Uses dnspython (a smoke-only dependency), so every consumer lives under ``tests/smoke/``
— which the default ``python -m pytest`` run ignores (``--ignore=tests/smoke``).
"""

from __future__ import annotations

from typing import cast

STUB_DNS_A = "203.0.113.99"  # RFC 5737 documentation range
STUB_DNS_AAAA = "2001:db8::99"  # RFC 3849 documentation range


def nxdomain_record(
    *,
    authoritative: bool = False,
    recursion_available: bool = False,
    ede_info_code: int | None = None,
    ede_text: str = "",
) -> dict[str, object]:
    """Build the record dict for an NXDOMAIN answer (the issue #267 upstream shapes).

    Default (a Quad9-style BLOCK): RA=0, AA=0. ``authoritative`` raises AA (an
    authoritative NXDOMAIN, RA=0/AA=1); ``recursion_available`` raises RA (a forwarder
    relaying a natural NXDOMAIN, RA=1/AA=0). Optional ``ede_info_code``/``ede_text``
    attach an RFC 8914 EDE option (EXTRA-TEXT = provider name).
    """
    rec: dict[str, object] = {"nxdomain": True, "aa": authoritative, "ra": recursion_available}
    if ede_info_code is not None:
        rec["ede_info_code"] = ede_info_code
        rec["ede_text"] = ede_text
    return rec


def addrs_for(
    rec: dict[str, object] | None,
    want_v6: bool,
    *,
    sentinel_a: str = STUB_DNS_A,
    sentinel_aaaa: str = STUB_DNS_AAAA,
) -> list[str] | None:
    """The address list for a record/family: sentinel when unregistered, the record's
    own list when set, ``None`` (NODATA) when registered without that family.
    """
    if rec is None:
        return [sentinel_aaaa if want_v6 else sentinel_a]
    return rec.get("aaaa" if want_v6 else "a")  # type: ignore[return-value]


def build_response(
    records: dict[str, dict[str, object]],
    data: bytes,
    *,
    sentinel_a: str = STUB_DNS_A,
    sentinel_aaaa: str = STUB_DNS_AAAA,
) -> tuple[bytes | None, dict[str, str] | None]:
    """Build the wire response for a query against ``records`` (a name -> record map).

    Returns ``(wire, query_log)`` where ``query_log`` is ``{"name", "type"}`` for the
    caller to record (or ``None`` for an unparseable/question-less query). A normal
    answer comes from a RECURSIVE upstream (RA=1); only an NXDOMAIN record's AA/RA flags
    follow the registered block shape — that asymmetry is what makes upstream RA=0 a
    meaningful block signal.
    """
    import dns.edns
    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rdatatype
    import dns.rrset

    try:
        req = dns.message.from_wire(data)
    except Exception:  # noqa: BLE001
        return None, None
    resp = dns.message.make_response(req)
    if not req.question:
        return resp.to_wire(), None
    q = req.question[0]
    name = q.name.to_text().lower()
    qlog = {"name": name, "type": dns.rdatatype.to_text(q.rdtype)}
    rec = records.get(name)
    target_rec = records.get(str(rec["cname"])) if (rec is not None and "cname" in rec) else None

    if rec is not None and rec.get("nxdomain"):
        resp.set_rcode(dns.rcode.NXDOMAIN)
        # make_response starts with RA=0/AA=0 (the Quad9 block shape). Raise AA/RA only
        # for the control shapes (authoritative / forwarded-natural NXDOMAIN).
        if rec.get("aa"):
            resp.flags |= dns.flags.AA
        if rec.get("ra"):
            resp.flags |= dns.flags.RA
        ede_info_code = cast(int | None, rec.get("ede_info_code"))
        if ede_info_code is not None:
            # Attach an RFC 8914 EDE option so Unbound passes it upstream-side.
            ede_text = str(rec.get("ede_text", "")) or None
            ede_opt = dns.edns.EDEOption(cast("dns.edns.EDECode", int(ede_info_code)), text=ede_text)
            resp.use_edns(edns=0, options=[ede_opt])
        return resp.to_wire(), qlog

    # Non-NXDOMAIN (normal) answers come from a RECURSIVE upstream (Quad9-style), RA=1.
    resp.flags |= dns.flags.RA
    if q.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
        return resp.to_wire(), qlog  # other qtypes: empty NOERROR
    want_v6 = q.rdtype == dns.rdatatype.AAAA
    rtype = "AAAA" if want_v6 else "A"
    if rec is not None and "cname" in rec:
        target = str(rec["cname"])
        resp.answer.append(dns.rrset.from_text(q.name, 60, "IN", "CNAME", target))
        ips = addrs_for(target_rec, want_v6, sentinel_a=sentinel_a, sentinel_aaaa=sentinel_aaaa)
        if ips:
            resp.answer.append(dns.rrset.from_text(target, 60, "IN", rtype, *ips))
        return resp.to_wire(), qlog
    ips = addrs_for(rec, want_v6, sentinel_a=sentinel_a, sentinel_aaaa=sentinel_aaaa)
    if ips:
        resp.answer.append(dns.rrset.from_text(q.name, 60, "IN", rtype, *ips))
    return resp.to_wire(), qlog
