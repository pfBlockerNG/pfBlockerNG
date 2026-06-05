"""Self-tests pinning the Phase-4 per-case loop primitives.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run only by the smoke workflow:

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Each test pins one helper against the REAL VM so a regression in the helper (or
a broken inject/reload) goes RED. The FALSE-GREEN GUARD
(:func:`test_false_green_guard`) asserts the WRONG block shape and REQUIRES it
to fail — proving the probe distinguishes a true block from a true pass.

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps; without them they skip cleanly (the fixture skips on missing
prerequisites). They are NOT the matrix (Phase 5) — just enough to pin the
primitives.
"""

from __future__ import annotations

import os

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer, expected_control_answer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> SmokeVM:
    """Deploy the branch .pkg once for the helper self-tests; configure the DNS upstream
    (``wire_dns_upstream`` -> the mock via the 10.0.2.2 host alias; path chosen by env)."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.wire_dns_upstream(smoke_vm)
    return smoke_vm


# --------------------------------------------------------------------------- #
# 1) Deploy self-test
# --------------------------------------------------------------------------- #


def test_deploy_registers_package(deployed_vm: SmokeVM) -> None:
    """After deploy, the PHP CLI exists and ``update`` exits 0."""
    ls = deployed_vm.ssh("test", "-f", h.PFB_CLI, timeout=20)
    assert ls.returncode == 0, f"{h.PFB_CLI} missing after deploy"
    result = deployed_vm.ssh(h.PHP_BIN, h.PFB_CLI, "update", timeout=600)
    assert result.returncode == 0, f"pfblockerng.php update failed: {result.stderr!r}"


# --------------------------------------------------------------------------- #
# 2) Config-injection self-test (read-back + control resolve)
# --------------------------------------------------------------------------- #


def test_inject_value_roundtrips(deployed_vm: SmokeVM) -> None:
    """A value set via the config API reads back via the config API."""
    snippet = (
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, "
        f"array_merge(config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array()), "
        f"array('pfb_dnsbl' => 'on')));\n"
        "write_config('smoke selftest');\necho 'OK';"
    )
    res = h.php_eval(deployed_vm, snippet)
    assert "OK" in res.stdout, f"inject write failed: {res.stderr!r}"
    back = h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/pfb_dnsbl")
    assert back.strip() == "on", f"read-back mismatch: {back!r}"


def test_inject_control_record_resolves(deployed_vm: SmokeVM) -> None:
    """A control local-data injected in CONFIG resolves after a reload."""
    name = h.unique_domain("selftest-control")
    ip = "192.0.2.250"
    h.set_control_records(deployed_vm, {name: {"A": ip}}, {})
    # The reload regenerates unbound.conf; the config-baked record must survive.
    h.reload(deployed_vm, "update")
    answer = h.dns_probe(deployed_vm, name, "A")
    assert h.resolves_to(answer, ip), f"{name} -> {answer.records}, expected {ip}"


# --------------------------------------------------------------------------- #
# 3) Reload / reset self-test
# --------------------------------------------------------------------------- #


def test_reset_returns_to_baseline(deployed_vm: SmokeVM) -> None:
    """reset() runs clear* + a forced update and leaves Unbound ready."""
    h.reset(deployed_vm)
    # The baked control name still resolves (reset didn't break the resolver).
    name, expected_ip = expected_control_answer()
    if not name:
        pytest.skip("no baked control name (SMOKE_CONTROL_NAME unset)")
    answer = h.dns_probe(deployed_vm, name, "A")
    assert answer.records, f"baked control {name!r} gone after reset"
    if expected_ip is not None:
        assert h.resolves_to(answer, expected_ip)


# --------------------------------------------------------------------------- #
# 4) DNS probe + assert helpers (pure, no VM) + false-green guard
# --------------------------------------------------------------------------- #


def test_dns_assert_helpers_pure() -> None:
    """The shape-assert helpers classify each block shape correctly."""
    assert h.is_nxdomain(h.DnsAnswer("NXDOMAIN", []))
    assert not h.is_nxdomain(h.DnsAnswer("NOERROR", ["0.0.0.0"]))
    assert h.is_null_ip(h.DnsAnswer("NOERROR", ["0.0.0.0"]))
    assert not h.is_null_ip(h.DnsAnswer("NOERROR", ["192.0.2.1"]))
    assert h.is_vip(h.DnsAnswer("NOERROR", [h.DEFAULT_DNSBL_VIP4]))
    assert h.resolves_to(h.DnsAnswer("NOERROR", ["192.0.2.1"]), "192.0.2.1")


def test_false_green_guard() -> None:
    """A WRONG-shape assertion MUST fail — proves no silent false-green.

    An NXDOMAIN block asserted as a null-IP pass must be REJECTED. This test
    passes precisely because the wrong assertion is false; flipping the helper
    to be lenient would make this test go red.
    """
    nxdomain_block = h.DnsAnswer("NXDOMAIN", [])
    # The block is real; asserting it "resolves to" a pass IP must be false.
    assert not h.resolves_to(nxdomain_block, "192.0.2.1")
    assert not h.is_null_ip(nxdomain_block)
    assert not h.is_vip(nxdomain_block)
    # And a real pass must NOT read as a block.
    real_pass = h.DnsAnswer("NOERROR", ["192.0.2.1"])
    assert not h.is_nxdomain(real_pass)


def test_dns_probe_absent_resolves_via_stub(deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
    """An otherwise-unknown name resolves to the STUB SENTINEL and is recorded upstream.

    With the stub as Unbound's sole upstream, a name with no local-data / block is
    forwarded and answered by a server WE control — it returns the sentinel (never a
    leaked real-internet A) and logs the query. This pins the upstream wiring: the
    probe reads real resolver state, and "forwarded vs answered locally" is observable.
    """
    name = h.unique_domain("definitely-absent")
    stub_dns.reset_queries()
    answer = h.dns_probe(deployed_vm, name, "A")
    assert h.resolves_to(answer, STUB_DNS_A), f"absent name should resolve to the stub sentinel, got {answer}"
    assert stub_dns.received(name), f"{name} should have been forwarded to the stub upstream"


# --------------------------------------------------------------------------- #
# 5) IP probe self-test (fed vs non-fed; rule reference)
# --------------------------------------------------------------------------- #


def test_ip_probe_membership_and_rule(deployed_vm: SmokeVM, mock_feeds: object) -> None:
    """A fed IP is a table member, a non-fed IP isn't, and a rule references it."""
    fed_ip = "198.51.100.7"
    non_fed = "198.51.100.200"
    feed_url = h.write_local_feed(deployed_vm, "smoke_ip_selftest.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="smokeipself", feed_url=feed_url, header="smokeipself")
    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, fed_ip), f"{fed_ip} not in {spec.alias}: {members}"
        assert not h.member_present(members, non_fed), f"{non_fed} unexpectedly in {spec.alias}"
        assert h.rule_references(deployed_vm, spec.alias), f"no rule references {spec.alias}"


# --------------------------------------------------------------------------- #
# 6) ABP harness extensions (ADR-07) — PURE, no VM
#    Pin the feed-body builder + the config-injection snippet so a regression in
#    the ABP wiring (wrong settings key, a dropped extra row) goes RED without a
#    booted VM, exactly like the pure DNS-assert guards above.
# --------------------------------------------------------------------------- #


def test_abp_feed_body_has_header_and_lines() -> None:
    """``abp_feed`` prepends the sniffed ABP header so pfBlockerNG tags it ABP."""
    body = h.abp_feed("||evil.example^", "@@||good.example^")
    # The FIRST line must be the marker pfBlockerNG header-sniffs (inc:7934); a
    # body that does not start with it is parsed as a plain feed, not ABP.
    assert body.splitlines()[0] == h.ABP_HEADER
    assert "||evil.example^" in body
    assert "@@||good.example^" in body


def test_abp_inject_snippet_emits_user_regex_and_cap() -> None:
    """A DnsblCase carrying user_regex + regex_cap renders the matching config keys.

    pfb_regex_list is a base64 TEXTAREA field (CRLF-joined) — a PLAIN value would be
    base64_decoded into garbage that crashes the python INI load — so the snippet must
    carry the base64 of the CRLF-joined patterns, NOT the raw regex text.
    """
    patterns = [r"ad[0-9]+\.example\.net", r"(a+)+\.evil\.example"]
    spec = h.DnsblCase(
        aliasname="smokeabp",
        feed_url="/var/db/pfblockerng/smokeabp.txt",
        header="smokeabp",
        user_regex=patterns,
        regex_cap=True,
    )
    snippet = h._dnsbl_inject_snippet(spec)
    assert "'pfb_regex' => 'on'" in snippet
    assert "'pfb_regex_cap' => 'on'" in snippet
    expected_b64 = h._b64_textarea(patterns)
    assert f"'pfb_regex_list' => '{expected_b64}'" in snippet
    # Raw regex text must NOT appear (it is base64-encoded, not plain).
    assert "ad[0-9]+" not in snippet


def test_abp_inject_snippet_emits_extra_rows() -> None:
    """extra_rows append additional headers/urls to the SAME DNSBL group's row[].

    Two ABP-bodied rows == two ABP feeds whose rules the Python build merges — the
    cross-feed ``@@``/``$badfilter`` vehicle. Both headers + urls must appear, and
    the group's logging/aliasname stay single (one group, many rows).
    """
    spec = h.DnsblCase(
        aliasname="smokexfeed",
        feed_url="/var/db/pfblockerng/feedA.txt",
        header="feedA",
        extra_rows=[("feedB", "/var/db/pfblockerng/feedB.txt")],
    )
    snippet = h._dnsbl_inject_snippet(spec)
    assert "'header' => 'feedA'" in snippet
    assert "'header' => 'feedB'" in snippet
    assert "/var/db/pfblockerng/feedA.txt" in snippet
    assert "/var/db/pfblockerng/feedB.txt" in snippet


def test_abp_inject_snippet_default_is_unchanged() -> None:
    """A plain DnsblCase (no ABP fields) emits NO regex keys and exactly one row —
    proving the ADR-07 fields are additive and the ADR-04 matrix is byte-stable."""
    spec = h.DnsblCase(aliasname="plain", feed_url="/var/db/pfblockerng/plain.txt", header="plain")
    snippet = h._dnsbl_inject_snippet(spec)
    assert "pfb_regex" not in snippet
    assert "regex_cap" not in snippet
    assert "custom" not in snippet
    assert snippet.count("'header' =>") == 1


def test_abp_inject_snippet_emits_cname_validation() -> None:
    """cname_validation -> the pfb_cname setting (ini python_cname)."""
    spec = h.DnsblCase(
        aliasname="smokecname",
        feed_url="/var/db/pfblockerng/smokecname.txt",
        header="smokecname",
        cname_validation=True,
    )
    snippet = h._dnsbl_inject_snippet(spec)
    assert "'pfb_cname' => 'on'" in snippet


def test_abp_inject_snippet_emits_custom_list() -> None:
    """custom_domains -> a base64 'custom' field (the sovereign Custom_List vehicle)."""
    spec = h.DnsblCase(
        aliasname="smokecust",
        feed_url="/var/db/pfblockerng/smokecust.txt",
        header="smokecust",
        custom_domains=["evil.example.com", "ads.example.net"],
    )
    snippet = h._dnsbl_inject_snippet(spec)
    assert "$list['custom'] = base64_encode(" in snippet
    # The domains ride along CRLF-joined inside the base64-encoded literal.
    assert "evil.example.com" in snippet


# --------------------------------------------------------------------------- #
# 7) Stub CNAME chain (issue #41) — PURE, no VM
#    Pin the stub's CNAME-chain answer so a regression goes RED without a booted
#    VM: a registered name must answer with a 2-rrset chain (CNAME + the target's
#    sentinel) so a forwarding Unbound surfaces an_numrrsets > 1; an UNregistered
#    name still gets the plain single-rrset sentinel.
# --------------------------------------------------------------------------- #


def _stub_answer(server: _StubDnsServer, name: str, rtype: str) -> object:
    """Build a wire query for (name, rtype), feed it to the stub, parse the reply."""
    import dns.message
    import dns.rdatatype

    query = dns.message.make_query(name, dns.rdatatype.from_text(rtype))
    wire = server._build_response(query.to_wire())
    assert wire is not None
    return dns.message.from_wire(wire)


def test_stub_cname_chain_is_two_rrsets_and_consistent() -> None:
    """A CNAME chain answers ``src CNAME tgt`` + the TARGET's own A/AAAA (2 rrsets).

    That 2-rrset answer is what makes a forwarding Unbound expose ``an_numrrsets > 1``
    to pfb_unbound.py's CNAME walk (a raw Unbound ``local-data`` CNAME would yield a
    single rrset — Unbound does not chase it). And it must be CONSISTENT: the A query
    chains to the target's IPv4, the AAAA query to the target's IPv6 — the target's
    OWN registered addresses, not a generic sentinel.
    """
    import dns.rdatatype

    src, tgt = h.unique_domain("stubsrc"), h.unique_domain("stubtgt")
    server = _StubDnsServer(port=0)
    try:
        server.set_records(tgt, a=("198.51.100.5",), aaaa=("2001:db8::5",))
        server.register_cname(src, tgt)

        reply = _stub_answer(server, src, "A")
        assert [rr.rdtype for rr in reply.answer] == [dns.rdatatype.CNAME, dns.rdatatype.A]  # type: ignore[attr-defined]
        cname_rr, a_rr = reply.answer  # type: ignore[attr-defined]
        assert cname_rr[0].target.to_text().lower() == f"{tgt}."
        assert a_rr.name.to_text().lower() == f"{tgt}."
        assert a_rr[0].address == "198.51.100.5"

        reply6 = _stub_answer(server, src, "AAAA")
        assert [rr.rdtype for rr in reply6.answer] == [dns.rdatatype.CNAME, dns.rdatatype.AAAA]  # type: ignore[attr-defined]
        assert reply6.answer[1][0].address == "2001:db8::5"  # type: ignore[attr-defined]
    finally:
        server.stop()


def test_stub_unregistered_name_is_plain_sentinel() -> None:
    """An UNregistered name (and a cleared registration) gets the single-rrset sentinel."""
    import dns.rdatatype

    src, tgt = h.unique_domain("stubsrc"), h.unique_domain("stubtgt")
    server = _StubDnsServer(port=0)
    try:
        server.register_cname(src, tgt)
        server.clear_cname()
        reply = _stub_answer(server, src, "A")
        assert [rr.rdtype for rr in reply.answer] == [dns.rdatatype.A]  # type: ignore[attr-defined]
        assert reply.answer[0][0].address == STUB_DNS_A  # type: ignore[attr-defined]
    finally:
        server.stop()


def test_stub_records_queries() -> None:
    """The stub records every query it answers — the observability the matrix asserts on.

    ``received(name)`` is the upstream-side signal that a name was FORWARDED (not blocked
    locally); a name the stub never saw returns an empty list. ``reset_queries`` clears it.
    """
    seen, never = h.unique_domain("stubseen"), h.unique_domain("stubnever")
    server = _StubDnsServer(port=0)
    try:
        _stub_answer(server, seen, "A")
        assert server.received(seen), "answered query must be recorded"
        assert server.received(seen, "A")
        assert not server.received(never), "a name the stub never saw must be absent"
        server.reset_queries()
        assert not server.received(seen), "reset_queries clears the log"
    finally:
        server.stop()


def test_stub_register_a_and_nxdomain() -> None:
    """register_a overrides the sentinel; register_nxdomain denies the name."""
    import dns.rcode

    pinned, gone = h.unique_domain("stubpinned"), h.unique_domain("stubgone")
    server = _StubDnsServer(port=0)
    try:
        server.register_a(pinned, "192.0.2.7")
        reply = _stub_answer(server, pinned, "A")
        assert reply.answer[0][0].address == "192.0.2.7"  # type: ignore[attr-defined]
        server.register_nxdomain(gone)
        reply = _stub_answer(server, gone, "A")
        assert reply.rcode() == dns.rcode.NXDOMAIN  # type: ignore[attr-defined]
        assert not reply.answer  # type: ignore[attr-defined]
    finally:
        server.stop()


def test_stub_set_records_families_multi_and_nodata() -> None:
    """set_records gives a name its own A/AAAA: multiple IPs, missing family -> NODATA,
    and wrong-family addresses are rejected."""
    import dns.rcode

    multi, v4only, bad = h.unique_domain("stubmulti"), h.unique_domain("stubv4"), h.unique_domain("stubbad")
    server = _StubDnsServer(port=0)
    try:
        # Multiple A, one AAAA.
        server.set_records(multi, a=("203.0.113.1", "203.0.113.2"), aaaa=("2001:db8::1",))
        a_reply = _stub_answer(server, multi, "A")
        assert {r.address for r in a_reply.answer[0]} == {"203.0.113.1", "203.0.113.2"}  # type: ignore[attr-defined]
        aaaa_reply = _stub_answer(server, multi, "AAAA")
        assert aaaa_reply.answer[0][0].address == "2001:db8::1"  # type: ignore[attr-defined]

        # A only -> AAAA is NODATA (empty NOERROR), not the sentinel.
        server.set_records(v4only, a=("203.0.113.9",))
        no6 = _stub_answer(server, v4only, "AAAA")
        assert no6.rcode() == dns.rcode.NOERROR and not no6.answer  # type: ignore[attr-defined]

        # Family is validated.
        with pytest.raises(ValueError):
            server.set_records(bad, a=("2001:db8::bad",))  # IPv6 in an A
    finally:
        server.stop()


def test_b64_textarea_matches_pfblockerng_decode() -> None:
    """``_b64_textarea`` produces what ``pfbng_text_area_decode`` expects: base64 of a
    CRLF-joined list (so base64_decode + explode("\\r\\n") returns the lines back)."""
    import base64

    lines = [r"trackerx-", r"ad[0-9]+\.example\.net"]
    encoded = h._b64_textarea(lines)
    assert base64.b64decode(encoded).decode().split("\r\n") == lines
    assert h._b64_textarea([]) == "", "empty list -> empty value (no entries)"


def test_mock_dns_upstream_snippet_base64_encodes_forward_zone() -> None:
    """The mock-DNS wiring forwards the ROOT zone to 10.0.2.2@<ephemeral-port>.

    ``unbound/custom_options`` is a base64 field (pfSense ``base64_decode``s it in
    ``unbound_generate_config_text``), so the forward-zone must ride INSIDE
    ``base64_encode(...)`` — never a raw assign that would decode to garbage. forwarding
    and dnssec are dropped so there is no competing root forward-zone and the mock's
    unsigned answers are not marked bogus. The explicit ``@port`` is what frees the mock
    from host :53 (the parallel-safety lever)."""
    snippet = h._mock_dns_upstream_snippet(5399)
    assert f"forward-addr: {h.GUEST_TO_HOST_ALIAS}@5399" in snippet
    assert 'name: "."' in snippet
    # Forward-zone text is base64-encoded by PHP at RUNTIME (not pre-encoded in Python),
    # so it rides as the literal argument to base64_encode — assert the wrapper.
    assert "$u['custom_options'] = base64_encode(" in snippet
    assert "unset($u['forwarding']);" in snippet  # no competing root forward-zone
    assert "unset($u['dnssec']);" in snippet  # unsigned mock answers
    assert "services_unbound_configure();" in snippet


def test_wire_dns_upstream_dispatches_on_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """``wire_dns_upstream`` picks the upstream path by SMOKE_DNS_UPSTREAM — every value asserted.

    Scenario: the dispatcher must DEFAULT to the System-DNS path (so CI, which sets
    nothing, stays on :53 unchanged) and select the parallel-safe mock path only on
    explicit opt-in; an unknown value must fail loudly, not silently pick a wrong upstream.

      Given the two upstream helpers are stubbed to record which one ran
      When  SMOKE_DNS_UPSTREAM is {unset, 'system', 'mock', 'MOCK', 'bogus'}
      Then  the call routes to {system, system, mock, mock, RuntimeError} respectively
    """
    called: list[str] = []
    monkeypatch.setattr(h, "use_system_dns_upstream", lambda vm, *, timeout=120.0: called.append("system"))
    monkeypatch.setattr(h, "use_mock_dns_upstream", lambda vm, *, timeout=120.0: called.append("mock"))
    vm = object()  # the stubs ignore it

    # Given no env (CI) — Then default to the System-DNS path (preserves :53).
    monkeypatch.delenv("SMOKE_DNS_UPSTREAM", raising=False)
    h.wire_dns_upstream(vm)  # type: ignore[arg-type]
    assert called == ["system"]

    # Given explicit 'system' — Then system.
    called.clear()
    monkeypatch.setenv("SMOKE_DNS_UPSTREAM", "system")
    h.wire_dns_upstream(vm)  # type: ignore[arg-type]
    assert called == ["system"]

    # Given 'mock' (case-insensitively) — Then the ephemeral-port path.
    for value in ("mock", "MOCK"):
        called.clear()
        monkeypatch.setenv("SMOKE_DNS_UPSTREAM", value)
        h.wire_dns_upstream(vm)  # type: ignore[arg-type]
        assert called == ["mock"], value

    # Given an unknown value — Then RAISE (no silent fallback to a wrong upstream).
    monkeypatch.setenv("SMOKE_DNS_UPSTREAM", "bogus")
    with pytest.raises(RuntimeError, match="SMOKE_DNS_UPSTREAM"):
        h.wire_dns_upstream(vm)  # type: ignore[arg-type]
