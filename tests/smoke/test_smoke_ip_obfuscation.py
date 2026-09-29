"""Live-VM smoke: obfuscated IP spellings in a DNSBL feed land in the DNSBL IP tables.

A client dials ``||0xC0000204^``, ``0xc6.0x33.0x64.0x9`` and ``203.0.28942`` as the IPv4
address it decodes under WHATWG URL rules (192.0.2.4, 198.51.100.9, 203.0.113.14). With
DNSBL IP enabled, pfBlockerNG collects each one into ``pfB_DNSBLIP_v4``:
``pfb_dnsbl_abp_extract_ip()`` decodes ``||`` anchors, and ``pfb_ipv4_numeric_host()`` decodes
plain lines. None of them is staged for Python. Previously the two anchors were staged as ABP rows that ``parse_abp()``
silently dropped, and the two plain spellings became domain rules that matched no real traffic.

The addresses come from the RFC 5737/3849 documentation ranges. ``sanitize_ipaddr()`` drops
those ranges only when IP Suppression is on (issue #760); ``deploy()`` pins Suppression off.

DESELECTED from the default ``python -m pytest``; select with ``-k ip_obfuscation``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

HEADER = "smokeipobf"
# Feed line -> the IPv4 a client dials. Distinct, non-adjacent addresses so each is asserted on its own.
V4_LINES = {
    "||0xC0000204^": "192.0.2.4",  # ABP anchor, hex DWORD
    "0xc6.0x33.0x64.0x9": "198.51.100.9",  # plain line, dotted hex
    "203.0.28942": "203.0.113.14",  # plain line, short form (last part fills the low 16 bits)
    "::ffff:c633:6405": "198.51.100.5",  # plain line, IPv4-mapped IPv6 (used to land in the v6 table)
    "198.51.100.77": "198.51.100.77",  # canonical control: collected before this change too
}
# Numeric but invalid (08 is not octal): parse-error log on the branch, never a rule.
INVALID_LINE = "||08.08.08.08^"
# The obfuscated hosts, as they would appear in the Python staging file (compared lower-cased).
NUMERIC_HOSTS = ("0xc0000204", "0xc6.0x33.0x64.0x9", "203.0.28942", "08.08.08.08")
# Plain spellings that used to become domain rules. They are fixed literals, not unique_domain(),
# because the whole point is that they are IPv4 spellings; they are neither RFC 6761 names nor
# HSTS-preload names, and each is flushed from the Unbound cache before its probe.
NUMERIC_PLAIN = ("0xc6.0x33.0x64.0x9", "203.0.28942")


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once, with the DNSBL VIP and System DNS pointed at the stub."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        # MODULE ISOLATION: dnsbl_ip_action is merged into the DNSBL settings and reset() keeps it.
        try:
            h.clear_dnsbl_settings(smoke_vm)
        except Exception as cleanup_exc:  # noqa: BLE001
            print(f"[smoke] clear_dnsbl_settings failed on ip-obfuscation teardown (suppressed): {cleanup_exc!r}")
        h.collect_host_diagnostics(smoke_vm)


@pytest.mark.timeout(300)  # same inject + DNSBL-IP Force Reload shape as test_smoke_adr62 row 4
def test_ip_obfuscation_spellings_collect_into_dnsblip_tables(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Scenario: every IP spelling a client decodes is firewalled, and none becomes a domain rule.

    Given a DNSBL feed, loaded with DNSBL IP = Deny_Both, that holds a hex-DWORD anchor,
      a dotted-hex line, a short-form line, an IPv4-mapped IPv6 line, an invalid numeric
      anchor, one canonical IPv4 and a control domain,
    When a Force Reload loads it,
    Then the control domain is VIP-blocked (the feed loaded),
      pfB_DNSBLIP_v4 holds every decoded address and pfB_DNSBLIP_v6 holds none of them,
      the Python staging file carries none of the obfuscated hosts,
      and the plain numeric spellings resolve upstream instead of hitting a domain rule.
    """
    vm = deployed_vm
    control = h.unique_domain("ipobf")
    body = h.abp_feed(*V4_LINES, INVALID_LINE, control)
    feed_url = h.write_local_feed(vm, "smoke_ip_obfuscation.txt", body)
    spec = h.DnsblCase(
        aliasname=HEADER, feed_url=feed_url, header=HEADER, mode=h.DnsblMode.VIP, dnsbl_ip_action="Deny_Both"
    )
    with h.CaseContext(vm, spec):
        # The first answer after the reload is authoritative.
        ans = h.dns_probe_client(client_vm, control, "A")
        assert h.is_vip(ans), f"control {control} expected VIP block (feed loaded), got {ans}"

        h.apply_filter_sync(vm)
        v6 = h.pfctl_table_members(vm, "pfB_DNSBLIP_v6")
        v4 = h.pfctl_table_members(vm, "pfB_DNSBLIP_v4")
        missing = {line: ip for line, ip in V4_LINES.items() if not h.member_present(v4, ip)}
        assert not missing, f"pfB_DNSBLIP_v4 lacks {missing} (feed line -> expected IP); actual members: {v4}"
        # A decimal misread of the invalid 08.08.08.08 would add 8.8.8.8; nothing else here decodes to it.
        assert not h.member_present(v4, "8.8.8.8"), f"{INVALID_LINE} must not be collected; pfB_DNSBLIP_v4: {v4}"
        assert not h.member_present(v6, "8.8.8.8"), f"{INVALID_LINE} must not be collected; pfB_DNSBLIP_v6: {v6}"
        # The IPv4-mapped line is an IPv4 packet on the wire: it must not stay in the v6 table.
        bad = [m for m in v6 if "c633:6405" in m.lower() or "198.51.100.5" in m]
        assert not bad, f"mapped line must not stay in pfB_DNSBLIP_v6: {bad}; members {v6}"

        staged_path = f"{h.PFB_DBDIR}/dnsbl/{HEADER}.txt"
        staged = vm.ssh("cat", staged_path)
        assert staged.returncode == 0 and control in staged.stdout, (
            f"{staged_path} is not this pass's staging file (expected a {control} row): "
            f"rc={staged.returncode} content={staged.stdout[:2000]!r} stderr={staged.stderr!r}"
        )
        leaked = [host for host in NUMERIC_HOSTS if host in staged.stdout.lower()]
        assert not leaked, (
            f"IP spellings staged for Python, expected none: {leaked}; {staged_path}:\n{staged.stdout[:2000]}"
        )

        h.unblock_egress()  # a name with no domain rule must reach the controlled stub
        for name in NUMERIC_PLAIN:
            h.flush_unbound_name(vm, name)
            ans = h.dns_probe_client(client_vm, name, "A")
            assert h.resolves_to(ans, STUB_DNS_A), (
                f"{name} is an IPv4 spelling, not a domain: expected the stub answer {STUB_DNS_A}, got {ans}"
            )
