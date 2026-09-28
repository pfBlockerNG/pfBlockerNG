"""Live-VM smoke: a bracketed IPv6 ABP anchor in a DNSBL feed lands in ``pfB_DNSBLIP_v6``.

A client dials ``||[2001:db8::1]^`` as 2001:db8::1. With DNSBL IP enabled,
``pfb_dnsbl_abp_extract_ip()`` unbrackets the ``||`` host and collects it into
``pfB_DNSBLIP_v6``; the line is not staged for Python. Previously the brackets made
``is_ipaddrv6()`` reject it, so the line was staged as an ABP row that ``parse_abp()``
silently dropped and the address was never firewalled.

The address comes from the RFC 3849 documentation range. ``sanitize_ipaddr()`` drops that
range only when IP Suppression is on (issue #760); ``deploy()`` pins Suppression off.

DESELECTED from the default ``python -m pytest``; select with ``-k bracketed_v6``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

HEADER = "smokeabpv6"
V6_LINE, V6_IP = "||[2001:db8::1]^", "2001:db8::1"


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
            print(f"[smoke] clear_dnsbl_settings failed on bracketed-v6 teardown (suppressed): {cleanup_exc!r}")
        h.collect_host_diagnostics(smoke_vm)


@pytest.mark.timeout(300)  # same inject + DNSBL-IP Force Reload shape as test_smoke_adr62 row 4
def test_abp_bracketed_v6_anchor_collects_into_dnsblip_v6(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Scenario: a bracketed IPv6 anchor is firewalled and not staged for Python.

    Given a DNSBL feed, loaded with DNSBL IP = Deny_Both, that holds ``||[2001:db8::1]^``
      and a control domain,
    When a Force Reload loads it,
    Then the control domain is VIP-blocked (the feed loaded),
      pfB_DNSBLIP_v6 holds 2001:db8::1,
      and the Python staging file carries the control but not 2001:db8::1.
    """
    vm = deployed_vm
    control = h.unique_domain("abpv6")
    body = h.abp_feed(V6_LINE, control)
    feed_url = h.write_local_feed(vm, "smoke_abp_bracketed_v6.txt", body)
    spec = h.DnsblCase(
        aliasname=HEADER, feed_url=feed_url, header=HEADER, mode=h.DnsblMode.VIP, dnsbl_ip_action="Deny_Both"
    )
    with h.CaseContext(vm, spec):
        # The first answer after the reload is authoritative.
        ans = h.dns_probe_client(client_vm, control, "A")
        assert h.is_vip(ans), f"control {control} expected VIP block (feed loaded), got {ans}"

        h.apply_filter_sync(vm)
        v6 = h.pfctl_table_members(vm, "pfB_DNSBLIP_v6")
        assert h.member_present(v6, V6_IP), f"{V6_LINE}: expected {V6_IP} in pfB_DNSBLIP_v6, got {v6}"

        staged_path = f"{h.PFB_DBDIR}/dnsbl/{HEADER}.txt"
        staged = vm.ssh("cat", staged_path)
        assert staged.returncode == 0 and control in staged.stdout, (
            f"{staged_path} is not this pass's staging file (expected a {control} row): "
            f"rc={staged.returncode} content={staged.stdout[:2000]!r} stderr={staged.stderr!r}"
        )
        assert V6_IP not in staged.stdout.lower(), (
            f"{V6_IP} staged for Python, expected none; {staged_path}:\n{staged.stdout[:2000]}"
        )
