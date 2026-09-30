"""Live-VM smoke: a plain '<IP>/<mask>' DNSBL line is rejected into the parse-error log (#3366).

A scheme-less ``192.0.2.0/24`` or ``2001:db8::/32`` line used to be collected as the bare address
(``192.0.2.0``), blocking one host while the feed claimed a network. It now lands in
dnsbl_parsed_error.log and in neither DNSBL IP table, in lenient and strict mode; a plain
control IP on the same feed is still collected.

The addresses come from the RFC 5737 / RFC 3849 documentation ranges; ``deploy()`` pins IP
Suppression off, so the control is collected.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow; select it there with ``-k plain_cidr``::

    python -m pytest tests/smoke -m smoke --override-ini="addopts=" -k plain_cidr
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

HEADER = "smokeplaincidr"
V4_CIDR, V6_CIDR, CONTROL_IP = "192.0.2.0/24", "2001:db8::/32", "198.51.100.30"


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
            print(f"[smoke] clear_dnsbl_settings failed on plain-cidr teardown (suppressed): {cleanup_exc!r}")
        h.collect_host_diagnostics(smoke_vm)


@pytest.mark.timeout(300)  # same inject + DNSBL-IP reload shape as test_smoke_dnsbl_empty_scheme_ip
@pytest.mark.parametrize("lenient", [True, False], ids=["lenient", "strict"])
def test_plain_cidr_lines_rejected_and_control_ip_collected(
    deployed_vm: SmokeVM, client_vm: SmokeVM, lenient: bool
) -> None:
    """Scenario: plain CIDR lines are parse errors; a plain IP on the same feed is firewalled.

    Given a DNSBL feed, loaded with DNSBL IP = Deny_Both in the given scheme mode, that holds
      ``192.0.2.0/24``, ``2001:db8::/32``, the control IP ``198.51.100.30`` and a control domain,
    When the feed is reloaded,
    Then the control domain is VIP-blocked (the feed loaded),
      pfB_DNSBLIP_v4 holds 198.51.100.30 but not 192.0.2.0, pfB_DNSBLIP_v6 lacks 2001:db8::,
      and the parse-error log gains a line naming each CIDR.
    """
    vm = deployed_vm
    mode = "lenient" if lenient else "strict"
    # Per-mode header and feed: with a shared one, the second case's control never got the VIP block.
    header = f"{HEADER}{mode}"
    control = h.unique_domain("plaincidr")
    body = "\n".join([V4_CIDR, V6_CIDR, CONTROL_IP, control]) + "\n"
    feed_url = h.write_local_feed(vm, f"smoke_dnsbl_plain_cidr_{mode}.txt", body)
    spec = h.DnsblCase(
        aliasname=header, feed_url=feed_url, header=header, mode=h.DnsblMode.VIP, dnsbl_ip_action="Deny_Both"
    )
    v4_before = h.count_log_marker(vm, h.DNSBL_PARSE_ERR_LOG, V4_CIDR)
    v6_before = h.count_log_marker(vm, h.DNSBL_PARSE_ERR_LOG, V6_CIDR)
    try:
        h.inject(vm, spec)
        h.set_dnsbl_lenient(vm, lenient)
        h.reload(vm, "update")

        h.flush_unbound_name(vm, control)
        # reload() waits for the swap, so the first answer is authoritative.
        ans = h.dns_probe_client(client_vm, control, "A")
        assert h.is_vip(ans), f"control {control} expected VIP block (feed loaded), got {ans}"

        h.apply_filter_sync(vm)
        v4 = h.pfctl_table_members(vm, "pfB_DNSBLIP_v4")
        v6 = h.pfctl_table_members(vm, "pfB_DNSBLIP_v6")
        assert h.member_present(v4, CONTROL_IP), f"{mode}: expected {CONTROL_IP} in pfB_DNSBLIP_v4, got {v4}"
        assert not h.member_present(v4, "192.0.2.0"), f"{mode}: 192.0.2.0 from {V4_CIDR} in v4: {v4}"
        assert not h.member_present(v6, "2001:db8::"), f"{mode}: 2001:db8:: from {V6_CIDR} in v6: {v6}"

        assert h.count_log_marker(vm, h.DNSBL_PARSE_ERR_LOG, V4_CIDR) > v4_before, (
            f"{mode}: {V4_CIDR} missing from the DNSBL parse-error log:\n"
            f"{h.read_log_file(vm, h.DNSBL_PARSE_ERR_LOG)[-2000:]}"
        )
        assert h.count_log_marker(vm, h.DNSBL_PARSE_ERR_LOG, V6_CIDR) > v6_before, (
            f"{mode}: {V6_CIDR} missing from the DNSBL parse-error log"
        )
    finally:
        h.reset(vm)
        h.set_dnsbl_lenient(vm, True)
        vm.ssh("/bin/rm", "-f", feed_url)
