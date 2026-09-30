"""Live-VM smoke: empty-scheme IP lines land in the DNSBL IP tables; embedded URLs do not.

A DNSBL feed line ``://192.0.2.10^`` (the "block regardless of scheme" shape) lists that IPv4
address, and ``://[2001:db8::10]^$third-party`` that IPv6 address (options dropped), in both
lenient and strict mode. A ``://`` after a ``/``, ``?`` or ``#`` is part of the path or query,
so ``evil.com/x?u=http://198.51.100.20/`` lists the domain only, never 198.51.100.20.

The addresses come from the RFC 5737 / RFC 3849 documentation ranges; ``deploy()`` pins IP
Suppression off, so they are collected.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow; select it there with ``-k empty_scheme``::

    python -m pytest tests/smoke -m smoke --override-ini="addopts=" -k empty_scheme
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

HEADER = "smokeemptyscheme"
V4_IP, V6_IP, EMBEDDED_IP = "192.0.2.10", "2001:db8::10", "198.51.100.20"


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
            print(f"[smoke] clear_dnsbl_settings failed on empty-scheme teardown (suppressed): {cleanup_exc!r}")
        h.collect_host_diagnostics(smoke_vm)


@pytest.mark.timeout(300)  # same inject + DNSBL-IP reload shape as test_smoke_abp_bracketed_v6
@pytest.mark.parametrize("lenient", [True, False], ids=["lenient", "strict"])
def test_empty_scheme_ip_collected_and_embedded_url_ignored(
    deployed_vm: SmokeVM, client_vm: SmokeVM, lenient: bool
) -> None:
    """Scenario: empty-scheme IP lines are firewalled; an IP inside a query string is not.

    Given a DNSBL feed, loaded with DNSBL IP = Deny_Both in the given scheme mode, that holds
      ``://192.0.2.10^``, ``://[2001:db8::10]^$third-party``,
      ``evil.com/x?u=http://198.51.100.20/`` and a control domain,
    When the feed is reloaded,
    Then the control domain is VIP-blocked (the feed loaded),
      pfB_DNSBLIP_v4 holds 192.0.2.10 and pfB_DNSBLIP_v6 holds 2001:db8::10,
      and 198.51.100.20 is in neither table.
    """
    vm = deployed_vm
    mode = "lenient" if lenient else "strict"
    # Per-mode header and feed: with a shared one, the second case's control never got the VIP block.
    header = f"{HEADER}{mode}"
    control = h.unique_domain("emptyscheme")
    body = (
        "\n".join([f"://{V4_IP}^", f"://[{V6_IP}]^$third-party", "evil.com/x?u=http://" + EMBEDDED_IP + "/", control])
        + "\n"
    )
    feed_url = h.write_local_feed(vm, f"smoke_dnsbl_empty_scheme_ip_{mode}.txt", body)
    spec = h.DnsblCase(
        aliasname=header, feed_url=feed_url, header=header, mode=h.DnsblMode.VIP, dnsbl_ip_action="Deny_Both"
    )
    try:
        h.inject(vm, spec)
        h.set_dnsbl_lenient(vm, lenient)
        h.reload(vm, "update")

        h.flush_unbound_name(vm, control)
        ans = h.dns_probe_client_until(client_vm, control, h.is_vip)
        assert h.is_vip(ans), f"control {control} expected VIP block (feed loaded), got {ans}"

        h.apply_filter_sync(vm)
        v4 = h.pfctl_table_members(vm, "pfB_DNSBLIP_v4")
        v6 = h.pfctl_table_members(vm, "pfB_DNSBLIP_v6")
        assert h.member_present(v4, V4_IP), f"{mode}: expected {V4_IP} in pfB_DNSBLIP_v4, got {v4}"
        assert h.member_present(v6, V6_IP), f"{mode}: expected {V6_IP} in pfB_DNSBLIP_v6, got {v6}"
        assert not h.member_present(v4, EMBEDDED_IP), f"{mode}: {EMBEDDED_IP} from a query string in v4: {v4}"
        assert not h.member_present(v6, EMBEDDED_IP), f"{mode}: {EMBEDDED_IP} from a query string in v6: {v6}"
    finally:
        h.reset(vm)
        h.set_dnsbl_lenient(vm, True)
        vm.ssh("/bin/rm", "-f", feed_url)
