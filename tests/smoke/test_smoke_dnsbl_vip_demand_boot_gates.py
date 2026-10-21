"""Issue #3539: boot tears down served DNSBL VIP state when the package gate is off."""

from __future__ import annotations

import pytest

from . import helpers as h
from . import test_smoke_dnsbl_vip_demand as demand
from .conftest import SmokeVM
from .test_smoke_dnsbl_vip_demand import deployed_vm  # noqa: F401 -- pytest fixture re-export


@pytest.mark.reboot
@pytest.mark.timeout(900)
def test_boot_with_package_off_tears_down_leftover_served_vip_state(
    deployed_vm: SmokeVM,  # noqa: F811 -- pytest fixture re-export
    lan_interface: SmokeVM,
) -> None:
    """Serve a real VIP block with NAT, disable only the package without applying, then reboot.

    Boot must remove the conf, cert, NAT and marked VIP, stop lighttpd and prevent rc start revival.
    """
    vm = deployed_vm
    domain = h.unique_domain("vipbootgate")
    feed = h.write_local_feed(vm, "smoke_vip_demand_boot_gate.txt", f"{domain}\n")
    with demand._restoring_baseline(vm):
        demand._write_state(vm, feed=feed, logging="enabled", auto_vip=True, settings={"dnsbl_interface": "lan"})
        demand._force_update(vm)
        h.apply_filter_sync(vm)
        vip = h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4)
        web = demand._lighty_state(vm)
        assert vip and demand._vip_alias_devices(vm, vip), f"before: managed VIP not live: {vip!r}"
        assert web.running and web.conf and web.cert, f"before: web server not fully served: {web}"
        answer = h.dns_probe(vm, domain, "A")
        assert h.is_vip(answer, vip=vip), f"before: expected VIP {vip!r}, got {answer}"
        rows = demand._dnsbl_nat_rows(vm)
        assert len(rows) == 2 and demand._live_rdr_lines(vm, vip), f"before: DNSBL NAT missing: {rows!r}"

        # Config-only gate change: leave all serving artifacts for the real boot path to remove.
        h.set_package_enabled(vm, False)
        web = demand._lighty_state(vm)
        assert web.running and web.conf and web.cert, f"gate change unexpectedly applied teardown before boot: {web}"
        h.reboot_vm(vm)

        problems = demand._web_down_problems(demand._lighty_state(vm), conf=True, cert=True)
        marked = h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4)
        if marked or demand._vip_alias_devices(vm, vip):
            problems.append(f"managed VIP survived boot: config={marked!r}, address={vip!r}")
        after_rows = demand._dnsbl_nat_rows(vm)
        after_live = demand._live_rdr_lines(vm, vip)
        if after_rows or after_live:
            problems.append(f"DNSBL NAT survived boot: config={after_rows!r}, loaded={after_live!r}")
        demand._expect_no_problems(vm, "after package-off boot", problems)

        result = vm.ssh("/bin/sh", demand._DNSBL_RC, "start", timeout=60.0)
        assert result.returncode == 0, f"rc start failed: {result}"
        demand._expect_no_problems(
            vm,
            "rc start after package-off boot",
            demand._web_down_problems(demand._lighty_state(vm), conf=True, cert=True),
        )
