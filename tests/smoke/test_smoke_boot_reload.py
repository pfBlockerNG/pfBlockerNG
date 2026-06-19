"""Issue #334 — continent/IP ``pfB_*`` aliases lost across a reboot.

REPRODUCE-FIRST regression guard. A pfBlockerNG IP/GeoIP feed builds a
``pfB_<name>_v4`` urltable alias plus an auto firewall rule that references it.
The Redmine report (#15567) is that after a reboot those aliases are gone and the
firewall is not reloaded, so rules referencing ``pfB_<Continent>_v4`` stay
unresolvable until a manual filter reload.

Root cause (code, current ``devel``): ``sync_package_pfblockerng()`` short-circuits
on the boot path (``is_platform_booting()``, ``pfblockerng.inc:9952``) — it recreates
only the DNSBL VIP/NAT/webserver and returns, so it does NOT rebuild the IP/GeoIP
alias tables and does NOT call ``filter_configure()``. The only boot-time alias
handling is the ``earlyshellcmd`` running ``pfblockerng.sh aliastables``, which
restores from the archive for RAMDISK/``md`` installs only (``pfblockerng.sh:202``).

This test pins the END STATE the fix must guarantee: after a reboot, the IP alias
table is still populated AND a pf rule still references it. It runs on the smoke
VM's standard (non-ramdisk) install — the lowest-risk reboot scenario — and is the
empirical probe for which half of the contract is actually lost there.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``) AND from
``-m smoke`` (it carries its own ``reboot`` marker, because rebooting the shared
session VM is destructive). Run only by an explicit dispatch::

    python -m pytest tests/smoke -m reboot --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and the
smoke deps; without them it skips cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.reboot


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for the reboot module.

    Egress stays OPEN across reloads: the ``update`` path also builds DNSBL
    (``pfb_create_dnsbl``) and a dark egress deadlocks the guest. ``ensure_dnsbl_vip``
    + ``use_system_dns_upstream`` give DNSBL a sinkhole VIP and a reachable upstream so
    a full ``update`` completes cleanly. The session VM is torn down at end of run, so
    a full guest snapshot is collected on teardown.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    try:
        yield smoke_vm
    finally:
        # Rebuild the aliases the reboot may have dropped, so the box is left in a
        # known-good state for any later dispatch on the same image. Best-effort —
        # never mask the test result.
        try:
            h.reload(smoke_vm, "update")
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] reboot teardown reload failed (non-fatal): {exc}")
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


def test_ip_alias_and_rule_survive_reboot(deployed_vm: SmokeVM) -> None:
    """Scenario: a ``pfB_<name>_v4`` Deny alias + its auto rule survive a reboot.

    Background:
        A Deny IP feed builds the ``pfB_<name>_v4`` urltable alias and an auto
        firewall rule that references it.

    Given the feed is injected and reloaded
        the alias table contains the fed IP AND a pf rule references the alias.
    When the guest is rebooted (the boot-time sync path runs)
        ``sync_package_pfblockerng()`` takes the ``is_platform_booting()`` branch.
    Then the alias table is STILL populated AND a rule STILL references it.

    The before-state is asserted first (proving the alias/rule WERE present), so a
    post-reboot failure proves the reboot CAUSED the loss — the #334 reproduction.
    On current ``devel`` this is expected to fail; the fix makes it pass.
    """
    vm = deployed_vm
    fed_ip = "198.51.100.77"  # RFC 5737 TEST-NET-2 (inert documentation IP)
    spec = h.IpCase(aliasname="Cont334", feed_url="", action="Deny_Both", family="v4")
    spec.feed_url = h.write_local_feed(vm, "issue334_deny.txt", f"{fed_ip}\n")

    # --- Given: inject + reload build the alias table and the referencing rule ---
    h.inject(vm, spec)
    h.reload(vm, "update")

    before_members = h.wait_pfctl_table(vm, spec.alias)
    assert h.member_present(before_members, fed_ip), (
        f"precondition: {spec.alias} must contain {fed_ip} after reload, got {before_members!r}"
    )
    assert h.rule_references(vm, spec.alias), f"precondition: a pf rule must reference {spec.alias} after reload"

    # --- When: reboot the guest, exercising the boot-time sync short-circuit ---
    h.reboot_vm(vm)

    # --- Then: the alias table + its rule reference must STILL be present ---
    after_members = h.wait_pfctl_table(vm, spec.alias)
    assert h.member_present(after_members, fed_ip), (
        f"issue #334: {spec.alias} lost member {fed_ip} after reboot — the boot path "
        f"did not rebuild the IP alias table; got {after_members!r}"
    )
    assert h.rule_references(vm, spec.alias), (
        f"issue #334: no pf rule references {spec.alias} after reboot — the boot path "
        "did not reload the firewall filter"
    )
