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

Two legs, because the install kind changes what survives a reboot:

* **standard** — a normal disk install. The ``pfB_*`` alias DEFINITION lives in
  ``config.xml`` and the urltable backing file persists on disk, so pfSense core's
  boot ``filter_configure`` may repopulate the table independently of pfBlockerNG.
* **ramdisk** — ``<system><use_mfs_tmpvar>`` enabled, so /var is wiped on boot. This
  is the reporter's scenario: the earlyshellcmd restores the aliastables archive,
  then the pfBlockerNG boot short-circuit neither rebuilds nor reloads the filter.

Both legs pin the SAME end state the fix must guarantee: after a reboot, the IP
alias table is still populated AND a pf rule still references it.

The slow work (inject → reload → reboot) runs in the module fixture, NOT the test
body: the smoke workflow caps the test BODY at 30s (``--timeout=30``,
``timeout_func_only=true``), but fixtures are exempt — same reason the ~2 min
``deploy`` fixture is. The test body is pure assertions on the captured observation.

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
from dataclasses import dataclass

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.reboot

# A throwaway marker dropped in /var right before the ramdisk reboot. pfSense's MFS
# wipes /var on every boot (it only restores a known set: RRD, DHCP leases, logs,
# captive portal — NOT a top-level /var file), so the sentinel VANISHING after the
# reboot is direct, implementation-agnostic proof that /var really came up as a memory
# filesystem. If it SURVIVES, the config flag did not engage MFS and the ramdisk leg
# would be a false negative — so the leg asserts on this.
VAR_WIPE_SENTINEL = "/var/PFB_SMOKE_WIPE_SENTINEL"


@dataclass
class RebootObservation:
    """The alias/rule state captured before and after one reboot, for one leg."""

    ramdisk: bool
    fed_ip: str
    alias: str
    before_members: list[str]
    before_rule: bool
    archive_present: bool
    after_members: list[str]
    after_rule: bool
    # ramdisk leg only: was the /var sentinel created pre-reboot, and did /var actually
    # get wiped on the reboot (MFS engaged)?
    sentinel_created: bool | None = None
    var_wiped: bool | None = None
    var_mount: str = ""


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
    try:
        h.snapshot_unbound_conf(smoke_vm)
        h.ensure_dnsbl_vip(smoke_vm)
        h.use_system_dns_upstream(smoke_vm)

        yield smoke_vm
    finally:
        # Diagnostics FIRST: the revert reboot below wipes the MFS /var this module ran
        # on, so a snapshot taken after it would show a fresh disk-backed /var instead
        # of the module's (possibly failing) end-of-run state.
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)

        # Leave RAM disks OFF and rebuild the aliases the reboot may have dropped, so
        # the box is left in a known-good state. Best-effort — never mask the result.
        # The reboot is REQUIRED (issue #765): set_ramdisk only flips the config flag,
        # so without it the running /var stays MFS and every module that runs after this
        # one on the shared session VM inherits writes that vanish on the next reboot.
        try:
            h.set_ramdisk(smoke_vm, False)
            h.reload(smoke_vm, "update")
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] ramdisk-off teardown failed (non-fatal): {exc}")
        # Own try: a flaky reload above must not skip the reboot — with the flag already
        # flipped off, the reboot alone completes the MFS-to-disk transition.
        try:
            h.reboot_vm(smoke_vm)
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] ramdisk-off teardown reboot failed (non-fatal): {exc}")


@pytest.fixture(scope="module", params=[False, True], ids=["standard", "ramdisk"])
def reboot_observation(request: pytest.FixtureRequest, deployed_vm: SmokeVM) -> RebootObservation:
    """Build a Deny IP alias, capture its state, reboot, recapture — once per leg.

    All VM I/O (inject → reload → reboot → recapture) lives HERE so the 30s test-body
    timeout never covers the ~1 min reboot. ``params`` runs ``standard`` first (pristine
    install) then ``ramdisk`` (enables ``use_mfs_tmpvar``, which the next reboot honours).
    """
    vm = deployed_vm
    ramdisk: bool = request.param
    fed_ip = "198.51.100.77"  # RFC 5737 TEST-NET-2 (inert documentation IP)
    spec = h.IpCase(aliasname=f"Cont334{'ram' if ramdisk else 'std'}", feed_url="", action="Deny_Both", family="v4")

    # Given: (ramdisk leg) enable RAM disks BEFORE the reload so the reload registers
    # the earlyshellcmd and archives the aliastables under use_mfs_tmpvar.
    if ramdisk:
        h.set_ramdisk(vm, True)

    spec.feed_url = h.write_local_feed(vm, f"issue334_{'ram' if ramdisk else 'std'}.txt", f"{fed_ip}\n")
    h.inject(vm, spec)
    h.reload(vm, "update")
    h.apply_filter_sync(vm)

    before_members = h.pfctl_table_members(vm, spec.alias)
    before_rule = h.pfctl_rule_has_alias(vm, spec.alias)
    archive_present = ramdisk and h.archive_exists(vm, h.ALIASARCHIVE)

    # ramdisk leg: drop a /var sentinel so the post-reboot check can PROVE /var came up
    # as a memory filesystem (the sentinel is wiped) rather than persisting on disk.
    # Confirm it actually landed — a sentinel that was never created would read as
    # "wiped" after the reboot and make the MFS proof a false green.
    sentinel_created: bool | None = None
    if ramdisk:
        vm.ssh("/usr/bin/touch", VAR_WIPE_SENTINEL)
        sentinel_created = vm.ssh("test", "-e", VAR_WIPE_SENTINEL).returncode == 0

    # When: reboot the guest, exercising the boot-time sync short-circuit and, on the
    # ramdisk leg, the /var wipe + earlyshellcmd archive restore.
    h.reboot_vm(vm)

    # Then (captured): the alias table + its rule reference, post-reboot.
    after_members = h.pfctl_table_members(vm, spec.alias)
    after_rule = h.pfctl_rule_has_alias(vm, spec.alias)

    var_wiped: bool | None = None
    var_mount = ""
    if ramdisk:
        var_wiped = vm.ssh("test", "-e", VAR_WIPE_SENTINEL).returncode != 0
        mounts = vm.ssh("/sbin/mount")
        var_mount = next((ln for ln in mounts.stdout.splitlines() if " on /var " in ln), "")

    return RebootObservation(
        ramdisk=ramdisk,
        fed_ip=fed_ip,
        alias=spec.alias,
        before_members=before_members,
        before_rule=before_rule,
        archive_present=archive_present,
        after_members=after_members,
        after_rule=after_rule,
        sentinel_created=sentinel_created,
        var_wiped=var_wiped,
        var_mount=var_mount,
    )


def test_ip_alias_and_rule_survive_reboot(reboot_observation: RebootObservation) -> None:
    """Scenario: a ``pfB_<name>_v4`` Deny alias + its auto rule survive a reboot.

    Given a Deny IP feed is injected and reloaded
        the alias table contains the fed IP AND a pf rule references the alias.
    When the guest is rebooted (the boot-time sync path runs)
    Then the alias table is STILL populated AND a rule STILL references it.

    The before-state is asserted first (proving the alias/rule WERE present), so a
    post-reboot failure proves the reboot CAUSED the loss — the #334 reproduction.
    On current ``devel`` at least the ramdisk leg is expected to fail; the fix makes
    both legs pass.
    """
    obs = reboot_observation
    leg = "ramdisk" if obs.ramdisk else "standard"

    # --- Given (before reboot): the alias table + rule were built ---
    assert h.member_present(obs.before_members, obs.fed_ip), (
        f"precondition [{leg}]: {obs.alias} must contain {obs.fed_ip} after reload, got {obs.before_members!r}"
    )
    assert obs.before_rule, f"precondition [{leg}]: a pf rule must reference {obs.alias} after reload"
    if obs.ramdisk:
        assert obs.archive_present, (
            f"precondition [ramdisk]: {h.ALIASARCHIVE}.{{zst,bz2}} must exist pre-reboot (the "
            "earlyshellcmd restore source) — else the ramdisk path is not actually exercised"
        )
        # The sentinel must have been created pre-reboot, else the wipe check below is a
        # false green (a sentinel that never existed also reads as "gone" after reboot).
        assert obs.sentinel_created, (
            f"precondition [ramdisk]: {VAR_WIPE_SENTINEL} must exist pre-reboot — could not "
            "create it, so the post-reboot wipe assertion cannot be trusted"
        )
        # Prove MFS actually engaged: the /var sentinel must be GONE after the reboot,
        # which means /var came up fresh (memory FS) and the alias survived via the
        # archive restore — not because /var merely persisted on disk.
        assert obs.var_wiped, (
            "precondition [ramdisk]: /var was NOT wiped on reboot — use_mfs_tmpvar did not "
            f"engage a memory filesystem, so this leg is a false negative (mount: {obs.var_mount!r})"
        )

    # --- Then (after reboot): the alias table + its rule must STILL be present ---
    assert h.member_present(obs.after_members, obs.fed_ip), (
        f"issue #334 [{leg}]: {obs.alias} lost member {obs.fed_ip} after reboot — "
        f"the boot path did not rebuild the IP alias table; got {obs.after_members!r}"
    )
    assert obs.after_rule, (
        f"issue #334 [{leg}]: no pf rule references {obs.alias} after reboot — "
        "the boot path did not reload the firewall filter"
    )
