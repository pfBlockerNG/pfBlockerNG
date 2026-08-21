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
from pathlib import Path

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

# issue #2621 (Part of #2617): the module's ALREADY-happening reboots also prove the
# boot path's login.conf CA carry. The rc.d hook is installed by install.sh in
# production, but the .pkg deploy this module uses does NOT install it — so the
# fixture stages it itself (same technique as test_repo_install's GUEST_HOOK_PATH /
# _stage_generate_hook).
GUEST_HOOK_PATH = "/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"
HOOK_SRC = Path(__file__).resolve().parents[2] / "scripts" / "rc.d" / "pfblockerng_repo_generate.sh"
LOGIN_CONF = "/etc/login.conf"
LOGIN_CA_ENTRY = "SSL_CA_CERT_PATH=/etc/ssl/certs"
CA_DIR = "/etc/ssl/certs"
# A dummy CA-dir entry seeded ONLY when CA_DIR is empty/missing: the hook's
# _logincap_setenv_add() refuses to carry the variable over an empty/missing trust
# store (scripts/rc.d/pfblockerng_repo_generate.sh), so an image that ships no CA
# bundle would make the boot-carry assertion below a false negative rather than
# proving the boot path itself.
CA_DUMMY = f"{CA_DIR}/pfb-smoke-reboot-dummy.0"


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
    # issue #2621: the login.conf CA-carry boot-path proof (both legs — login.conf
    # lives on the root fs, never on ramdisk /var).
    login_ca_normalized: bool | None = None
    login_ca_after: bool | None = None
    login_db_after: bool | None = None
    nginx_pid: str = ""
    nginx_env_has_ca: bool | None = None


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

    # issue #2621: stage the rc.d hook the .pkg deploy above does NOT install
    # (install.sh does, in production) so the module's reboots exercise its JOB 2
    # boot reconcile — same technique as test_repo_install's _stage_generate_hook.
    smoke_vm.ssh("/bin/mkdir", "-p", "/".join(GUEST_HOOK_PATH.split("/")[:-1]))
    h.scp_to_guest(smoke_vm, HOOK_SRC, GUEST_HOOK_PATH)
    smoke_vm.ssh("/bin/chmod", "755", GUEST_HOOK_PATH)

    # Seed CA_DIR only if it is empty/missing: _logincap_setenv_add() (JOB 2's write
    # side, scripts/rc.d/pfblockerng_repo_generate.sh) refuses to carry the variable
    # over an empty/missing trust store, which would make the boot-carry assertion a
    # false negative on an image that ships no CA bundle rather than proving the boot
    # path itself. Recorded so teardown removes exactly what was seeded here.
    ls_ca = smoke_vm.ssh("/bin/sh", "-c", f"ls -A {CA_DIR} 2>/dev/null")
    ca_seeded = not ls_ca.stdout.strip()
    if ca_seeded:
        smoke_vm.ssh("/bin/mkdir", "-p", CA_DIR)
        smoke_vm.ssh("/usr/bin/touch", CA_DUMMY)

    try:
        yield smoke_vm
    finally:
        # Diagnostics FIRST: the revert reboot below wipes the MFS /var this module ran
        # on, so a snapshot taken after it would show a fresh disk-backed /var instead
        # of the module's (possibly failing) end-of-run state.
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)

        # issue #2621: revoke the carry and remove what this fixture staged/seeded,
        # BEFORE the module's final ramdisk-off reboot below — that reboot must leave
        # the guest without the hook and without the CA carry, matching a box that
        # never had #2617 installed. Each step is its own best-effort try/except
        # (matching this fixture's existing teardown style below): a failure here must
        # never mask the module's test result.
        try:
            revoke = smoke_vm.ssh("/bin/sh", GUEST_HOOK_PATH, "login-ca-revoke")
            if revoke.returncode != 0:
                print(f"[smoke] login-ca-revoke teardown rc={revoke.returncode} (non-fatal): {revoke.stderr!r}")
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] login-ca-revoke teardown failed (non-fatal): {exc}")
        if ca_seeded:
            try:
                smoke_vm.ssh("/bin/rm", "-f", CA_DUMMY)
            except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
                print(f"[smoke] CA dummy removal teardown failed (non-fatal): {exc}")
        try:
            smoke_vm.ssh("/bin/rm", "-f", GUEST_HOOK_PATH)
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] hook removal teardown failed (non-fatal): {exc}")

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

    # issue #2621: normalize the login.conf CA carry BEFORE the reboot (both legs —
    # login.conf lives on the root fs, never on ramdisk /var) so a post-reboot
    # presence is attributable to the boot reconcile, not a leftover from a prior
    # module/hook run. login-ca-revoke is consent-independent (it runs even though
    # this box's default consent is On), which is exactly what "normalize" needs.
    revoke = vm.ssh("/bin/sh", GUEST_HOOK_PATH, "login-ca-revoke")
    if revoke.returncode != 0:
        print(f"[smoke] pre-reboot login-ca-revoke rc={revoke.returncode}: {revoke.stderr!r}")
    login_ca_normalized = LOGIN_CA_ENTRY not in h.read_log_file(vm, LOGIN_CONF)

    # When: reboot the guest, exercising the boot-time sync short-circuit (and, on the
    # ramdisk leg, the /var wipe + earlyshellcmd archive restore) AND (issue #2621) the
    # rc.d hook's JOB 2 boot reconcile.
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

    # issue #2621 / #2617: the boot reconcile (JOB 2, default-on) must have carried
    # SSL_CA_CERT_PATH into login.conf's default class and recompiled login.conf.db,
    # and a daemon started by init (nginx) must show the setenv in its OWN process
    # environment — the process-start inheritance proof, not just a file edit.
    login_ca_after = LOGIN_CA_ENTRY in h.read_log_file(vm, LOGIN_CONF)
    login_db_after = vm.ssh("test", "-f", "/etc/login.conf.db").returncode == 0
    pgrep_res = vm.ssh("pgrep -x nginx || true")
    nginx_pid = next(iter(pgrep_res.stdout.split()), "")
    nginx_env_has_ca: bool | None = None
    if nginx_pid:
        procstat_res = vm.ssh("procstat", "-e", nginx_pid)
        nginx_env_has_ca = LOGIN_CA_ENTRY in procstat_res.stdout

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
        login_ca_normalized=login_ca_normalized,
        login_ca_after=login_ca_after,
        login_db_after=login_db_after,
        nginx_pid=nginx_pid,
        nginx_env_has_ca=nginx_env_has_ca,
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


def test_login_ca_carry_applies_at_boot(reboot_observation: RebootObservation) -> None:
    """Issues #2621/#2617 — the rc.d hook's boot reconcile carries the CA path.

    Scenario: a real guest reboot exercises the default-on JOB 2 boot reconcile.

    Given the login.conf CA carry was revoked (normalized) before the reboot
    When the guest reboots (the rc.d hook's boot reconcile runs, consent default-on)
    Then login.conf's ``default`` class carries ``SSL_CA_CERT_PATH`` again,
        ``login.conf.db`` is recompiled, AND a daemon started by init (nginx)
        inherited the setenv in its OWN process environment.

    This is the process-start inheritance proof issue #2617 reserved for a live
    reboot, piggybacked on THIS module's already-happening reboot instead of a
    production firewall's. Runs on both legs for free: login.conf lives on the
    root fs, not ramdisk /var, so standard and ramdisk equally prove it.
    """
    obs = reboot_observation
    leg = "ramdisk" if obs.ramdisk else "standard"

    # --- Given (setup validity): the pre-reboot revoke actually normalized state ---
    assert obs.login_ca_normalized is True, (
        f"setup [{leg}]: pre-reboot login-ca-revoke did not clear {LOGIN_CA_ENTRY!r} from "
        f"{LOGIN_CONF} (login_ca_normalized={obs.login_ca_normalized!r}) — the post-reboot "
        "presence check below would be vacuous (proving a leftover, not the boot path)"
    )

    # --- Then (after reboot): the boot reconcile must have carried the CA path ---
    assert obs.login_ca_after is True, (
        f"issue #2617 [{leg}]: {LOGIN_CA_ENTRY!r} is absent from {LOGIN_CONF} after reboot "
        f"(login_ca_after={obs.login_ca_after!r}) — the rc.d hook's boot reconcile "
        "(JOB 2, default-on) did not carry it"
    )
    assert obs.login_db_after is True, (
        f"issue #2617 [{leg}]: /etc/login.conf.db is missing after reboot "
        f"(login_db_after={obs.login_db_after!r}) — cap_mkdb did not recompile the login "
        "capability database"
    )
    assert obs.nginx_pid, (
        f"issue #2621 [{leg}]: no nginx process found after reboot (pgrep -x nginx, got "
        f"nginx_pid={obs.nginx_pid!r}) — cannot prove an init-started daemon inherited the "
        "default-class setenv"
    )
    assert obs.nginx_env_has_ca is True, (
        f"issue #2617 [{leg}]: nginx (pid {obs.nginx_pid!r}) does not carry {LOGIN_CA_ENTRY!r} "
        f"in its own process environment (nginx_env_has_ca={obs.nginx_env_has_ca!r}) — the "
        "default-class setenv exists but was not inherited by a daemon started after the "
        "boot reconcile ran"
    )
