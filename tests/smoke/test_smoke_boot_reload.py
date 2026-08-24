"""Issue #334 — continent/IP ``pfB_*`` aliases lost across a reboot — and, riding
the same reboots, issues #2621/#2617 — the login.conf CA carry across a real boot
(file-side reconcile on the standard leg, daemon env inheritance on the ramdisk leg).

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
import subprocess
import time
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
# production, but the .pkg deploy this module uses does NOT — the fixture stages it.
# The two legs prove complementary halves of #2617's boot claim:
#   standard — revoke first, reboot: the boot reconcile re-adds the carry (file
#     side), while nginx must NOT have it in env — init fixes the rc tree's
#     environment from the compiled db AS OF BOOT START, and the revoke left it clean.
#   ramdisk  — login-ca-sync first (carry compiled BEFORE the reboot), reboot: nginx
#     MUST now carry it — the daemon-inheritance proof, one boot after the write.
GUEST_HOOK_PATH = "/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"
HOOK_SRC = Path(__file__).resolve().parents[2] / "src/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"
LOGIN_CONF = "/etc/login.conf"
LOGIN_CA_ENTRY = "SSL_CA_CERT_PATH=/etc/ssl/certs"
CA_DIR = "/etc/ssl/certs"
# Seeded ONLY when CA_DIR is empty/missing: _logincap_setenv_add() refuses an
# empty/missing trust store, which would turn the boot-carry proof into a setup red.
CA_DUMMY = f"{CA_DIR}/pfb-smoke-reboot-dummy.0"


def _scp_to_guest(vm: SmokeVM, local: Path, remote: str, *, timeout: float = 120.0) -> None:
    """Copy a local file to the guest via ``scp`` (per-suite copy, mirrors install-pkg.sh)."""
    argv = [
        "scp",
        "-i",
        vm.ssh_key_path,
        "-P",
        str(vm.ssh_port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "BatchMode=yes",
        str(local),
        f"{vm.ssh_target}:{remote}",
    ]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"scp {local} -> {remote} failed: rc={result.returncode} {result.stderr!r}")


def _default_class_record(login_conf_text: str) -> str:
    """The ``default:`` record only — the class #2617's placement contract names."""
    record: list[str] = []
    in_default = False
    for line in login_conf_text.splitlines():
        if in_default:
            record.append(line)
            if not line.endswith("\\"):
                break
        elif line.startswith("default:"):
            record.append(line)
            in_default = True
            if not line.endswith("\\"):
                break
    return "\n".join(record)


def _login_ca_in_default_class(vm: SmokeVM) -> tuple[bool, bool]:
    """(read_ok, entry_present_in_default_record) — rc-checked, never ''-on-failure."""
    res = vm.ssh("/bin/cat", LOGIN_CONF)
    if res.returncode != 0:
        return False, False
    return True, LOGIN_CA_ENTRY in _default_class_record(res.stdout)


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
    # issues #2621/#2617: the login.conf CA-carry boot-path proof (constants block
    # explains the two legs' complementary roles).
    login_conf_read_ok: bool | None = None
    login_conf_preboot_read_ok: bool | None = None
    login_ca_preboot_clean: bool | None = None  # standard leg: revoke really cleared it
    login_ca_preboot_present: bool | None = None  # ramdisk leg: sync really compiled it
    login_ca_after: bool | None = None
    login_ca_wait_s: float | None = None
    nginx_pid: str = ""
    nginx_procstat_rc: int | None = None
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
    try:
        h.snapshot_unbound_conf(smoke_vm)
        h.ensure_dnsbl_vip(smoke_vm)
        h.use_system_dns_upstream(smoke_vm)

        # issue #2621: stage the rc.d hook the .pkg deploy above does NOT install,
        # and seed the CA dir only when the hook's own populated-dir glob would see
        # it as empty (plain `ls`, dotfiles excluded — matching the glob's view).
        # Inside the try: a mid-staging failure must still reach the teardown below.
        _scp_to_guest(smoke_vm, HOOK_SRC, GUEST_HOOK_PATH)
        chmod = smoke_vm.ssh("/bin/chmod", "755", GUEST_HOOK_PATH)
        if chmod.returncode != 0:
            raise RuntimeError(f"chmod on the staged hook failed: {chmod.stderr!r}")
        ls_ca = smoke_vm.ssh("/bin/sh", "-c", f"ls {CA_DIR} 2>/dev/null")
        if not ls_ca.stdout.strip():
            smoke_vm.ssh("/bin/mkdir", "-p", CA_DIR)
            touch = smoke_vm.ssh("/usr/bin/touch", CA_DUMMY)
            if touch.returncode != 0:
                raise RuntimeError(f"seeding {CA_DUMMY} failed: {touch.stderr!r}")

        yield smoke_vm
    finally:
        # Diagnostics FIRST: the revert reboot below wipes the MFS /var this module ran
        # on, so a snapshot taken after it would show a fresh disk-backed /var instead
        # of the module's (possibly failing) end-of-run state.
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)

        # issue #2621: revoke the carry and remove what this fixture staged/seeded,
        # BEFORE the module's final ramdisk-off reboot below — that reboot must leave
        # the guest without the hook and without the CA carry. Revoke runs first
        # (it needs the hook still present) and each step reports its own failure,
        # so a failed revoke is never masked by a clean rm.
        try:
            revoke = smoke_vm.ssh("/bin/sh", GUEST_HOOK_PATH, "login-ca-revoke")
            if revoke.returncode != 0:
                print(f"[smoke] login-ca revoke teardown failed (non-fatal): {revoke.stderr!r}")
            cleanup = smoke_vm.ssh("/bin/rm", "-f", CA_DUMMY, GUEST_HOOK_PATH)
            if cleanup.returncode != 0:
                print(f"[smoke] login-ca file cleanup failed (non-fatal): {cleanup.stderr!r}")
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] login-ca teardown failed (non-fatal): {exc}")

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

    # issues #2621/#2617, complementary per leg (see the constants block): the
    # standard leg REVOKES so the post-reboot file state is attributable to the boot
    # reconcile (and nginx, whose env init fixes from the then-clean db at boot
    # start, must NOT carry it); the ramdisk leg SYNCS so the carry is compiled
    # BEFORE the reboot and nginx MUST carry it — the daemon-inheritance proof.
    login_ca_preboot_clean: bool | None = None
    login_ca_preboot_present: bool | None = None
    _verb = "login-ca-sync" if ramdisk else "login-ca-revoke"
    verb_res = vm.ssh("/bin/sh", GUEST_HOOK_PATH, _verb)
    if verb_res.returncode != 0:
        print(f"[smoke] pre-reboot {_verb} rc={verb_res.returncode}: {verb_res.stderr!r}")
    login_conf_preboot_read_ok, _present = _login_ca_in_default_class(vm)
    if ramdisk:
        login_ca_preboot_present = _present
    else:
        login_ca_preboot_clean = not _present

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

    # issues #2621/#2617 post-reboot captures. The file-side read POLLS with a
    # bounded deadline: pfSense runs the package rc.d scripts late in boot, so a
    # fast readiness pass can land before JOB 2 wrote — the deadline's expiry is a
    # distinguishable capture outcome, never a hidden sleep.
    deadline = time.monotonic() + 120.0
    login_conf_read_ok, login_ca_after = _login_ca_in_default_class(vm)
    while not (login_conf_read_ok and login_ca_after) and time.monotonic() < deadline:
        time.sleep(3.0)
        login_conf_read_ok, login_ca_after = _login_ca_in_default_class(vm)
    login_ca_wait_s = 120.0 - max(0.0, deadline - time.monotonic())

    pgrep_res = vm.ssh("pgrep -x nginx || true")
    nginx_pid = next(iter(pgrep_res.stdout.split()), "")
    nginx_procstat_rc: int | None = None
    nginx_env_has_ca: bool | None = None
    if nginx_pid:
        procstat_res = vm.ssh("procstat", "-e", nginx_pid)
        nginx_procstat_rc = procstat_res.returncode
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
        login_conf_read_ok=login_conf_read_ok,
        login_conf_preboot_read_ok=login_conf_preboot_read_ok,
        login_ca_preboot_clean=login_ca_preboot_clean,
        login_ca_preboot_present=login_ca_preboot_present,
        login_ca_after=login_ca_after,
        login_ca_wait_s=login_ca_wait_s,
        nginx_pid=nginx_pid,
        nginx_procstat_rc=nginx_procstat_rc,
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
    """Issues #2621/#2617 — the login.conf CA carry across a real boot, both halves.

    Scenario (standard leg — file-side reconcile):
      Given the carry was revoked (file and db clean at boot start)
      When the guest reboots (JOB 2 boot reconcile, consent default-on)
      Then the ``default`` class carries the entry again, and nginx does NOT
          have it in env — init fixed the rc tree's environment from the
          then-clean compiled db at boot start. (The db itself is never probed
          here: the ramdisk leg's inheritance proof only passes if the hook
          compiled it, so compilation is proven transitively; byte-level
          compile behaviour is the shellspec suites' job.)

    Scenario (ramdisk leg — daemon inheritance, the proof #2617 reserved for a
    live reboot):
      Given the carry was synced (compiled into the db BEFORE the reboot)
      When the guest reboots
      Then nginx carries the entry in its OWN process environment.
    """
    obs = reboot_observation
    leg = "ramdisk" if obs.ramdisk else "standard"

    assert obs.login_conf_preboot_read_ok is True, (
        f"capture [{leg}]: could not read {LOGIN_CONF} over ssh BEFORE the reboot — "
        "a transport failure during setup, not a verdict on the verbs"
    )
    assert obs.login_conf_read_ok is True, (
        f"capture [{leg}]: could not read {LOGIN_CONF} over ssh after the reboot — "
        "a transport failure, not a verdict on the boot reconcile"
    )
    assert obs.login_ca_after is True, (
        f"issue #2617 [{leg}]: {LOGIN_CA_ENTRY!r} is absent from {LOGIN_CONF}'s default "
        f"class after reboot (waited {obs.login_ca_wait_s:.0f}s) — the boot reconcile "
        "(JOB 2, default-on) did not carry it"
    )
    assert obs.nginx_pid, f"capture [{leg}]: no nginx process found after reboot — cannot judge daemon env inheritance"
    assert obs.nginx_procstat_rc == 0, (
        f"capture [{leg}]: procstat -e rc={obs.nginx_procstat_rc!r} — a tool failure, not a verdict on inheritance"
    )

    if obs.ramdisk:
        assert obs.login_ca_preboot_present is True, (
            "setup [ramdisk]: pre-reboot login-ca-sync did not land the carry — the "
            "inheritance proof below would be vacuous"
        )
        assert obs.nginx_env_has_ca is True, (
            f"issue #2617 [ramdisk]: nginx (pid {obs.nginx_pid}) does not carry "
            f"{LOGIN_CA_ENTRY!r} in its environment although the compiled db held it at "
            "boot start — the init-started-daemon inheritance the whole design rests on"
        )
    else:
        assert obs.login_ca_preboot_clean is True, (
            "setup [standard]: pre-reboot login-ca-revoke did not clear the carry — the "
            "file-side proof below would show a leftover, not the boot path"
        )
        assert obs.nginx_env_has_ca is False, (
            f"model [standard]: nginx carries {LOGIN_CA_ENTRY!r} although the db was "
            "clean at boot start — same-boot application exists after all; relax this "
            "assertion and the two-leg design if this reproduces"
        )
