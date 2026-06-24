"""Issue #468 — DNSBL survives a RAM-disk /var reboot (python integration re-staged).

On a RAM-disk /var (``use_mfs_tmpvar``) a reboot wipes ``/var/unbound``. The MFS
restore archive (``pfb_aliastables``) already globs ``/var/unbound/pfb_unbound*`` +
``pfb_py_*`` and the boot ``earlyshellcmd`` untars it — but the archive was only
(re)built on IP-alias/firewall-rule changes, so a DNSBL-only config never archived
the python integration and DNSBL came up dead after every reboot. The fix builds
the archive on DNSBL-only updates too.

REPRODUCE-FIRST: assert the domain sinkholes BEFORE the reboot, then require it to
still sinkhole AFTER a RAM-disk reboot (pfb_unbound.py re-staged + matcher rebuilt
from the restored manifest), with NO manual update. Verified RED on pre-fix code.

All slow VM I/O (inject -> reload -> reboot -> recovery poll) lives in the MODULE
FIXTURE, never the test body: the smoke workflow caps the test BODY at 30s
(``--timeout=30 timeout_func_only=true``) but fixtures are exempt (same reason the
~2 min deploy + the #334 reboot fixture are). The body is pure assertions.

reboot marker (destructive — reboots the shared session VM). Run::

    python -m pytest tests/smoke/test_smoke_dnsbl_ramdisk_reboot.py \
        -m reboot --override-ini="addopts=" -rA -s
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.reboot

VAR_WIPE_SENTINEL = "/var/PFB_SMOKE_468_WIPE"
PFB_UNBOUND = "/var/unbound/pfb_unbound.py"
RECOVERY_DEADLINE = 240  # seconds to wait for DNSBL to self-heal post-reboot


@dataclass
class DnsblRebootObservation:
    """DNSBL state captured around one RAM-disk reboot (built in the fixture)."""

    domain: str
    sinkholes_before: bool
    var_wiped: bool
    staged_after: bool
    var_unbound_ls: str
    recovered: bool
    recovered_after_s: int


def _sinkholes(vm: SmokeVM, domain: str) -> bool:
    try:
        return h.resolves_to(h.dns_probe(vm, domain, "A"), h.DEFAULT_DNSBL_VIP4)
    except Exception:  # noqa: BLE001 -- mid-restart no-answer counts as "not yet"
        return False


@pytest.fixture(scope="module")
def dnsbl_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg with DNSBL infra (sinkhole VIP + system upstream), once."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    try:
        yield smoke_vm
    finally:
        try:
            h.set_ramdisk(smoke_vm, False)
            h.reload(smoke_vm, "update")
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the result
            print(f"[smoke] #468 teardown reload failed (non-fatal): {exc}")
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


@pytest.fixture(scope="module")
def reboot_observation(dnsbl_vm: SmokeVM) -> DnsblRebootObservation:
    """ALL slow VM I/O for the #468 scenario — runs in the fixture (no 30s body cap).

    Given a DNSBL feed blocking a unique domain with RAM-disk /var enabled,
      And the domain sinkholes (DNSBL works before the reboot),
    When the guest is rebooted (MFS wipes /var/unbound; the boot re-stage runs),
    Then capture: /var really wiped (MFS), pfb_unbound.py re-staged, and whether the
      domain self-recovers to the sinkhole within RECOVERY_DEADLINE (no manual update).
    """
    vm = dnsbl_vm
    domain = h.unique_domain("pfb468")

    # Given: RAM disks ON before the reload; a DNSBL feed blocking `domain`, applied.
    h.set_ramdisk(vm, True)
    feed_url = h.write_local_feed(vm, "issue468.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smoke468", feed_url=feed_url, header="smoke468", mode=h.DnsblMode.VIP)
    h.inject(vm, spec)
    h.reload(vm, "update")
    h.wait_unbound_ready(vm)

    sinkholes_before = _sinkholes(vm, domain)

    # MFS proof sentinel, then reboot.
    vm.ssh("/usr/bin/touch", VAR_WIPE_SENTINEL)
    h.reboot_vm(vm)
    h.wait_unbound_ready(vm)

    var_wiped = vm.ssh("test", "-e", VAR_WIPE_SENTINEL).returncode != 0
    staged_after = vm.ssh("test", "-f", PFB_UNBOUND).returncode == 0
    var_unbound_ls = vm.ssh("/bin/ls", "-la", "/var/unbound").stdout

    # Poll for self-recovery (pfb_unbound.py staged AND sinkholing) with NO manual update.
    waited = 0
    recovered = False
    while waited <= RECOVERY_DEADLINE:
        if vm.ssh("test", "-f", PFB_UNBOUND).returncode == 0 and _sinkholes(vm, domain):
            recovered = True
            break
        time.sleep(10)
        waited += 10

    return DnsblRebootObservation(
        domain=domain,
        sinkholes_before=sinkholes_before,
        var_wiped=var_wiped,
        staged_after=staged_after,
        var_unbound_ls=var_unbound_ls,
        recovered=recovered,
        recovered_after_s=waited,
    )


def test_dnsbl_survives_ramdisk_var_reboot(reboot_observation: DnsblRebootObservation) -> None:
    """A DNSBL-blocked domain must still sinkhole after a RAM-disk /var reboot (#468)."""
    obs = reboot_observation

    # Precondition: DNSBL worked BEFORE the reboot (else the after-state proves nothing).
    assert obs.sinkholes_before, f"precondition: {obs.domain} must sinkhole to {h.DEFAULT_DNSBL_VIP4} before the reboot"
    # The leg is genuinely a RAM-disk /var (MFS wiped the sentinel).
    assert obs.var_wiped, (
        f"{VAR_WIPE_SENTINEL} survived the reboot — use_mfs_tmpvar did not engage; not a RAM-disk /var"
    )
    # #468 core: pfb_unbound.py re-staged into the chroot after the wipe.
    assert obs.staged_after, (
        f"#468: {PFB_UNBOUND} missing after RAM-disk reboot (not re-staged).\n/var/unbound:\n{obs.var_unbound_ls}"
    )
    # #468 end-state: still sinkholing — matcher rebuilt from the restored manifest, no manual update.
    assert obs.recovered, (
        f"#468: {obs.domain} did not sinkhole again within {RECOVERY_DEADLINE}s of a RAM-disk reboot "
        f"(staged_after={obs.staged_after}); DNSBL stays down until a manual update"
    )
