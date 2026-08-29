"""Issue #468 — DNSBL survives a RAM-disk /var reboot (python integration re-staged).

On a RAM-disk /var (``use_mfs_tmpvar``) a reboot wipes ``/var/unbound``, so DNSBL
came up dead after every reboot. The fix adds a DEDICATED DNSBL cache, independent
of the IP-alias archive: ``pfb_dnsbl_cache('save')`` archives the generated python
integration (``/var/unbound/pfb_unbound*`` + ``pfb_py_*``) whenever DNSBL actually
changes, and a separate boot ``earlyshellcmd`` (``pfblockerng.sh dnsbl_cache
restore``) untars it then re-stages the shipped files — pure file ops, no reload.
Unbound's normal start then loads the restored files.

REPRODUCE-FIRST: assert the domain sinkholes BEFORE the reboot, then require it to
still sinkhole AFTER a RAM-disk reboot (pfb_unbound.py re-staged + matcher rebuilt
from the restored manifest), with NO manual update. Verified RED on pre-fix code.

Issue #1255 rides the SAME reboot cycle: the shipped TLD-Wildcard public-suffix
oracle (``dnsbl_psl``) is archive-EXCLUDED (re-staged fresh from the package
dir by ``dnsbl_cache_stage()``, like ``pfb_py_hsts.txt``) while the ini
(``python_tld_wildcard = on``) rides the archived ``pfb_unbound*`` set -- so a
wildcard-blocked sub-domain must ALSO still sinkhole post-reboot, proving both
halves were restored.

All slow VM I/O (inject -> reload -> reboot -> recovery poll) lives in the MODULE
FIXTURE, never the test body: the smoke workflow caps the test BODY at 30s
(``--timeout=30 timeout_func_only=true``) but fixtures are exempt (same reason the
~2 min deploy + the #334 reboot fixture are). The body is pure assertions.

reboot marker (destructive — reboots the shared session VM). Run::

    python -m pytest tests/smoke/test_smoke_dnsbl_ramdisk_reboot.py \
        -m reboot --override-ini="addopts=" -rA -s
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.reboot

VAR_WIPE_SENTINEL = "/var/PFB_SMOKE_468_WIPE"
PFB_UNBOUND = "/var/unbound/pfb_unbound.py"
PFB_DNSBL_PSL = "/var/unbound/dnsbl_psl"  # issue #1255: PSL authority, archive-EXCLUDED, re-staged
RECOVERY_DEADLINE = 240  # seconds to wait for DNSBL to self-heal post-reboot


@dataclass
class DnsblRebootObservation:
    """DNSBL state captured around one RAM-disk reboot (built in the fixture)."""

    domain: str
    sinkholes_before: bool
    var_wiped: bool
    staged_after: bool
    var_unbound_ls: str
    manifest_raw_refs: list[str]
    manifest_missing_refs: list[str]
    manifest_generation_dirs: list[str]
    recovered: bool
    recovered_after_s: int
    # issue #1255: TLD-Wildcard blocking observed over the SAME reboot cycle.
    wild_sub_domain: str
    wild_sinkholes_before: bool
    tld_oracle_staged_after: bool
    wild_recovered: bool


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
        # Diagnostics FIRST: the revert reboot below wipes the MFS /var this module ran
        # on, so a snapshot taken after it would show a fresh disk-backed /var instead
        # of the module's (possibly failing) end-of-run state.
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)
        # The reboot is REQUIRED (issue #765): set_ramdisk only flips the config flag,
        # so without it the running /var stays MFS and every module that runs after this
        # one on the shared session VM inherits writes that vanish on the next reboot.
        try:
            h.set_ramdisk(smoke_vm, False)
            h.reload(smoke_vm, "update")
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the result
            print(f"[smoke] #468 ramdisk-off teardown failed (non-fatal): {exc}")
        # Own try: a flaky reload above must not skip the reboot — with the flag already
        # flipped off, the reboot alone completes the MFS-to-disk transition.
        try:
            h.reboot_vm(smoke_vm)
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the result
            print(f"[smoke] #468 ramdisk-off teardown reboot failed (non-fatal): {exc}")


@pytest.fixture(scope="module")
def reboot_observation(dnsbl_vm: SmokeVM) -> DnsblRebootObservation:
    """ALL slow VM I/O for the #468 scenario — runs in the fixture (no 30s body cap).

    Given a DNSBL feed blocking a unique domain (TLD-Wildcard ON, so a second listed
      2-label domain wildcard-blocks a never-listed sub-domain too) with RAM-disk
      /var enabled, and both sinkhole (DNSBL works before the reboot),
    When the guest is rebooted (MFS wipes /var/unbound; the boot re-stage runs),
    Then capture: /var really wiped (MFS), pfb_unbound.py re-staged, the TLD-Wildcard
      oracle re-staged, and whether the domain AND the wildcard sub-domain self-recover
      to the sinkhole within RECOVERY_DEADLINE (no manual update).
    """
    vm = dnsbl_vm
    domain = h.unique_domain("pfb468")
    # issue #1255: a 2-label registrable domain -- TLD-Wildcard ON wildcard-blocks it
    # AND every sub-domain; `wild_sub_domain` is never itself listed, so it sinkholing
    # proves the ZONE match survived the reboot, not a coincidental exact hit.
    wild_domain = h.unique_domain("pfb468tld")
    wild_sub_domain = "x." + wild_domain

    # Given: RAM disks ON before the reload; a DNSBL feed blocking `domain` and
    # `wild_domain`, TLD-Wildcard ON, applied.
    h.set_ramdisk(vm, True)
    feed_url = h.write_local_feed(vm, "issue468.txt", f"{domain}\n{wild_domain}\n")
    spec = h.DnsblCase(
        aliasname="smoke468", feed_url=feed_url, header="smoke468", mode=h.DnsblMode.VIP, tld_enabled=True
    )
    h.inject(vm, spec)
    h.reload(vm, "update")
    h.wait_unbound_ready(vm)

    sinkholes_before = _sinkholes(vm, domain)
    wild_sinkholes_before = _sinkholes(vm, wild_sub_domain)

    # MFS proof sentinel, then reboot.
    vm.ssh("/usr/bin/touch", VAR_WIPE_SENTINEL)
    h.reboot_vm(vm)
    h.wait_unbound_ready(vm)

    var_wiped = vm.ssh("test", "-e", VAR_WIPE_SENTINEL).returncode != 0
    staged_after = vm.ssh("test", "-f", PFB_UNBOUND).returncode == 0
    tld_oracle_staged_after = vm.ssh("test", "-f", PFB_DNSBL_PSL).returncode == 0
    var_unbound_ls = vm.ssh("/bin/ls", "-la", "/var/unbound").stdout
    manifest_probe = h.php_eval(
        vm,
        "$m = json_decode(@file_get_contents('/var/unbound/pfb_py_sources.json'), TRUE);\n"
        "$refs = array(); $missing = array(); $dirs = array();\n"
        "foreach (($m['feeds'] ?? array()) as $row) {\n"
        "  $raw = $row['raw'] ?? '';\n"
        "  if (!is_string($raw) || $raw === '') { $missing[] = '<invalid>'; continue; }\n"
        "  $refs[] = $raw; $dirs[dirname($raw)] = TRUE;\n"
        "  if (!is_file('/var/unbound/' . $raw)) { $missing[] = $raw; }\n"
        "}\n"
        "echo '<<PFB1357>>' . json_encode(array(\n"
        "  'refs' => $refs, 'missing' => $missing, 'dirs' => array_keys($dirs)\n"
        ")) . '<<END1357>>';",
        timeout=30.0,
    )
    if manifest_probe.returncode != 0:
        raise RuntimeError(f"#1357 post-MFS manifest probe failed: {manifest_probe.stderr}")
    manifest_state = json.loads(manifest_probe.stdout.split("<<PFB1357>>", 1)[1].split("<<END1357>>", 1)[0])
    print(f"[smoke] #1357 post-MFS manifest refs: {manifest_state}")

    # Poll for self-recovery (pfb_unbound.py staged AND both sinkholes) with NO manual update.
    recovered = False
    wild_recovered = False
    staged_now = False
    recovery_started = time.monotonic()

    def recovery_observed() -> bool:
        nonlocal recovered, staged_now, wild_recovered
        staged_now = vm.ssh("test", "-f", PFB_UNBOUND).returncode == 0
        recovered = recovered or (staged_now and _sinkholes(vm, domain))
        wild_recovered = wild_recovered or (staged_now and _sinkholes(vm, wild_sub_domain))
        return recovered and wild_recovered

    try:
        h.wait_until(recovery_observed, timeout=RECOVERY_DEADLINE, interval=10.0)
    except RuntimeError as exc:
        raise RuntimeError(
            "salvage cap expired / stuck or environment: RAM-disk reboot recovery expected "
            f"recovered=True and wild_recovered=True; observed recovered={recovered} "
            f"wild_recovered={wild_recovered} staged={staged_now}"
        ) from exc
    waited = int(time.monotonic() - recovery_started)

    return DnsblRebootObservation(
        domain=domain,
        sinkholes_before=sinkholes_before,
        var_wiped=var_wiped,
        staged_after=staged_after,
        var_unbound_ls=var_unbound_ls,
        manifest_raw_refs=manifest_state["refs"],
        manifest_missing_refs=manifest_state["missing"],
        manifest_generation_dirs=manifest_state["dirs"],
        recovered=recovered,
        recovered_after_s=waited,
        wild_sub_domain=wild_sub_domain,
        wild_sinkholes_before=wild_sinkholes_before,
        tld_oracle_staged_after=tld_oracle_staged_after,
        wild_recovered=wild_recovered,
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
    # #1357: the archive restores the manifest and its complete immutable raw set
    # before the matcher can self-recover from that manifest.
    assert obs.manifest_raw_refs, "#1357: restored DNSBL manifest has no feed raw references"
    assert obs.manifest_missing_refs == [], (
        f"#1357: restored manifest references missing raws: {obs.manifest_missing_refs!r}\n"
        f"/var/unbound:\n{obs.var_unbound_ls}"
    )
    assert len(obs.manifest_generation_dirs) == 1 and re.fullmatch(
        r"pfb_py_raw\.[0-9a-f]{32}", obs.manifest_generation_dirs[0]
    ), f"#1357: restored raws are not one immutable generation: {obs.manifest_generation_dirs!r}"
    # #468 end-state: still sinkholing — matcher rebuilt from the restored manifest, no manual update.
    assert obs.recovered, (
        f"#468: {obs.domain} did not sinkhole again within {RECOVERY_DEADLINE}s of a RAM-disk reboot "
        f"(staged_after={obs.staged_after}); DNSBL stays down until a manual update"
    )


def test_dnsbl_tld_wildcard_survives_ramdisk_var_reboot(reboot_observation: DnsblRebootObservation) -> None:
    """issue #1255: TLD-Wildcard blocking (oracle + ini) survives a RAM-disk /var reboot.

    Given TLD-Wildcard ON wildcard-blocks a never-listed sub-domain of a listed
    2-label domain BEFORE the reboot,
    When the RAM-disk /var reboot wipes /var/unbound,
    Then the shipped oracle is re-staged fresh (``dnsbl_cache_stage()``, archive-
    EXCLUDED like ``pfb_py_hsts.txt``) and the archived ini (``python_tld_wildcard =
    on``) is restored, so the sub-domain STILL sinkholes with NO manual update.
    """
    obs = reboot_observation

    # Precondition: the wildcard ZONE covered the sub-domain BEFORE the reboot.
    assert obs.wild_sinkholes_before, (
        f"precondition: {obs.wild_sub_domain} must sinkhole (TLD-Wildcard ON) before the reboot"
    )
    # issue #1255 core: the shipped oracle re-staged into the chroot after the wipe.
    assert obs.tld_oracle_staged_after, (
        f"issue #1255: {PFB_DNSBL_PSL} missing after RAM-disk reboot (TLD-Wildcard oracle not re-staged)."
        f"\n/var/unbound:\n{obs.var_unbound_ls}"
    )
    # End-state: still sinkholing — the wildcard ZONE survived the reboot, no manual update.
    assert obs.wild_recovered, (
        f"issue #1255: {obs.wild_sub_domain} did not sinkhole again within {RECOVERY_DEADLINE}s of a "
        f"RAM-disk reboot (oracle_staged={obs.tld_oracle_staged_after}); TLD-Wildcard blocking stays "
        "down until a manual update"
    )
