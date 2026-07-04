"""ADR-35 — live-VM smoke coverage for managed firewall object ownership and teardown.

Proves on a real pfSense CE VM that:

* Enable → the pfBlockerNG-owned sinkhole VIP (``pfB_AUTO_VIP_v4``) and DNSBL NAT
  rule (``pfB DNSBL - DO NOT EDIT``) are created in config.xml. (The harness
  provisions only the v4 auto-VIP; the symmetric v6 path is pinned off-box by
  ``DnsblMarkedVipTest``.)
* Disable → the VIP and NAT are removed; no pfB-owned VIP of either family remains.
* Uninstall → a seeded ORPHAN VIP is swept (before-and-after); user-created VIP
  and NAT rule survive; ``installedpackages/pfblockerng*`` sections are gone.

Config.xml assertions are done via the pfSense config API (``php_eval`` /
``config_get_path`` / ``marked_vip_subnet``), following the smoke-suite pattern —
never reading the file directly. VIP/NAT assertions are config.xml reads, not DNS
probes; ``helpers.unique_domain()`` is not needed here.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``). Run
only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and the
smoke deps; without them they skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

# Package name on the devel channel (matches test_repo_install.py's PKG_NAME).
_PKG_NAME = "pfSense-pkg-pfBlockerNG-devel"

# Descr markers that identify pfBlockerNG-owned objects (mirrors pfb_is_managed_obj in pfblockerng.inc).
_AUTO_VIP_DESCR_V4 = "pfB_AUTO_VIP_v4"
_AUTO_VIP_DESCR_V6 = "pfB_AUTO_VIP_v6"
_DNSBL_NAT_DESCR_PFX = "pfB DNSBL"  # pfb_create_dnsbl uses 'pfB DNSBL - DO NOT EDIT'

# User-object descriptors seeded in Scenario C to prove they survive uninstall.
_USER_VIP_DESCR = "my-test-user-vip-do-not-delete"
_USER_NAT_DESCR = "my-test-user-nat-do-not-delete"


# --------------------------------------------------------------------------- #
# Module-scoped deployed_vm: install the branch .pkg once for all three tests
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(  # noqa: ARG001
    smoke_vm: SmokeVM,
    stub_dns: _StubDnsServer,
    lan_interface: SmokeVM,
) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the managed-objects module.

    Depends on ``lan_interface`` to ensure a LAN VLAN subinterface is
    provisioned before these tests run (the single-NIC smoke image boots with
    no LAN assigned; these tests create LAN-scoped VIP and NAT rules).

    Egress stays OPEN across reloads: ``pkg add`` pulls RUN_DEPENDS and the
    DNSBL update path runs ``pfb_create_dnsbl`` which touches pfSense state.
    ``ensure_dnsbl_vip`` + ``use_system_dns_upstream`` give DNSBL a sinkhole
    VIP and a reachable upstream so the full update completes cleanly.

    The master switch ``enable_cb`` is turned ON here so DNSBL ``$mode`` can
    reach ``'enabled'`` (the enable chain is ``enable_cb`` AND ``pfb_dnsbl`` AND
    the resolver up). The per-test toggles then flip ``pfb_dnsbl`` /
    ``pfb_dnsvip_auto`` / the interface. Without this the module silently relied
    on an earlier test in the full fan-out leaking ``enable_cb='on'`` — so the
    managed-object legs failed when run in isolation (the #487 selective-dispatch
    leg).
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.set_package_enabled(smoke_vm, True)
    h.use_system_dns_upstream(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


@pytest.fixture(autouse=True)
def _ensure_pkg_installed(deployed_vm: SmokeVM) -> None:
    """Redeploy the package if a prior test in this module uninstalled it.

    The uninstall scenarios ``pkg delete`` the package mid-module; without this,
    every subsequent test under the module-scoped ``deployed_vm`` would fail to
    reload ('Could not open input file ... pfblockerng.php'). Cheap install-state
    probe; redeploy + re-seed only when the package is actually missing.
    """
    if not h.pkg_installed(deployed_vm):
        h.deploy(deployed_vm)
        h.snapshot_unbound_conf(deployed_vm)
        h.ensure_dnsbl_vip(deployed_vm)
        h.set_package_enabled(deployed_vm, True)
        h.use_system_dns_upstream(deployed_vm)


# --------------------------------------------------------------------------- #
# Internal helpers for config.xml VIP / NAT / section reads
# --------------------------------------------------------------------------- #


def _vip_descr_present(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> bool:
    """True iff ``virtualip/vip[]`` contains an entry whose ``descr`` == ``descr``."""
    return h.marked_vip_subnet(vm, descr, timeout=timeout) != ""


def _nat_pfb_dnsbl_present(vm: SmokeVM, *, timeout: float = 60.0) -> bool:
    """True iff ``nat/rule[]`` contains an entry whose ``descr`` starts with 'pfB DNSBL'."""
    pre = (
        "$found = FALSE;\n"
        "foreach (config_get_path('nat/rule', array()) as $r) {\n"
        f"  if (strpos((string) ($r['descr'] ?? ''), {h._php_str(_DNSBL_NAT_DESCR_PFX)}) !== FALSE)"
        "  { $found = TRUE; break; }\n"
        "}"
    )
    val = h._php_read_scalar(vm, pre, "$found ? 'yes' : 'no'", timeout=timeout)
    return val == "yes"


def _pfb_sections_present(vm: SmokeVM, *, timeout: float = 60.0) -> bool:
    """True iff any ``installedpackages/pfblockerng*`` section survives in config.xml."""
    pre = (
        "$found = FALSE;\n"
        "$all = config_get_path('installedpackages', array());\n"
        "foreach (array_keys($all) as $k) {\n"
        "  if (strpos((string) $k, 'pfblockerng') === 0) { $found = TRUE; break; }\n"
        "}"
    )
    val = h._php_read_scalar(vm, pre, "$found ? 'yes' : 'no'", timeout=timeout)
    return val == "yes"


def _seed_user_vip(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> None:
    """Inject a minimal user VIP row (descr-only sentinel; no real subnet needed)."""
    snippet = (
        "$vips = config_get_path('virtualip/vip', array());\n"
        "$found = FALSE;\n"
        f"foreach ($vips as $v) {{\n"
        f"  if (($v['descr'] ?? '') === {h._php_str(descr)}) {{ $found = TRUE; break; }}\n"
        "}\n"
        "if (!$found) {\n"
        "  $vips[] = array(\n"
        f"    'descr' => {h._php_str(descr)},\n"
        "    'mode' => 'ipalias',\n"
        "    'interface' => 'lo0',\n"
        "    'type' => 'single',\n"
        "    'subnet' => '127.0.0.200',\n"
        "    'subnet_bits' => '32',\n"
        "    'uniqid' => 'pfbusrvip',\n"
        "  );\n"
        "  config_set_path('virtualip/vip', $vips);\n"
        "  write_config('pfBlockerNG smoke: seed user VIP');\n"
        "}\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_user_vip({descr!r}) failed: {result.returncode} {result.stderr!r}")


def _seed_user_nat(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> None:
    """Inject a minimal user NAT rule row (descr-only sentinel; no real rule needed)."""
    snippet = (
        "$rules = config_get_path('nat/rule', array());\n"
        "$found = FALSE;\n"
        f"foreach ($rules as $r) {{\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{ $found = TRUE; break; }}\n"
        "}\n"
        "if (!$found) {\n"
        "  $rules[] = array(\n"
        f"    'descr' => {h._php_str(descr)},\n"
        "    'interface' => 'lo0',\n"
        "    'protocol' => 'tcp',\n"
        "    'destination' => array('any' => TRUE),\n"
        "    'target' => '127.0.0.200',\n"
        "    'created' => array('time' => '0'),\n"
        "    'updated' => array('time' => '0'),\n"
        "  );\n"
        "  config_set_path('nat/rule', $rules);\n"
        "  write_config('pfBlockerNG smoke: seed user NAT');\n"
        "}\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_user_nat({descr!r}) failed: {result.returncode} {result.stderr!r}")


def _remove_vip_by_descr(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> None:
    """Remove any ``virtualip/vip`` row with this descr — idempotent (no-op if already gone).

    Scenario C/D seed a USER (non-pfB-owned) VIP to prove the uninstall sweep leaves it
    alone; that means the sweep never cleans it up, so the test must (issue #582).
    """
    snippet = (
        "$vips = config_get_path('virtualip/vip', array());\n"
        f"$kept = array_values(array_filter($vips, function ($v) {{\n"
        f"  return ($v['descr'] ?? '') !== {h._php_str(descr)};\n"
        "}));\n"
        "config_set_path('virtualip/vip', $kept);\n"
        "write_config('pfBlockerNG smoke: remove seeded user VIP');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_remove_vip_by_descr({descr!r}) failed: {result.returncode} {result.stderr!r}")


def _remove_nat_by_descr(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> None:
    """Remove any ``nat/rule`` row with this descr — idempotent (no-op if already gone).

    Scenario C/D seed a USER (non-pfB-owned) NAT rule to prove the uninstall sweep leaves
    it alone; that means the sweep never cleans it up, so the test must (issue #582).
    """
    snippet = (
        "$rules = config_get_path('nat/rule', array());\n"
        f"$kept = array_values(array_filter($rules, function ($r) {{\n"
        f"  return ($r['descr'] ?? '') !== {h._php_str(descr)};\n"
        "}));\n"
        "config_set_path('nat/rule', $kept);\n"
        "write_config('pfBlockerNG smoke: remove seeded user NAT');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_remove_nat_by_descr({descr!r}) failed: {result.returncode} {result.stderr!r}")


def _seed_orphan_vip(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> None:
    """Inject an orphan VIP: carries the pfBlockerNG marker but pfb_dnsvip4 is cleared.

    The VIP double-guard in pfb_manage_dnsbl_vip checks that the VIP's subnet ==
    the address stored in pfb_dnsvip4/pfb_dnsvip6. With pfb_dnsvip4 cleared the
    guard would SKIP this entry, making it a genuine orphan that only the ADR-35
    marker sweep can catch. The sweep reads descr only — so the orphan IS swept
    despite the double-guard miss.
    """
    snippet = (
        # 1. Clear the pfb_dnsvip4 reference so the double-guard cannot match.
        f"$d = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        "unset($d['pfb_dnsvip4']);\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $d);\n"
        # 2. Inject the orphan VIP with the pfBlockerNG marker.
        "$vips = config_get_path('virtualip/vip', array());\n"
        "$found = FALSE;\n"
        f"foreach ($vips as $v) {{\n"
        f"  if (($v['descr'] ?? '') === {h._php_str(descr)}) {{ $found = TRUE; break; }}\n"
        "}\n"
        "if (!$found) {\n"
        "  $vips[] = array(\n"
        f"    'descr' => {h._php_str(descr)},\n"
        "    'mode' => 'ipalias',\n"
        "    'interface' => 'lo0',\n"
        "    'type' => 'single',\n"
        "    'subnet' => '10.10.10.99',\n"
        "    'subnet_bits' => '32',\n"
        "    'uniqid' => 'pfborphanvip',\n"
        "  );\n"
        "  config_set_path('virtualip/vip', $vips);\n"
        "}\n"
        "write_config('pfBlockerNG smoke: seed orphan VIP');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_orphan_vip({descr!r}) failed: {result.returncode} {result.stderr!r}")


def _pkg_delete(vm: SmokeVM, *, timeout: float = 300.0) -> None:
    """Uninstall the package via ``pkg delete`` (triggers pre-deinstall sweep).

    Captures stdout/stderr, asserts rc==0, and prints output on failure so
    diagnostics are visible in CI logs.
    """
    # Dump pkg info before delete so diagnostics show what was installed.
    info = vm.ssh("pkg", "info", _PKG_NAME, timeout=30.0)
    if info.returncode != 0:
        print(
            f"[_pkg_delete] pkg info {_PKG_NAME!r} before delete — not registered"
            f" (rc={info.returncode}):\n{info.stdout}\n{info.stderr}"
        )

    result = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y", _PKG_NAME, timeout=timeout)
    if result.returncode != 0:
        print(
            f"[_pkg_delete] pkg delete failed rc={result.returncode}\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}"
        )
        raise AssertionError(f"pkg delete {_PKG_NAME!r} returned rc={result.returncode} (expected 0)")


# --------------------------------------------------------------------------- #
# Scenario A — enable → VIP + NAT present in config.xml
# --------------------------------------------------------------------------- #


def test_managed_objects_enable_creates_vip_and_nat(deployed_vm: SmokeVM) -> None:
    """ADR-35 Scenario A: enabling DNSBL with pfb_dnsvip_auto creates pfB-owned objects.

    Scenario: enable creates pfB-owned VIP and DNSBL NAT.
      Background: pfBlockerNG installed; auto-VIP feature enabled.

      Given pfb_dnsvip_auto is OFF and DNSBL is disabled,
        Then pfB_AUTO_VIP_v4 is absent from virtualip/vip[] (before-state).
        And no nat/rule[] entry has a 'pfB DNSBL' descr prefix (before-state).

      When pfb_dnsvip_auto is toggled ON and DNSBL is enabled, then a full reload runs,

      Then virtualip/vip[] contains an entry with descr='pfB_AUTO_VIP_v4'.
        And nat/rule[] contains an entry whose descr starts with 'pfB DNSBL'.
    """
    vm = deployed_vm
    try:
        # GIVEN — disable DNSBL, auto-VIP off; assert the before-state.
        h.set_dnsvip_auto(vm, False)
        h.set_dnsbl_enabled(vm, False)
        h.reload(vm, "update")

        assert not _vip_descr_present(vm, _AUTO_VIP_DESCR_V4), (
            "pfB_AUTO_VIP_v4 present before enable — before-state is not clean" + f"\n{h.fwobj_state_snapshot(vm)}"
        )
        assert not _nat_pfb_dnsbl_present(vm), (
            "pfB DNSBL NAT rule present before enable — before-state is not clean" + f"\n{h.fwobj_state_snapshot(vm)}"
        )

        # WHEN — set dnsbl_interface to 'lan' (NAT is only emitted when iface != 'lo0'),
        # enable auto-VIP + DNSBL, and run a full reload.
        h.set_dnsbl_interface(vm, "lan")
        h.set_dnsvip_auto(vm, True)
        h.set_dnsbl_enabled(vm, True)
        h.reload(vm, "update")

        # THEN — both owned objects must now be present.
        assert _vip_descr_present(vm, _AUTO_VIP_DESCR_V4), (
            "pfB_AUTO_VIP_v4 not created in virtualip/vip after enabling DNSBL + auto-VIP"
            + f"\n{h.fwobj_state_snapshot(vm)}"
        )
        assert _nat_pfb_dnsbl_present(vm), (
            "pfB DNSBL NAT rule not created in nat/rule after enabling DNSBL" + f"\n{h.fwobj_state_snapshot(vm)}"
        )
    finally:
        # Restore to a known baseline so Scenario B and C start clean.
        h.set_dnsbl_interface(vm, "lo0")
        h.set_dnsvip_auto(vm, False)
        h.set_dnsbl_enabled(vm, False)
        h.ensure_dnsbl_vip(vm)
        h.reload(vm, "update")


# --------------------------------------------------------------------------- #
# Scenario B — disable → VIP + NAT removed from config.xml
# --------------------------------------------------------------------------- #


def test_managed_objects_disable_removes_vip_and_nat(deployed_vm: SmokeVM) -> None:
    """ADR-35 Scenario B: disabling DNSBL removes pfB-owned VIP and DNSBL NAT.

    Scenario: disable removes pfB-owned VIP and DNSBL NAT.

      Given DNSBL is enabled with pfb_dnsvip_auto ON (auto-VIP in config.xml),
        And pfB_AUTO_VIP_v4 is present in virtualip/vip[] (before-state),
        And a pfB DNSBL NAT entry is present in nat/rule[] (before-state),

      When DNSBL is disabled and a full reload runs,

      Then virtualip/vip[] has NO entry with a pfB-owned marker.
        And nat/rule[] has NO entry whose descr starts with 'pfB DNSBL'.
    """
    vm = deployed_vm
    try:
        # GIVEN — set dnsbl_interface to 'lan' (NAT is only emitted when iface != 'lo0'),
        # enable auto-VIP + DNSBL; assert both objects present (before-state).
        h.set_dnsbl_interface(vm, "lan")
        h.set_dnsvip_auto(vm, True)
        h.set_dnsbl_enabled(vm, True)
        h.reload(vm, "update")

        assert _vip_descr_present(vm, _AUTO_VIP_DESCR_V4), (
            "pfB_AUTO_VIP_v4 absent before disable — before-state setup failed" + f"\n{h.fwobj_state_snapshot(vm)}"
        )
        assert _nat_pfb_dnsbl_present(vm), (
            "pfB DNSBL NAT absent before disable — before-state setup failed" + f"\n{h.fwobj_state_snapshot(vm)}"
        )

        # WHEN — disable DNSBL and reload.
        h.set_dnsbl_enabled(vm, False)
        h.reload(vm, "update")

        # THEN — both must be gone.
        assert not _vip_descr_present(vm, _AUTO_VIP_DESCR_V4), (
            "pfB_AUTO_VIP_v4 still present in config.xml after disabling DNSBL"
        )
        assert not _vip_descr_present(vm, _AUTO_VIP_DESCR_V6), (
            "pfB_AUTO_VIP_v6 still present in config.xml after disabling DNSBL"
        )
        assert not _nat_pfb_dnsbl_present(vm), "pfB DNSBL NAT still present in nat/rule after disabling DNSBL"
    finally:
        h.set_dnsbl_interface(vm, "lo0")
        h.set_dnsvip_auto(vm, False)
        h.set_dnsbl_enabled(vm, False)
        h.ensure_dnsbl_vip(vm)
        h.reload(vm, "update")


# --------------------------------------------------------------------------- #
# Scenario B2 — pfb_dnsbl_nonat opt-out skips NAT creation (issue #381)
# --------------------------------------------------------------------------- #


def test_managed_objects_nonat_skips_nat(deployed_vm: SmokeVM) -> None:
    """Issue #381 Scenario B2: pfb_dnsbl_nonat=on skips the managed DNSBL NAT rule.

    Scenario: DNSBL NAT opt-out prevents pfB DNSBL port-forward creation.
      Background: pfBlockerNG installed; DNSBL interface set to lan.

      Given pfb_dnsbl_nonat is OFF, DNSBL is disabled, and interface is lo0,
        Then no nat/rule[] entry starts with 'pfB DNSBL' (before-state is clean).

      When pfb_dnsbl_nonat is OFF, interface=lan, auto-VIP ON, and DNSBL is enabled,
        Then nat/rule[] CONTAINS a 'pfB DNSBL' entry — the NAT is created by default.
        (This is the before-state for the opt-out; it would remain True on pre-fix code.)

      Then (opt-out ON) pfb_dnsbl_nonat is set ON and a reload runs,
        Then nat/rule[] has NO 'pfB DNSBL' entry — the managed NAT is removed.
        (This assertion is RED on pre-fix code where the toggle is ignored.)
    """
    vm = deployed_vm
    try:
        # GIVEN — baseline: DNSBL off, opt-out cleared, interface lo0.
        h.set_dnsbl_nonat(vm, False)
        h.set_dnsbl_interface(vm, "lo0")
        h.set_dnsbl_enabled(vm, False)
        h.reload(vm, "update")

        assert not _nat_pfb_dnsbl_present(vm), (
            "pfB DNSBL NAT present before test — before-state is not clean" + f"\n{h.fwobj_state_snapshot(vm)}"
        )

        # WHEN (opt-out OFF) — enable DNSBL on lan with auto-VIP: NAT must be created.
        h.set_dnsbl_interface(vm, "lan")
        h.set_dnsvip_auto(vm, True)
        h.set_dnsbl_nonat(vm, False)
        h.set_dnsbl_enabled(vm, True)
        h.reload(vm, "update")

        assert _nat_pfb_dnsbl_present(vm), (
            "pfB DNSBL NAT not created when pfb_dnsbl_nonat=off — default NAT path broken"
            + f"\n{h.fwobj_state_snapshot(vm)}"
        )

        # THEN (opt-out ON) — flip pfb_dnsbl_nonat and reload: NAT must be gone.
        h.set_dnsbl_nonat(vm, True)
        h.reload(vm, "update")

        assert not _nat_pfb_dnsbl_present(vm), (
            "pfB DNSBL NAT still present after pfb_dnsbl_nonat=on reload"
            " — expected: no pfB DNSBL nat/rule[]; actual:" + f"\n{h.fwobj_state_snapshot(vm)}"
        )
    finally:
        h.set_dnsbl_nonat(vm, False)
        h.set_dnsbl_interface(vm, "lo0")
        h.set_dnsvip_auto(vm, False)
        h.set_dnsbl_enabled(vm, False)
        h.ensure_dnsbl_vip(vm)
        h.reload(vm, "update")


# --------------------------------------------------------------------------- #
# Scenario C — orphan + user objects on uninstall
# --------------------------------------------------------------------------- #


def test_managed_objects_uninstall_sweeps_orphan_preserves_user_objects(deployed_vm: SmokeVM) -> None:
    """ADR-35 Scenario C: uninstall sweeps the orphan VIP; user VIP and NAT survive.

    Scenario: uninstall sweeps orphan, preserves user objects.

      Given an ORPHAN VIP (descr='pfB_AUTO_VIP_v4', pfb_dnsvip4 cleared so
            the double-guard cannot match it) is present in virtualip/vip[],
        And a USER VIP (descr='my-test-user-vip-do-not-delete') is present,
        And a USER NAT rule (descr='my-test-user-nat-do-not-delete') is present,
        And all three are confirmed in config.xml (before-state asserted),

      When pfBlockerNG is uninstalled via 'pkg delete',

      Then the orphan VIP is GONE from virtualip/vip[] (swept by ADR-35 deinstall sweep).
        And the user VIP is STILL PRESENT in virtualip/vip[] (not a pfB marker).
        And the user NAT rule is STILL PRESENT in nat/rule[] (not a pfB marker).
        And installedpackages/pfblockerng* sections are GONE from config.xml.
    """
    vm = deployed_vm

    # GIVEN — select the full-removal uninstall path (pfb_keep defaults to 'on'; a test that
    # asserts sections-gone must set pfb_keep=off explicitly — see issue #484).
    h.set_pfb_keep(vm, False)
    # GIVEN — seed the three objects; first confirm DNSBL is disabled / clean.
    h.set_dnsbl_enabled(vm, False)
    h.set_dnsvip_auto(vm, False)
    h.reload(vm, "update")

    # Seed the orphan VIP (pfB marker, but pfb_dnsvip4 cleared so the double-guard
    # in pfb_manage_dnsbl_vip would skip it — only the ADR-35 sweep catches it).
    # The USER VIP/NAT (below) are deliberately NOT pfB-owned, so the uninstall sweep
    # never removes them (that is the behaviour under test) — everything from here on
    # is wrapped so the finally can remove them itself; otherwise they leak into
    # config.xml as permanent generic pfSense rows for every later test/module sharing
    # this guest (issue #582).
    try:
        _seed_orphan_vip(vm, _AUTO_VIP_DESCR_V4)

        # Seed user objects (no pfB marker — must survive uninstall).
        _seed_user_vip(vm, _USER_VIP_DESCR)
        _seed_user_nat(vm, _USER_NAT_DESCR)

        # BEFORE-STATE: assert all three are present.
        assert _vip_descr_present(vm, _AUTO_VIP_DESCR_V4), (
            "orphan VIP (pfB_AUTO_VIP_v4) not present before uninstall — seeding failed"
        )
        assert _vip_descr_present(vm, _USER_VIP_DESCR), "user VIP not present before uninstall — seeding failed"

        # Check user NAT is present.
        pre = (
            "$found = FALSE;\n"
            "foreach (config_get_path('nat/rule', array()) as $r) {\n"
            f"  if (($r['descr'] ?? '') === {h._php_str(_USER_NAT_DESCR)}) {{ $found = TRUE; break; }}\n"
            "}"
        )
        user_nat_before = h._php_read_scalar(vm, pre, "$found ? 'yes' : 'no'")
        assert user_nat_before == "yes", "user NAT rule not present before uninstall — seeding failed"

        # Assert installedpackages/pfblockerng* sections exist before uninstall.
        assert _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* absent before uninstall — unexpected clean state"
        )

        # WHEN — uninstall pfBlockerNG (triggers pfblockerng_php_pre_deinstall_command →
        # owned-object sweep before pfb_remove_config_settings).
        _pkg_delete(vm)

        # THEN — read config.xml state after uninstall.
        # The orphan VIP must be swept by the owned-object sweep.
        assert not _vip_descr_present(vm, _AUTO_VIP_DESCR_V4), (
            "orphan pfB_AUTO_VIP_v4 still present after uninstall — ADR-35 sweep did not run"
        )

        # User VIP must survive (not a pfB marker — never swept).
        assert _vip_descr_present(vm, _USER_VIP_DESCR), (
            "user VIP was DELETED during uninstall — ADR-35 sweep incorrectly removed a user object"
        )

        # User NAT rule must survive.
        post_nat = (
            "$found = FALSE;\n"
            "foreach (config_get_path('nat/rule', array()) as $r) {\n"
            f"  if (($r['descr'] ?? '') === {h._php_str(_USER_NAT_DESCR)}) {{ $found = TRUE; break; }}\n"
            "}"
        )
        user_nat_after = h._php_read_scalar(vm, post_nat, "$found ? 'yes' : 'no'")
        assert user_nat_after == "yes", (
            "user NAT rule was DELETED during uninstall — ADR-35 sweep incorrectly removed a user object"
        )

        # pfBlockerNG config sections must be gone.
        assert not _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* still present after uninstall — pfb_remove_config_settings did not run"
        )
    finally:
        _remove_vip_by_descr(vm, _USER_VIP_DESCR)
        _remove_nat_by_descr(vm, _USER_NAT_DESCR)


# --------------------------------------------------------------------------- #
# Scenario D — uninstall keep=on: live objects gone; sections retained (#484)
# --------------------------------------------------------------------------- #


def test_managed_objects_uninstall_keep_on_removes_orphan_retains_sections(deployed_vm: SmokeVM) -> None:
    """ADR-35 / issue #484 Scenario D: uninstall with keep=on removes orphan VIP but retains sections.

    Scenario: uninstall keep=on — live pfB-owned objects torn down unconditionally;
    user objects and settings sections retained because pfb_keep=on.

      Given pfb_keep is set to 'on' (retain settings + data on uninstall),
        And an ORPHAN VIP (descr='pfB_AUTO_VIP_v4', pfb_dnsvip4 cleared) is present in
            virtualip/vip[] (before-state),
        And a USER VIP (descr='my-test-user-vip-do-not-delete') is present (before-state),
        And a USER NAT rule (descr='my-test-user-nat-do-not-delete') is present (before-state),
        And installedpackages/pfblockerng* sections are present (before-state),

      When pfBlockerNG is uninstalled via 'pkg delete',

      Then the orphan VIP is GONE from virtualip/vip[] (live-object sweep is unconditional).
        And the user VIP is STILL PRESENT in virtualip/vip[] (not a pfB marker; never swept).
        And the user NAT rule is STILL PRESENT in nat/rule[] (not a pfB marker; never swept).
        And installedpackages/pfblockerng* sections are STILL PRESENT (pfb_keep=on retains them).

      This is the core #484 fix: before the fix the deinstall keep-gate blocked the live-object
      sweep entirely, so pfB-owned objects were left behind on uninstall when keep='on'.
      After the fix, live-object teardown runs unconditionally; pfb_keep gates only
      the settings/data removal.
    """
    vm = deployed_vm

    # GIVEN — set keep=on; confirm DNSBL is disabled; seed orphan + user objects.
    h.set_pfb_keep(vm, True)
    h.set_dnsbl_enabled(vm, False)
    h.set_dnsvip_auto(vm, False)
    h.reload(vm, "update")

    # The USER VIP/NAT (seeded below) are deliberately NOT pfB-owned, so the uninstall
    # sweep never removes them (that is the behaviour under test) — wrapped so the
    # finally can remove them itself; otherwise they leak into config.xml as permanent
    # generic pfSense rows for every later test/module sharing this guest (issue #582).
    try:
        _seed_orphan_vip(vm, _AUTO_VIP_DESCR_V4)
        _seed_user_vip(vm, _USER_VIP_DESCR)
        _seed_user_nat(vm, _USER_NAT_DESCR)

        # BEFORE-STATE: assert all objects present.
        assert _vip_descr_present(vm, _AUTO_VIP_DESCR_V4), (
            "orphan VIP (pfB_AUTO_VIP_v4) not present before keep=on uninstall — seeding failed"
        )
        assert _vip_descr_present(vm, _USER_VIP_DESCR), "user VIP not present before keep=on uninstall — seeding failed"

        pre_nat = (
            "$found = FALSE;\n"
            "foreach (config_get_path('nat/rule', array()) as $r) {\n"
            f"  if (($r['descr'] ?? '') === {h._php_str(_USER_NAT_DESCR)}) {{ $found = TRUE; break; }}\n"
            "}"
        )
        assert h._php_read_scalar(vm, pre_nat, "$found ? 'yes' : 'no'") == "yes", (
            "user NAT rule not present before keep=on uninstall — seeding failed"
        )
        assert _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* absent before keep=on uninstall — unexpected clean state"
        )

        # WHEN — uninstall pfBlockerNG with pfb_keep=on.
        _pkg_delete(vm)

        # THEN — orphan VIP is GONE (live-object sweep is unconditional, regardless of pfb_keep).
        assert not _vip_descr_present(vm, _AUTO_VIP_DESCR_V4), (
            "orphan pfB_AUTO_VIP_v4 still present after keep=on uninstall — "
            "live-object teardown did not run unconditionally (the #484 bug: keep-gate blocked the sweep)\n"
            + h.deinstall_debug(vm)
        )

        # THEN — user VIP survives (not a pfB marker — never swept).
        assert _vip_descr_present(vm, _USER_VIP_DESCR), (
            "user VIP was DELETED during keep=on uninstall — sweep incorrectly removed a user object"
        )

        # THEN — user NAT rule survives.
        post_nat = (
            "$found = FALSE;\n"
            "foreach (config_get_path('nat/rule', array()) as $r) {\n"
            f"  if (($r['descr'] ?? '') === {h._php_str(_USER_NAT_DESCR)}) {{ $found = TRUE; break; }}\n"
            "}"
        )
        assert h._php_read_scalar(vm, post_nat, "$found ? 'yes' : 'no'") == "yes", (
            "user NAT rule was DELETED during keep=on uninstall — sweep incorrectly removed a user object"
        )

        # THEN — pfblockerng* sections are STILL PRESENT (pfb_keep=on retains settings + data).
        assert _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* GONE after keep=on uninstall — "
            "pfb_keep=on should have retained settings sections (the #484 fix: keep gates only settings/data)"
        )
    finally:
        _remove_vip_by_descr(vm, _USER_VIP_DESCR)
        _remove_nat_by_descr(vm, _USER_NAT_DESCR)
