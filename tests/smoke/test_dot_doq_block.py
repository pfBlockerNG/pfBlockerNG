"""ADR-37 — live-VM smoke coverage for optional DoT/DoQ BLOCK on port 853.

Proves on a real pfSense CE VM that:

* **Case 1 (Enable path):** enabling DoT/DoQ block on the primary non-WAN interface
  creates exactly one ``filter/rule`` entry (``pfB_DoT_Block_<iface>``) with the
  correct §2.2 field values; ``pfctl -sr`` confirms the block rule is active with
  the self-exempt guard.
* **Case 2 (Disable path):** disabling removes all ``pfB_DoT_Block_*`` entries
  from ``filter/rule``; ``pfctl -sr`` shows no pfBlockerNG port-853 block rules.
* **Case 3 (User-rule survival):** a user ``filter/rule`` entry (no pfB marker)
  survives enable → disable → uninstall without modification.
* **Case 4 (Stale-interface prune):** enabling on two interfaces then reducing to
  one removes the dropped-interface rule while keeping the retained-interface rule.
  Skipped when the VM exposes fewer than two non-WAN interfaces.
* **Case 5 (Exception alias branch):** enabling with a non-empty alias name wires
  a negated-alias source in config.xml; clearing the alias switches the source to
  ``<any>`` — both branches asserted.
* **Case 6 (Uninstall sweep):** uninstalling the package with block enabled sweeps
  all ``pfB_DoT_Block_*`` entries while a user filter rule survives and
  ``installedpackages/pfblockerng*`` sections are removed.
* **Case 7 (Self-exempt guard):** ``pfctl -sr`` output contains the block rule for
  port 853 and the rule includes the ``self``-negation token confirming the
  firewall-self exemption is active.
* **Rule Action selector:** the action field flips the rule ``type`` — default
  ``reject`` (before-state) switches to ``block`` when the selector is set.
* **Floating mode:** the Floating Rule option replaces the per-interface rule(s) with a
  single floating rule (``floating=yes``, ``direction=in``) over the selected interfaces.

Cases 1–3 and 5–7 require at least one non-WAN interface and skip cleanly on a
WAN-only VM (e.g. the default smoke image). The interface is discovered at runtime
via ``_discover_non_wan_ifaces()`` — never hardcoded.

All cases use config.xml reads via the pfSense config API (``php_eval`` /
``config_get_path``). ``pfctl -sr`` confirmation is the on-box live gate for
Cases 1, 2, and 7. Full client-to-:853 block behaviour (a second host attempting a
TCP connection to an external :853 server and being dropped) requires a second host
and is a documented maintainer manual-smoke item (ADR-37 §7) — not a CI gate.

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

# Package name on the devel channel (matches test_dns_redirect.py).
_PKG_NAME = "pfSense-pkg-pfBlockerNG-devel"

# Marker prefix for DoT/DoQ-block owned rules (mirrors PFB_DOT_BLOCK_DESCR_PFX).
_DOT_BLOCK_DESCR_PFX = "pfB_DoT_Block_"

# Marker for the single floating DoT/DoQ-block rule (mirrors PFB_DOT_BLOCK_FLOATING_DESCR).
_DOT_BLOCK_FLOATING_DESCR = "pfB_DoT_Block_Floating"

# User filter rule descriptor seeded in Cases 3 and 6 to prove survival.
_USER_FILTER_DESCR = "my-user-filter-dot-block-smoke"

# A synthetic alias name used in Case 5 (must pass is_validaliasname).
_EXCEPTION_ALIAS = "DoT_Exceptions_Test"


# --------------------------------------------------------------------------- #
# Module-scoped deployed_vm: install the branch .pkg once for all cases
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for the dot_doq_block module.

    Egress stays OPEN across reloads: ``pkg add`` pulls RUN_DEPENDS from the
    pfSense repo. ``ensure_dnsbl_vip`` gives DNSBL a sinkhole VIP (required for
    the package to accept a reload). ``use_system_dns_upstream`` points Unbound
    at the runner-side mock so the DNSBL update path completes cleanly.
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
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


@pytest.fixture(autouse=True)
def _ensure_pkg_installed(deployed_vm: SmokeVM) -> None:
    """Redeploy the package if a prior test in this module uninstalled it.

    The uninstall cases ``pkg delete`` the package mid-module; without this,
    every subsequent test under the module-scoped ``deployed_vm`` would fail to
    reload ('Could not open input file ... pfblockerng.php'). Cheap install-state
    probe; redeploy + re-seed only when the package is actually missing.
    """
    if not h.pkg_installed(deployed_vm):
        h.deploy(deployed_vm)
        h.snapshot_unbound_conf(deployed_vm)
        h.ensure_dnsbl_vip(deployed_vm)
        h.use_system_dns_upstream(deployed_vm)


@pytest.fixture(scope="module")
def primary_iface(deployed_vm: SmokeVM) -> str:
    """Return the first discovered non-WAN interface short name.

    Skips the test (and any test that uses this fixture) when the VM has no
    non-WAN interfaces — e.g. the default smoke image which has WAN only.
    The set matches what ``pfb_build_if_list(FALSE, FALSE)`` returns.
    """
    available = _discover_non_wan_ifaces(deployed_vm)
    if not available:
        pytest.skip("requires ≥1 non-WAN interface; VM is WAN-only")
    return available[0]


# --------------------------------------------------------------------------- #
# Internal helpers — config.xml queries for DoT/DoQ block state
# --------------------------------------------------------------------------- #


def _filter_dot_block_count(vm: SmokeVM, descr_prefix: str, *, timeout: float = 60.0) -> int:
    """Count ``filter/rule`` entries whose ``descr`` starts with ``descr_prefix``."""
    pre = (
        "$count = 0;\n"
        "foreach (config_get_path('filter/rule', array()) as $r) {\n"
        f"  if (strpos((string) ($r['descr'] ?? ''), {h._php_str(descr_prefix)}) === 0)"
        "  { $count++; }\n"
        "}"
    )
    val = h._php_read_scalar(vm, pre, "$count", timeout=timeout)
    return int(val)


def _filter_rule_field(vm: SmokeVM, descr: str, field: str, *, timeout: float = 60.0) -> str:
    """Read a scalar field from the ``filter/rule`` entry with an exact ``descr``."""
    pre = (
        "$val = '';\n"
        "foreach (config_get_path('filter/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{\n"
        f"    $val = (string) ($r[{h._php_str(field)}] ?? '');\n"
        "    break;\n"
        "  }\n"
        "}"
    )
    return h._php_read_scalar(vm, pre, "$val", timeout=timeout)


def _filter_rule_nested_field(vm: SmokeVM, descr: str, parent: str, child: str, *, timeout: float = 60.0) -> str:
    """Read a nested field (``rule[parent][child]``) from a ``filter/rule`` entry."""
    pre = (
        "$val = '';\n"
        "foreach (config_get_path('filter/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{\n"
        f"    $sub = $r[{h._php_str(parent)}] ?? array();\n"
        f"    $val = (string) ($sub[{h._php_str(child)}] ?? '');\n"
        "    break;\n"
        "  }\n"
        "}"
    )
    return h._php_read_scalar(vm, pre, "$val", timeout=timeout)


def _filter_rule_has_key(vm: SmokeVM, descr: str, parent: str, child: str, *, timeout: float = 60.0) -> bool:
    """True iff ``rule[parent][child]`` key exists in a ``filter/rule`` entry."""
    pre = (
        "$found = FALSE;\n"
        "foreach (config_get_path('filter/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{\n"
        f"    $sub = $r[{h._php_str(parent)}] ?? array();\n"
        f"    $found = array_key_exists({h._php_str(child)}, $sub);\n"
        "    break;\n"
        "  }\n"
        "}"
    )
    val = h._php_read_scalar(vm, pre, "$found ? 'yes' : 'no'", timeout=timeout)
    return val == "yes"


def _filter_rule_present(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> bool:
    """True iff a ``filter/rule`` entry with this exact ``descr`` exists."""
    pre = (
        "$found = FALSE;\n"
        "foreach (config_get_path('filter/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{ $found = TRUE; break; }}\n"
        "}"
    )
    return h._php_read_scalar(vm, pre, "$found ? 'yes' : 'no'", timeout=timeout) == "yes"


def _is_block_853_line(line: str) -> bool:
    """True iff a ``pfctl -sr`` line is a block rule for port 853.

    pfctl renders port 853 as the ``/etc/services`` name ``domain-s`` (DoT/DoQ), not the
    literal ``853`` — so a ``"853" in line`` test alone misses a correctly-loaded rule.
    """
    return "block" in line and ("853" in line or "domain-s" in line)


def _pfctl_sr_block_853_protos(vm: SmokeVM, *, timeout: float = 30.0) -> set[str]:
    """The protocols ({"tcp","udp"}) with a loaded block rule for port 853 (#723).

    pf expands the config-level ``tcp/udp`` block into per-protocol rules; returning the
    set lets the positive gate require BOTH (a lost UDP-853/DoQ leg with TCP-853/DoT kept
    must fail) while absence checks use the empty set.

    Raises ``RuntimeError`` when ``pfctl -sr`` itself fails (rc != 0) — an ERROR is NOT
    the same as "no rule loaded", and collapsing the two previously made a broken pfctl
    read false-green every negative/absence gate built on this function.
    """
    result = vm.ssh(h.PFCTL, "-sr", timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"{h.PFCTL} -sr failed (rc={result.returncode}): stderr={result.stderr!r} — "
            f"cannot determine the port-853 block rule state; NOT treating as absent"
        )
    protos: set[str] = set()
    for line in result.stdout.splitlines():
        if not _is_block_853_line(line):
            continue
        if " proto tcp " in line:
            protos.add("tcp")
        if " proto udp " in line:
            protos.add("udp")
    return protos


def _pfctl_sr_has_block_853(vm: SmokeVM, *, timeout: float = 30.0) -> bool:
    """Positive render gate: BOTH protocols of the 853 block are loaded (#723)."""
    return {"tcp", "udp"} <= _pfctl_sr_block_853_protos(vm, timeout=timeout)


def _pfctl_sr_block_853_absent(vm: SmokeVM, *, timeout: float = 30.0) -> bool:
    """Negative render gate: NO 853 block rule of either protocol remains loaded."""
    return not _pfctl_sr_block_853_protos(vm, timeout=timeout)


def _pfctl_sr_block_853_has_self_exempt(vm: SmokeVM, *, timeout: float = 30.0) -> bool:
    """True iff the port-853 block rule in ``pfctl -sr`` carries a self-exempt guard.

    pfSense renders the negated ``(self)`` destination as ``! (self)`` and port 853 as the
    service name ``domain-s``. We look for the negation indicator ``!`` and ``self`` on the
    same line as the block rule for port 853.

    Raises ``RuntimeError`` when ``pfctl -sr`` itself fails (rc != 0) — an ERROR is NOT
    "no self-exempt guard": returning False here false-greened the negative gate (#582),
    same collapse as ``_pfctl_sr_block_853_protos`` before its fix.
    """
    result = vm.ssh(h.PFCTL, "-sr", timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"{h.PFCTL} -sr failed (rc={result.returncode}): stderr={result.stderr!r} — "
            f"cannot determine the self-exempt guard state; NOT treating as absent"
        )
    for line in result.stdout.splitlines():
        if _is_block_853_line(line) and "self" in line and "!" in line:
            return True
    return False


def _dot_block_match_report(vm: SmokeVM, *, expected_present: bool, timeout: float = 30.0) -> str:
    """Expected-vs-actual report for the DoT/DoQ block live-pf gate (printed on failure).

    The harness has no assertion framework, so a failing live-pf check must put the
    comparison on the terminal — what was EXPECTED next to what ``pfctl -sr`` ACTUALLY held.
    Lists the live block rules that mention port 853 / ``domain-s`` verbatim.
    """
    result = vm.ssh(h.PFCTL, "-sr", timeout=timeout)
    if result.returncode != 0:
        actual = [f"<pfctl -sr failed: rc={result.returncode} {result.stderr.strip()}>"]
    else:
        actual = [ln.strip() for ln in result.stdout.splitlines() if _is_block_853_line(ln)]
    want = "PRESENT (both protocols)" if expected_present else "ABSENT (no protocol)"
    matched = _pfctl_sr_block_853_protos(vm, timeout=timeout)
    body = "\n".join(f"      {ln}" for ln in actual) if actual else "      (no block rule for port 853 / domain-s)"
    body = f"      protocols matched: {matched or '{}'} — positive gate needs {{'tcp', 'udp'}}\n" + body
    return (
        f"  Expecting a pfBlockerNG DoT/DoQ block rule to be {want} in the live filter ruleset:\n"
        f"    destination : ! (self)\n"
        f"    dest port   : domain-s (853)\n"
        f"  Actual port-853 block rules (pfctl -sr):\n"
        f"{body}"
    )


def _pfb_sections_present(vm: SmokeVM, *, timeout: float = 60.0) -> bool:
    """True iff any ``installedpackages/pfblockerng*`` section survives in config.xml."""
    pre = (
        "$found = FALSE;\n"
        "$all = config_get_path('installedpackages', array());\n"
        "foreach (array_keys($all) as $k) {\n"
        "  if (strpos((string) $k, 'pfblockerng') === 0) { $found = TRUE; break; }\n"
        "}"
    )
    return h._php_read_scalar(vm, pre, "$found ? 'yes' : 'no'", timeout=timeout) == "yes"


def _discover_non_wan_ifaces(vm: SmokeVM, *, timeout: float = 60.0) -> list[str]:
    """Return the non-WAN interface short names available on the VM.

    Uses the pfSense config API (``get_configured_interface_with_descr()``
    minus 'wan') — the same set ``pfb_build_if_list(FALSE, FALSE)`` returns.
    """
    pre = (
        "$ifaces = array();\n"
        "foreach (get_configured_interface_with_descr() as $k => $v) {\n"
        "  if ($k !== 'wan') { $ifaces[] = $k; }\n"
        "}"
    )
    raw = h._php_read_scalar(vm, pre, "implode(',', $ifaces)", timeout=timeout)
    return [i.strip() for i in raw.split(",") if i.strip()]


# --------------------------------------------------------------------------- #
# Config setters for the three ADR-37 registered fields
# --------------------------------------------------------------------------- #


def _set_dot_block(
    vm: SmokeVM,
    *,
    enabled: bool,
    ifaces: list[str],
    exception: str = "",
    action: str | None = None,
    floating: bool | None = None,
    timeout: float = 60.0,
) -> None:
    """Write the DoT/DoQ-block config fields and persist config.xml.

    ``action`` selects the rule disposition ('block' | 'reject'). When None the
    key is left ABSENT, so the gateway's registered default (reject) applies —
    exercising the default path an upgrading install takes.

    ``floating`` selects the rule mode: True = a single floating rule, False =
    one rule per interface. When None the key is left ABSENT (gateway default =
    off = per-interface).
    """
    toggle = "on" if enabled else ""
    iface_val = ",".join(ifaces)
    # When action/floating is None, UNSET the key so the gateway's registered default applies
    # (reject / per-interface). Merely omitting the assignment would leave a prior test's value
    # in config.xml, making the default-path cases depend on VM state and test order.
    action_line = (
        f"$d['dnsbl_dot_block_action'] = {h._php_str(action)};\n"
        if action is not None
        else "unset($d['dnsbl_dot_block_action']);\n"
    )
    floating_line = (
        f"$d['dnsbl_dot_block_floating'] = {h._php_str('on' if floating else '')};\n"
        if floating is not None
        else "unset($d['dnsbl_dot_block_floating']);\n"
    )
    snippet = (
        f"$d = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        f"$d['dnsbl_dot_block']         = {h._php_str(toggle)};\n"
        f"$d['dnsbl_dot_block_int']     = {h._php_str(iface_val)};\n"
        f"$d['dnsbl_dot_block_exclude'] = {h._php_str(exception)};\n"
        f"{action_line}"
        f"{floating_line}"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: set DoT/DoQ block config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_dot_block failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _seed_user_filter(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> None:
    """Inject a minimal user filter rule (no pfB marker) — must survive all lifecycle steps."""
    snippet = (
        "$rules = config_get_path('filter/rule', array());\n"
        "$found = FALSE;\n"
        "foreach ($rules as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{ $found = TRUE; break; }}\n"
        "}\n"
        "if (!$found) {\n"
        "  $rules[] = array(\n"
        f"    'descr' => {h._php_str(descr)},\n"
        "    'type' => 'pass',\n"
        "    'interface' => 'lo0',\n"
        "    'protocol' => 'tcp',\n"
        "    'source' => array('any' => TRUE),\n"
        "    'destination' => array('any' => TRUE),\n"
        "  );\n"
        "  config_set_path('filter/rule', $rules);\n"
        "  write_config('pfBlockerNG smoke: seed user filter for DoT block test');\n"
        "}\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_user_filter({descr!r}) failed: rc={result.returncode} {result.stderr!r}")


def _seed_pf_alias(vm: SmokeVM, name: str, cidr: str = "192.0.2.0/24", *, timeout: float = 60.0) -> None:
    """Create a pfSense network alias so pfctl can resolve 'from !<name>' without a syntax error.

    Writes one entry to ``aliases/alias`` (type=network, address=cidr) and persists
    config.xml.  Idempotent: skips creation when an alias with ``name`` already exists.
    """
    snippet = (
        "$aliases = config_get_path('aliases/alias', array());\n"
        "$found = FALSE;\n"
        f"foreach ($aliases as $a) {{\n"
        f"  if (($a['name'] ?? '') === {h._php_str(name)}) {{ $found = TRUE; break; }}\n"
        "}\n"
        "if (!$found) {\n"
        "  $aliases[] = array(\n"
        f"    'name'    => {h._php_str(name)},\n"
        "    'type'    => 'network',\n"
        f"    'address' => {h._php_str(cidr)},\n"
        "    'descr'   => 'pfBlockerNG smoke: exception alias',\n"
        "    'detail'  => '',\n"
        "  );\n"
        "  config_set_path('aliases/alias', $aliases);\n"
        "  write_config('pfBlockerNG smoke: seed pfSense alias for exception');\n"
        "}\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_pf_alias({name!r}) failed: rc={result.returncode} {result.stderr!r}")


def _remove_pf_alias(vm: SmokeVM, name: str, *, timeout: float = 60.0) -> None:
    """Remove the pfSense alias with ``name`` from ``aliases/alias`` (best-effort; ignores missing)."""
    snippet = (
        "$aliases = config_get_path('aliases/alias', array());\n"
        "$out = array();\n"
        "foreach ($aliases as $a) {\n"
        f"  if (($a['name'] ?? '') !== {h._php_str(name)}) {{ $out[] = $a; }}\n"
        "}\n"
        "config_set_path('aliases/alias', $out);\n"
        "write_config('pfBlockerNG smoke: remove pfSense alias for exception');\n"
        "echo 'OK';"
    )
    h.php_eval(vm, snippet, timeout=timeout)  # best-effort; ignore rc/stdout


def _cleanup_dot_block(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Disable DoT/DoQ block and reload — shared teardown used by finally blocks."""
    try:
        _set_dot_block(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False, timeout=timeout)
        h.apply_filter_sync(vm, timeout=timeout)
    except Exception:
        pass  # best-effort in teardown; don't mask the test failure


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
# Case 1 — Enable path: block rule created + pfctl -sr confirms it active
# --------------------------------------------------------------------------- #


def test_dot_doq_block_rule_appears_on_enable(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 Case 1: enabling DoT/DoQ block on the primary non-WAN interface creates the pfB-owned filter rule.

    Scenario: enable path — block rule created with correct §2.2 field values.

      Background: pfBlockerNG installed; DoT/DoQ block disabled.

      Given no pfB_DoT_Block_* entries in filter/rule (before-state),
        And pfctl -sr shows no pfBlockerNG port-853 block rule (before-state),

      When DoT/DoQ block is enabled on the primary non-WAN interface and a full reload runs,

      Then filter/rule contains exactly 1 pfB_DoT_Block_<iface> entry.
        And the entry carries the correct §2.2 field values:
            - type: reject (the default for the outbound LAN->WAN block rule)
            - ipprotocol: inet46
            - protocol: tcp/udp
            - destination.network: (self), not-negated
            - destination.port: 853
            - statetype: keep state
        And pfctl -sr shows the block rule active for port 853.
    """
    vm = deployed_vm
    iface = primary_iface
    descr = _DOT_BLOCK_DESCR_PFX + iface

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DoT/DoQ block filter rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — disable DoT block; assert before-state clean.
        _set_dot_block(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        assert _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX) == 0, (
            "pfB_DoT_Block_* filter/rule entries present before enable — before-state not clean"
        )
        assert _pfctl_sr_block_853_absent(vm), (
            "pfctl -sr shows a port-853 block rule before enable — before-state not clean\n"
            + _dot_block_match_report(vm, expected_present=False)
        )

        # WHEN — enable on the primary interface and reload.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — exactly 1 filter/rule entry for the primary interface.
        count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface)
        assert count == 1, f"Expected 1 pfB_DoT_Block_{iface} filter/rule entry after enable, got {count}"

        # THEN — field-by-field verification. Default action is Reject (the rule is an
        # outbound LAN->WAN block, so Reject fast-fails the client to plain DNS).
        assert _filter_rule_field(vm, descr, "type") == "reject", f"{descr}: type != 'reject' (default)"
        assert _filter_rule_field(vm, descr, "ipprotocol") == "inet46", f"{descr}: ipprotocol != 'inet46'"
        assert _filter_rule_field(vm, descr, "protocol") == "tcp/udp", f"{descr}: protocol != 'tcp/udp'"
        assert _filter_rule_field(vm, descr, "statetype") == "keep state", f"{descr}: statetype != 'keep state'"

        # Destination: negated (self) with port 853.
        assert _filter_rule_nested_field(vm, descr, "destination", "network") == "(self)", (
            f"{descr}: destination.network != '(self)'"
        )
        assert _filter_rule_has_key(vm, descr, "destination", "not"), (
            f"{descr}: destination.not key absent (self-exempt negation missing)"
        )
        assert _filter_rule_nested_field(vm, descr, "destination", "port") == "853", (
            f"{descr}: destination.port != '853'"
        )

        # THEN — pfctl -sr confirms the block rule is active.
        assert _pfctl_sr_has_block_853(vm), (
            "pfctl -sr shows no block rule for port 853 after enable\n"
            + _dot_block_match_report(vm, expected_present=True)
            + "\n"
            + h.pf_state_dump(vm)
        )

    finally:
        _cleanup_dot_block(vm)


def test_dot_doq_block_action_selector_sets_rule_type(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37: the Rule Action selector drives the DoT/DoQ block rule disposition.

    Scenario: the action field flips the rule 'type' between reject and block.

      Background: pfBlockerNG installed; master + DNSBL enabled.

      Given DoT/DoQ block enabled with the default action (reject),
        And the rule 'type' is 'reject' (before-state — proves the flip causes the change),

      When the action is changed to 'block' and a full reload runs,

      Then the same pfB_DoT_Block_<iface> rule now carries type 'block'.
    """
    vm = deployed_vm
    iface = primary_iface
    descr = _DOT_BLOCK_DESCR_PFX + iface

    try:
        # GIVEN — $mode='enabled' so DoT/DoQ block rules are created on reload.
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)

        # GIVEN — enable with the DEFAULT action (key absent → reject); assert before-state.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="", action=None)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        assert _filter_rule_field(vm, descr, "type") == "reject", f"{descr}: default type != 'reject' (before-state)"

        # WHEN — switch the action to Block and reload.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="", action="block")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — the rule disposition follows the selector.
        assert _filter_rule_field(vm, descr, "type") == "block", (
            f"{descr}: type != 'block' after selecting the Block action"
        )

    finally:
        _cleanup_dot_block(vm)


def test_dot_doq_block_floating_mode_single_rule(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37: the Floating Rule option replaces per-interface rules with one floating rule.

    Scenario: switching to floating mode prunes the per-interface rule and creates a single
    floating rule (direction in) covering the selected interface(s).

      Background: pfBlockerNG installed; master + DNSBL enabled.

      Given DoT/DoQ block enabled per-interface (floating off),
        And a pfB_DoT_Block_<iface> rule exists and no floating marker exists (before-state),

      When the Floating Rule option is enabled and a full reload runs,

      Then the per-interface rule is gone, replaced by a single pfB_DoT_Block_Floating rule
        carrying floating=yes, direction=in, and the selected interface in its interface list.
    """
    vm = deployed_vm
    iface = primary_iface
    per_iface_descr = _DOT_BLOCK_DESCR_PFX + iface

    try:
        # GIVEN — $mode='enabled' and per-interface DoT block; assert before-state.
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="", floating=False)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        assert _filter_dot_block_count(vm, per_iface_descr) == 1, (
            f"{per_iface_descr}: per-interface rule absent before floating switch (before-state)"
        )
        assert _filter_dot_block_count(vm, _DOT_BLOCK_FLOATING_DESCR) == 0, (
            "floating rule present before floating switch (before-state not clean)"
        )

        # WHEN — enable the floating option and reload.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="", floating=True)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — per-interface rule pruned; exactly one floating rule with the right shape.
        assert _filter_dot_block_count(vm, per_iface_descr) == 0, (
            f"{per_iface_descr}: per-interface rule not pruned after switching to floating"
        )
        assert _filter_dot_block_count(vm, _DOT_BLOCK_FLOATING_DESCR) == 1, (
            "expected exactly one pfB_DoT_Block_Floating rule after enabling floating mode"
        )
        assert _filter_rule_field(vm, _DOT_BLOCK_FLOATING_DESCR, "floating") == "yes", (
            "floating rule must carry floating=yes"
        )
        assert _filter_rule_field(vm, _DOT_BLOCK_FLOATING_DESCR, "quick") == "yes", (
            "floating rule must carry quick=yes (first-match)"
        )
        assert _filter_rule_field(vm, _DOT_BLOCK_FLOATING_DESCR, "direction") == "in", (
            "floating rule direction must be in"
        )
        assert _filter_rule_field(vm, _DOT_BLOCK_FLOATING_DESCR, "type") == "reject", (
            "floating rule type must be reject (default action carried into floating mode)"
        )
        assert iface in _filter_rule_field(vm, _DOT_BLOCK_FLOATING_DESCR, "interface").split(","), (
            f"floating rule interface list must contain {iface}"
        )

    finally:
        _cleanup_dot_block(vm)


# --------------------------------------------------------------------------- #
# Case 2 — Disable path: all pfB_DoT_Block_* rules removed, pfctl clean
# --------------------------------------------------------------------------- #


def test_dot_doq_block_rule_removed_on_disable(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 Case 2: disabling DoT/DoQ block removes all pfB_DoT_Block_* rules.

    Scenario: disable path — rule removed from config.xml and pfctl.

      Given DoT/DoQ block is enabled on the primary non-WAN interface,
        And pfB_DoT_Block_<iface> entry is present in filter/rule (before-state),
        And pfctl -sr shows a port-853 block rule (before-state),

      When DoT/DoQ block is disabled and a full reload runs,

      Then filter/rule has no pfB_DoT_Block_* entries.
        And pfctl -sr shows no pfBlockerNG port-853 block rules.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DoT/DoQ block filter rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — enable on the primary interface; assert before-state with rule present.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        assert _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface) == 1, (
            f"pfB_DoT_Block_{iface} filter/rule entry absent before disable — setup failed"
        )
        assert _pfctl_sr_has_block_853(vm), (
            "pfctl -sr shows no port-853 block before disable — setup failed\n"
            + _dot_block_match_report(vm, expected_present=True)
        )

        # WHEN — disable and reload.
        _set_dot_block(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — all pfB_DoT_Block_* entries must be gone.
        assert _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX) == 0, (
            "pfB_DoT_Block_* filter/rule entries still present after disable"
        )

        # THEN — pfctl -sr must show no port-853 block rule.
        assert _pfctl_sr_block_853_absent(vm), (
            "pfctl -sr still shows port-853 block rule after disable\n"
            + _dot_block_match_report(vm, expected_present=False)
        )

    finally:
        _cleanup_dot_block(vm)


# --------------------------------------------------------------------------- #
# Case 3 — User-rule survival: a user filter/rule survives enable → disable → uninstall
# --------------------------------------------------------------------------- #


def test_user_filter_rule_survives_disable_and_uninstall(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 Case 3: a user filter/rule without a pfB marker is never touched.

    Scenario: user-rule survival — enable, disable, uninstall do not modify user rules.

      Given a user filter/rule entry (descr='my-user-filter-dot-block-smoke', no pfB
            marker) is present in config.xml,
        And DoT/DoQ block is disabled initially (before-state),

      When DoT/DoQ block is enabled on the primary non-WAN interface and a reload runs (pfB rule appears),
        Then the user filter/rule is still present (survives enable).

      When DoT/DoQ block is disabled and a reload runs (pfB rule removed),
        Then the user filter/rule is still present (survives disable).

      When pfBlockerNG is uninstalled via pkg delete,
        Then the user filter/rule is still present (survives uninstall).
        And no pfB_DoT_Block_* entries remain.
        And installedpackages/pfblockerng* sections are gone.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DoT/DoQ block filter rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — select the full-removal uninstall path (pfb_keep defaults to 'on'; a test that
        # asserts sections-gone must set pfb_keep=off explicitly — see issue #484).
        h.set_pfb_keep(vm, False)
        # GIVEN — seed the user filter rule; assert block is disabled.
        _set_dot_block(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        _seed_user_filter(vm, _USER_FILTER_DESCR)

        assert _filter_rule_present(vm, _USER_FILTER_DESCR), (
            "user filter rule not present before enable — seeding failed"
        )
        assert not _filter_rule_present(vm, _DOT_BLOCK_DESCR_PFX + iface), (
            f"pfB_DoT_Block_{iface} already present before enable — state not clean"
        )

        # WHEN — enable on the primary interface.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — pfB rule appears; user rule survives enable.
        assert _filter_rule_present(vm, _DOT_BLOCK_DESCR_PFX + iface), f"pfB_DoT_Block_{iface} not created after enable"
        assert _filter_rule_present(vm, _USER_FILTER_DESCR), (
            "user filter rule was removed during enable — should never be touched"
        )

        # WHEN — disable.
        _set_dot_block(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — pfB rule gone; user rule survives disable.
        assert not _filter_rule_present(vm, _DOT_BLOCK_DESCR_PFX + iface), (
            f"pfB_DoT_Block_{iface} still present after disable"
        )
        assert _filter_rule_present(vm, _USER_FILTER_DESCR), (
            "user filter rule was removed during disable — should never be touched"
        )

        # WHEN — re-enable for the uninstall step.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        assert _filter_rule_present(vm, _DOT_BLOCK_DESCR_PFX + iface), (
            f"pfB_DoT_Block_{iface} not recreated before uninstall step"
        )

        # WHEN — uninstall.
        _pkg_delete(vm)

        # THEN — pfB rules gone; user rule survives; pfblockerng sections gone.
        assert not _filter_rule_present(vm, _DOT_BLOCK_DESCR_PFX + iface), (
            f"pfB_DoT_Block_{iface} still present after uninstall — ADR-35/37 sweep did not run\n"
            + h.deinstall_debug(vm)
        )
        assert _filter_rule_present(vm, _USER_FILTER_DESCR), (
            "user filter rule was DELETED during uninstall — ADR-35 sweep incorrectly removed a user object"
        )
        assert not _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* still present after uninstall — pfb_remove_config_settings did not run"
        )

    except Exception:
        # Best-effort teardown: package may already be gone after uninstall.
        try:
            _cleanup_dot_block(vm)
        except Exception:
            pass
        raise


# --------------------------------------------------------------------------- #
# Case 4 — Stale-interface prune: reduce from two interfaces to one
# --------------------------------------------------------------------------- #


def test_stale_interface_rule_pruned_on_reconcile(deployed_vm: SmokeVM) -> None:
    """ADR-37 Case 4: removing an interface from the selection prunes its rule.

    Scenario: stale-interface prune — reduce two interfaces to one.

      Background: VM has at least two non-WAN interfaces available.

      Given DoT/DoQ block enabled on the first two discovered non-WAN interfaces
        (e.g. lan + opt1 — names are discovered, never assumed),
        And the first interface's pfB_DoT_Block_ rule present (before-state),
        And the second interface's pfB_DoT_Block_ rule present (before-state),

      When the selection is reduced to the first interface only and a reload runs,

      Then the second interface's pfB_DoT_Block_ entry is GONE from filter/rule.
        And the first interface's pfB_DoT_Block_ entry is STILL PRESENT.
    """
    vm = deployed_vm

    # Discover available non-WAN interfaces.
    available = _discover_non_wan_ifaces(vm)
    if len(available) < 2:
        pytest.skip(f"Case 4 (stale-interface prune) requires ≥2 non-WAN interfaces; VM has: {available!r}")

    iface_keep = available[0]  # typically 'lan'
    iface_drop = available[1]  # typically 'opt1'

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DoT/DoQ block filter rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — enable on both interfaces; assert both rules present.
        _set_dot_block(vm, enabled=True, ifaces=[iface_keep, iface_drop], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        assert _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface_keep) == 1, (
            f"pfB_DoT_Block_{iface_keep} rule absent before prune — setup failed"
        )
        assert _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface_drop) == 1, (
            f"pfB_DoT_Block_{iface_drop} rule absent before prune — setup failed"
        )

        # WHEN — reduce to keep-interface only.
        _set_dot_block(vm, enabled=True, ifaces=[iface_keep], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — drop-interface rule removed.
        drop_count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface_drop)
        assert drop_count == 0, f"pfB_DoT_Block_{iface_drop} filter/rule entry ({drop_count}) still present after prune"

        # THEN — keep-interface rule remains (exactly 1).
        keep_count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface_keep)
        assert keep_count == 1, (
            f"pfB_DoT_Block_{iface_keep} filter/rule entry count is {keep_count} after prune (expected 1)"
        )

    finally:
        _cleanup_dot_block(vm)


# --------------------------------------------------------------------------- #
# Case 5 — Exception alias branch: alias set → negated source; empty → <any>
# --------------------------------------------------------------------------- #


def test_exception_alias_source_in_config_xml_when_set(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 Case 5: exception alias wires negated-alias source; empty gives <any>.

    Scenario: exception alias branch — both states asserted (before and after).

      Given DoT/DoQ block is disabled.

      When DoT/DoQ block is enabled on the primary non-WAN interface
            with dnsbl_dot_block_exclude = 'DoT_Exceptions_Test',

      Then filter/rule entry has:
            - source.address == 'DoT_Exceptions_Test'
            - source.not key present (negated)

      When dnsbl_dot_block_exclude is cleared ('') and a reload runs,

      Then filter/rule entry source is <any> (source.any key present; address absent).
    """
    vm = deployed_vm
    iface = primary_iface
    descr = _DOT_BLOCK_DESCR_PFX + iface

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DoT/DoQ block filter rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — start from disabled state.
        _set_dot_block(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        assert _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX) == 0, (
            "pfB_DoT_Block_* entries present before Case 5 — state not clean"
        )

        # Create a real pfSense network alias so pfctl can resolve 'from !<alias>'
        # without a syntax error when the ruleset is applied after reload.
        _seed_pf_alias(vm, _EXCEPTION_ALIAS, "192.0.2.0/24")

        # WHEN — enable with exception alias set.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception=_EXCEPTION_ALIAS)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — rule has negated-alias source.
        src_addr = _filter_rule_nested_field(vm, descr, "source", "address")
        assert src_addr == _EXCEPTION_ALIAS, f"{descr}: source.address == {src_addr!r}, expected {_EXCEPTION_ALIAS!r}"
        assert _filter_rule_has_key(vm, descr, "source", "not"), (
            f"{descr}: source.not key absent (negation missing for exception alias)"
        )

        # WHEN — clear the exception alias.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — rule source is <any> (source.any key present; address absent).
        assert _filter_rule_has_key(vm, descr, "source", "any"), (
            f"{descr}: source.any key absent when exception is empty"
        )
        src_addr_clear = _filter_rule_nested_field(vm, descr, "source", "address")
        assert src_addr_clear == "", (
            f"{descr}: source.address == {src_addr_clear!r} when exception cleared (expected '')"
        )

    finally:
        _remove_pf_alias(vm, _EXCEPTION_ALIAS)
        _cleanup_dot_block(vm)


# --------------------------------------------------------------------------- #
# Case 6 — Uninstall sweep: all pfB_DoT_Block_* gone; user filter rule survives
# --------------------------------------------------------------------------- #


def test_uninstall_sweep_removes_all_dot_block_rules(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 Case 6: uninstall sweeps all pfB_DoT_Block_* entries; user rule survives.

    Scenario: uninstall sweep — owned rules gone, user rule preserved, sections gone.

      Given DoT/DoQ block is enabled on the primary non-WAN interface
            (pfB_DoT_Block_<iface> in filter/rule, confirmed in config.xml as
            before-state),
        And a user filter/rule entry (no pfB marker) is present in config.xml,
        And installedpackages/pfblockerng* sections are present (before-state),

      When pfBlockerNG is uninstalled via 'pkg delete',

      Then all pfB_DoT_Block_* entries are GONE from filter/rule.
        And no pfBlockerNG-owned filter/rule entries remain.
        And the user filter/rule entry is STILL PRESENT and unchanged.
        And installedpackages/pfblockerng* sections are GONE from config.xml.
    """
    vm = deployed_vm
    iface = primary_iface

    # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
    # pfblockerng will create DoT/DoQ block filter rules on reload (#484 coupling).
    h.set_package_enabled(vm, True)
    h.set_dnsbl_enabled(vm, True)
    # GIVEN — select the full-removal uninstall path (pfb_keep defaults to 'on'; a test
    # that asserts sections-gone must set pfb_keep=off explicitly — see issue #484).
    h.set_pfb_keep(vm, False)
    # GIVEN — enable DoT block on the primary interface and seed a user filter rule.
    _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
    h.reload(vm, "update", wait_unbound=False)
    h.apply_filter_sync(vm)
    _seed_user_filter(vm, _USER_FILTER_DESCR)

    # BEFORE-STATE: assert all objects are present before uninstall.
    assert _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface) == 1, (
        f"pfB_DoT_Block_{iface} filter/rule entry absent before uninstall — setup failed"
    )
    assert _filter_rule_present(vm, _USER_FILTER_DESCR), "user filter rule absent before uninstall — seeding failed"
    assert _pfb_sections_present(vm), "installedpackages/pfblockerng* absent before uninstall — unexpected clean state"

    # WHEN — uninstall pfBlockerNG (triggers pfblockerng_php_pre_deinstall_command →
    # owned-object sweep before pfb_remove_config_settings).
    _pkg_delete(vm)

    # THEN — all pfB_DoT_Block_* entries are gone.
    assert _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX) == 0, (
        "pfB_DoT_Block_* filter/rule entries still present after uninstall — ADR-35/37 sweep did not run\n"
        + h.deinstall_debug(vm)
    )

    # THEN — user filter rule survives.
    assert _filter_rule_present(vm, _USER_FILTER_DESCR), (
        "user filter rule was DELETED during uninstall — ADR-35 sweep incorrectly removed a user object"
    )

    # THEN — pfBlockerNG config sections are gone.
    assert not _pfb_sections_present(vm), (
        "installedpackages/pfblockerng* still present after uninstall — pfb_remove_config_settings did not run"
    )


# --------------------------------------------------------------------------- #
# Case 7 — Self-exempt guard: pfctl -sr confirms the !<self> guard is active
# --------------------------------------------------------------------------- #


def test_self_exempt_guard_in_pfctl_output(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 Case 7: pfctl -sr confirms the port-853 block rule carries self-exempt.

    Scenario: self-exempt guard — on-box pfctl output proves the guard is active.

      Background: pfBlockerNG installed; DoT/DoQ block disabled.

      Given no pfB_DoT_Block_* entries in filter/rule (before-state),
        And pfctl -sr shows no port-853 block rule with self-exempt (before-state),

      When DoT/DoQ block is enabled on the primary non-WAN interface and a full reload runs,

      Then pfctl -sr contains a block rule for port 853.
        And the rule in pfctl -sr carries the self-exempt negation token ('!' + 'self'),
            confirming the firewall itself is excluded from the block.

      NOTE: full client-to-:853 block behaviour (a client being prevented from
      opening a TCP/UDP connection to an external :853 server) requires a second host
      on the network and is a documented maintainer manual-smoke item (ADR-37 §7).
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DoT/DoQ block filter rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — disable DoT block; assert before-state clean.
        _set_dot_block(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        assert _pfctl_sr_block_853_absent(vm), (
            "pfctl -sr shows a port-853 block rule before enable — before-state not clean\n"
            + _dot_block_match_report(vm, expected_present=False)
        )
        assert not _pfctl_sr_block_853_has_self_exempt(vm), (
            "pfctl -sr shows self-exempt port-853 rule before enable — before-state not clean\n"
            + _dot_block_match_report(vm, expected_present=False)
        )

        # WHEN — enable on the primary interface and reload.
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — pfctl -sr contains the block rule for port 853.
        assert _pfctl_sr_has_block_853(vm), (
            "pfctl -sr shows no block rule for port 853 after enable\n"
            + _dot_block_match_report(vm, expected_present=True)
            + "\n"
            + h.pf_state_dump(vm)
        )

        # THEN — the rule carries the self-exempt guard ('!' + 'self' on the block line).
        assert _pfctl_sr_block_853_has_self_exempt(vm), (
            "pfctl -sr block rule for port 853 does not carry the self-exempt negation guard "
            "('!' + 'self' tokens absent on the block-853 line) — the firewall is NOT exempt from its own rule\n"
            + _dot_block_match_report(vm, expected_present=True)
        )

    finally:
        _cleanup_dot_block(vm)


# --------------------------------------------------------------------------- #
# Case 8 — Master-disable coupling: DoT rules absent when master OFF
# --------------------------------------------------------------------------- #


def test_dot_block_master_disable_removes_rules_despite_toggle_on(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 / issue #484 Case 8: master-disable forces DoT block rules absent even with toggle ON.

    Scenario: $mode-coupling — master enable_cb=off removes DoT block rules unconditionally.

      Background: pfBlockerNG installed; DoT block disabled; DNSBL enabled.

      Given DoT block is enabled on the primary non-WAN interface (toggle ON),
        And the master switch (enable_cb) is ON,
        And 1 pfB_DoT_Block_<iface> filter/rule entry is present (before-state),
        And pfctl -sr shows the port-853 block rule (before-state),

      When the master switch is turned OFF (enable_cb='') and a full reload runs,

      Then filter/rule has 0 pfB_DoT_Block_* entries (rules force-removed by $mode coupling).
        And pfctl -sr shows no port-853 block rule.

      Note: the DoT toggle (dnsbl_dot_block) remains ON throughout; the removal is caused
      solely by the master switch, proving the $mode-coupling in pfb_create_dnsbl.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — ensure master ON; enable DoT block; assert before-state present.
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        before_count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface)
        assert before_count == 1, (
            f"Expected 1 pfB_DoT_Block_{iface} filter/rule entry before master-disable, got {before_count}"
        )
        assert _pfctl_sr_has_block_853(vm), (
            "pfctl -sr shows no port-853 block before master-disable — before-state setup failed\n"
            + _dot_block_match_report(vm, expected_present=True)
        )

        # WHEN — turn master OFF; reload (dnsbl_dot_block toggle remains ON).
        h.set_package_enabled(vm, False)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — all DoT block filter rules must be gone (force-removed by $mode coupling).
        after_count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX)
        assert after_count == 0, (
            f"pfB_DoT_Block_* filter/rule entries still present ({after_count}) after master-disable — "
            f"$mode-coupling did not force-remove DoT block rules when enable_cb='' (master OFF)\n"
            + _dot_block_match_report(vm, expected_present=False)
        )

        # THEN — pfctl confirms no port-853 block.
        assert _pfctl_sr_block_853_absent(vm), (
            "pfctl -sr still shows a port-853 block rule after master-disable\n"
            + _dot_block_match_report(vm, expected_present=False)
        )

    finally:
        # Restore baseline: master ON, DoT block disabled.
        h.set_package_enabled(vm, True)
        _cleanup_dot_block(vm)


# --------------------------------------------------------------------------- #
# Case 9 — DNSBL-disable coupling: DoT rules absent when DNSBL toggle OFF
# --------------------------------------------------------------------------- #


def test_dot_block_dnsbl_disable_removes_rules_despite_toggle_on(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 / issue #484 Case 9: DNSBL-off forces DoT block rules absent even with toggle ON.

    Scenario: $mode-coupling — DNSBL toggle pfb_dnsbl='' removes DoT block rules unconditionally.

      Background: pfBlockerNG installed; master ON; DoT block toggle ON.

      Given master ON + DNSBL ON + DoT block ON → 1 pfB_DoT_Block_<iface> entry present
        (before-state: positive guard — proves rules appear when all enablers are ON),

      When DNSBL is turned OFF (pfb_dnsbl='') and a full reload runs
        (master remains ON; dnsbl_dot_block toggle remains ON),

      Then filter/rule has 0 pfB_DoT_Block_* entries (force-removed by $mode coupling).
        And pfctl -sr shows no port-853 block rule.

      Note: the positive guard (rule present when all enablers are ON) prevents this test
      from masking a regression where rules are always absent.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — master ON + DNSBL ON + DoT block ON; assert before-state with rule present.
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        before_count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface)
        assert before_count == 1, (
            f"Expected 1 pfB_DoT_Block_{iface} filter/rule entry before DNSBL-disable (positive guard), "
            f"got {before_count} — rule absent even when all enablers are ON"
        )
        assert _pfctl_sr_has_block_853(vm), (
            "pfctl -sr shows no port-853 block before DNSBL-disable — before-state setup failed\n"
            + _dot_block_match_report(vm, expected_present=True)
        )

        # WHEN — turn DNSBL OFF; reload (master ON; dnsbl_dot_block toggle remains ON).
        h.set_dnsbl_enabled(vm, False)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — all DoT block filter rules must be gone (force-removed by $mode coupling).
        after_count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX)
        assert after_count == 0, (
            f"pfB_DoT_Block_* filter/rule entries still present ({after_count}) after DNSBL-disable — "
            f"$mode-coupling did not force-remove DoT block rules when pfb_dnsbl='' (DNSBL OFF)\n"
            + _dot_block_match_report(vm, expected_present=False)
        )

        # THEN — pfctl confirms no port-853 block.
        assert _pfctl_sr_block_853_absent(vm), (
            "pfctl -sr still shows a port-853 block rule after DNSBL-disable\n"
            + _dot_block_match_report(vm, expected_present=False)
        )

    finally:
        # Restore baseline: DNSBL ON, DoT block disabled.
        h.set_dnsbl_enabled(vm, True)
        _cleanup_dot_block(vm)


# --------------------------------------------------------------------------- #
# Case 10 — Uninstall keep=on: live rules gone; sections retained (#484)
# --------------------------------------------------------------------------- #


def test_dot_block_uninstall_keep_on_removes_rules_retains_sections(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-37 / issue #484 Case 10: uninstall with keep=on removes DoT rules but retains sections.

    Scenario: uninstall keep=on — live firewall objects torn down unconditionally;
    settings sections retained because pfb_keep=on.

      Given pfb_keep is set to 'on' (retain settings + data on uninstall),
        And DoT block is enabled on the primary non-WAN interface (toggle ON),
        And 1 pfB_DoT_Block_<iface> filter/rule entry is present (before-state),
        And a user filter/rule entry (no pfB marker) is present in config.xml (before-state),
        And installedpackages/pfblockerng* sections are present (before-state),

      When pfBlockerNG is uninstalled via 'pkg delete',

      Then all pfB_DoT_Block_* filter/rule entries are GONE (live sweep is unconditional).
        And the user filter/rule entry is STILL PRESENT (user objects never swept).
        And installedpackages/pfblockerng* sections are STILL PRESENT (pfb_keep=on retains them).

      This is the core #484 fix: before the fix the deinstall keep-gate blocked the live-object
      sweep, so pfB-owned rules were left behind. After the fix, live-object teardown runs
      unconditionally; pfb_keep gates only the settings/data removal.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DoT/DoQ block filter rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — set keep=on; enable DoT block; seed user filter; assert all before-states.
        h.set_pfb_keep(vm, True)
        _set_dot_block(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        _seed_user_filter(vm, _USER_FILTER_DESCR)

        before_count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX + iface)
        assert before_count == 1, (
            f"Expected 1 pfB_DoT_Block_{iface} filter/rule entry before keep=on uninstall, got {before_count}"
        )
        assert _filter_rule_present(vm, _USER_FILTER_DESCR), (
            "user filter rule not present before keep=on uninstall — seeding failed"
        )
        assert _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* absent before keep=on uninstall — unexpected clean state"
        )

        # WHEN — uninstall pfBlockerNG with pfb_keep=on.
        _pkg_delete(vm)

        # THEN — pfB-owned DoT block rules are GONE (live-object teardown is unconditional).
        after_count = _filter_dot_block_count(vm, _DOT_BLOCK_DESCR_PFX)
        assert after_count == 0, (
            f"pfB_DoT_Block_* filter/rule entries still present ({after_count}) after keep=on uninstall — "
            f"live-object teardown did not run unconditionally (the #484 bug: keep-gate blocked the sweep)\n"
            + h.deinstall_debug(vm)
        )

        # THEN — user filter rule survives (never swept).
        assert _filter_rule_present(vm, _USER_FILTER_DESCR), (
            "user filter rule was DELETED during keep=on uninstall — sweep incorrectly removed a user object"
        )

        # THEN — pfblockerng* sections are STILL PRESENT (pfb_keep=on retains settings + data).
        assert _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* GONE after keep=on uninstall — "
            "pfb_keep=on should have retained settings sections (the #484 fix: keep gates only settings/data)"
        )

    finally:
        # Best-effort teardown — runs on success too so the retained config (keep=on leaves
        # the DNSBL section in place) does not bleed the DoT-block toggle into the next module.
        # _cleanup_dot_block is internally best-effort: its config write turns the toggle off
        # even with the package uninstalled, and its reload no-ops when the package is gone.
        _cleanup_dot_block(vm)
