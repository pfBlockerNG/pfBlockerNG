"""ADR-36 — live-VM smoke coverage for optional NAT DNS-redirection.

Proves on a real pfSense CE VM that:

* **Case 1 (Enable path):** enabling DNS redirect on the primary non-WAN interface
  creates exactly 2 ``nat/rule`` entries (``pfB_DNS_Redirect_<iface>_v4`` +
  ``pfB_DNS_Redirect_<iface>_v6``) using ``associated-rule-id='pass'`` (pfSense-native
  inline ``rdr pass`` — no hand-rolled filter/rule companion needed), each with the
  correct §2.2 field values; ``pfctl -sn`` confirms the rdr rules are active.
* **Case 2 (Disable path):** disabling removes all ``pfB_DNS_Redirect_*`` entries
  from ``nat/rule``; ``pfctl -sn`` shows no pfBlockerNG rdr rules for port 53.
* **Case 3 (User-rule survival):** a user ``nat/rule`` entry (no pfB marker)
  survives enable → disable without modification.
* **Case 4 (Stale-interface prune):** enabling on two interfaces then reducing to
  one removes the dropped-interface rules while keeping the retained-interface rules.
  Skipped when the VM exposes fewer than two non-WAN interfaces.
* **Case 5 (Exception alias branch):** enabling with a non-empty alias name wires
  a negated-alias source in config.xml; clearing the alias switches the source to
  ``<any>`` — both branches asserted for both IP families.  A real pfSense network
  alias is created before the reload so pfctl can resolve ``from !<alias>`` without
  a syntax error.
* **Case 6 (Uninstall sweep):** uninstalling the package with redirect enabled
  sweeps all ``pfB_DNS_Redirect_*`` entries while a user NAT rule survives and
  ``installedpackages/pfblockerng*`` sections are removed.

Cases 1–3 and 5–6 require at least one non-WAN interface and skip cleanly on a
WAN-only VM (e.g. the default smoke image). The interface is discovered at runtime
via ``_discover_non_wan_ifaces()`` — never hardcoded.

All cases use config.xml reads via the pfSense config API (``php_eval`` /
``config_get_path``). ``pfctl -sn`` rdr confirmation is the on-box live gate for
Cases 1 and 2. Full client-redirect behaviour (a host bypassing the redirect is
redirected and answered by Unbound) requires a second host and is a documented
maintainer manual-smoke item — not a CI gate.

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

# Package name on the devel channel (matches test_smoke_managed_objects.py).
_PKG_NAME = "pfSense-pkg-pfBlockerNG-devel"

# Marker prefix for DNS-redirect owned rules (mirrors PFB_DNS_REDIR_DESCR_V4_PFX).
_REDIR_DESCR_PFX = "pfB_DNS_Redirect_"

# Family suffixes appended by the builder.
_V4_SFX = "_v4"
_V6_SFX = "_v6"

# User NAT descriptor seeded in Cases 3 and 6 to prove survival.
_USER_NAT_DESCR = "my-user-nat-dns-redir-smoke"

# A synthetic alias name used in Case 5 (must pass is_validaliasname).
_EXCEPTION_ALIAS = "DNS_Exceptions_Test"


# --------------------------------------------------------------------------- #
# Module-scoped deployed_vm: install the branch .pkg once for all cases
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(  # noqa: ARG001
    smoke_vm: SmokeVM,
    stub_dns: _StubDnsServer,
    lan_interface: SmokeVM,
) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the dns_redirect module.

    Depends on ``lan_interface`` to ensure a LAN VLAN subinterface is
    provisioned before these tests run (the single-NIC smoke image boots with
    no LAN assigned; DNS redirect tests create LAN-scoped NAT/VIP rules).

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


# --------------------------------------------------------------------------- #
# Internal helpers — config.xml queries for DNS-redirect state
# --------------------------------------------------------------------------- #


def _redir_descr_for(iface: str, family: str) -> str:
    """Return the expected descr marker for a given interface + family pair."""
    sfx = _V4_SFX if family == "inet" else _V6_SFX
    return f"{_REDIR_DESCR_PFX}{iface}{sfx}"


def _nat_redir_count(vm: SmokeVM, descr_prefix: str, *, timeout: float = 60.0) -> int:
    """Count ``nat/rule`` entries whose ``descr`` starts with ``descr_prefix``."""
    pre = (
        "$count = 0;\n"
        "foreach (config_get_path('nat/rule', array()) as $r) {\n"
        f"  if (strpos((string) ($r['descr'] ?? ''), {h._php_str(descr_prefix)}) === 0)"
        "  { $count++; }\n"
        "}"
    )
    val = h._php_read_scalar(vm, pre, "$count", timeout=timeout)
    return int(val)


def _filter_redir_count(vm: SmokeVM, descr_prefix: str, *, timeout: float = 60.0) -> int:
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


def _nat_rule_field(vm: SmokeVM, descr: str, field: str, *, timeout: float = 60.0) -> str:
    """Read a scalar field from the ``nat/rule`` entry with an exact ``descr``."""
    pre = (
        "$val = '';\n"
        "foreach (config_get_path('nat/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{\n"
        f"    $val = (string) ($r[{h._php_str(field)}] ?? '');\n"
        "    break;\n"
        "  }\n"
        "}"
    )
    return h._php_read_scalar(vm, pre, "$val", timeout=timeout)


def _nat_rule_nested_field(vm: SmokeVM, descr: str, parent: str, child: str, *, timeout: float = 60.0) -> str:
    """Read a nested field (``rule[parent][child]``) from a ``nat/rule`` entry."""
    pre = (
        "$val = '';\n"
        "foreach (config_get_path('nat/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{\n"
        f"    $sub = $r[{h._php_str(parent)}] ?? array();\n"
        f"    $val = (string) ($sub[{h._php_str(child)}] ?? '');\n"
        "    break;\n"
        "  }\n"
        "}"
    )
    return h._php_read_scalar(vm, pre, "$val", timeout=timeout)


def _nat_rule_has_key(vm: SmokeVM, descr: str, parent: str, child: str, *, timeout: float = 60.0) -> bool:
    """True iff ``rule[parent][child]`` key exists in a ``nat/rule`` entry (value may be empty)."""
    pre = (
        "$found = FALSE;\n"
        "foreach (config_get_path('nat/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{\n"
        f"    $sub = $r[{h._php_str(parent)}] ?? array();\n"
        f"    $found = array_key_exists({h._php_str(child)}, $sub);\n"
        "    break;\n"
        "  }\n"
        "}"
    )
    val = h._php_read_scalar(vm, pre, "$found ? 'yes' : 'no'", timeout=timeout)
    return val == "yes"


def _nat_rule_present(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> bool:
    """True iff a ``nat/rule`` entry with this exact ``descr`` exists."""
    pre = (
        "$found = FALSE;\n"
        "foreach (config_get_path('nat/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(descr)}) {{ $found = TRUE; break; }}\n"
        "}"
    )
    return h._php_read_scalar(vm, pre, "$found ? 'yes' : 'no'", timeout=timeout) == "yes"


def _real_iface(vm: SmokeVM, iface: str, *, timeout: float = 60.0) -> str:
    """Resolve a pfSense config interface name (e.g. 'lan') to its device (e.g. 'vtnet2').

    ``pfctl -sn`` renders a loaded rdr rule on the PHYSICAL device, never the config
    name, so the live-pf gate must compare against the resolved device.
    """
    return h._php_read_scalar(vm, "", f"get_real_interface({h._php_str(iface)})", timeout=timeout).strip()


def _pfctl_sn_redir_protos(vm: SmokeVM, iface: str, *, timeout: float = 30.0) -> set[str]:
    """The protocols ({"tcp","udp"}) with a loaded pfBlockerNG DNS-redirect rdr rule on ``iface``.

    Returns the SET of matched protocols rather than a bare bool (#723): pf expands a
    config-level ``tcp/udp`` rule into per-protocol rules, so a regression rendering only
    one protocol must fail the positive gate (require both) while the teardown gate still
    checks full absence (empty set).

    Matches the LOADED form, which differs from the config / rules.debug form twice over:

      * the rule is on the interface's PHYSICAL device (e.g. ``vtnet2``), not the config
        name (``lan``) — resolved via :func:`_real_iface`;
      * ``pfctl`` renders destination port 53 as the ``/etc/services`` name ``domain``,
        not the literal ``53``.

    A matching line looks like::

        rdr pass on vtnet2 inet proto tcp from any to ! (self) port = domain -> 127.0.0.1

    so the redirect hallmark is the ``to ! (self)`` self-exemption on the resolved device,
    with the port rendered as ``domain`` (or numerically, defensively).
    """
    dev = _real_iface(vm, iface)
    result = vm.ssh(h.PFCTL, "-sn", timeout=timeout)
    protos: set[str] = set()
    if result.returncode != 0:
        return protos
    for line in result.stdout.splitlines():
        # Match the redirect hallmark explicitly: an rdr `on <device>` whose destination is
        # the negated self (`to ! (self)`). The anchored ` on {dev} ` (not a bare substring)
        # avoids a device-name prefix false match (e.g. vtnet2 vs vtnet20), and `to ! (self)`
        # is the redirect's self-exemption — together they keep the gate specific.
        if "rdr" not in line or not dev or f" on {dev} " not in line or "to ! (self)" not in line:
            continue
        if "domain" in line or "port = 53" in line or "port 53" in line:
            if " proto tcp " in line:
                protos.add("tcp")
            if " proto udp " in line:
                protos.add("udp")
    return protos


def _pfctl_sn_has_redir(vm: SmokeVM, iface: str, *, timeout: float = 30.0) -> bool:
    """Positive render gate: BOTH protocols of the tcp/udp redirect are loaded (#723)."""
    return {"tcp", "udp"} <= _pfctl_sn_redir_protos(vm, iface, timeout=timeout)


def _pfctl_sn_redir_absent(vm: SmokeVM, iface: str, *, timeout: float = 30.0) -> bool:
    """Negative render gate: NO redirect rule of either protocol remains loaded."""
    return not _pfctl_sn_redir_protos(vm, iface, timeout=timeout)


def _redir_match_report(vm: SmokeVM, iface: str, *, expected_present: bool, timeout: float = 30.0) -> str:
    """Expected-vs-actual report for the DNS-redirect live-pf gate (printed on failure).

    The harness has no assertion framework, so a failing live-pf check must put the
    comparison on the terminal itself — what the matcher EXPECTED next to what
    ``pfctl -sn`` ACTUALLY held — so a reader never has to guess. Resolves the config
    iface to its device and lists the live rdr rules on that device verbatim.
    """
    dev = _real_iface(vm, iface, timeout=timeout)
    result = vm.ssh(h.PFCTL, "-sn", timeout=timeout)
    if result.returncode != 0:
        actual = [f"<pfctl -sn failed: rc={result.returncode} {result.stderr.strip()}>"]
    else:
        actual = [ln.strip() for ln in result.stdout.splitlines() if "rdr" in ln and dev and dev in ln]
    want = "PRESENT (both protocols)" if expected_present else "ABSENT (no protocol)"
    matched = _pfctl_sn_redir_protos(vm, iface, timeout=timeout)
    body = "\n".join(f"      {ln}" for ln in actual) if actual else "      (no rdr rules on this device)"
    return (
        f"  Expecting a pfBlockerNG DNS-redirect rdr rule to be {want} in the live nat ruleset:\n"
        f"    device      : {dev}  (config iface {iface!r})\n"
        f"    destination : ! (self)\n"
        f"    dest port   : domain (53)\n"
        f"    protocols   : expected {{'tcp', 'udp'}} both rendered — matched {matched or '{}'}\n"
        f"  Actual rdr rules on {dev} (pfctl -sn):\n"
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
# Config setters for the three ADR-36 registered fields
# --------------------------------------------------------------------------- #


def _set_dns_redirect(
    vm: SmokeVM, *, enabled: bool, ifaces: list[str], exception: str = "", timeout: float = 60.0
) -> None:
    """Write the three DNS-redirect config fields and persist config.xml.

    Uses ``config_set_path`` on the DNSBL-settings section directly (these are
    registered fields, but the smoke harness writes the section atomically the
    same way ``inject()`` writes other settings — config-API over pfSsh.php).
    """
    toggle = "on" if enabled else ""
    iface_val = ",".join(ifaces)
    snippet = (
        f"$d = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        f"$d['dnsbl_redir']         = {h._php_str(toggle)};\n"
        f"$d['dnsbl_redir_int']     = {h._php_str(iface_val)};\n"
        f"$d['dnsbl_redir_exclude'] = {h._php_str(exception)};\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: set DNS redirect config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_dns_redirect failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _set_pfb_keep(vm: SmokeVM, *, keep: bool, timeout: float = 60.0) -> None:
    """Set the ``pfb_keep`` flag ('on' retains settings/data on disable+uninstall).

    The uninstall sweep that removes pfBlockerNG-owned firewall objects runs only on
    the full-removal path (``pfb_keep != 'on'``). ``pfb_keep`` defaults to 'on' (issue
    #281), so a test that asserts the owned objects are swept must select the
    full-removal path explicitly. The ``keep='on'`` uninstall path (owned objects must
    still be removed while settings are retained) is tracked in issue #484.
    """
    value = "on" if keep else "off"
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        f"$g['pfb_keep'] = {h._php_str(value)};\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        "write_config('pfBlockerNG smoke: set pfb_keep');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_pfb_keep failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _seed_user_nat(vm: SmokeVM, descr: str, *, timeout: float = 60.0) -> None:
    """Inject a minimal user NAT rule (no pfB marker) — must survive enable/disable/uninstall."""
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
        "  write_config('pfBlockerNG smoke: seed user NAT for DNS redirect test');\n"
        "}\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_user_nat({descr!r}) failed: rc={result.returncode} {result.stderr!r}")


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
        "  write_config('pfBlockerNG smoke: seed pfSense alias for dns redirect exception');\n"
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
        "write_config('pfBlockerNG smoke: remove pfSense alias for dns redirect exception');\n"
        "echo 'OK';"
    )
    h.php_eval(vm, snippet, timeout=timeout)  # best-effort; ignore rc/stdout


def _cleanup_redirect(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Disable redirect and reload — shared teardown used by finally blocks."""
    try:
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", timeout=timeout, wait_unbound=False)
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
# Case 1 — Enable path: both families created + pfctl -sn confirms rdr active
# --------------------------------------------------------------------------- #


def test_dns_redirect_enable_creates_nat_and_filter_rules(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 Case 1: enabling redirect on the primary non-WAN interface creates pfB-owned NAT rules.

    Scenario: enable path — both IP families created, pfctl -sn confirms rdr renders.

      Background: pfBlockerNG installed; DNS redirect disabled.

      Given no pfB_DNS_Redirect_* entries in nat/rule or filter/rule (before-state),
        And pfctl -sn shows no rdr rules for port 53 on the primary interface (before-state),

      When DNS redirect is enabled on the primary non-WAN interface and a full reload runs,

      Then nat/rule contains exactly 2 pfB_DNS_Redirect_<iface>_* entries (v4 + v6).
        And filter/rule contains 0 pfB_DNS_Redirect_<iface>_* entries (associated-rule-id='pass'
            causes pfSense to emit an inline rdr pass — no hand-rolled companion needed).
        And each nat/rule entry carries the correct §2.2 field values:
            - associated-rule-id: 'pass'
            - ipprotocol: inet (v4) / inet6 (v6)
            - target: 127.0.0.1 (v4) / ::1 (v6)
            - protocol: tcp/udp
            - local-port: 53
            - natreflection: disable
            - destination: (self) network, not-negated, port 53
        And pfctl -sn shows rdr rules on the primary interface for port 53
            (proving the rules actually render in the live pf ruleset).
    """
    vm = deployed_vm
    iface = primary_iface
    descr_v4 = _redir_descr_for(iface, "inet")
    descr_v6 = _redir_descr_for(iface, "inet6")

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DNS-redirect NAT rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — disable redirect; assert before-state clean.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        assert _nat_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* nat/rule entries present before enable — before-state not clean"
        )
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* filter/rule entries present before enable — before-state not clean"
        )
        assert _pfctl_sn_redir_absent(vm, iface), (
            f"pfctl -sn shows an rdr rule on {iface} before enable — before-state not clean\n"
            + _redir_match_report(vm, iface, expected_present=False)
        )

        # WHEN — enable on the primary interface and reload.
        # Snapshot before/after so the per-step state diff (SMOKE_STATE_DIFF, end of
        # log) shows config.xml gaining the rdr rows, whether /tmp/rules.debug gains
        # the rdr, the interface IPs (ifconfig.txt), and any rdr in pf_nat.txt —
        # localising where a "in config, absent from pf" failure happens on the VM.
        h.snap_state(vm, "redir_pre")
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        h.snap_state(vm, "redir_enabled")

        # THEN — exactly 2 nat/rule entries (v4 + v6).
        nat_count = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface)
        assert nat_count == 2, f"Expected 2 pfB_DNS_Redirect_{iface}_* nat/rule entries after enable, got {nat_count}"

        # THEN — 0 hand-rolled filter/rule PASS companion entries.
        # The NAT rules use associated-rule-id='pass' — pfSense emits an inline rdr pass
        # and manages the companion firewall pass automatically. No separate filter/rule entry.
        filter_count = _filter_redir_count(vm, _REDIR_DESCR_PFX + iface)
        assert filter_count == 0, (
            f"Expected 0 pfB_DNS_Redirect_{iface}_* filter/rule entries after enable "
            f"(associated-rule-id='pass' — no hand-rolled companion), got {filter_count}"
        )

        # THEN — associated-rule-id='pass' on the v4 NAT rule.
        rid_v4 = _nat_rule_field(vm, descr_v4, "associated-rule-id")
        assert rid_v4 == "pass", (
            f"{descr_v4}: associated-rule-id == {rid_v4!r}, expected 'pass' (causes pfSense to emit inline rdr pass)"
        )

        # THEN — field-by-field verification on the v4 rule.
        assert _nat_rule_field(vm, descr_v4, "ipprotocol") == "inet", f"{descr_v4}: ipprotocol != 'inet'"
        assert _nat_rule_field(vm, descr_v4, "target") == "127.0.0.1", f"{descr_v4}: target != '127.0.0.1'"
        assert _nat_rule_field(vm, descr_v4, "protocol") == "tcp/udp", f"{descr_v4}: protocol != 'tcp/udp'"
        assert _nat_rule_field(vm, descr_v4, "local-port") == "53", f"{descr_v4}: local-port != '53'"
        assert _nat_rule_field(vm, descr_v4, "natreflection") == "disable", f"{descr_v4}: natreflection != 'disable'"
        # Destination: (self) with negation and port 53.
        assert _nat_rule_nested_field(vm, descr_v4, "destination", "network") == "(self)", (
            f"{descr_v4}: destination.network != '(self)'"
        )
        assert _nat_rule_has_key(vm, descr_v4, "destination", "not"), (
            f"{descr_v4}: destination.not key absent (self-exempt negation missing)"
        )
        assert _nat_rule_nested_field(vm, descr_v4, "destination", "port") == "53", (
            f"{descr_v4}: destination.port != '53'"
        )

        # THEN — associated-rule-id='pass' on the v6 NAT rule.
        rid_v6 = _nat_rule_field(vm, descr_v6, "associated-rule-id")
        assert rid_v6 == "pass", f"{descr_v6}: associated-rule-id == {rid_v6!r}, expected 'pass'"

        # THEN — field-by-field verification on the v6 rule.
        assert _nat_rule_field(vm, descr_v6, "ipprotocol") == "inet6", f"{descr_v6}: ipprotocol != 'inet6'"
        assert _nat_rule_field(vm, descr_v6, "target") == "::1", f"{descr_v6}: target != '::1'"
        assert _nat_rule_field(vm, descr_v6, "protocol") == "tcp/udp", f"{descr_v6}: protocol != 'tcp/udp'"
        assert _nat_rule_field(vm, descr_v6, "local-port") == "53", f"{descr_v6}: local-port != '53'"
        assert _nat_rule_field(vm, descr_v6, "natreflection") == "disable", f"{descr_v6}: natreflection != 'disable'"
        assert _nat_rule_nested_field(vm, descr_v6, "destination", "network") == "(self)", (
            f"{descr_v6}: destination.network != '(self)'"
        )
        assert _nat_rule_has_key(vm, descr_v6, "destination", "not"), (
            f"{descr_v6}: destination.not key absent (self-exempt negation missing)"
        )
        assert _nat_rule_nested_field(vm, descr_v6, "destination", "port") == "53", (
            f"{descr_v6}: destination.port != '53'"
        )

        # THEN — pfctl -sn confirms the rdr rules are ACTIVE in the live pf ruleset.
        # This is the key gate that proves associated-rule-id='pass' actually renders.
        assert _pfctl_sn_has_redir(vm, iface), (
            f"pfctl -sn shows no rdr rule on {iface} for port 53 after enable — "
            f"associated-rule-id='pass' did NOT render in the live pf ruleset\n"
            + _redir_match_report(vm, iface, expected_present=True)
            + "\n"
            + h.pf_state_dump(vm)
        )

    finally:
        _cleanup_redirect(vm)


# --------------------------------------------------------------------------- #
# Case 2 — Disable path: all pfB_DNS_Redirect_* rules removed, pfctl clean
# --------------------------------------------------------------------------- #


def test_dns_redirect_disable_removes_nat_and_filter_rules(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 Case 2: disabling redirect removes all pfB_DNS_Redirect_* rules.

    Scenario: disable path — rules removed from config.xml and pfctl.

      Given DNS redirect is enabled on the primary non-WAN interface,
        And pfB_DNS_Redirect_<iface>_* entries are present in nat/rule (before-state),
        And filter/rule has 0 pfB_DNS_Redirect_<iface>_* entries (associated-rule-id='pass' —
            pfSense manages the companion automatically; no hand-rolled entries stored),
        And pfctl -sn shows rdr rules on the primary interface for port 53 (before-state),

      When DNS redirect is disabled and a full reload runs,

      Then nat/rule has no pfB_DNS_Redirect_* entries.
        And filter/rule has no pfB_DNS_Redirect_* entries (was already 0).
        And pfctl -sn shows no rdr rules on the primary interface for port 53.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DNS-redirect NAT rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — enable on the primary interface; assert before-state with rules present.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        assert _nat_redir_count(vm, _REDIR_DESCR_PFX + iface) == 2, (
            f"pfB_DNS_Redirect_{iface}_* nat/rule entries absent before disable — setup failed"
        )
        # No filter/rule entries: associated-rule-id='pass' — pfSense emits inline rdr pass
        # without any hand-rolled companion stored in config.xml.
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX + iface) == 0, (
            f"pfB_DNS_Redirect_{iface}_* filter/rule entries present before disable — unexpected "
            f"(associated-rule-id='pass' means no hand-rolled companions should exist)"
        )
        assert _pfctl_sn_has_redir(vm, iface), (
            f"pfctl -sn shows no rdr on {iface} before disable — setup failed\n"
            + _redir_match_report(vm, iface, expected_present=True)
        )

        # WHEN — disable and reload.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — all pfB_DNS_Redirect_* entries must be gone.
        assert _nat_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* nat/rule entries still present after disable"
        )
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* filter/rule entries still present after disable"
        )

        # THEN — pfctl -sn must show no rdr rule for port 53 on the primary interface.
        assert _pfctl_sn_redir_absent(vm, iface), (
            f"pfctl -sn still shows an rdr rule on {iface} after disable\n"
            + _redir_match_report(vm, iface, expected_present=False)
        )

    finally:
        _cleanup_redirect(vm)


# --------------------------------------------------------------------------- #
# Case 3 — User-rule survival: a user nat/rule survives enable → disable
# --------------------------------------------------------------------------- #


def test_dns_redirect_user_nat_rule_survives_enable_disable(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 Case 3: a user nat/rule without a pfB marker is never touched.

    Scenario: user-rule survival — enable then disable does not modify user rules.

      Given a user nat/rule entry (descr='my-user-nat-dns-redir-smoke', no pfB
            marker) is present in config.xml,
        And DNS redirect is disabled initially (before-state),

      When DNS redirect is enabled on the primary non-WAN interface and a reload runs (pfB rules appear),
        Then the user nat/rule is still present (survives enable).

      When DNS redirect is disabled and a reload runs (pfB rules removed),
        Then the user nat/rule is still present (survives disable).
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DNS-redirect NAT rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — seed the user NAT rule; assert redirect is disabled.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        _seed_user_nat(vm, _USER_NAT_DESCR)

        assert _nat_rule_present(vm, _USER_NAT_DESCR), "user NAT rule not present before enable — seeding failed"
        assert not _nat_rule_present(vm, _redir_descr_for(iface, "inet")), (
            f"{_redir_descr_for(iface, 'inet')} already present before enable — state not clean"
        )

        # WHEN — enable on the primary interface.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — pfB rules appear; user rule survives.
        assert _nat_rule_present(vm, _redir_descr_for(iface, "inet")), (
            f"{_redir_descr_for(iface, 'inet')} not created after enable"
        )
        assert _nat_rule_present(vm, _USER_NAT_DESCR), (
            "user NAT rule was removed during enable — should never be touched"
        )

        # WHEN — disable.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — pfB rules gone; user rule still present.
        assert not _nat_rule_present(vm, _redir_descr_for(iface, "inet")), (
            f"{_redir_descr_for(iface, 'inet')} still present after disable"
        )
        assert _nat_rule_present(vm, _USER_NAT_DESCR), (
            "user NAT rule was removed during disable — should never be touched"
        )

    finally:
        _cleanup_redirect(vm)


# --------------------------------------------------------------------------- #
# Case 4 — Stale-interface prune: reduce from two interfaces to one
# --------------------------------------------------------------------------- #


def test_dns_redirect_stale_interface_pruned_on_reduce(deployed_vm: SmokeVM) -> None:
    """ADR-36 Case 4: removing an interface from the selection prunes its rules.

    Scenario: stale-interface prune — reduce two interfaces to one.

      Background: VM has at least two non-WAN interfaces available.

      Given redirect enabled on the first two discovered non-WAN interfaces
        (e.g. lan + opt1 — names are discovered, never assumed),
        And both interfaces' pfB_DNS_Redirect_* nat/rule entries present (before-state),
        And both interfaces' filter/rule counts are 0 (associated-rule-id='pass';
            no hand-rolled companion entries),

      When the selection is reduced to the first interface only and a reload runs,

      Then the second interface's pfB_DNS_Redirect_* entries are GONE from nat/rule.
        And the first interface's pfB_DNS_Redirect_* entries are STILL PRESENT (both families).
        And filter/rule has 0 pfB_DNS_Redirect_* entries for either interface throughout.
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
        # pfblockerng will create DNS-redirect NAT rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — enable on both interfaces; assert both nat/rule sets present.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface_keep, iface_drop], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        assert _nat_redir_count(vm, _REDIR_DESCR_PFX + iface_keep) == 2, (
            f"pfB_DNS_Redirect_{iface_keep}_* nat/rule entries absent before prune — setup failed"
        )
        assert _nat_redir_count(vm, _REDIR_DESCR_PFX + iface_drop) == 2, (
            f"pfB_DNS_Redirect_{iface_drop}_* nat/rule entries absent before prune — setup failed"
        )
        # No filter/rule entries: associated-rule-id='pass' — no hand-rolled companions.
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX + iface_keep) == 0, (
            f"pfB_DNS_Redirect_{iface_keep}_* filter/rule entries present before prune — unexpected "
            f"(associated-rule-id='pass' means no hand-rolled companions should exist)"
        )
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX + iface_drop) == 0, (
            f"pfB_DNS_Redirect_{iface_drop}_* filter/rule entries present before prune — unexpected "
            f"(associated-rule-id='pass' means no hand-rolled companions should exist)"
        )

        # WHEN — reduce to keep-interface only.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface_keep], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — drop-interface nat/rule entries removed; filter/rule was and remains 0.
        drop_nat = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface_drop)
        assert drop_nat == 0, f"pfB_DNS_Redirect_{iface_drop}_* nat/rule entries ({drop_nat}) still present after prune"
        drop_filter = _filter_redir_count(vm, _REDIR_DESCR_PFX + iface_drop)
        assert drop_filter == 0, (
            f"pfB_DNS_Redirect_{iface_drop}_* filter/rule entries ({drop_filter}) still present after prune"
        )

        # THEN — keep-interface rules remain: 2 NAT (inet + inet6); filter/rule still 0.
        keep_nat = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface_keep)
        assert keep_nat == 2, (
            f"pfB_DNS_Redirect_{iface_keep}_* nat/rule entries reduced to {keep_nat} after prune (expected 2)"
        )
        keep_filter = _filter_redir_count(vm, _REDIR_DESCR_PFX + iface_keep)
        assert keep_filter == 0, (
            f"pfB_DNS_Redirect_{iface_keep}_* filter/rule entries is {keep_filter} after prune "
            f"(expected 0 — associated-rule-id='pass', no hand-rolled companions)"
        )

    finally:
        _cleanup_redirect(vm)


# --------------------------------------------------------------------------- #
# Case 5 — Exception alias branch: alias set → negated source; empty → <any>
# --------------------------------------------------------------------------- #


def test_dns_redirect_exception_alias_branch(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 Case 5: exception alias wires negated-alias source; empty = <any>.

    Scenario: exception alias branch — both states, both IP families.

      Given redirect is disabled.

      When redirect is enabled on the primary non-WAN interface with dnsbl_redir_exclude = 'DNS_Exceptions_Test',

      Then each nat/rule entry (v4 + v6) has:
            - source.address == 'DNS_Exceptions_Test'
            - source.not key present (negated)

      When dnsbl_redir_exclude is cleared ('') and a reload runs,

      Then each nat/rule entry (v4 + v6) has source.any key (source = <any>)
            and source.address is absent.
    """
    vm = deployed_vm
    iface = primary_iface
    descr_v4 = _redir_descr_for(iface, "inet")
    descr_v6 = _redir_descr_for(iface, "inet6")

    try:
        # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
        # pfblockerng will create DNS-redirect NAT rules on reload (#484 coupling).
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        # GIVEN — start from disabled state.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        assert _nat_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* entries present before Case 5 — state not clean"
        )

        # Create a real pfSense network alias so pfctl can resolve 'from !<alias>'
        # without a syntax error when the ruleset is applied after reload.
        _seed_pf_alias(vm, _EXCEPTION_ALIAS, "192.0.2.0/24")

        # WHEN — enable with exception alias set.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception=_EXCEPTION_ALIAS)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — v4 rule has negated-alias source.
        v4_src_addr = _nat_rule_nested_field(vm, descr_v4, "source", "address")
        assert v4_src_addr == _EXCEPTION_ALIAS, (
            f"{descr_v4}: source.address == {v4_src_addr!r}, expected {_EXCEPTION_ALIAS!r}"
        )
        assert _nat_rule_has_key(vm, descr_v4, "source", "not"), (
            f"{descr_v4}: source.not key absent (negation missing for exception alias)"
        )

        # THEN — v6 rule has negated-alias source.
        v6_src_addr = _nat_rule_nested_field(vm, descr_v6, "source", "address")
        assert v6_src_addr == _EXCEPTION_ALIAS, (
            f"{descr_v6}: source.address == {v6_src_addr!r}, expected {_EXCEPTION_ALIAS!r}"
        )
        assert _nat_rule_has_key(vm, descr_v6, "source", "not"), (
            f"{descr_v6}: source.not key absent (negation missing for exception alias)"
        )

        # WHEN — clear the exception alias.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — v4 rule source is <any> (source.any key present; address absent).
        assert _nat_rule_has_key(vm, descr_v4, "source", "any"), (
            f"{descr_v4}: source.any key absent when exception is empty"
        )
        v4_src_addr_clear = _nat_rule_nested_field(vm, descr_v4, "source", "address")
        assert v4_src_addr_clear == "", (
            f"{descr_v4}: source.address == {v4_src_addr_clear!r} when exception cleared (expected '')"
        )

        # THEN — v6 rule source is <any>.
        assert _nat_rule_has_key(vm, descr_v6, "source", "any"), (
            f"{descr_v6}: source.any key absent when exception is empty"
        )
        v6_src_addr_clear = _nat_rule_nested_field(vm, descr_v6, "source", "address")
        assert v6_src_addr_clear == "", (
            f"{descr_v6}: source.address == {v6_src_addr_clear!r} when exception cleared (expected '')"
        )

    finally:
        _remove_pf_alias(vm, _EXCEPTION_ALIAS)
        _cleanup_redirect(vm)


# --------------------------------------------------------------------------- #
# Case 6 — Uninstall sweep: all pfB_DNS_Redirect_* gone; user NAT survives
# --------------------------------------------------------------------------- #


def test_dns_redirect_uninstall_sweeps_owned_rules_preserves_user_nat(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 Case 6: uninstall sweeps all pfB_DNS_Redirect_* entries; user NAT survives.

    Scenario: uninstall sweep — owned rules gone, user rule and sections gone.

      Given DNS redirect is enabled on the primary non-WAN interface
            (pfB_DNS_Redirect_<iface>_* in nat/rule, confirmed in config.xml as
            before-state; filter/rule has 0 pfB entries — associated-rule-id='pass'),
        And a user nat/rule entry (no pfB marker) is present in config.xml,
        And installedpackages/pfblockerng* sections are present (before-state),

      When pfBlockerNG is uninstalled via 'pkg delete',

      Then all pfB_DNS_Redirect_* entries are GONE from nat/rule.
        And filter/rule has 0 pfB_DNS_Redirect_* entries (was already 0; stays 0).
        And no pfBlockerNG nat/rule entries remain.
        And the user nat/rule entry is STILL PRESENT and unchanged.
        And installedpackages/pfblockerng* sections are GONE from config.xml.
    """
    vm = deployed_vm
    iface = primary_iface

    # GIVEN — establish $mode='enabled' (master ON + DNSBL ON + resolver up) so
    # pfblockerng will create DNS-redirect NAT rules on reload (#484 coupling).
    h.set_package_enabled(vm, True)
    h.set_dnsbl_enabled(vm, True)
    # GIVEN — enable redirect on the primary interface and seed a user NAT rule.
    # Select the full-removal uninstall path: the owned-object sweep runs only when
    # pfb_keep != 'on', and pfb_keep defaults to 'on' (issue #281). The keep='on'
    # uninstall path (owned objects swept, settings retained) is tracked in #484.
    _set_pfb_keep(vm, keep=False)
    _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
    h.reload(vm, "update", wait_unbound=False)
    h.apply_filter_sync(vm)
    _seed_user_nat(vm, _USER_NAT_DESCR)

    # BEFORE-STATE: assert nat/rule entries present; filter/rule entries are 0 (no companions).
    assert _nat_redir_count(vm, _REDIR_DESCR_PFX + iface) == 2, (
        f"pfB_DNS_Redirect_{iface}_* nat/rule entries absent before uninstall — setup failed"
    )
    # associated-rule-id='pass' — no hand-rolled filter/rule companions are stored.
    assert _filter_redir_count(vm, _REDIR_DESCR_PFX + iface) == 0, (
        f"pfB_DNS_Redirect_{iface}_* filter/rule entries present before uninstall — unexpected "
        f"(associated-rule-id='pass' means no hand-rolled companions should exist)"
    )
    assert _nat_rule_present(vm, _USER_NAT_DESCR), "user NAT rule absent before uninstall — seeding failed"
    assert _pfb_sections_present(vm), "installedpackages/pfblockerng* absent before uninstall — unexpected clean state"

    # WHEN — uninstall pfBlockerNG (triggers pfblockerng_php_pre_deinstall_command →
    # owned-object sweep before pfb_remove_config_settings).
    _pkg_delete(vm)

    # THEN — all pfB_DNS_Redirect_* entries are gone.
    assert _nat_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
        "pfB_DNS_Redirect_* nat/rule entries still present after uninstall — ADR-35/36 sweep did not run\n"
        + h.deinstall_debug(vm)
    )
    assert _filter_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
        "pfB_DNS_Redirect_* filter/rule entries still present after uninstall"
    )

    # THEN — user NAT rule survives.
    assert _nat_rule_present(vm, _USER_NAT_DESCR), (
        "user NAT rule was DELETED during uninstall — ADR-35 sweep incorrectly removed a user object"
    )

    # THEN — pfBlockerNG config sections are gone.
    assert not _pfb_sections_present(vm), (
        "installedpackages/pfblockerng* still present after uninstall — pfb_remove_config_settings did not run"
    )


# --------------------------------------------------------------------------- #
# Case 7 — Master-disable coupling: redirect rules absent when master OFF
# --------------------------------------------------------------------------- #


def test_dns_redirect_master_disable_removes_rules_despite_toggle_on(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 / issue #484 Case 7: master-disable forces redirect rules absent even with toggle ON.

    Scenario: $mode-coupling — master enable_cb=off removes redirect rules unconditionally.

      Background: pfBlockerNG installed; DNS redirect disabled; DNSBL enabled.

      Given DNS redirect is enabled on the primary non-WAN interface (toggle ON),
        And the master switch (enable_cb) is ON,
        And 2 pfB_DNS_Redirect_<iface>_* nat/rule entries are present (before-state),
        And pfctl -sn shows rdr rules on the primary interface (before-state),

      When the master switch is turned OFF (enable_cb='') and a full reload runs,

      Then nat/rule has 0 pfB_DNS_Redirect_* entries (rules force-removed by $mode coupling).
        And pfctl -sn shows no rdr rules on the primary interface for port 53.

      Note: the redirect TOGGLE (dnsbl_redir) remains ON throughout; the removal is caused
      solely by the master switch, proving the $mode-coupling in pfblockerng_php_pre_deinstall
      and pfb_create_dnsbl (devel: DNS-redirect/DoT rules coupled to $mode==='enabled').
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — ensure master ON; enable redirect; assert before-state present.
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        before_count = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface)
        assert before_count == 2, (
            f"Expected 2 pfB_DNS_Redirect_{iface}_* nat/rule entries before master-disable, got {before_count}"
        )
        assert _pfctl_sn_has_redir(vm, iface), (
            f"pfctl -sn shows no rdr on {iface} before master-disable — before-state setup failed\n"
            + _redir_match_report(vm, iface, expected_present=True)
        )

        # WHEN — turn master OFF; reload (dnsbl_redir toggle remains ON).
        h.set_package_enabled(vm, False)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — all redirect nat rules must be gone (force-removed by $mode coupling).
        after_count = _nat_redir_count(vm, _REDIR_DESCR_PFX)
        assert after_count == 0, (
            f"pfB_DNS_Redirect_* nat/rule entries still present ({after_count}) after master-disable — "
            f"$mode-coupling did not force-remove redirect rules when enable_cb='' (master OFF)\n"
            + _redir_match_report(vm, iface, expected_present=False)
        )

        # THEN — pfctl confirms no rdr rule.
        assert _pfctl_sn_redir_absent(vm, iface), (
            f"pfctl -sn still shows an rdr rule on {iface} after master-disable\n"
            + _redir_match_report(vm, iface, expected_present=False)
        )

    finally:
        # Restore baseline: master ON, redirect disabled.
        h.set_package_enabled(vm, True)
        _cleanup_redirect(vm)


# --------------------------------------------------------------------------- #
# Case 8 — DNSBL-disable coupling: redirect rules absent when DNSBL toggle OFF
# --------------------------------------------------------------------------- #


def test_dns_redirect_dnsbl_disable_removes_rules_despite_toggle_on(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 / issue #484 Case 8: DNSBL-off forces redirect rules absent even with toggle ON.

    Scenario: $mode-coupling — DNSBL toggle pfb_dnsbl='' removes redirect rules unconditionally.

      Background: pfBlockerNG installed; master ON; DNS redirect toggle ON.

      Given master ON + DNSBL ON + redirect ON → 2 pfB_DNS_Redirect_<iface>_* entries present
        (before-state: prove all-ON produces rules — this is the positive guard),

      When DNSBL is turned OFF (pfb_dnsbl='') and a full reload runs
        (master remains ON; redirect toggle dnsbl_redir remains ON),

      Then nat/rule has 0 pfB_DNS_Redirect_* entries (force-removed by $mode coupling).
        And pfctl -sn shows no rdr rules on the primary interface for port 53.

      Note: the positive guard (rules present when all enablers are ON) prevents this
      test from masking a regression where rules are always absent regardless.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — master ON + DNSBL ON + redirect ON; assert before-state with rules present.
        h.set_package_enabled(vm, True)
        h.set_dnsbl_enabled(vm, True)
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        before_count = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface)
        assert before_count == 2, (
            f"Expected 2 pfB_DNS_Redirect_{iface}_* nat/rule entries before DNSBL-disable (positive guard), "
            f"got {before_count} — rules absent even when all enablers are ON"
        )
        assert _pfctl_sn_has_redir(vm, iface), (
            f"pfctl -sn shows no rdr on {iface} before DNSBL-disable — before-state setup failed\n"
            + _redir_match_report(vm, iface, expected_present=True)
        )

        # WHEN — turn DNSBL OFF; reload (master ON; dnsbl_redir toggle remains ON).
        h.set_dnsbl_enabled(vm, False)
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)

        # THEN — all redirect nat rules must be gone (force-removed by $mode coupling).
        after_count = _nat_redir_count(vm, _REDIR_DESCR_PFX)
        assert after_count == 0, (
            f"pfB_DNS_Redirect_* nat/rule entries still present ({after_count}) after DNSBL-disable — "
            f"$mode-coupling did not force-remove redirect rules when pfb_dnsbl='' (DNSBL OFF)\n"
            + _redir_match_report(vm, iface, expected_present=False)
        )

        # THEN — pfctl confirms no rdr rule.
        assert _pfctl_sn_redir_absent(vm, iface), (
            f"pfctl -sn still shows an rdr rule on {iface} after DNSBL-disable\n"
            + _redir_match_report(vm, iface, expected_present=False)
        )

    finally:
        # Restore baseline: DNSBL ON, redirect disabled.
        h.set_dnsbl_enabled(vm, True)
        _cleanup_redirect(vm)


# --------------------------------------------------------------------------- #
# Case 9 — Uninstall keep=on: live rules gone; sections + data retained (#484)
# --------------------------------------------------------------------------- #


def test_dns_redirect_uninstall_keep_on_removes_rules_retains_sections(
    deployed_vm: SmokeVM, primary_iface: str
) -> None:
    """ADR-36 / issue #484 Case 9: uninstall with keep=on removes redirect rules but retains sections.

    Scenario: uninstall keep=on — live firewall objects torn down unconditionally;
    settings sections retained because pfb_keep=on.

      Given pfb_keep is set to 'on' (retain settings + data on uninstall),
        And DNS redirect is enabled on the primary non-WAN interface (redirect toggle ON),
        And 2 pfB_DNS_Redirect_<iface>_* nat/rule entries are present (before-state),
        And a user nat/rule entry (no pfB marker) is present in config.xml (before-state),
        And installedpackages/pfblockerng* sections are present (before-state),

      When pfBlockerNG is uninstalled via 'pkg delete',

      Then all pfB_DNS_Redirect_* nat/rule entries are GONE (live sweep is unconditional).
        And the user nat/rule entry is STILL PRESENT (user objects never swept).
        And installedpackages/pfblockerng* sections are STILL PRESENT (pfb_keep=on retains them).

      This is the core #484 fix: before the fix the deinstall keep-gate blocked the live-object
      sweep, so pfB-owned rules were left behind. After the fix, live-object teardown runs
      unconditionally; pfb_keep gates only the settings/data removal.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — set keep=on; enable redirect; seed user NAT; assert all before-states.
        h.set_pfb_keep(vm, True)
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update", wait_unbound=False)
        h.apply_filter_sync(vm)
        _seed_user_nat(vm, _USER_NAT_DESCR)

        before_nat = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface)
        assert before_nat == 2, (
            f"Expected 2 pfB_DNS_Redirect_{iface}_* nat/rule entries before keep=on uninstall, got {before_nat}"
        )
        assert _nat_rule_present(vm, _USER_NAT_DESCR), (
            "user NAT rule not present before keep=on uninstall — seeding failed"
        )
        assert _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* absent before keep=on uninstall — unexpected clean state"
        )

        # WHEN — uninstall pfBlockerNG with pfb_keep=on.
        _pkg_delete(vm)

        # THEN — pfB-owned redirect rules are GONE (live-object teardown is unconditional).
        after_nat = _nat_redir_count(vm, _REDIR_DESCR_PFX)
        assert after_nat == 0, (
            f"pfB_DNS_Redirect_* nat/rule entries still present ({after_nat}) after keep=on uninstall — "
            f"live-object teardown did not run unconditionally (the #484 bug: keep-gate blocked the sweep)\n"
            + h.deinstall_debug(vm)
        )

        # THEN — user NAT rule survives (never swept).
        assert _nat_rule_present(vm, _USER_NAT_DESCR), (
            "user NAT rule was DELETED during keep=on uninstall — sweep incorrectly removed a user object"
        )

        # THEN — pfblockerng* sections are STILL PRESENT (pfb_keep=on retains settings + data).
        assert _pfb_sections_present(vm), (
            "installedpackages/pfblockerng* GONE after keep=on uninstall — "
            "pfb_keep=on should have retained settings sections (the #484 fix: keep gates only settings/data)"
        )

    finally:
        # Best-effort teardown — runs on success too so the retained config (keep=on leaves
        # the DNSBL section in place) does not bleed the redirect toggle into the next module.
        # _cleanup_redirect is internally best-effort: its config write turns the toggle off
        # even with the package uninstalled, and its reload no-ops when the package is gone.
        _cleanup_redirect(vm)
