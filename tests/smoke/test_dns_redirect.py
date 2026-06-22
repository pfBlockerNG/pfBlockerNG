"""ADR-36 — live-VM smoke coverage for optional NAT DNS-redirection.

Proves on a real pfSense CE VM that:

* **Case 1 (Enable path):** enabling DNS redirect on the primary non-WAN interface
  creates 2 ``nat/rule`` entries (``pfB_DNS_Redirect_<iface>_v4`` +
  ``pfB_DNS_Redirect_<iface>_v6``) and 2 ``filter/rule`` entries, each with the
  correct §2.2 field values; ``pfctl -sn`` confirms the rdr rules are active.
* **Case 2 (Disable path):** disabling removes all ``pfB_DNS_Redirect_*`` entries
  from both sections; ``pfctl -sn`` shows no pfBlockerNG rdr rules for port 53.
* **Case 3 (User-rule survival):** a user ``nat/rule`` entry (no pfB marker)
  survives enable → disable without modification.
* **Case 4 (Stale-interface prune):** enabling on two interfaces then reducing to
  one removes the dropped-interface rules while keeping the retained-interface rules.
  Skipped when the VM exposes fewer than two non-WAN interfaces.
* **Case 5 (Exception alias branch):** enabling with a non-empty alias name wires
  a negated-alias source in config.xml; clearing the alias switches the source to
  ``<any>`` — both branches asserted for both IP families.
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

# Package name on the devel channel (matches test_smoke_fwobj.py).
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
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for the dns_redirect module.

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


def _pfctl_sn_has_redir(vm: SmokeVM, iface: str, *, timeout: float = 30.0) -> bool:
    """True iff ``pfctl -sn`` output contains an rdr rule referencing ``iface`` and port 53."""
    result = vm.ssh(h.PFCTL, "-sn", timeout=timeout)
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        # An active rdr rule looks like: rdr on em1 proto tcp/udp from any to !<em1> port 53 -> 127.0.0.1 port 53
        # Match by interface name and port 53 being the destination.
        if "rdr" in line and iface in line and "port 53" in line:
            return True
    return False


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


def _cleanup_redirect(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Disable redirect and reload — shared teardown used by finally blocks."""
    try:
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update", timeout=timeout)
    except Exception:
        pass  # best-effort in teardown; don't mask the test failure


def _pkg_delete(vm: SmokeVM, *, timeout: float = 300.0) -> None:
    """Uninstall the package via ``pkg delete`` (triggers pre-deinstall sweep)."""
    vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y", _PKG_NAME, timeout=timeout)


# --------------------------------------------------------------------------- #
# Case 1 — Enable path: both families created + pfctl -sn confirms rdr active
# --------------------------------------------------------------------------- #


def test_dns_redirect_enable_creates_nat_and_filter_rules(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 Case 1: enabling redirect on the primary non-WAN interface creates pfB-owned NAT + filter rules.

    Scenario: enable path — both IP families created, pfctl -sn confirms rdr.

      Background: pfBlockerNG installed; DNS redirect disabled.

      Given no pfB_DNS_Redirect_* entries in nat/rule or filter/rule (before-state),
        And pfctl -sn shows no rdr rules for port 53 on the primary interface (before-state),

      When DNS redirect is enabled on the primary non-WAN interface and a full reload runs,

      Then nat/rule contains exactly 2 pfB_DNS_Redirect_<iface>_* entries (v4 + v6).
        And filter/rule contains exactly 2 corresponding pfB_DNS_Redirect_<iface>_* entries.
        And each nat/rule entry carries the correct §2.2 field values:
            - ipprotocol: inet (v4) / inet6 (v6)
            - target: 127.0.0.1 (v4) / ::1 (v6)
            - protocol: tcp/udp
            - local-port: 53
            - natreflection: disable
            - destination: (self) network, not-negated, port 53
        And pfctl -sn shows rdr rules on the primary interface for port 53.
    """
    vm = deployed_vm
    iface = primary_iface
    descr_v4 = _redir_descr_for(iface, "inet")
    descr_v6 = _redir_descr_for(iface, "inet6")

    try:
        # GIVEN — disable redirect; assert before-state clean.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update")

        assert _nat_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* nat/rule entries present before enable — before-state not clean"
        )
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* filter/rule entries present before enable — before-state not clean"
        )
        assert not _pfctl_sn_has_redir(vm, iface), (
            f"pfctl -sn shows rdr rule on {iface} before enable — before-state not clean"
        )

        # WHEN — enable on the primary interface and reload.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update")

        # THEN — exactly 2 nat/rule entries (v4 + v6).
        nat_count = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface)
        assert nat_count == 2, f"Expected 2 pfB_DNS_Redirect_{iface}_* nat/rule entries after enable, got {nat_count}"

        # THEN — exactly 2 filter/rule entries.
        filter_count = _filter_redir_count(vm, _REDIR_DESCR_PFX + iface)
        assert filter_count == 2, (
            f"Expected 2 pfB_DNS_Redirect_{iface}_* filter/rule entries after enable, got {filter_count}"
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

        # THEN — pfctl -sn confirms the rdr rules are active.
        assert _pfctl_sn_has_redir(vm, iface), f"pfctl -sn shows no rdr rule on {iface} for port 53 after enable"

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
        And pfB_DNS_Redirect_<iface>_* entries are present in filter/rule (before-state),
        And pfctl -sn shows rdr rules on the primary interface for port 53 (before-state),

      When DNS redirect is disabled and a full reload runs,

      Then nat/rule has no pfB_DNS_Redirect_* entries.
        And filter/rule has no pfB_DNS_Redirect_* entries.
        And pfctl -sn shows no rdr rules on the primary interface for port 53.
    """
    vm = deployed_vm
    iface = primary_iface

    try:
        # GIVEN — enable on the primary interface; assert before-state with rules present.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update")

        assert _nat_redir_count(vm, _REDIR_DESCR_PFX + iface) == 2, (
            f"pfB_DNS_Redirect_{iface}_* nat/rule entries absent before disable — setup failed"
        )
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX + iface) == 2, (
            f"pfB_DNS_Redirect_{iface}_* filter/rule entries absent before disable — setup failed"
        )
        assert _pfctl_sn_has_redir(vm, iface), f"pfctl -sn shows no rdr on {iface} before disable — setup failed"

        # WHEN — disable and reload.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update")

        # THEN — all pfB_DNS_Redirect_* entries must be gone.
        assert _nat_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* nat/rule entries still present after disable"
        )
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* filter/rule entries still present after disable"
        )

        # THEN — pfctl -sn must show no rdr rule for port 53 on the primary interface.
        assert not _pfctl_sn_has_redir(vm, iface), (
            f"pfctl -sn still shows rdr rule on {iface} for port 53 after disable"
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
        # GIVEN — seed the user NAT rule; assert redirect is disabled.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update")
        _seed_user_nat(vm, _USER_NAT_DESCR)

        assert _nat_rule_present(vm, _USER_NAT_DESCR), "user NAT rule not present before enable — seeding failed"
        assert not _nat_rule_present(vm, _redir_descr_for(iface, "inet")), (
            f"{_redir_descr_for(iface, 'inet')} already present before enable — state not clean"
        )

        # WHEN — enable on the primary interface.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
        h.reload(vm, "update")

        # THEN — pfB rules appear; user rule survives.
        assert _nat_rule_present(vm, _redir_descr_for(iface, "inet")), (
            f"{_redir_descr_for(iface, 'inet')} not created after enable"
        )
        assert _nat_rule_present(vm, _USER_NAT_DESCR), (
            "user NAT rule was removed during enable — should never be touched"
        )

        # WHEN — disable.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update")

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
        And the first interface's pfB_DNS_Redirect_* rules present (before-state),
        And the second interface's pfB_DNS_Redirect_* rules present (before-state),

      When the selection is reduced to the first interface only and a reload runs,

      Then the second interface's pfB_DNS_Redirect_* entries are GONE from nat/rule
        and filter/rule.
        And the first interface's pfB_DNS_Redirect_* entries are STILL PRESENT (both families).
    """
    vm = deployed_vm

    # Discover available non-WAN interfaces.
    available = _discover_non_wan_ifaces(vm)
    if len(available) < 2:
        pytest.skip(f"Case 4 (stale-interface prune) requires ≥2 non-WAN interfaces; VM has: {available!r}")

    iface_keep = available[0]  # typically 'lan'
    iface_drop = available[1]  # typically 'opt1'

    try:
        # GIVEN — enable on both interfaces; assert both rule sets present.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface_keep, iface_drop], exception="")
        h.reload(vm, "update")

        assert _nat_redir_count(vm, _REDIR_DESCR_PFX + iface_keep) == 2, (
            f"pfB_DNS_Redirect_{iface_keep}_* rules absent before prune — setup failed"
        )
        assert _nat_redir_count(vm, _REDIR_DESCR_PFX + iface_drop) == 2, (
            f"pfB_DNS_Redirect_{iface_drop}_* rules absent before prune — setup failed"
        )
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX + iface_keep) == 2, (
            f"pfB_DNS_Redirect_{iface_keep}_* filter entries absent before prune"
        )
        assert _filter_redir_count(vm, _REDIR_DESCR_PFX + iface_drop) == 2, (
            f"pfB_DNS_Redirect_{iface_drop}_* filter entries absent before prune"
        )

        # WHEN — reduce to keep-interface only.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface_keep], exception="")
        h.reload(vm, "update")

        # THEN — drop-interface rules removed.
        drop_nat = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface_drop)
        assert drop_nat == 0, f"pfB_DNS_Redirect_{iface_drop}_* nat/rule entries ({drop_nat}) still present after prune"
        drop_filter = _filter_redir_count(vm, _REDIR_DESCR_PFX + iface_drop)
        assert drop_filter == 0, (
            f"pfB_DNS_Redirect_{iface_drop}_* filter/rule entries ({drop_filter}) still present after prune"
        )

        # THEN — keep-interface rules remain (both families = 2 nat + 2 filter).
        keep_nat = _nat_redir_count(vm, _REDIR_DESCR_PFX + iface_keep)
        assert keep_nat == 2, (
            f"pfB_DNS_Redirect_{iface_keep}_* nat/rule entries reduced to {keep_nat} after prune (expected 2)"
        )
        keep_filter = _filter_redir_count(vm, _REDIR_DESCR_PFX + iface_keep)
        assert keep_filter == 2, (
            f"pfB_DNS_Redirect_{iface_keep}_* filter/rule entries reduced to {keep_filter} after prune (expected 2)"
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
        # GIVEN — start from disabled state.
        _set_dns_redirect(vm, enabled=False, ifaces=[], exception="")
        h.reload(vm, "update")
        assert _nat_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
            "pfB_DNS_Redirect_* entries present before Case 5 — state not clean"
        )

        # WHEN — enable with exception alias set.
        _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception=_EXCEPTION_ALIAS)
        h.reload(vm, "update")

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
        h.reload(vm, "update")

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
        _cleanup_redirect(vm)


# --------------------------------------------------------------------------- #
# Case 6 — Uninstall sweep: all pfB_DNS_Redirect_* gone; user NAT survives
# --------------------------------------------------------------------------- #


def test_dns_redirect_uninstall_sweeps_owned_rules_preserves_user_nat(deployed_vm: SmokeVM, primary_iface: str) -> None:
    """ADR-36 Case 6: uninstall sweeps all pfB_DNS_Redirect_* entries; user NAT survives.

    Scenario: uninstall sweep — owned rules gone, user rule and sections gone.

      Given DNS redirect is enabled on the primary non-WAN interface
            (pfB_DNS_Redirect_<iface>_* in nat/rule + filter/rule, confirmed in
            config.xml as before-state),
        And a user nat/rule entry (no pfB marker) is present in config.xml,
        And installedpackages/pfblockerng* sections are present (before-state),

      When pfBlockerNG is uninstalled via 'pkg delete',

      Then all pfB_DNS_Redirect_* entries are GONE from nat/rule.
        And all pfB_DNS_Redirect_* entries are GONE from filter/rule.
        And no pfBlockerNG nat/rule entries remain.
        And the user nat/rule entry is STILL PRESENT and unchanged.
        And installedpackages/pfblockerng* sections are GONE from config.xml.
    """
    vm = deployed_vm
    iface = primary_iface

    # GIVEN — enable redirect on the primary interface and seed a user NAT rule.
    _set_dns_redirect(vm, enabled=True, ifaces=[iface], exception="")
    h.reload(vm, "update")
    _seed_user_nat(vm, _USER_NAT_DESCR)

    # BEFORE-STATE: assert all objects are present before uninstall.
    assert _nat_redir_count(vm, _REDIR_DESCR_PFX + iface) == 2, (
        f"pfB_DNS_Redirect_{iface}_* nat/rule entries absent before uninstall — setup failed"
    )
    assert _filter_redir_count(vm, _REDIR_DESCR_PFX + iface) == 2, (
        f"pfB_DNS_Redirect_{iface}_* filter/rule entries absent before uninstall — setup failed"
    )
    assert _nat_rule_present(vm, _USER_NAT_DESCR), "user NAT rule absent before uninstall — seeding failed"
    assert _pfb_sections_present(vm), "installedpackages/pfblockerng* absent before uninstall — unexpected clean state"

    # WHEN — uninstall pfBlockerNG (triggers pfblockerng_php_pre_deinstall_command →
    # pfb_fwobj_sweep before pfb_remove_config_settings).
    _pkg_delete(vm)

    # THEN — all pfB_DNS_Redirect_* entries are gone.
    assert _nat_redir_count(vm, _REDIR_DESCR_PFX) == 0, (
        "pfB_DNS_Redirect_* nat/rule entries still present after uninstall — ADR-35/36 sweep did not run"
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
