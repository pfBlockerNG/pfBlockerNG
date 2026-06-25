"""Live-VM smoke: pfBlockerNG IP rule on LAN must NOT drop user's pre-existing LAN pass rules.

Pins the fix for issue #532: a pfBlockerNG Deny_Outbound rule assigned to the LAN interface
with an absent ``pass_order`` caused the second reload to OVERWRITE the interface's filter rules
in config.xml with only pfBlockerNG's own auto-rule, silently deleting every user pass rule (e.g.
"Default allow LAN to any"). The missing default meant the rule-order reconciliation in
``sync_package_pfblockerng()`` bucketed those user rules into ``$permit_rules``, which is only
re-emitted for ``order_1``..``order_4`` — not for an empty order — so they were dropped from
config.xml and live pf on reload #2, cutting LAN clients off via the default-deny.

The fix (pfblockerng.inc:11044): ``$pfb['order']`` defaults to
``$pfb['ipconfig']['pass_order'] ?: 'order_0'``. Under ``order_0`` user pass-rules route into
``$other_rules`` and are always re-emitted.

Scenario: a LAN-interface pfBlockerNG block rule MUST NOT drop "Default allow LAN to any" across
two consecutive reloads — the minimum cycle that triggered the drop before the fix.

Non-obvious facts:

* The trigger is a NON-FLOATING (per-interface LAN) rule with ``pass_order`` ABSENT. A floating
  rule (``enable_float=on``) uses a different code path and does not trigger it. The killstates
  test deliberately uses floating to AVOID this bug; this test intentionally uses non-floating
  on the LAN to DETECT it.
* Two consecutive reloads bound the cycle: the alias builds, the pfB deny rule lands, and the
  reconciliation rewrites filter/rule at least once. Before the fix, the user LAN rules are gone
  by the end of the cycle (observed as early as reload #1, depending on install-time syncs).
* The harness SSH/control plane runs over the WAN SLIRP path (port 2222 on 127.0.0.1), not the
  LAN. A pfB LAN rule cannot cut our own harness access (we never talked over the LAN).
* We use ``inbound_interface``/``outbound_interface`` = ``'lan'`` (the pfSense friendly name),
  not ``SMOKE_IP_IFACE`` (which defaults to ``'wan'``). The injection is done via a dedicated
  PHP-eval snippet directly in the fixture, mirroring ``_ip_inject_snippet`` but targeting LAN.

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    python -m pytest tests/smoke/test_smoke_lan_rule_preserve.py -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``); without these the
cases skip cleanly.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

# pfBlockerNG config paths (mirrors killstates; same shape).
CFG_IP_SETTINGS = "installedpackages/pfblockerngipsettings/config/0"
CFG_IP_V4_LISTS = "installedpackages/pfblockernglistsv4/config"
CFG_GLOBAL = "installedpackages/pfblockerng/config/0"

# LAN interface friendly name (the pfSense value stored in filter/rule 'interface').
LAN_IFACE = "lan"

# Feed identity — inert RFC 5737 content (public IPs; killstates proves publicness matters,
# but here we only care that the rule is built, not that it intercepts live traffic).
FEED_HEADER = "pfblanpreserve"
FEED_FILE = "pfb_lan_preserve_ip.txt"
# write_local_feed() writes under /var/db/pfblockerng; the feed source's URL must be that
# on-disk path (pfb_download() realpath()s a local-file feed), not the bare filename.
FEED_PATH = f"{h.PFB_DBDIR}/{FEED_FILE}"
ALIAS_TABLE = f"pfB_{FEED_HEADER}_v4"
DUMMY_IP = "203.0.113.200"  # RFC 5737 TEST-NET-3, always-in alias so the rule is built

# The user LAN pass rule description pfSense bakes into fresh images.
DEFAULT_ALLOW_LAN_DESCR = "Default allow LAN to any"

# Brief settle after reload for pf table + filter state to stabilise.
SETTLE_SECS = 2.0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _inject_lan_ip_rule(vm: SmokeVM, *, pass_order: str | None = None, timeout: float = 90.0) -> None:
    """Inject a Deny_Outbound IPv4 rule on the LAN interface, pass_order absent or explicit.

    Mirrors ``_ip_inject_snippet`` from helpers.py but targets ``'lan'`` for both
    inbound/outbound — the exact interface configuration that triggers the bug (the existing
    helper hardcodes ``SMOKE_IP_IFACE`` which defaults to ``'wan'``).

    ``pass_order`` drives the IP-settings ``pass_order`` field — the one the reconciliation
    reads (``$pfb['ipconfig']['pass_order']``, pfblockerng.inc:11044), NOT a list-row key.
    ``None`` removes it (the absent-key pre-fix trigger); an explicit value (e.g. ``'order_0'``)
    exercises the configured-order branch.
    """
    row = {"header": FEED_HEADER, "url": FEED_PATH, "state": "Enabled", "format": "auto"}
    listcfg = {"aliasname": FEED_HEADER, "action": "Deny_Outbound", "cron": "EveryDay"}
    ipset = {"inbound_interface": LAN_IFACE, "outbound_interface": LAN_IFACE}
    pass_order_line = (
        f"$ip['pass_order'] = {h._php_str(pass_order)};\n" if pass_order is not None else "unset($ip['pass_order']);\n"
    )
    snippet = (
        f"$g = config_get_path({h._php_str(CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(CFG_GLOBAL)}, $g);\n"
        f"$ip = config_get_path({h._php_str(CFG_IP_SETTINGS)}, array());\n"
        f"$ip = array_merge($ip, {h._php_kv_array(ipset)});\n"
        f"{pass_order_line}"
        f"config_set_path({h._php_str(CFG_IP_SETTINGS)}, $ip);\n"
        f"$list = {h._php_kv_array(listcfg)};\n"
        f"$list['row'] = array({h._php_kv_array(row)});\n"
        f"config_set_path({h._php_str(CFG_IP_V4_LISTS)}, array($list));\n"
        "write_config('pfBlockerNG smoke: LAN rule preserve test');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_inject_lan_ip_rule failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _get_filter_rules(vm: SmokeVM, *, timeout: float = 60.0) -> list[dict[str, str]]:
    """Return filter/rule rows from config.xml as list of dicts (descr, type, interface).

    Each entry has keys ``descr``, ``type``, ``interface`` so callers can assert
    presence/absence of specific rules without parsing XML directly.
    """
    # json_encode the rows (NOT implode) — a delimiter-joined string is fragile: a single-quoted
    # PHP '\n' is a literal backslash-n, not a newline, and a descr can contain the field
    # separator. JSON round-trips descr/type/interface verbatim.
    snippet = (
        "$out = array();\n"
        "foreach (config_get_path('filter/rule', array()) as $r) {\n"
        "    $out[] = array('descr' => $r['descr'] ?? '', 'type' => $r['type'] ?? '', "
        "'interface' => $r['interface'] ?? '');\n"
        "}\n"
        "echo '<<RULES>>' . json_encode($out) . '<<END>>';"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    if "<<RULES>>" not in res.stdout or "<<END>>" not in res.stdout:
        raise RuntimeError(f"_get_filter_rules: unexpected output: {res.stdout!r} {res.stderr!r}")
    raw = res.stdout.split("<<RULES>>", 1)[1].split("<<END>>", 1)[0]
    return json.loads(raw)


def _has_default_allow_lan(rules: list[dict[str, str]]) -> bool:
    """True iff the LAN 'Default allow LAN to any' pass rule is present.

    Matched case-insensitively as a substring: the factory descr carries a ' rule' suffix and
    varies in capitalisation across images ('Default Allow LAN to any rule'). The needle excludes
    the sibling IPv6 rule ('... LAN IPv6 to any ...'), so only the IPv4 LAN allow matches.
    """
    needle = DEFAULT_ALLOW_LAN_DESCR.lower()
    return any(needle in r["descr"].lower() and r["type"] == "pass" and r["interface"] == LAN_IFACE for r in rules)


def _has_pfb_lan_rule(rules: list[dict[str, str]]) -> bool:
    """True iff the pfBlockerNG auto-rule for the LAN feed appears in filter/rule."""
    return any(FEED_HEADER in r["descr"] for r in rules)


def _rule_diag(vm: SmokeVM, label: str, rules: list[dict[str, str]]) -> str:
    """Expected-vs-actual diagnostic for a LAN rule assertion failure.

    Prints:
      - the config.xml filter/rule snapshot (what the sync wrote)
      - the live pf rules snapshot (what pfctl -sr shows)
    to help localise whether the drop is at config.xml level or at pf-load level.
    """
    pfctl = vm.ssh(
        "/bin/sh", "-c", "pfctl -sr 2>/dev/null | grep -i lan || echo '(no LAN lines)'", timeout=30
    ).stdout.strip()
    alias = vm.ssh(
        "/bin/sh",
        "-c",
        f"pfctl -t {ALIAS_TABLE} -T show 2>/dev/null | tr -d ' ' || echo '(no alias)'",
        timeout=30,
    ).stdout.strip()
    rules_fmt = "\n".join(f"  {r['type']:6} {r['interface']:6} {r['descr']}" for r in rules) or "  (none)"
    return (
        f"\n  [{label}] config.xml filter/rule (descr | type | interface):\n{rules_fmt}\n"
        f"  [{label}] live pf rules (pfctl -sr | grep -i lan):\n{pfctl}\n"
        f"  [{label}] alias {ALIAS_TABLE} members:\n{alias}"
    )


# --------------------------------------------------------------------------- #
# Module fixture: deploy once, write the feed, inject a LAN Deny_Outbound rule
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def lan_rule_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg; write the IP feed; ready for per-test injection.

    Given: the smoke VM is booted and the branch .pkg is available.
    When:  we deploy the package and write the local feed file (DUMMY_IP — the
           rule is built but the feed content is inert, we only care about the
           filter/rule reconciliation).
    Then:  the VM is ready for per-test injection + reload cycles.

    The feed is written once at module scope; each test re-injects the config
    (with or without pass_order) and runs its own reload cycle.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    h.deploy(smoke_vm)
    # No DNS upstream needed: this test exercises firewall-rule reconciliation only (a LOCAL
    # feed file, no name resolution), so it does not depend on the stub-DNS relay fixture.
    h.write_local_feed(smoke_vm, FEED_FILE, f"{DUMMY_IP}/32\n")

    yield smoke_vm


# --------------------------------------------------------------------------- #
# Helpers: two-reload cycle used by both test legs
# --------------------------------------------------------------------------- #


def _run_two_reload_cycle(
    vm: SmokeVM, *, timeout: float = 600.0
) -> tuple[
    list[dict[str, str]],  # rules_before (baseline)
    list[dict[str, str]],  # rules_after_r1 (after reload #1)
    list[dict[str, str]],  # rules_after_r2 (after reload #2)
]:
    """Capture filter/rule state at baseline, after reload #1, and after reload #2.

    Reload #1 builds the alias table (no deny rule yet).
    Reload #2 is when the pfB deny rule lands and the reconciliation rewrites filter/rule.
    Before the fix, reload #2 drops user LAN pass rules (the pass_order bug).
    After the fix, reload #2 preserves them.

    Returns three rule snapshots for the caller's assertions.
    """
    rules_before = _get_filter_rules(vm)

    # Reload #1: build the alias.
    h.force_ip_refetch(vm, f"{FEED_HEADER}_v4")
    h.reload(vm, "update", timeout=timeout)
    time.sleep(SETTLE_SECS)
    rules_after_r1 = _get_filter_rules(vm)

    # Reload #2: this is when the pre-fix code drops user LAN rules.
    h.force_ip_refetch(vm, f"{FEED_HEADER}_v4")
    h.reload(vm, "update", timeout=timeout)
    time.sleep(SETTLE_SECS)
    rules_after_r2 = _get_filter_rules(vm)

    return rules_before, rules_after_r1, rules_after_r2


# --------------------------------------------------------------------------- #
# Test 1: pass_order ABSENT (the pre-fix trigger) — user LAN rules must survive
# --------------------------------------------------------------------------- #


def test_lan_user_rules_preserved_when_pass_order_absent(lan_rule_vm: SmokeVM) -> None:
    """LAN user pass rules survive two reloads when IP settings have no explicit pass_order.

    Scenario: pfBlockerNG Deny_Outbound on the LAN interface, pass_order absent — the
    exact configuration that triggered the bug. The fix defaults order to 'order_0', routing
    user pass-rules into $other_rules (always re-emitted) instead of $permit_rules (dropped
    for empty order).

    Given: pfBlockerNG enabled; one Deny_Outbound feed targeting the LAN interface; NO
           pass_order in IP settings; "Default allow LAN to any" present in filter/rule.
    When:  two consecutive reloads run (alias build, then the pfB deny rule landing and the
           reconciliation rewriting filter/rule).
    Then:  "Default allow LAN to any" is STILL in config.xml filter/rule after EACH reload AND
           visible to pfctl — the fix routes it through $other_rules instead of $permit_rules.
    And:   the pfBlockerNG deny auto-rule for the LAN feed IS present in filter/rule (proves
           the reconciliation actually ran and the assertion is not vacuous).

    Fail-before: on pre-fix code the reload cycle drops the user pass rules (pass_order unset ->
    $pfb['order'] empty -> bucketed into $permit_rules -> silently omitted), caught at the
    after-reload-#1 or after-reload-#2 assertion.
    Pass-after: fix defaults $pfb['order'] = 'order_0' -> routes into $other_rules -> preserved.
    """
    vm = lan_rule_vm

    # Given: inject with pass_order ABSENT (the trigger).
    _inject_lan_ip_rule(vm, pass_order=None)

    # Given (before-state): assert the default LAN allow IS present at baseline.
    rules_before, rules_after_r1, rules_after_r2 = _run_two_reload_cycle(vm)

    # --- BEFORE-STATE assertion (mandatory — proves the later survival is meaningful) ---
    assert _has_default_allow_lan(rules_before), (
        f"Before-state: '{DEFAULT_ALLOW_LAN_DESCR}' must be present in config.xml at baseline "
        f"(otherwise the post-reload assertion is vacuous — it can't 'survive' if it never existed)."
        + _rule_diag(vm, "baseline", rules_before)
    )

    # --- After reload #1: user LAN rules must still be present ---
    assert _has_default_allow_lan(rules_after_r1), (
        f"After reload #1: '{DEFAULT_ALLOW_LAN_DESCR}' must still be present in config.xml.\n"
        f"  expected: type=pass interface={LAN_IFACE} descr={DEFAULT_ALLOW_LAN_DESCR!r}\n"
        f"  actual:   see filter/rule dump below" + _rule_diag(vm, "after-reload-1", rules_after_r1)
    )

    # --- After reload #2: the critical assertion — user rules must NOT have been dropped ---
    assert _has_default_allow_lan(rules_after_r2), (
        f"After reload #2: '{DEFAULT_ALLOW_LAN_DESCR}' was DROPPED from config.xml — "
        f"this is the bug fixed in #532 (pass_order absent -> user pass rules bucketed into "
        f"$permit_rules -> dropped when order is empty).\n"
        f"  expected: type=pass interface={LAN_IFACE} descr={DEFAULT_ALLOW_LAN_DESCR!r} — PRESENT\n"
        f"  actual:   ABSENT — user LAN clients are now cut off by the default-deny"
        + _rule_diag(vm, "after-reload-2", rules_after_r2)
    )

    # And: the pfB deny auto-rule IS present (proves reconciliation ran — the assertion is real).
    assert _has_pfb_lan_rule(rules_after_r2), (
        f"After reload #2: the pfBlockerNG auto-rule for {FEED_HEADER!r} is missing from filter/rule — "
        f"the reconciliation did not run, so the user-rule survival assertion above is not evidence "
        f"of the fix (the reconciliation never had a chance to drop them either)."
        + _rule_diag(vm, "after-reload-2-pfb-check", rules_after_r2)
    )

    # And: the default LAN allow is visible in live pf (not just config.xml).
    pfctl_lan = vm.ssh(
        "/bin/sh", "-c", "pfctl -sr 2>/dev/null | grep -i 'Default' || echo '(none)'", timeout=30
    ).stdout.strip()
    assert DEFAULT_ALLOW_LAN_DESCR.lower() in pfctl_lan.lower(), (
        f"After reload #2: 'Default allow LAN to any' is in config.xml but NOT visible in live pf.\n"
        f"  expected: a 'pass ... label ...' line referencing the LAN allow\n"
        f"  actual pfctl -sr (Default lines):\n{pfctl_lan}" + _rule_diag(vm, "pfctl-check", rules_after_r2)
    )


# --------------------------------------------------------------------------- #
# Test 2: explicit pass_order='order_0' — same guarantee via the configured path
# --------------------------------------------------------------------------- #


def test_lan_user_rules_preserved_when_pass_order_explicit_order_0(lan_rule_vm: SmokeVM) -> None:
    """LAN user pass rules survive two reloads when pass_order is explicitly 'order_0'.

    Branch coverage: the fix ensures the ABSENT-pass_order path defaults to 'order_0'.
    This test pins that an EXPLICIT 'order_0' also preserves user pass rules — regression
    guard so a future change cannot silently break the configured-order path.

    Given: pfBlockerNG enabled; one Deny_Outbound feed targeting the LAN; pass_order='order_0'
           explicitly set; "Default allow LAN to any" present in filter/rule.
    When:  two consecutive reloads (alias build, then deny rule landing + reconciliation).
    Then:  "Default allow LAN to any" is STILL present in config.xml filter/rule AND the
           pfBlockerNG deny auto-rule was committed (reconciliation actually ran).
    """
    vm = lan_rule_vm

    # Given: inject with explicit pass_order='order_0'.
    _inject_lan_ip_rule(vm, pass_order="order_0")

    rules_before, _, rules_after_r2 = _run_two_reload_cycle(vm)

    # Before-state: default LAN allow present at baseline.
    assert _has_default_allow_lan(rules_before), (
        f"Before-state: '{DEFAULT_ALLOW_LAN_DESCR}' must be present at baseline."
        + _rule_diag(vm, "baseline", rules_before)
    )

    # After reload #2: user rules preserved with explicit order_0.
    assert _has_default_allow_lan(rules_after_r2), (
        f"After reload #2 (explicit pass_order='order_0'): '{DEFAULT_ALLOW_LAN_DESCR}' was DROPPED — "
        f"the explicit order_0 path is broken.\n"
        f"  expected: type=pass interface={LAN_IFACE} descr={DEFAULT_ALLOW_LAN_DESCR!r} — PRESENT\n"
        f"  actual:   ABSENT" + _rule_diag(vm, "after-reload-2", rules_after_r2)
    )

    # And: pfB deny rule present (reconciliation ran).
    assert _has_pfb_lan_rule(rules_after_r2), (
        f"After reload #2: pfBlockerNG auto-rule for {FEED_HEADER!r} is missing — "
        f"reconciliation did not run." + _rule_diag(vm, "after-reload-2-pfb-check", rules_after_r2)
    )
