"""Live-VM smoke: pfBlockerNG "Clear firewall states" (killstates) on an IP block.

Proves the pf state-preservation behaviour and the killstates remedy, end to end on a
real two-VM pfSense CE setup (civm = the LAN client behind the firewall):

  1. killstates OFF ⇒ a firewall state created BEFORE an IP is blocked SURVIVES the
     pfBlockerNG update that blocks it. pf matches established flows by state before
     rules, so that flow keeps bypassing the brand-new block — the classic gotcha
     (a new connection IS rejected; the pre-existing one is not).
  2. killstates ON ⇒ pfBlockerNG kills the state for the newly-blocked IP on Update
     (``pfb_remove_states`` → ``pfctl -k``), so the block takes effect immediately for
     the existing flow too.

Non-obvious facts this exercises (each cost a live investigation):

* The pfB Deny_Outbound rule is FLOATING (on WAN), not on the LAN interface. A LAN-
  interface pfB IP rule was found to DROP the baked "Default allow LAN to any" rule on a
  second reload — cutting the client off entirely (a real, reproducible side effect). A
  floating Deny_Outbound blocks the client's forwarded traffic at WAN egress without
  touching the LAN ruleset, so the client stays connected across reloads. killstates
  kills states by the blocked IP regardless of which interface the rule is on.
* The victim is a PUBLIC IP (RFC 5737 TEST-NET-3). killstates deliberately EXCLUDES
  RFC1918 / local-subnet / reserved IPs (pfblockerng.inc:8827-8838), so a private or
  WAN-subnet victim would never be cleared — a public dst is what a real blocked
  outbound connection targets anyway.
* killstates only fires on an update that does NOT rebuild the ruleset
  (``!filter_configure``, inc:15081). Adding an IP to an EXISTING rule's alias is a
  table-content change (no rule change) ⇒ filter_configure stays FALSE ⇒ killstates runs.
  ``force_ip_refetch`` defeats the per-feed reuse gate so the edited local feed is
  actually re-parsed (a plain update reuses the cached copy).
* The state is a pending TCP state (``SYN_SENT``): the harness has no civm-reachable
  responding public target, but the SYN still PASSES the LAN rule and creates the
  state, and killstates behaves identically for pending and established states.

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    python -m pytest tests/smoke/test_smoke_killstates.py -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` + ``client_vm`` (civm) fixtures and the branch ``.pkg``
(``SMOKE_PKG``); without these the cases skip cleanly.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import PFSENSE_LAN_IP, SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

# pfBlockerNG IP settings section (killstates / interface / logging live here).
CFG_IP_SETTINGS = "installedpackages/pfblockerngipsettings/config/0"

# The blocked victim: a PUBLIC IP (RFC 5737 TEST-NET-3, inert/non-routable) — public so
# killstates does not suppress it as local/private. DUMMY keeps the alias non-empty (the
# rule built) while the victim is UNBLOCKED, so the pre-block state can be created.
VICTIM = "203.0.113.9"
DUMMY = "203.0.113.77"
HEADER = "pfbkillstates"  # IP feed header → on-disk file pfbkillstates_v4.txt
ALIAS_TABLE = f"pfB_{HEADER}_v4"  # the pf alias table the rule references
FEED_FILE = "pfb_killstates_ip.txt"

# Settle budget for the alias replace + kill-states to land after a reload.
SETTLE_SECS = 2.0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _set_ipcfg(vm: SmokeVM, kv: dict[str, str], *, timeout: float = 60.0) -> None:
    """Merge key=value pairs into the pfBlockerNG IP settings section + write_config."""
    sets = "".join(f"$ip[{h._php_str(k)}] = {h._php_str(v)};\n" for k, v in kv.items())
    snippet = (
        f"$ip = config_get_path({h._php_str(CFG_IP_SETTINGS)}, array());\n{sets}"
        f"config_set_path({h._php_str(CFG_IP_SETTINGS)}, $ip);\n"
        "write_config('pfBlockerNG smoke: killstates ipcfg');\necho 'OK';"
    )
    r = h.php_eval(vm, snippet, timeout=timeout)
    if r.returncode != 0 or "OK" not in r.stdout:
        raise RuntimeError(f"_set_ipcfg failed: rc={r.returncode} {r.stderr!r} {r.stdout!r}")


def _civm_connect(cl: SmokeVM, *, timeout: float = 20.0) -> int:
    """civm attempts a TCP connection to the victim through pfSense; return curl's rc.

    Pins a host route for the victim via pfSense (civm has two equal-metric default
    routes; without the pin the SYN may egress the mgmt NIC). The SYN passes the LAN
    rule (when unblocked) and creates a firewall state, or is rejected (when blocked).
    """
    r = cl.ssh(
        "/bin/sh",
        "-c",
        f"dev=$(ip -4 -o addr show | awk '/192\\.168\\.1\\./{{print $2; exit}}'); "
        f'ip route replace {VICTIM}/32 via {PFSENSE_LAN_IP} dev "$dev" 2>/dev/null || true; '
        f"curl -s -o /dev/null --connect-timeout 3 --max-time 4 http://{VICTIM}/ >/dev/null 2>&1; echo rc=$?",
        timeout=timeout,
    )
    marker = "rc="
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith(marker)), "rc=-1")
    return int(line[len(marker) :] or -1)


def _establish_victim_state(vm: SmokeVM, cl: SmokeVM, *, attempts: int = 6) -> str:
    """civm opens a connection to the (unblocked) victim until a pf state appears.

    The SYN passing the LAN allow creates a SYN_SENT state (pf tcp.first ~120s). A fresh
    reload can briefly leave the WAN gateway re-initialising, so retry until the state is
    observed; once created it persists well past the per-test window. Returns the state
    lines. Raises with rich civm/pfSense diagnostics if no state forms.
    """
    for _ in range(attempts):
        _civm_connect(cl)
        time.sleep(1.0)
        st = _victim_states(vm)
        if VICTIM in st:
            return st
        time.sleep(2.0)
    raise AssertionError(
        f"could not create a firewall state to {VICTIM} from civm after {attempts} attempts.\n"
        f"{_civm_diag(cl)}\n{_state_diag(vm)}"
    )


def _civm_diag(cl: SmokeVM) -> str:
    """civm-side reachability diagnostics. Never raises."""
    try:
        out = cl.ssh(
            "/bin/sh",
            "-c",
            "echo rc=$(curl -s -o /dev/null --connect-timeout 3 --max-time 4 -w '%{http_code}' "
            f"http://{VICTIM}/ 2>&1; echo :$?); "
            f"ping -c1 -W2 {PFSENSE_LAN_IP} >/dev/null 2>&1 && echo pf_ping=ok || echo pf_ping=FAIL; "
            "ip route get " + VICTIM + " 2>&1 | head -1",
            timeout=20,
        ).stdout.strip()
    except Exception:
        out = "(error)"
    return f"  civm: {out}"


def _victim_states(vm: SmokeVM, *, timeout: float = 30.0) -> str:
    """The pf state-table lines referencing the victim (empty string if none)."""
    return vm.ssh("/bin/sh", "-c", f"pfctl -ss 2>/dev/null | grep '{VICTIM}' || true", timeout=timeout).stdout.strip()


def _rule_block_packets(vm: SmokeVM, *, timeout: float = 30.0) -> int:
    """Packets the floating pfB reject rule has actually dropped (its pf counter).

    ``pfctl -sr -vv`` prints each rule followed by a ``[ Evaluations: N Packets: M ... ]``
    line; M is the count the rule has matched (= blocked, for this `block` rule). Reading it
    before/after a connection attempt proves the rule DROPPED the traffic, not just that the
    victim is listed in the alias. Returns -1 if the counter can't be read.
    """
    out = vm.ssh(
        "/bin/sh",
        "-c",
        f"pfctl -sr -vv 2>/dev/null | grep -A1 '{ALIAS_TABLE}' "
        "| grep -oE 'Packets: [0-9]+' | head -1 | grep -oE '[0-9]+'",
        timeout=timeout,
    ).stdout.strip()
    return int(out or -1)


def _state_diag(vm: SmokeVM) -> str:
    """On-box diagnostics for a killstates failure. Never raises."""

    def _try(cmd: str) -> str:
        try:
            return vm.ssh("/bin/sh", "-c", cmd, timeout=20).stdout.strip()
        except Exception:
            return "(error)"

    tbl = _try(f"pfctl -t {ALIAS_TABLE} -T show 2>/dev/null | tr -d ' ' || true")
    rule = _try(f"pfctl -sr 2>/dev/null | grep -i {HEADER} || echo '(no rule)'")
    lan_allow = _try("pfctl -sr 2>/dev/null | grep -i 'Default Allow LAN' || echo '(no LAN allow!)'")
    log = _try(
        "grep -iE 'Removed .* state|Kill States|Filter Reload' "
        "/var/log/pfblockerng/pfblockerng.log 2>/dev/null | tail -6 || true"
    )
    return f"  alias {ALIAS_TABLE}: {tbl!r}\n  rule: {rule!r}\n  lan_allow: {lan_allow!r}\n  log:\n{log}"


def _assert_fresh_connection_blocked(vm: SmokeVM, cl: SmokeVM) -> None:
    """Prove the floating reject rule actually DROPS a fresh connection to the victim.

    A brand-new connection (no matching state) must traverse the rules and be dropped at
    WAN egress, bumping the rule's packet counter. Asserting the delta — not just alias
    membership — is the behavioural proof that the block is live, not inert.
    """
    pkts_before = _rule_block_packets(vm)
    assert pkts_before >= 0, (
        f"could not read the floating reject rule's packet counter before the connection attempt "
        f"— is the rule present and referencing {ALIAS_TABLE}?\n{_state_diag(vm)}"
    )
    _civm_connect(cl)
    time.sleep(1.5)
    pkts_after = _rule_block_packets(vm)
    assert pkts_after >= 0, (
        f"could not read the reject rule's packet counter after the connection attempt.\n{_state_diag(vm)}"
    )
    assert pkts_after > pkts_before, (
        f"a fresh connection to the blocked {VICTIM} did not increment the reject rule's packet "
        f"counter (before={pkts_before}, after={pkts_after}) — the rule is not dropping traffic.\n"
        f"{_state_diag(vm)}"
    )


def _block_victim(vm: SmokeVM, *, timeout: float = 600.0) -> None:
    """Add the victim to the existing rule's alias and run an Update.

    Feed CONTENT change only (the rule already exists) ⇒ no rule change ⇒
    ``filter_configure`` stays FALSE ⇒ killstates is eligible to run. ``force_ip_refetch``
    defeats the per-feed reuse gate so the edited feed is actually re-parsed.
    """
    h.write_local_feed(vm, FEED_FILE, f"{VICTIM}/32\n")
    h.force_ip_refetch(vm, f"{HEADER}_v4")
    h.reload(vm, "update", timeout=timeout)
    time.sleep(SETTLE_SECS)


def _unblock_baseline(vm: SmokeVM, *, kill_on: bool, timeout: float = 600.0) -> None:
    """Reset to the per-test baseline: victim UNBLOCKED, killstates flag set as wanted."""
    h.write_local_feed(vm, FEED_FILE, f"{DUMMY}/32\n")
    _set_ipcfg(vm, {"killstates": "on" if kill_on else ""})
    h.force_ip_refetch(vm, f"{HEADER}_v4")
    h.reload(vm, "update", timeout=timeout)


# --------------------------------------------------------------------------- #
# Module fixture: deploy once, wire a floating WAN Deny_Outbound rule (victim unblocked)
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def ip_block_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg; wire a floating WAN Deny_Outbound (reject) rule, victim unblocked.

    Given: the smoke VM is booted and the branch .pkg is available; civm is up.
    When:  we deploy and inject one IP block feed (header ``pfbkillstates``) whose alias
           starts with only DUMMY (so the rule is built but the victim is NOT blocked),
           as a floating rule (enable_float) with logging on.
    Then:  the module VM is ready: the reject rule exists, the victim is reachable enough
           for civm to create a firewall state to it.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    h.deploy(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)

    feed = h.write_local_feed(smoke_vm, FEED_FILE, f"{DUMMY}/32\n")
    h.inject(
        smoke_vm,
        h.IpCase(aliasname=HEADER, feed_url=feed, action="Deny_Outbound", family="v4", header=HEADER),
    )
    # FLOATING rule (inject wired the interface to wan): enable_float flips Deny_Outbound to
    # a floating `block out quick` on WAN that catches the client's forwarded traffic without
    # disturbing the LAN allow. Global IP logging on so the block is visible in filter.log.
    # outbound_deny_action defaults to 'reject'.
    _set_ipcfg(smoke_vm, {"enable_float": "on", "enable_log": "on"})
    h.reload(smoke_vm, "update")
    yield smoke_vm


# --------------------------------------------------------------------------- #
# Test 1: killstates OFF ⇒ the pre-existing state SURVIVES the block
# --------------------------------------------------------------------------- #


def test_killstates_off_preserves_state_bypassing_new_block(ip_block_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """killstates OFF: a state created before the block SURVIVES the update (the gotcha).

    Given: a floating WAN reject rule whose alias does NOT yet contain the victim, Clear-States
           OFF, and a civm connection that created a firewall state to the victim.
    When:  the victim is added to the block alias and pfBlockerNG runs an Update.
    Then:  the pre-existing state is STILL present — pf matches it before rules, so that
           flow bypasses the brand-new block.
    And:   the victim IS in the live block alias AND a brand-new connection is actively dropped
           by the rule — so the survival above is genuine state-preservation (old flow bypasses,
           new flow blocked), not an inert rule.
    """
    vm = ip_block_vm
    _unblock_baseline(vm, kill_on=False)

    # When: civm creates a state to the still-unblocked victim.
    before = _establish_victim_state(vm, client_vm)

    # When: block the victim (Clear-States OFF).
    _block_victim(vm)

    # Then: the pre-existing state SURVIVED (killstates off) — pf matches it before rules,
    # so that flow keeps bypassing the brand-new block.
    after = _victim_states(vm)
    assert VICTIM in after, (
        f"killstates OFF must PRESERVE the existing state to {VICTIM}, but it was cleared.\n"
        f"  before: {before!r}\n  after: {after!r}\n{_state_diag(vm)}"
    )

    # And: the block is genuinely loaded for NEW flows — the victim is in the live pf alias
    # table the floating reject rule references (so the survival above is state-preservation,
    # not an inert rule).
    table = vm.ssh("/bin/sh", "-c", f"pfctl -t {ALIAS_TABLE} -T show 2>/dev/null | tr -d ' '", timeout=30).stdout
    assert VICTIM in table, (
        f"expected {VICTIM} in the live block alias {ALIAS_TABLE} (the rule is active), got:\n{table}"
    )

    # And: a fresh (un-stated) connection to the victim is actually DROPPED by the rule — the
    # behavioural proof that new flows are blocked while the old state above is preserved.
    _assert_fresh_connection_blocked(vm, client_vm)


# --------------------------------------------------------------------------- #
# Test 2: killstates ON ⇒ the state is CLEARED so the block takes effect
# --------------------------------------------------------------------------- #


def test_killstates_on_clears_state_so_block_takes_effect(ip_block_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """killstates ON: pfBlockerNG kills the state on Update, so the block takes effect.

    Given: a floating WAN reject rule whose alias does NOT yet contain the victim, Clear-States
           ON, and a civm connection that created a firewall state to the victim.
    When:  the victim is added to the block alias and pfBlockerNG runs an Update.
    Then:  the state for the victim is GONE — pfBlockerNG's pfb_remove_states killed it,
           so the existing flow now hits the reject too (no state to bypass the block).
    And:   a connection to the victim is actively dropped by the rule (the block is live).
    """
    vm = ip_block_vm
    _unblock_baseline(vm, kill_on=True)

    # When: civm creates a state to the still-unblocked victim.
    before = _establish_victim_state(vm, client_vm)

    # When: block the victim (Clear-States ON).
    _block_victim(vm)

    # Then: the state was KILLED (killstates on) — the block now applies to that flow too.
    after = _victim_states(vm)
    assert VICTIM not in after, (
        f"killstates ON must CLEAR the state to {VICTIM} on update, but it survived.\n"
        f"  before: {before!r}\n  after: {after!r}\n{_state_diag(vm)}"
    )

    # And: the block is live — a connection to the victim is actually dropped by the rule.
    _assert_fresh_connection_blocked(vm, client_vm)
