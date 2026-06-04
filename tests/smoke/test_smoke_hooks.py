"""ADR-12 — live-VM smoke coverage for the pre/post update command hooks.

pfBlockerNG runs admin-configured commands once per update pass: a ``pre`` hook at
the TOP of ``sync_package_pfblockerng`` (``pfblockerng.inc:7388``) and a ``post``
hook at the closing tail (``:11227``), via ``pfb_run_hooks($when, $ctx)``. Each
enabled hook runs AS ROOT in the HOST context (NOT chrooted) under
``PFB_<K>=<v> … /usr/bin/timeout -s TERM -k 5 <timeout> /bin/sh -c <command> 2>&1``.
A non-zero exit OR a timeout (rc 124) is logged and the update CONTINUES — a hook
can never abort or stall the pass; with no enabled hooks the pass is byte-identical.

These tests drive the REAL production path: ``helpers.reload(vm, scope)`` runs the
same ``pfblockerng.php <scope>`` CLI the GUI/cron use, which calls
``sync_package_pfblockerng`` and therefore fires the hooks. We observe each hook by
having it dump ``/usr/bin/env`` to a ``/tmp`` marker on the guest (host context, so
readable straight back over SSH) and parsing its ``PFB_*`` vars, plus exit-code /
timeout markers for the safety branches.

WHAT THIS FILE AUTOMATES (ADR §7 manual-smoke checklist):

* **No-op** — no enabled hooks ⇒ no marker, update succeeds (the OFF branch + the
  byte-identical baseline).
* **Pre/post fire + context** — both fire points with their full exported context;
  the pre-vs-post context branch (pre has no IP/DNSBL/STATUS/CHANGED_ALIASES keys).
* **Trigger values** — ``PFB_TRIGGER`` for both reachable verbs (``update`` ⇒
  ``cron``; ``updateip``/``updatednsbl`` ⇒ ``force-reload``).
* **IP/DNSBL-changed** — both sides of ``PFB_IP_CHANGED`` (1 on an IP-affecting
  pass, 0 on a DNSBL-only reload) with ``PFB_DNSBL_CHANGED``.
* **Safety — non-zero** — a hook that exits non-zero is logged and the pass
  continues (the next/other hooks still run).
* **Safety — timeout** — a hook that overruns its ``timeout`` is killed mid-run and
  the pass continues.

WHAT STAYS MAINTAINER-MANUAL (the smoke image has neither package): **HA sync** (no
CARP pair on the single-NIC image) and the **HAProxy recipe end-to-end** (no HAProxy
package installed). Those two ADR §7 items remain in the manual checklist.

VERIFIED FROM SOURCE (re-confirmed while writing):

* ``update`` ⇒ ``sync_package_pfblockerng('cron')`` (``pfblockerng.php:205``) ⇒
  ``$cron='cron'`` ⇒ ``PFB_TRIGGER=cron`` (``pfb_hook_trigger``, ``inc:1858``). The
  ADR's nominal ``PFB_TRIGGER=update`` value (``$cron=''``) is a settings-save /
  de-install path — NOT reachable via any ``reload()`` verb — so it is OUT of smoke
  scope. ``updateip``/``updatednsbl`` ⇒ ``$cron`` is the verb ⇒ ``force-reload``.
* ``updatednsbl`` sets ``$pfb['reuse']='on'`` + ``reuse_dnsbl='on'`` (``inc:7407``)
  and does NOT touch the IP feeds; ``$pfb['filter_configure']`` is set TRUE only when
  the IP-rules section finds an autorule/aliastable CHANGE (``inc:10840`` →
  ``:10879``). So a DNSBL-only reload over an UNCHANGED IP ruleset leaves
  ``filter_configure`` FALSE ⇒ ``PFB_IP_CHANGED='0'`` (``inc:11229``). We make the 0
  side reliable by first running a full ``update`` to settle any pending IP rules,
  then the ``updatednsbl`` reload whose post hook we read.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``). Run
only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps; without them they skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _MockFeedServer, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the hook module (mirrors the matrix fixture).

    Egress stays OPEN here and across every reload: the update path the hooks fire
    from needs a working resolver/network (``pfb_create_dnsbl`` rebuilds DNSBL, and
    a dark egress deadlocks the guest). ``ensure_dnsbl_vip`` + ``use_system_dns_upstream``
    give DNSBL a sinkhole VIP and a reachable upstream so a DNSBL build actually does
    real work — required for ``PFB_DNSBL_CHANGED=1`` to be observable. Hooks are
    cleared up front AND on teardown so no stray hook bleeds into another module's
    reloads. The session VM is torn down at end of run, so collect a full guest
    snapshot on teardown for post-mortem.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    # Defensive: start from a known-clean hook list so nothing left over from an
    # earlier module/run can fire during this module's reloads.
    h.clear_update_hooks(smoke_vm)
    try:
        yield smoke_vm
    finally:
        # Leave NO hooks behind — a stray enabled hook would fire on the next
        # module's reloads. Then collect diagnostics (best-effort, never masks a result).
        h.clear_update_hooks(smoke_vm)
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# 1) OFF branch — no enabled hooks ⇒ no marker, update still succeeds
# --------------------------------------------------------------------------- #


def test_hooks_noop_no_marker(deployed_vm: SmokeVM) -> None:
    """No configured hooks ⇒ the runner is a byte-identical no-op (the OFF branch).

    ``pfb_get_hooks`` returns empty ⇒ ``pfb_run_hooks`` returns immediately
    (``inc:1783``), so no marker is created and the update completes (``reload``
    raises on a non-zero rc, so its return IS the success assertion). Clearing both
    the hook list AND the marker first makes "absent" meaningful — a stale marker or
    a leftover hook can't false-green this.
    """
    token = "noop"
    h.clear_update_hooks(deployed_vm)
    h.clear_hook_markers(deployed_vm, token)
    # A marker for this token that a (non-existent) post hook WOULD have written.
    marker = h.hook_marker_path(token, "post")
    assert not h.hook_marker_exists(deployed_vm, marker), "marker present before any reload (stale state?)"
    # reload() raises on failure, so reaching the asserts means the pass succeeded.
    h.reload(deployed_vm, "update")
    assert not h.hook_marker_exists(deployed_vm, marker), (
        "a hook marker appeared with NO hooks configured — the runner is not a no-op"
    )


# --------------------------------------------------------------------------- #
# 2) enabled flag is a real branch — disabled hook skipped, enabled hook runs
# --------------------------------------------------------------------------- #


def test_hooks_disabled_entry_not_run_then_enabled_runs(deployed_vm: SmokeVM) -> None:
    """The ``enabled`` flag gates a hook: ``enabled=''`` is skipped, ``'on'`` runs.

    Asserts BOTH sides of the same hook so the green proves enabling CAUSED the
    firing (CLAUDE.md before-state rule): with ``enabled=''`` the post env-dump hook
    is skipped (``pfb_get_hooks`` drops non-'on' entries, ``inc:1739``) ⇒ marker
    ABSENT; flip the SAME hook to ``enabled='on'``, clear the marker, reload ⇒ marker
    PRESENT. Disabled-first then enabled-second isolates the flag as the only change.
    """
    token = "enflag"
    marker = h.hook_marker_path(token, "post")

    # BEFORE: enabled='' ⇒ the hook is skipped, no marker.
    h.set_update_hooks(deployed_vm, [h.env_dump_hook(token, "post", enabled="")])
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    assert not h.hook_marker_exists(deployed_vm, marker), "disabled hook (enabled='') ran — the enabled gate is broken"

    # AFTER: flip the SAME hook to enabled='on' ⇒ it now runs.
    h.set_update_hooks(deployed_vm, [h.env_dump_hook(token, "post", enabled="on")])
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    assert h.hook_marker_exists(deployed_vm, marker), "enabled hook (enabled='on') did NOT run"

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 3) pre vs post fire points + their distinct exported context
# --------------------------------------------------------------------------- #


def test_hooks_pre_and_post_fire_with_context(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Both fire points run with the CORRECT, DISTINCT context (pre-vs-post branch).

    A ``pre`` and a ``post`` env-dump hook (distinct markers) fire in one IP-affecting
    update (an ``IpCase`` feed + ``updateip`` ⇒ the IP pass does real work). The
    contexts differ by design (``inc:7388`` pre vs ``inc:11227`` post):

    * ``pre`` ctx is JUST the trigger (no change has happened yet) ⇒ ``PFB_WHEN=pre``,
      ``PFB_TRIGGER=force-reload``, and NO ``PFB_IP_CHANGED`` key.
    * ``post`` ctx is the full set ⇒ ``PFB_WHEN=post``, ``PFB_TRIGGER=force-reload``,
      ``PFB_IP_CHANGED`` present, ``PFB_DNSBL_CHANGED`` present, ``PFB_STATUS=ok``, and
      ``PFB_CHANGED_ALIASES`` present-and-EMPTY (a stable reserved placeholder).

    The absence of ``PFB_IP_CHANGED`` on pre AND its presence on post is the proof
    the two fire points carry different contexts, not one shared blob.
    """
    token = "ctx"
    fed_ip = "198.51.100.5"
    feed_url = h.write_local_feed(deployed_vm, "smoke_hook_ctx_ip.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="smokehookctx", feed_url=feed_url, header="smokehookctx")

    h.inject(deployed_vm, spec)
    h.set_update_hooks(
        deployed_vm,
        [h.env_dump_hook(token, "pre"), h.env_dump_hook(token, "post")],
    )
    h.clear_hook_markers(deployed_vm, token)

    pre_marker = h.hook_marker_path(token, "pre")
    post_marker = h.hook_marker_path(token, "post")
    assert not h.hook_marker_exists(deployed_vm, pre_marker), "pre marker present before reload (stale state?)"
    assert not h.hook_marker_exists(deployed_vm, post_marker), "post marker present before reload (stale state?)"

    h.reload(deployed_vm, "updateip")

    pre_env = h.read_hook_env(deployed_vm, pre_marker)
    post_env = h.read_hook_env(deployed_vm, post_marker)
    assert pre_env is not None, "pre hook did not run (no marker)"
    assert post_env is not None, "post hook did not run (no marker)"

    # pre: trigger-only ctx, no post-only keys.
    assert pre_env.get("PFB_WHEN") == "pre", f"pre PFB_WHEN wrong: {pre_env}"
    assert pre_env.get("PFB_TRIGGER") == "force-reload", f"pre PFB_TRIGGER wrong: {pre_env}"
    assert "PFB_IP_CHANGED" not in pre_env, f"pre ctx leaked a post-only key PFB_IP_CHANGED: {pre_env}"

    # post: full ctx.
    assert post_env.get("PFB_WHEN") == "post", f"post PFB_WHEN wrong: {post_env}"
    assert post_env.get("PFB_TRIGGER") == "force-reload", f"post PFB_TRIGGER wrong: {post_env}"
    assert "PFB_IP_CHANGED" in post_env, f"post ctx missing PFB_IP_CHANGED: {post_env}"
    assert "PFB_DNSBL_CHANGED" in post_env, f"post ctx missing PFB_DNSBL_CHANGED: {post_env}"
    assert post_env.get("PFB_STATUS") == "ok", f"post PFB_STATUS wrong: {post_env}"
    # CHANGED_ALIASES is a reserved placeholder: present-and-empty, not absent.
    assert "PFB_CHANGED_ALIASES" in post_env, f"post ctx missing PFB_CHANGED_ALIASES: {post_env}"
    assert post_env["PFB_CHANGED_ALIASES"] == "", f"post PFB_CHANGED_ALIASES not empty: {post_env}"

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 4) PFB_TRIGGER — both reachable values (branch coverage of pfb_hook_trigger)
# --------------------------------------------------------------------------- #


def test_hooks_trigger_values(deployed_vm: SmokeVM) -> None:
    """``PFB_TRIGGER`` differs by verb: ``update`` ⇒ ``cron``; ``updatednsbl`` ⇒ ``force-reload``.

    Two distinct branches of ``pfb_hook_trigger`` (``inc:1853``), read off the SAME
    post hook across two reloads. Verified from the CLI dispatch: ``update`` calls
    ``sync_package_pfblockerng('cron')`` (``pfblockerng.php:205``) ⇒ ``cron``, while
    ``updatednsbl`` passes the verb through ⇒ ``force-reload``. The ``update`` (=
    ``$cron=''``) nominal ``PFB_TRIGGER=update`` value is a settings-save path, NOT
    reachable via any ``reload()`` verb, so it is out of smoke scope. We assert the
    first value, clear the marker, then assert the second — so the second green
    proves the verb changed the trigger.
    """
    token = "trig"
    marker = h.hook_marker_path(token, "post")
    h.set_update_hooks(deployed_vm, [h.env_dump_hook(token, "post")])

    # update ⇒ sync_package_pfblockerng('cron') ⇒ PFB_TRIGGER=cron.
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_cron = h.read_hook_env(deployed_vm, marker)
    assert env_cron is not None, "post hook did not run for 'update'"
    assert env_cron.get("PFB_TRIGGER") == "cron", f"'update' PFB_TRIGGER should be cron, got {env_cron}"

    # updatednsbl ⇒ PFB_TRIGGER=force-reload (distinct from the cron value above).
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "updatednsbl")
    env_fr = h.read_hook_env(deployed_vm, marker)
    assert env_fr is not None, "post hook did not run for 'updatednsbl'"
    assert env_fr.get("PFB_TRIGGER") == "force-reload", (
        f"'updatednsbl' PFB_TRIGGER should be force-reload, got {env_fr}"
    )

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 5) PFB_IP_CHANGED — both sides (IP-affecting pass vs DNSBL-only reload)
# --------------------------------------------------------------------------- #


def test_hooks_ip_changed_reflects_pass(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """``PFB_IP_CHANGED`` tracks the IP side: ``1`` on an IP pass, ``0`` on DNSBL-only.

    Both branches of ``inc:11229`` (``!empty($pfb['filter_configure']) ? '1' : '0'``),
    asserted in order:

    * An ``IpCase`` feed + a full ``update`` lands a new pf rule/table ⇒
      ``filter_configure`` TRUE ⇒ ``PFB_IP_CHANGED='1'``.
    * A subsequent full ``update`` over a CHANGED DNSBL feed but the SAME IP feed:
      the IP alias content is identical ⇒ no rule change ⇒ ``filter_configure`` stays
      FALSE ⇒ ``PFB_IP_CHANGED='0'``; the DNSBL feed content changed ⇒ the DNSBL
      builders report a change ⇒ ``PFB_DNSBL_CHANGED='1'``.

    ``PFB_DNSBL_CHANGED`` is ``$pfbupdate || $pfbpython`` — the DNSBL builders'
    return values (``inc:11258``), i.e. whether the DNSBL DATA actually changed this
    pass, NOT merely whether a feed is configured. Two source facts drive the second
    pass: (a) the targeted ``updatednsbl`` verb sets ``$pfb['reuse_dnsbl']='on'``
    (``inc:7437``) and RELOADS DNSBL from cache WITHOUT re-downloading, so an edited
    local feed is ignored on ``updatednsbl`` — it must be a full ``update`` to re-read
    the feed; (b) a full ``update`` re-downloads both feeds, so the changed DNSBL feed
    rebuilds (DNSBL_CHANGED=1) while the unchanged IP feed yields no rule change
    (IP_CHANGED=0). We therefore REWRITE the DNSBL feed with a new domain and run a
    full ``update`` for the second pass.
    """
    token = "ipchg"
    marker = h.hook_marker_path(token, "post")

    # IP side: a feed that creates a pf table + rule, then a DNSBL feed so the same
    # pass also has DNSBL work to do.
    fed_ip = "198.51.100.6"
    ip_feed = h.write_local_feed(deployed_vm, "smoke_hook_ipchg_ip.txt", f"{fed_ip}\n")
    ip_spec = h.IpCase(aliasname="smokehookipchg", feed_url=ip_feed, header="smokehookipchg")
    domain = h.unique_domain("hookipchg")
    dnsbl_feed = h.write_local_feed(deployed_vm, "smoke_hook_ipchg_dnsbl.txt", f"{domain}\n")
    dnsbl_spec = h.DnsblCase(
        aliasname="smokehookipchgd", feed_url=dnsbl_feed, header="smokehookipchgd", mode=h.DnsblMode.NULL
    )
    h.inject(deployed_vm, ip_spec)
    h.inject(deployed_vm, dnsbl_spec)
    h.set_update_hooks(deployed_vm, [h.env_dump_hook(token, "post")])

    # (1) IP-affecting full update ⇒ PFB_IP_CHANGED='1'.
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_ip = h.read_hook_env(deployed_vm, marker)
    assert env_ip is not None, "post hook did not run for the IP update"
    assert env_ip.get("PFB_IP_CHANGED") == "1", f"IP update should set PFB_IP_CHANGED=1, got {env_ip}"

    # (2) Full update over a CHANGED DNSBL feed + the SAME IP feed ⇒ PFB_IP_CHANGED='0'
    #     (IP alias content identical, no rule change) and PFB_DNSBL_CHANGED='1' (DNSBL
    #     feed content changed, builders report a change). A targeted updatednsbl would
    #     reload DNSBL from cache (reuse_dnsbl, inc:7437) and NOT re-read the edited
    #     local feed, so a full 'update' is required to pick up the feed change.
    domain2 = h.unique_domain("hookipchg2")
    h.write_local_feed(deployed_vm, "smoke_hook_ipchg_dnsbl.txt", f"{domain}\n{domain2}\n")
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_dnsbl = h.read_hook_env(deployed_vm, marker)
    assert env_dnsbl is not None, "post hook did not run for the DNSBL-only reload"
    assert env_dnsbl.get("PFB_IP_CHANGED") == "0", (
        f"DNSBL-only reload should set PFB_IP_CHANGED=0 (IP side reused, no rule change), got {env_dnsbl}"
    )
    assert env_dnsbl.get("PFB_DNSBL_CHANGED") == "1", (
        f"DNSBL-only reload over a real feed should set PFB_DNSBL_CHANGED=1, got {env_dnsbl}"
    )

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 6) Safety — a non-zero hook is logged and the update CONTINUES
# --------------------------------------------------------------------------- #


def test_hooks_failing_hook_does_not_abort_update(deployed_vm: SmokeVM) -> None:
    """A non-zero ``pre`` hook does NOT abort the pass — a later ``post`` hook runs.

    The ADR-12 contract (``inc:1826``): a hook's non-zero exit is logged and the
    update continues. A ``pre`` hook that runs then ``exit 7`` writes its marker
    (proving it ran) but its failure must not stop the pass; the ``post`` env-dump
    hook firing at the closing tail proves the pass completed. Markers cleared first
    so both "present" assertions are meaningful.
    """
    token = "fail"
    pre_marker = h.hook_marker_path(token, "pre")
    post_marker = h.hook_marker_path(token, "post")
    pre_hook = {
        "command": f"/bin/echo RAN > {pre_marker}; exit 7",
        "when": "pre",
        "enabled": "on",
        "description": f"smoke {token} pre non-zero",
        "timeout": "60",
    }
    h.set_update_hooks(deployed_vm, [pre_hook, h.env_dump_hook(token, "post")])
    h.clear_hook_markers(deployed_vm, token)
    assert not h.hook_marker_exists(deployed_vm, pre_marker), "pre marker present before reload (stale state?)"
    assert not h.hook_marker_exists(deployed_vm, post_marker), "post marker present before reload (stale state?)"

    h.reload(deployed_vm, "update")

    assert h.hook_marker_exists(deployed_vm, pre_marker), "the non-zero pre hook did not run (no marker)"
    pre_body = deployed_vm.ssh("cat", pre_marker).stdout
    assert "RAN" in pre_body, f"the non-zero pre hook's command did not actually execute: {pre_body!r}"
    assert h.hook_marker_exists(deployed_vm, post_marker), (
        "post hook did not run — the non-zero pre hook ABORTED the update (contract violated)"
    )

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 7) Safety — a hook that overruns its timeout is killed; the update CONTINUES
# --------------------------------------------------------------------------- #


def test_hooks_timeout_killed_update_continues(deployed_vm: SmokeVM) -> None:
    """A hook exceeding its ``timeout`` is KILLED mid-run; the update still completes.

    The ADR-12 timeout contract (``inc:1813`` ``/usr/bin/timeout -s TERM -k 5 <t>``;
    ``:1824`` rc 124 ⇒ logged + continue). A ``pre`` hook writes ``START``, then
    ``sleep 30`` with ``timeout='2'`` so it is killed BEFORE writing ``DONE``. The
    marker therefore contains ``START`` but NOT ``DONE`` (proof it was killed
    mid-run, not allowed to finish), and the ``post`` env-dump hook firing proves the
    pass continued past the kill. We also best-effort grep the pfBlockerNG log for
    the ``TIMED OUT`` line as extra evidence (not the primary assertion).
    """
    token = "tmout"
    pre_marker = h.hook_marker_path(token, "pre")
    post_marker = h.hook_marker_path(token, "post")
    pre_hook = {
        # START, then a sleep that overruns the 2s timeout, then DONE (never reached).
        "command": f"/bin/echo START > {pre_marker}; /bin/sleep 30; /bin/echo DONE >> {pre_marker}",
        "when": "pre",
        "enabled": "on",
        "description": f"smoke {token} pre timeout",
        "timeout": "2",
    }
    h.set_update_hooks(deployed_vm, [pre_hook, h.env_dump_hook(token, "post")])
    h.clear_hook_markers(deployed_vm, token)
    assert not h.hook_marker_exists(deployed_vm, pre_marker), "pre marker present before reload (stale state?)"
    assert not h.hook_marker_exists(deployed_vm, post_marker), "post marker present before reload (stale state?)"

    h.reload(deployed_vm, "update")

    pre_body = deployed_vm.ssh("cat", pre_marker).stdout
    assert "START" in pre_body, f"the timeout pre hook never ran (no START): {pre_body!r}"
    assert "DONE" not in pre_body, (
        f"the timeout pre hook ran to completion — it was NOT killed at its timeout: {pre_body!r}"
    )
    assert h.hook_marker_exists(deployed_vm, post_marker), (
        "post hook did not run — a timed-out pre hook STALLED the update (contract violated)"
    )

    # Best-effort extra evidence: the runner logs a "TIMED OUT" line (inc:1825). Pass
    # the pipeline as ONE string (ssh re-joins remote argv and the guest login shell
    # re-parses it — a separate ("sh","-c",cmd) argv would land the pipeline as $0/$1;
    # see dump_diagnostics).
    log_grep = deployed_vm.ssh(
        "/usr/bin/grep -i 'TIMED OUT' /var/log/pfblockerng/pfblockerng.log 2>/dev/null | tail -3 || true"
    )
    if "TIMED OUT" not in log_grep.stdout:
        print(f"[smoke] note: no 'TIMED OUT' line found in the pfBlockerNG log (non-fatal): {log_grep.stdout!r}")

    h.clear_update_hooks(deployed_vm)
