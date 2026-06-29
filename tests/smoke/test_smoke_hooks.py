"""ADR-12 — live-VM smoke coverage for the pre/post update command hooks.

pfBlockerNG runs admin-configured commands once per update pass: a ``pre`` hook at
the TOP of ``sync_package_pfblockerng`` (``pfblockerng.inc:7388``) and a ``post``
hook at the closing tail (``:11227``), via ``pfb_run_hooks($when, $ctx)``. Each
enabled hook runs AS ROOT in the HOST context (NOT chrooted) under
``PFB_<K>=<v> … /usr/bin/timeout --foreground -s TERM -k 5 <timeout> <script> > <tmp> 2>&1 < /dev/null``.
``--foreground`` stops timeout(1) (a FreeBSD process reaper in its default mode) from
waiting for descendants the hook spawns, and the temp-FILE capture (not exec()'s pipe)
stops such a daemon from holding the capture open — together a daemon the hook restarts
can't stall the pass or be killed by it (see the bg-daemon test).
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
  the pre-vs-post context branch (pre has no IP/DNSBL/STATUS/changed-list keys).
* **Trigger values** — ``PFB_TRIGGER`` for both reachable verbs (``update`` ⇒
  ``cron``; ``updateip``/``updatednsbl`` ⇒ ``force-reload``).
* **IP/DNSBL-changed** — both sides of ``PFB_IP_CHANGED`` (1 on an IP-affecting
  pass, 0 on a DNSBL-only reload) with ``PFB_DNSBL_CHANGED``.
* **Safety — non-zero** — a hook that exits non-zero is logged and the pass
  continues (the next/other hooks still run).
* **Safety — timeout** — a hook that overruns its ``timeout`` is killed mid-run and
  the pass continues.
* **Changed aliases/groups** — ``PFB_CHANGED_IP_ALIASES`` + ``PFB_CHANGED_DNSBL_GROUPS``
  (ADR-12 P6) are empty on a no-op pass; the updated ``pfB_*`` IP table appears in the
  former and the updated ``DNSBL_*`` group in the latter when feeds change.
* **Webhook recipe SHAPE** — a recipe-shaped ``post`` hook (the HAProxy pattern minus
  HAProxy) guards on ``PFB_IP_CHANGED`` / ``PFB_DNSBL_CHANGED`` and ``curl``s a
  runner-side sink, forwarding the changed-alias context with PER-FIELD
  ``--data-urlencode`` (the space-separated lists are URL-encoded, never naked). We
  assert the guard's OFF branch (no-op pass ⇒ no callback) AND its ON branch (a feed
  change ⇒ exactly one callback carrying the encoded payload), for both guards.

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
from .conftest import SmokeVM, _MockCallbackSink, _MockFeedServer, _StubDnsServer

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
      both changed-list keys present (ADR-12 P6: this ``updateip`` re-processes the
      injected IP feed, so the updated table ``pfB_smokehookctx_v4`` appears in
      ``PFB_CHANGED_IP_ALIASES``; no DNSBL group changes, so ``PFB_CHANGED_DNSBL_GROUPS``
      is present-and-empty — the DNSBL side's empty branch).

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
    # PFB_STATUS stays the sole reserved placeholder (always 'ok').
    # Both changed-list keys (ADR-12 P6) are always PRESENT; this updateip re-processed
    # the injected IP feed, so the updated table appears in PFB_CHANGED_IP_ALIASES while
    # PFB_CHANGED_DNSBL_GROUPS stays present-and-empty (no DNSBL group changed).
    assert "PFB_CHANGED_IP_ALIASES" in post_env, f"post ctx missing PFB_CHANGED_IP_ALIASES: {post_env}"
    assert spec.alias in post_env["PFB_CHANGED_IP_ALIASES"].split(), (
        f"updated IP table {spec.alias} not in PFB_CHANGED_IP_ALIASES: {post_env}"
    )
    assert "PFB_CHANGED_DNSBL_GROUPS" in post_env, f"post ctx missing PFB_CHANGED_DNSBL_GROUPS: {post_env}"
    assert post_env["PFB_CHANGED_DNSBL_GROUPS"] == "", (
        f"post PFB_CHANGED_DNSBL_GROUPS should be empty (no DNSBL change): {post_env}"
    )

    h.clear_update_hooks(deployed_vm)


def test_post_hook_output_precedes_end_marker(deployed_vm: SmokeVM) -> None:
    """The "UPDATE PROCESS ENDED" marker is logged AFTER the post-update hooks.

    The Update-page live tail (``pfb_livetail``, 'force' mode) stops streaming when
    the log reaches the ``UPDATE PROCESS ENDED`` marker. The ADR-12 post-update hooks
    log their output (``[ pfB Hook ] post <name> ...``) progressively — a HAProxy
    reload hook can run up to its timeout — so emitting the marker BEFORE the hooks
    truncated their output from the live view (it only reappeared on a manual 'View').
    The marker is now emitted after ``pfb_run_hooks('post', ...)``.

    Given a clean update log and an enabled post hook,
    When a force update runs,
    Then the post hook's runner line appears in the log BEFORE the terminal marker.
    Pre-fix the order was reversed (marker first), so this assertion FAILED then and
    passes only after the relocation.
    """
    token = "endorder"
    h.set_update_hooks(deployed_vm, [h.env_dump_hook(token, "post")])
    h.clear_hook_markers(deployed_vm, token)

    # Truncate the update log so the slice we read is exactly this one pass (truncate(1)
    # is a clean argv command — no shell redirection through the guest login shell).
    deployed_vm.ssh("/usr/bin/truncate", "-s", "0", h.PFB_LOG)

    h.reload(deployed_vm, "update")

    log = deployed_vm.ssh("cat", h.PFB_LOG).stdout
    hook_line = "[ pfB Hook ] post"
    marker = "UPDATE PROCESS ENDED"
    hook_pos = log.find(hook_line)
    marker_pos = log.find(marker)

    assert hook_pos != -1, f"post hook runner line {hook_line!r} absent from the update log:\n{log[-2000:]}"
    assert marker_pos != -1, f"terminal marker {marker!r} absent from the update log:\n{log[-2000:]}"
    assert hook_pos < marker_pos, (
        "post-hook output must be logged BEFORE the terminal marker so the live tail "
        f"streams it; got hook@{hook_pos} marker@{marker_pos} (marker emitted too early):\n{log[-2000:]}"
    )

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
    # Force the DNSBL re-fetch: even a full 'update' reuse-caches an unchanged-on-disk
    # feed (inc:8917), so a plain rewrite alone would be skipped (no re-parse, DNSBL
    # builders report no change). Touching the '.update' marker forces the re-parse fork
    # so PFB_DNSBL_CHANGED genuinely flips to 1.
    h.force_dnsbl_refetch(deployed_vm, dnsbl_spec.header)
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
        "script": f"hook_pre_{token}_fail.sh",
        "_body": f"#!/bin/sh\n/bin/echo RAN > {pre_marker}\nexit 7\n",
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
    assert "RAN" in pre_body, f"the non-zero pre hook's script did not actually execute: {pre_body!r}"
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
        "script": f"hook_pre_{token}_slow.sh",
        "_body": f"#!/bin/sh\n/bin/echo START > {pre_marker}\n/bin/sleep 30\n/bin/echo DONE >> {pre_marker}\n",
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


# --------------------------------------------------------------------------- #
# 7b) Capture model — a hook that restarts a daemon does NOT stall the pass
# --------------------------------------------------------------------------- #


def test_hooks_spawned_daemon_does_not_stall_pass(deployed_vm: SmokeVM) -> None:
    """A hook that backgrounds a long-lived child must NOT stall the update pass.

    THE BUG (the HAProxy graceful-reload recipe in the field): the hook restarts a
    daemon that inherits the hook's stdout/stderr. When those were exec()'s capture
    PIPE, the read never reached EOF while the daemon lived, so exec()/timeout(1) could
    not observe the hook PROCESS exiting — the WHOLE pass stalled for the timeout budget
    (then falsely logged ``TIMED OUT``) though the hook's own work finished in
    milliseconds. The fix captures to a temp FILE (held harmlessly by any daemon), so
    completion depends only on the hook process exiting.

    DETACHED launch on purpose. The pass is started with ``nohup … >> log 2>&1 </dev/null
    &`` and we then poll the LOG, rather than driving it through ``h.reload`` (a synchronous
    SSH command). The production hook runs under cron/GUI, not SSH; an SSH-driven reload
    would ALSO hang here for an unrelated reason (sshd waits for the channel pipes to close,
    which the backgrounded child holds), conflating the SSH-channel wait with the exec()
    stall we are actually testing. Detaching removes that confound: this SSH call returns at
    once and we observe the pass purely through its on-disk log/markers.

    Red→green WITHOUT a wall-clock assertion on the pass itself. The pre hook (fires at the
    TOP of the pass) backgrounds a child that inherits its stdout/stderr and sleeps 60s
    before writing ``CHILD_FINISHED``; its own ``timeout`` is 120s so a genuine overrun is
    impossible. The post env-dump hook fires only at the closing tail, i.e. only if the pass
    got PAST the pre hook:

    * FIXED runner — the pre hook returns at once, the pass runs to its post hook within
      seconds, so the post marker appears well inside the poll window while the orphaned
      child is still sleeping (``CHILD_FINISHED`` absent).
    * BROKEN (pipe-capture) runner — the pre hook's exec() blocks until the child exits
      (~60s), so the pass never reaches the post hook inside the window: the post marker is
      ABSENT — the failing discriminator.

    Also asserts the hook logged ``completed`` and NOT ``TIMED OUT`` (the killpg/124 variant).
    """
    token = "bgdaemon"
    sentinel = f"pfb_bg_{token}"  # unique argv tag so the finally can pkill the orphan
    pre_marker = h.hook_marker_path(token, "pre")
    child_marker = h.hook_marker_path(token, "child")
    post_marker = h.hook_marker_path(token, "post")
    pre_hook = {
        # Background a child that INHERITS the hook's stdout/stderr (no redirect on it) and
        # outlives the hook (sleep 60), only THEN writing CHILD_FINISHED. The hook finishes
        # its own work (HOOK_DONE) and exits immediately. The child runs under
        # ``sh -c '…' <sentinel>`` so <sentinel> rides its argv ($0) — pkill-able in the
        # finally (the bare `sleep`'s argv would not carry the marker path).
        "script": f"hook_pre_{token}_bg.sh",
        "_body": (
            "#!/bin/sh\n"
            f"/bin/echo START > {pre_marker}\n"
            f"/bin/sh -c '/bin/sleep 60; /bin/echo CHILD_FINISHED > {child_marker}' {sentinel} &\n"
            f"/bin/echo HOOK_DONE >> {pre_marker}\n"
        ),
        "when": "pre",
        "enabled": "on",
        "description": f"smoke {token} pre bgdaemon",
        "timeout": "120",
    }
    h.set_update_hooks(deployed_vm, [pre_hook, h.env_dump_hook(token, "post")])
    h.clear_hook_markers(deployed_vm, token)
    # Belt-and-braces: remove the child marker too (token clear covers pre/post/child).
    deployed_vm.ssh("/bin/rm", "-f", child_marker)
    h.wait_no_active_pfb_task(deployed_vm)  # a clean baseline — no prior pass in flight
    assert not h.hook_marker_exists(deployed_vm, pre_marker), "pre marker present before launch (stale state?)"
    assert not h.hook_marker_exists(deployed_vm, post_marker), "post marker present before launch (stale state?)"
    assert not h.hook_marker_exists(deployed_vm, child_marker), "child marker present before launch (stale state?)"

    try:
        # Launch the pass DETACHED (mirrors the GUI's mwexec_bg): this SSH call returns at
        # once because the pass's stdout/stderr go to the log, not the SSH channel.
        deployed_vm.ssh(
            f"nohup {h.PHP_BIN} {h.PFB_CLI} pfb_trigger scope=both force=false trigger=cron "
            f">> {h.PFB_LOG} 2>&1 </dev/null &"
        )

        # The post hook fires only at the closing tail — i.e. only if the pass got past the
        # stalling pre hook. On the fixed runner it appears within seconds; on the broken
        # runner the pass is stuck on the child for ~60s, so it stays absent for the window.
        # Window assumption: an unchanged-feed force=false pass completes well under 22s
        # (ADR-42 keeps it fast; observed ~3s on CE 2.8) — comfortably below the child's 60s
        # stall. If a heavily loaded runner ever flakes here, raise this window AND the
        # per-test pytest-timeout AND the child's sleep together (keep child >> window).
        reached_post = h.wait_until(
            lambda: h.hook_marker_exists(deployed_vm, post_marker),
            timeout=22.0,
            interval=1.0,
        )
        assert reached_post, (
            "the pass never reached its post hook within 22s: the pre hook STALLED the pass on "
            "its backgrounded child (exec() is still capturing via the inherited pipe, not a file)"
        )

        # The pre hook ran fully and exited (its own work is instant) — NOT killed mid-run.
        pre_body = deployed_vm.ssh("cat", pre_marker).stdout
        assert "START" in pre_body and "HOOK_DONE" in pre_body, (
            f"the bg-daemon pre hook did not run to its own completion: {pre_body!r}"
        )
        # The pass did NOT wait for the orphaned child (still sleeping ~60s): proof it
        # returned rather than blocking on the inherited capture.
        assert not h.hook_marker_exists(deployed_vm, child_marker), (
            "the pass blocked until the hook's backgrounded child finished (CHILD_FINISHED present)"
        )
        # The hook was logged completed, NOT TIMED OUT (catches the timeout/killpg variant).
        log_grep = deployed_vm.ssh(f"/usr/bin/grep '{token}' {h.PFB_LOG} 2>/dev/null | tail -5 || true")
        assert "TIMED OUT" not in log_grep.stdout, (
            f"the bg-daemon hook FALSELY timed out though its own work finished instantly: {log_grep.stdout!r}"
        )
    finally:
        # Kill the orphaned child first (by its argv sentinel) — that also unblocks a pass
        # still stalled on it (broken-runner path) — then let any pass settle before clearing.
        deployed_vm.ssh("/bin/sh", "-c", f"/bin/pkill -f {sentinel} 2>/dev/null; /bin/rm -f {child_marker}")
        h.wait_no_active_pfb_task(deployed_vm, timeout=30.0)
        h.clear_update_hooks(deployed_vm)
        h.clear_hook_markers(deployed_vm, token)


# --------------------------------------------------------------------------- #
# 8) PFB_CHANGED_IP_ALIASES + PFB_CHANGED_DNSBL_GROUPS — empty on a no-op pass,
#    the updated alias/group on a change (split by side)
# --------------------------------------------------------------------------- #


def test_hooks_changed_aliases_ip_and_dnsbl(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """``PFB_CHANGED_IP_ALIASES`` / ``PFB_CHANGED_DNSBL_GROUPS`` (ADR-12 P6) list what was
    GENUINELY UPDATED this pass, split by side (DNSBL groups are not firewall aliases).

    Both branches of the changed signal, with the no-op state asserted FIRST so a green
    proves the feed change CAUSED the alias/group to be reported (CLAUDE.md before/after
    rule):

    * **BEFORE (no-op).** After a first full ``update`` that processes the injected IP
      + DNSBL feeds, a SECOND full ``update`` over the SAME, UNCHANGED feeds reuse-caches
      both (inc:8917 / inc:10211 — ``.txt`` present, no ``.update`` marker) ⇒ neither the
      IP ``$pfb_alias_lists`` site nor the DNSBL per-group ``aliasupdate`` capture fires
      ⇒ BOTH ``PFB_CHANGED_IP_ALIASES`` and ``PFB_CHANGED_DNSBL_GROUPS`` are EMPTY (the
      post hook is enabled, so present-and-empty, not absent).
    * **AFTER (changed).** Rewriting BOTH feeds with new content AND forcing a genuine
      re-fetch (touch each feed's ``.update`` marker) re-processes both ⇒ the IP table
      ``pfB_<ip>_v4`` appears in ``PFB_CHANGED_IP_ALIASES`` and the DNSBL group
      ``DNSBL_<dnsbl>`` in ``PFB_CHANGED_DNSBL_GROUPS`` (each space-separated, on its own
      var). The always-rebuilt DNSBL specials (``DNSBL_Regex``/``DNSBL_IDN``/
      ``DNSBL_TLD_Allow``) are recorded OUTSIDE the per-group loop and must NOT appear —
      only genuinely aliasupdate-changed feed groups do (the production fix).

    Load-bearing semantic asserted explicitly: a pure alias-CONTENT change populates
    ``PFB_CHANGED_IP_ALIASES`` (the table changed via ``pfctl -T replace``, inc:11277)
    WITHOUT flipping ``PFB_IP_CHANGED`` (no firewall RULE change ⇒ ``filter_configure``
    stays FALSE) — so ``PFB_IP_CHANGED`` is ``0`` here even though the IP alias is in the
    changed-list. Reputation-mode-independent by construction: it is the genuinely-updated
    set (``$pfb_alias_lists`` + the per-group ``aliasupdate`` capture), NOT the
    rep-inflated ``$final_alias``.
    """
    token = "chgali"
    marker = h.hook_marker_path(token, "post")

    fed_ip = "198.51.100.7"
    ip_feed = h.write_local_feed(deployed_vm, "smoke_hook_chgali_ip.txt", f"{fed_ip}\n")
    ip_spec = h.IpCase(aliasname="smokehookchgip", feed_url=ip_feed, header="smokehookchgip")
    ip_on_disk_header = f"{ip_spec.header}_{ip_spec.family}"  # IP feed file is {header}{vtype} (inc:10126)
    domain = h.unique_domain("hookchg")
    dnsbl_feed = h.write_local_feed(deployed_vm, "smoke_hook_chgali_dnsbl.txt", f"{domain}\n")
    dnsbl_spec = h.DnsblCase(
        aliasname="smokehookchgd", feed_url=dnsbl_feed, header="smokehookchgd", mode=h.DnsblMode.NULL
    )
    h.inject(deployed_vm, ip_spec)
    h.inject(deployed_vm, dnsbl_spec)
    h.set_update_hooks(deployed_vm, [h.env_dump_hook(token, "post")])

    # Settle: a first full update processes both feeds (their aliases ARE updated here).
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    # Wait until the IP alias kernel table is actually LOADED before the no-op pass. ADR-40's gate
    # lists an alias on a reuse-cached pass iff its kernel table is empty (empty($pfctlck) → the #468
    # empty-table self-heal). If the settle update's `pfctl -T replace` load races the next pass's
    # $pfctlck read (slow/contended box), the no-op pass sees an empty table, self-heals, and reports
    # the alias — a non-deterministic false failure of the "empty changed-list" assertion below.
    # Polling the table non-empty here removes that race (it stays loaded between the two passes).
    assert h.wait_pfctl_table(deployed_vm, ip_spec.alias), (
        f"IP kernel table {ip_spec.alias} did not populate after the settle update"
    )

    # BEFORE: a second update over the UNCHANGED feeds reuse-caches both ⇒ both lists empty.
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_noop = h.read_hook_env(deployed_vm, marker)
    assert env_noop is not None, "post hook did not run for the no-op update"
    assert env_noop.get("PFB_CHANGED_IP_ALIASES", None) == "", (
        f"PFB_CHANGED_IP_ALIASES should be EMPTY when no IP alias was updated, got {env_noop}"
    )
    assert env_noop.get("PFB_CHANGED_DNSBL_GROUPS", None) == "", (
        f"PFB_CHANGED_DNSBL_GROUPS should be EMPTY when no DNSBL group was updated, got {env_noop}"
    )

    # AFTER: rewrite BOTH feeds with new content AND force a genuine re-fetch of each
    # (bust the reuse cache) ⇒ both are re-processed.
    domain2 = h.unique_domain("hookchg2")
    h.write_local_feed(deployed_vm, "smoke_hook_chgali_ip.txt", f"{fed_ip}\n203.0.113.9\n")
    h.write_local_feed(deployed_vm, "smoke_hook_chgali_dnsbl.txt", f"{domain}\n{domain2}\n")
    h.force_ip_refetch(deployed_vm, ip_on_disk_header)
    h.force_dnsbl_refetch(deployed_vm, dnsbl_spec.header)
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_chg = h.read_hook_env(deployed_vm, marker)
    assert env_chg is not None, "post hook did not run for the changed update"
    changed_ip = env_chg.get("PFB_CHANGED_IP_ALIASES", "").split()
    changed_dnsbl = env_chg.get("PFB_CHANGED_DNSBL_GROUPS", "").split()
    assert ip_spec.alias in changed_ip, f"updated IP table {ip_spec.alias} not in PFB_CHANGED_IP_ALIASES: {env_chg}"
    assert dnsbl_spec.alias in changed_dnsbl, (
        f"updated DNSBL group {dnsbl_spec.alias} not in PFB_CHANGED_DNSBL_GROUPS: {env_chg}"
    )
    # Production fix: ONLY genuinely-changed groups — the always-rebuilt specials are
    # added outside the per-group loop and must NOT bleed into the changed-groups list.
    for special in ("DNSBL_Regex", "DNSBL_IDN", "DNSBL_TLD_Allow"):
        assert special not in changed_dnsbl, (
            f"special {special} leaked into PFB_CHANGED_DNSBL_GROUPS (should be excluded): {changed_dnsbl!r}"
        )
    # Load-bearing distinction: the IP alias content changed (it is in the changed-list)
    # but no firewall RULE changed ⇒ PFB_IP_CHANGED stays '0'. This is exactly why a
    # data-changed webhook must guard on PFB_CHANGED_IP_ALIASES, not PFB_IP_CHANGED.
    assert env_chg.get("PFB_IP_CHANGED") == "0", (
        "PFB_IP_CHANGED should be '0' on a content-only IP change (no rule change) even though "
        f"PFB_CHANGED_IP_ALIASES is populated: {env_chg}"
    )

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 9) Webhook recipe SHAPE — a recipe-shaped post hook curls a runner-side sink and
#    forwards the url-encoded changed-alias payload (the HAProxy pattern, minus
#    HAProxy). Guard's OFF branch (no-op ⇒ no callback) vs ON branch (IP change ⇒
#    one callback carrying the encoded payload).
# --------------------------------------------------------------------------- #


def test_hooks_webhook_fires_on_ip_change(
    deployed_vm: SmokeVM, mock_feeds: _MockFeedServer, webhook_sink: _MockCallbackSink
) -> None:
    """An IP-guarded webhook ``post`` hook fires ONLY when IP blocklist DATA changed,
    with the changed-alias payload URL-encoded.

    The guard is ``[ -n "$PFB_CHANGED_IP_ALIASES" ]`` (non-empty changed-list), NOT
    ``PFB_IP_CHANGED=1``: a pure alias-CONTENT change goes through the ``pfctl -T
    replace`` else-branch (inc:11277) that does NOT set ``$pfb['filter_configure']``, so
    ``PFB_IP_CHANGED`` stays ``0`` even though the table changed and
    ``PFB_CHANGED_IP_ALIASES`` IS populated. Guarding on the rule flag would MISS this
    content-only reload — the exact case a webhook wants. Both sides of the guard, with
    the before-state asserted first (CLAUDE.md before/after rule):

    * **BEFORE (guard off).** After a settling full ``update`` lands the injected IP
      feed, a SECOND full ``update`` over the SAME, UNCHANGED feed hits the IP reuse
      cache (inc:10211 — ``.txt`` present, no ``.update`` marker, ``$pfbreuse``
      empty) ⇒ the feed is NOT re-parsed ⇒ its alias never reaches
      ``$pfb_alias_lists`` ⇒ ``PFB_CHANGED_IP_ALIASES`` is EMPTY ⇒ the
      ``[ -n "$PFB_CHANGED_IP_ALIASES" ] && curl …`` guard short-circuits ⇒ NO callback
      reaches the sink (``sink.callbacks == []``).
    * **AFTER (guard on).** Rewriting the IP feed with new content AND forcing a genuine
      re-fetch (``force_ip_refetch`` touches the ``.update`` marker, defeating the reuse
      gate) ⇒ the feed is re-parsed ⇒ its alias lands in ``PFB_CHANGED_IP_ALIASES`` ⇒
      the hook ``curl``s the sink EXACTLY ONCE. The recorded form body decodes
      (``parse_qs``) to ``ip_aliases`` whose space-decoded value CONTAINS the updated
      ``pfB_*`` table token — proving the per-field ``--data-urlencode`` round-trips the
      space-separated list intact (not a broken naked ``?ip=$VAR``). ``ip_changed``
      stays ``"0"`` on this content-only change (no rule change) — the load-bearing
      ``PFB_IP_CHANGED`` vs ``PFB_CHANGED_IP_ALIASES`` distinction.
    """
    fed_ip = "198.51.100.8"
    ip_feed = h.write_local_feed(deployed_vm, "smoke_hook_whip_ip.txt", f"{fed_ip}\n")
    ip_spec = h.IpCase(aliasname="smokehookwhip", feed_url=ip_feed, header="smokehookwhip")
    on_disk_header = f"{ip_spec.header}_{ip_spec.family}"  # IP feed file is {header}{vtype} (inc:10126)
    h.inject(deployed_vm, ip_spec)
    h.set_update_hooks(deployed_vm, [h.webhook_hook(webhook_sink.guest_url("/ip"), "whip", guard="IP")])

    # Settle: a first full update processes the IP feed (its alias IS updated here, so
    # this pass WOULD fire the hook — clear the sink afterwards so the no-op assertion
    # below is clean).
    h.reload(deployed_vm, "update")
    # Settle the IP kernel table before the no-op pass — see the race note in
    # test_hooks_changed_aliases_ip_and_dnsbl: an unloaded table makes the no-op pass self-heal
    # (#468) and populate PFB_CHANGED_IP_ALIASES, firing the guard and producing a flaky callback.
    assert h.wait_pfctl_table(deployed_vm, ip_spec.alias), (
        f"IP kernel table {ip_spec.alias} did not populate after the settle update"
    )

    # BEFORE (guard off): a second update over the UNCHANGED feed hits the reuse cache ⇒
    # PFB_CHANGED_IP_ALIASES empty ⇒ the guard short-circuits ⇒ curl never runs ⇒ no callback.
    webhook_sink.clear()
    h.reload(deployed_vm, "update")
    # Give any (erroneous) in-flight callback a moment to land before asserting absence.
    assert not webhook_sink.wait_for(1, timeout=3.0), (
        "a webhook callback arrived on a no-op pass — the non-empty PFB_CHANGED_IP_ALIASES "
        f"guard did not hold: {webhook_sink.callbacks}"
    )
    assert webhook_sink.callbacks == [], f"unexpected callback(s) on the guard-off pass: {webhook_sink.callbacks}"

    # AFTER (guard on): rewrite the IP feed AND force a genuine re-fetch (bust the reuse
    # cache) ⇒ the feed re-parses ⇒ PFB_CHANGED_IP_ALIASES populated ⇒ the hook fires once.
    webhook_sink.clear()
    h.write_local_feed(deployed_vm, "smoke_hook_whip_ip.txt", f"{fed_ip}\n203.0.113.18\n")
    h.force_ip_refetch(deployed_vm, on_disk_header)
    h.reload(deployed_vm, "update")
    assert webhook_sink.wait_for(1, timeout=10.0), "the IP-guarded webhook hook did not fire on the IP change"
    callbacks = webhook_sink.callbacks
    assert len(callbacks) == 1, f"expected exactly one webhook callback on the IP change, got {len(callbacks)}"
    rec = callbacks[0]
    assert rec.method == "POST", f"webhook should POST, got {rec.method}"
    # The space-separated list round-trips back to a real space after parse_qs; assert
    # the updated pfB_* table is a member of the split value (encoding survived intact).
    ip_aliases = rec.form.get("ip_aliases", [""])[0].split()
    assert ip_spec.alias in ip_aliases, (
        f"updated IP table {ip_spec.alias} not in the callback's ip_aliases {ip_aliases!r}: {rec.form}"
    )
    # Load-bearing distinction: a content-only change populates PFB_CHANGED_IP_ALIASES
    # (above) but does NOT flip PFB_IP_CHANGED (no firewall RULE change) — so the
    # forwarded ip_changed is '0'. This is precisely why the guard keys off the
    # changed-list, not the rule flag.
    assert rec.form.get("ip_changed") == ["0"], (
        f"callback ip_changed should be '0' on a content-only change (no rule change), got {rec.form}"
    )

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 10) Webhook guard branch — an IP-guarded AND a DNSBL-guarded hook; a DNSBL-only
#     change fires the DNSBL hook and NOT the IP hook (the other guard branch +
#     the DNSBL payload).
# --------------------------------------------------------------------------- #


def test_hooks_webhook_dnsbl_guard_branch(
    deployed_vm: SmokeVM, mock_feeds: _MockFeedServer, webhook_sink: _MockCallbackSink
) -> None:
    """With BOTH guards configured, a DNSBL-only change fires the DNSBL-guarded hook and
    NOT the IP-guarded one — proving each guard keys off its OWN changed-list.

    Two recipe-shaped ``post`` hooks on DISTINCT sink paths (``/ip`` vs ``/dnsbl``):
    one guarded on ``[ -n "$PFB_CHANGED_IP_ALIASES" ]``, one on
    ``[ -n "$PFB_CHANGED_DNSBL_GROUPS" ]``. We settle both feeds with a full ``update``,
    then change ONLY the DNSBL feed (and FORCE its re-fetch — see below) and run a full
    ``update``: the IP feed is untouched and reuse-cached ⇒ ``PFB_CHANGED_IP_ALIASES``
    EMPTY (IP hook's guard holds, no ``/ip`` callback), while the DNSBL feed is
    re-parsed ⇒ ``$pfb['aliasupdate']`` fires for its group ⇒ the group lands in
    ``PFB_CHANGED_DNSBL_GROUPS`` (DNSBL hook fires, a ``/dnsbl`` callback whose
    ``dnsbl_changed == "1"`` and whose ``dnsbl_groups`` CONTAINS the updated
    ``DNSBL_<group>`` token and EXCLUDES the always-rebuilt specials
    ``DNSBL_Regex``/``DNSBL_IDN``/``DNSBL_TLD_Allow``). This is the complementary guard
    branch to ``test_hooks_webhook_fires_on_ip_change`` and proves the DNSBL payload
    encodes AND the production per-group fix (genuine ``aliasupdate`` changes only,
    specials excluded).

    A full ``update`` (not ``updatednsbl``) is required AND the feed's ``.update`` marker
    must be forced: ``updatednsbl`` sets ``reuse_dnsbl`` and reloads from cache without
    re-downloading (``inc:7437``); even a full ``update`` reuse-caches an unchanged-on-disk
    feed (``inc:8917`` — ``.txt`` present, no ``.update``), so a plain rewrite would be
    skipped (``aliasupdate`` FALSE, group NOT recorded). ``force_dnsbl_refetch`` touches
    the ``.update`` marker to force the re-parse fork.
    """
    fed_ip = "198.51.100.9"
    ip_feed = h.write_local_feed(deployed_vm, "smoke_hook_whgd_ip.txt", f"{fed_ip}\n")
    ip_spec = h.IpCase(aliasname="smokehookwhgdip", feed_url=ip_feed, header="smokehookwhgdip")
    domain = h.unique_domain("hookwhgd")
    dnsbl_feed = h.write_local_feed(deployed_vm, "smoke_hook_whgd_dnsbl.txt", f"{domain}\n")
    dnsbl_spec = h.DnsblCase(
        aliasname="smokehookwhgdd", feed_url=dnsbl_feed, header="smokehookwhgdd", mode=h.DnsblMode.NULL
    )
    h.inject(deployed_vm, ip_spec)
    h.inject(deployed_vm, dnsbl_spec)
    ip_url = webhook_sink.guest_url("/ip")
    dnsbl_url = webhook_sink.guest_url("/dnsbl")
    h.set_update_hooks(
        deployed_vm,
        [h.webhook_hook(ip_url, "whgd", guard="IP"), h.webhook_hook(dnsbl_url, "whgd", guard="DNSBL")],
    )

    # Settle: a first full update processes both feeds (both WOULD fire here); clear the
    # sink afterwards so the DNSBL-only assertion below is clean.
    h.reload(deployed_vm, "update")
    # Settle the IP kernel table before the DNSBL-only pass — see the race note in
    # test_hooks_changed_aliases_ip_and_dnsbl: an unloaded IP table makes the no-op pass self-heal
    # (#468) and populate PFB_CHANGED_IP_ALIASES, firing the IP guard on a DNSBL-only change.
    assert h.wait_pfctl_table(deployed_vm, ip_spec.alias), (
        f"IP kernel table {ip_spec.alias} did not populate after the settle update"
    )
    webhook_sink.clear()

    # DNSBL-only change: rewrite ONLY the DNSBL feed, leave the IP feed untouched, and
    # FORCE the DNSBL re-fetch so the feed is genuinely re-parsed (aliasupdate fires).
    domain2 = h.unique_domain("hookwhgd2")
    h.write_local_feed(deployed_vm, "smoke_hook_whgd_dnsbl.txt", f"{domain}\n{domain2}\n")
    h.force_dnsbl_refetch(deployed_vm, dnsbl_spec.header)
    h.reload(deployed_vm, "update")

    # The DNSBL hook fires (its changed-list is non-empty); wait for that one callback.
    assert webhook_sink.wait_for(1, timeout=10.0), "the DNSBL-guarded webhook hook did not fire on the DNSBL change"
    callbacks = webhook_sink.callbacks
    dnsbl_calls = [c for c in callbacks if c.path == "/dnsbl"]
    ip_calls = [c for c in callbacks if c.path == "/ip"]
    assert len(dnsbl_calls) == 1, f"expected exactly one /dnsbl callback, got {len(dnsbl_calls)}: {callbacks}"
    # The IP guard held: the IP feed was reuse-cached ⇒ PFB_CHANGED_IP_ALIASES empty ⇒
    # the IP hook's curl never ran ⇒ no /ip call.
    assert ip_calls == [], (
        "the IP-guarded hook fired on a DNSBL-only change — its non-empty "
        f"PFB_CHANGED_IP_ALIASES guard did not hold: {ip_calls}"
    )
    rec = dnsbl_calls[0]
    assert rec.method == "POST", f"webhook should POST, got {rec.method}"
    assert rec.form.get("dnsbl_changed") == ["1"], f"callback dnsbl_changed should be '1', got {rec.form}"
    dnsbl_groups = rec.form.get("dnsbl_groups", [""])[0].split()
    assert dnsbl_spec.alias in dnsbl_groups, (
        f"updated DNSBL group {dnsbl_spec.alias} not in the callback's dnsbl_groups {dnsbl_groups!r}: {rec.form}"
    )
    # Production fix: the always-rebuilt specials are recorded OUTSIDE the per-group
    # loop and must NOT appear — only genuinely aliasupdate-changed feed groups do.
    for special in ("DNSBL_Regex", "DNSBL_IDN", "DNSBL_TLD_Allow"):
        assert special not in dnsbl_groups, (
            f"special {special} leaked into PFB_CHANGED_DNSBL_GROUPS (should be excluded): {dnsbl_groups!r}"
        )

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 11) issue #517 — unlock-forced DNSBL reload must report PFB_DNSBL_CHANGED=1
# --------------------------------------------------------------------------- #


def test_hooks_dnsbl_changed_unlock_forced(deployed_vm: SmokeVM) -> None:
    """An unlock-forced DNSBL reload (sole trigger: /tmp/dnsbl_unlock) reports
    ``PFB_DNSBL_CHANGED='1'`` to post-hooks (issue #517).

    Scenario: the reload gate in ``sync_package_pfblockerng`` fires because
    ``file_exists($pfb['dnsbl_unlock'])`` is true — no feed change, no fingerprint
    delta.  Before the fix, ``PFB_DNSBL_CHANGED`` was built from
    ``$pfb_data_changed || $pfbupdate || $pfbpython || $safesearch_update`` only,
    omitting the unlock condition, so the post-hook saw ``'0'`` even though the
    reload did fire.  A HAProxy-style recipe keyed on ``PFB_DNSBL_CHANGED`` would
    therefore MISS the re-lock.

    **Given** a post env-dump hook is enabled; DNSBL has been deployed (``deployed_vm``
    fixture guarantees this); there is NO pending feed change — a full ``update`` over
    the UNCHANGED on-disk feed reuse-caches the DNSBL data (no re-parse), so
    ``$pfb_data_changed``, ``$pfbupdate``, ``$pfbpython``, and ``$safesearch_update``
    are all false (the before-state asserts ``PFB_DNSBL_CHANGED='0'``).

    **And** a ``/tmp/dnsbl_unlock`` file is written on the guest with a valid
    ``domain,type`` row so the gate's ``file_exists($pfb['dnsbl_unlock'])`` is true.

    **When** ``helpers.reload(vm, 'update')`` fires the pass (still no feed change, so
    the unlock file is the SOLE reload trigger).

    **Then** the captured ``PFB_DNSBL_CHANGED`` from the post-hook env == ``'1'``
    (the unlock-forced reload is reported as a DNSBL change to post-hooks).

    FAILS on pre-fix code (``PFB_DNSBL_CHANGED`` is ``'0'``); PASSES after the fix.
    """
    import subprocess

    token = "unlkchg"
    marker = h.hook_marker_path(token, "post")

    h.set_update_hooks(deployed_vm, [h.env_dump_hook(token, "post")])

    # Settle: a full 'update' over the UNCHANGED on-disk feed reuse-caches the DNSBL
    # data (inc:8917) -- no re-parse, the builders report no change -- which is exactly
    # the no-feed-change pass we need. ('updatednsbl' force-reloads and re-marks the
    # group as updated, so it can never yield the '0' baseline -- it is the wrong verb.)
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_settle = h.read_hook_env(deployed_vm, marker)
    assert env_settle is not None, "post hook did not run during the settling pass"

    # Before-state: after settle, no unlock file present => PFB_DNSBL_CHANGED must be
    # '0' (the four feed-change flags are all false, and no unlock file is present).
    # This proves the *subsequent* '1' is caused by the unlock file, not leftover state.
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_before = h.read_hook_env(deployed_vm, marker)
    assert env_before is not None, "post hook did not run for the before-state pass"
    assert env_before.get("PFB_DNSBL_CHANGED") == "0", (
        "before-state: expected PFB_DNSBL_CHANGED='0' with no feed change and no unlock file, "
        f"got {env_before.get('PFB_DNSBL_CHANGED')!r} — {env_before}"
    )

    # Write /tmp/dnsbl_unlock on the guest with a valid domain,type row.
    # SmokeVM.ssh routes through /bin/sh (CLAUDE.md tcsh rule) so tee is safe here.
    domain = h.unique_domain("unlkchg")
    unlock_path = "/tmp/dnsbl_unlock"
    unlock_content = f"{domain},DNSBL\n"
    result = subprocess.run(
        deployed_vm.ssh_argv("tee", unlock_path),
        input=unlock_content,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"test_hooks_dnsbl_changed_unlock_forced: failed to write {unlock_path}: "
            f"rc={result.returncode} {result.stderr!r}"
        )

    # After-state: same no-feed-change 'update', but now the unlock file is present, so
    # the gate fires SOLELY on file_exists($pfb['dnsbl_unlock']). pfb_update_unbound()
    # unlinks the file during the reload, so the post-hook expression must have been
    # captured before the reload (the fix: $pfb_dnsbl_unlock_forced local var).
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_after = h.read_hook_env(deployed_vm, marker)
    assert env_after is not None, "post hook did not run for the unlock-forced pass"
    got = env_after.get("PFB_DNSBL_CHANGED")
    assert got == "1", (
        "unlock-forced DNSBL reload must set PFB_DNSBL_CHANGED='1' to post-hooks (issue #517): "
        f"expected '1', got {got!r}\nfull hook env: {env_after}"
    )

    h.clear_update_hooks(deployed_vm)


# --------------------------------------------------------------------------- #
# 12) issue #519 — unlock-forced IP re-block must report PFB_IP_CHANGED=1
# --------------------------------------------------------------------------- #


def test_hooks_ip_changed_unlock_forced(deployed_vm: SmokeVM) -> None:
    """An unlock-forced IP re-block (sole trigger: /tmp/ip_unlock) reports
    ``PFB_IP_CHANGED='1'`` to post-hooks (issue #519).

    Scenario: the no-rule-change ``else`` branch in ``sync_package_pfblockerng``
    fires because ``file_exists($pfb['ip_unlock'])`` is true — no feed change, no
    firewall rule change.  Before the fix, ``PFB_IP_CHANGED`` was emitted as
    ``!empty($pfb['filter_configure'])`` only (``inc:15310``), which is FALSE in the
    ``else`` branch, so the post-hook saw ``'0'`` even though the ``pfctl -T
    replace`` re-block did run.  A HAProxy-style recipe keyed on ``PFB_IP_CHANGED``
    would therefore MISS the re-lock.

    **Given** a post env-dump hook is enabled; an IP feed has been injected and
    settled so the pf aliastable ``pfB_smokehookilkchg_v4`` is active on the guest;
    there is NO pending feed change — a full ``update`` over the UNCHANGED on-disk
    feed reuse-caches the IP alias (``$pfbreuse`` path, ``inc:10211``), so
    ``$pfb['filter_configure']`` is FALSE (the before-state asserts
    ``PFB_IP_CHANGED='0'``).

    **And** a ``/tmp/ip_unlock`` file is written on the guest with a valid
    ``ip,table`` CSV row (RFC 5737 IP ``192.0.2.123`` and the settled table
    ``pfB_smokehookilkchg_v4``) so the ``else`` branch's
    ``file_exists($pfb['ip_unlock'])`` gate is true.

    **When** ``helpers.reload(vm, 'update')`` fires the pass (still no feed
    change, so the unlock file is the SOLE trigger).

    **Then** the captured ``PFB_IP_CHANGED`` from the post-hook env == ``'1'``
    (the unlock-forced re-block is reported as an IP change to post-hooks).

    FAILS on pre-fix code (``PFB_IP_CHANGED`` is ``'0'`` because the emit keys
    only on ``filter_configure``); PASSES after the fix adds a separate
    ``$pfb_ip_unlock_forced`` flag captured before the ``else`` branch unlinks the
    file and emits it alongside ``filter_configure``.
    """
    import subprocess

    token = "iulkchg"
    marker = h.hook_marker_path(token, "post")

    # Inject and settle an IP feed so the pf aliastable is active on the guest.
    # RFC 5737 test address; the table is the one this feed creates.
    inert_ip = "192.0.2.123"
    ip_feed = h.write_local_feed(deployed_vm, "smoke_hook_iulkchg_ip.txt", f"{inert_ip}\n")
    ip_spec = h.IpCase(aliasname="smokehookilkchg", feed_url=ip_feed, header="smokehookilkchg")
    h.inject(deployed_vm, ip_spec)
    h.set_update_hooks(deployed_vm, [h.env_dump_hook(token, "post")])

    # Settle: a full 'update' lands the IP feed and creates the pf aliastable.
    # After this pass, the on-disk feed is reuse-cached (inc:10211) so subsequent
    # 'update' runs over the same unchanged feed do NOT set filter_configure.
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_settle = h.read_hook_env(deployed_vm, marker)
    assert env_settle is not None, "post hook did not run during the settling pass"

    # Before-state: no unlock file present => PFB_IP_CHANGED must be '0'.
    # filter_configure is FALSE (feed is reuse-cached, no rule change), and no
    # unlock file exists to trigger the else-branch re-block.  This proves the
    # subsequent '1' is caused by the unlock file, not leftover state.
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_before = h.read_hook_env(deployed_vm, marker)
    assert env_before is not None, "post hook did not run for the before-state pass"
    assert env_before.get("PFB_IP_CHANGED") == "0", (
        "before-state: expected PFB_IP_CHANGED='0' with no feed change and no unlock file, "
        f"got {env_before.get('PFB_IP_CHANGED')!r} — {env_before}"
    )

    # Write /tmp/ip_unlock on the guest with a valid ip,table CSV row.
    # Format: "<ip>,<aliastable>\n" — matches pfb_unlock() fwrite at inc:10844.
    # SmokeVM.ssh routes through /bin/sh (CLAUDE.md tcsh rule) so tee is safe here.
    unlock_path = "/tmp/ip_unlock"
    unlock_content = f"{inert_ip},{ip_spec.alias}\n"
    result = subprocess.run(
        deployed_vm.ssh_argv("tee", unlock_path),
        input=unlock_content,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"test_hooks_ip_changed_unlock_forced: failed to write {unlock_path}: "
            f"rc={result.returncode} {result.stderr!r}"
        )

    # After-state: same no-feed-change 'update', but now the unlock file is present,
    # so the else branch sets $pfb['repcheck']=TRUE (inc:14930) and runs
    # pfctl -T replace for the active aliastable, re-inserting the IP.  The unlock
    # file is unlinked during the pass (inc:14929), so the fix must capture the
    # forced-re-block flag BEFORE the unlink and include it in the PFB_IP_CHANGED
    # expression at the emit site (the fix: $pfb_ip_unlock_forced local var).
    h.clear_hook_markers(deployed_vm, token)
    h.reload(deployed_vm, "update")
    env_after = h.read_hook_env(deployed_vm, marker)
    assert env_after is not None, "post hook did not run for the unlock-forced pass"
    got = env_after.get("PFB_IP_CHANGED")
    assert got == "1", (
        "unlock-forced IP re-block must set PFB_IP_CHANGED='1' to post-hooks (issue #519): "
        f"expected '1', got {got!r}\nfull hook env: {env_after}"
    )

    h.clear_update_hooks(deployed_vm)
