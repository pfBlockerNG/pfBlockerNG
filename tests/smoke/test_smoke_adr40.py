"""ADR-40 live-VM smoke coverage: content-addressed alias reload gating + forward-delta apply.

Covers the three independently-valuable correctness properties that ADR-40
ships, each pinned by a before-and-after assertion so it is evidence the code
works, not just that it runs:

Phase 3 — content-addressed gate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
pfBlockerNG gates alias reloads on CONTENT, not feed-fetch.  The last-applied
set mirror (``/var/db/aliastables/<alias>.txt``) is compared against the newly
computed canonical set; ``pfctl -T replace`` (or ``-T add``/``-T delete``) and
ADR-12 ``PFB_CHANGED_IP_ALIASES`` are driven ONLY by aliases whose membership
set actually changed.

* **Idempotence** — a second update over unchanged feed content emits an empty
  ``PFB_CHANGED_IP_ALIASES``.  The content-gate short-circuits the reload.

* **Surgical reload on content change** — when feed content changes, the alias
  appears in ``PFB_CHANGED_IP_ALIASES`` and the pf table reflects the new set.

Phase 4 — forward-delta apply
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For a changed table, pfBlockerNG applies ``pfctl -t <t> -T add / -T delete``
for small-churn changes (churn ratio < ``PFB_DELTA_CHURN_THRESHOLD`` = 0.05)
and falls back to ``pfctl -T replace`` for large-churn or when
``pfb_alias_delta_mode`` is forced to ``'replace'``.  The key invariant in
both cases: ``pfctl -t <t> -T show`` membership equals the canonical desired
set (the same end-state as a full replace).

* **Delta apply (small churn)** — a one-entry change applies as ``-T add`` +
  the old entry ``-T delete``; the pf table end-state is exactly the new
  feed content.

* **Replace fallback (mode=replace)** — with ``pfb_alias_delta_mode='replace'``
  forced, the same change applies as a full ``-T replace`` (not delta); the
  pf table end-state is still correct.

* **Delta end-state == replace** — the above two together prove that delta and
  replace produce identical pf table membership; there is no drift.

These tests drive the REAL production path via ``helpers.reload(vm, 'update')``
and observe results through the ADR-12 post-hook env and on-box
``pfctl -t <alias> -T show`` (same pattern as ``test_smoke_hooks.py``).

WHAT STAYS MANUAL / OUT OF SCOPE HERE:

* **Cross-list dedup/reputation scope widening** (ADR-40 §2 hybrid scope) —
  ``enable_dup`` / ``enable_drep`` config toggles require harness helpers not
  yet in the fixture set.  The correctness property is unit-pinned in
  ``AliasContentGateTest::testCrossListScopeWidensDuplicateList``.

* **Multi-million-entry data-plane latency measurement** — the lock-hold drop
  from ``-T replace`` to ``-T add``/``-T delete`` at scale requires live
  traffic on real hardware; not reproducible in CI.  Owner: maintainer manual
  smoke (ADR-40 §7).

* **Large-churn replace fallback (auto mode)** — crossing the 5% threshold
  requires synthesising a large alias table in the smoke harness, which would
  dominate test time.  The churn-ratio logic is unit-pinned in
  ``AliasDeltaApplyTest::testLargeChurnFallsBackToReplace``.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run via the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps; without them these tests skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def adr40_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the ADR-40 content-gate module.

    Egress stays OPEN throughout (``pkg add`` + pfBlockerNG's feed-fetch paths
    need a reachable network).  Each test installs and clears its own post-hook;
    we do a defensive clear up front and on teardown so no stray hook bleeds
    into another module's reloads.  Diagnostics are collected on teardown for
    post-mortem when a test fails.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    h.clear_update_hooks(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.clear_update_hooks(smoke_vm)
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# 1) Idempotence — second update over unchanged feed content emits no aliases
# --------------------------------------------------------------------------- #


def test_adr40_content_gate_idempotence(adr40_vm: SmokeVM) -> None:
    """A second reload over an UNCHANGED feed produces PFB_CHANGED_IP_ALIASES=''.

    Scenario A (ADR-40 §2): content-addressed skip.

    Background: pfBlockerNG loads a local feed once (first update), writing the
    canonical set mirror to ``/var/db/aliastables/<alias>.txt``.  On the NEXT
    update, the feed is re-read and the new canonical set is compared against
    the mirror.  When the sets are IDENTICAL, ``pfb_alias_set_different()``
    returns FALSE, the alias is NOT added to ``$pfb_alias_lists``, and
    ``PFB_CHANGED_IP_ALIASES`` is EMPTY.

    **Given** a single IPv4 local feed with a stable IP (192.0.2.201, RFC 5737)
    and a post env-dump hook; the feed is settled by a first update.

    **And** (before-state): the pf table contains the settled IP — proving the
    first load ran and the table is populated, so an empty ``PFB_CHANGED_IP_ALIASES``
    on the second pass cannot be explained by "the table never loaded".

    **When** ``force_ip_refetch`` defeats the download-reuse cache (so the SAME
    unchanged feed content is genuinely re-read and re-parsed, not skipped) and
    ``helpers.reload(vm, 'update')`` runs again.

    **Then** the post hook fires and ``PFB_CHANGED_IP_ALIASES`` does NOT contain
    the alias — ``pfb_alias_set_different()`` compared the freshly re-parsed
    (identical) set against the mirror and returned FALSE; the content-gate, not
    the reuse-cache skip, is what short-circuited the reload.

    **And** the pf table still holds the settled IP (confirming no phantom flush).

    Before Phase 3: ``$pfb_alias_lists`` was populated from the download loop
    (feed re-fetched → alias always added, regardless of content), so a
    no-content-change update still emitted the alias in ``PFB_CHANGED_IP_ALIASES``
    — a false positive triggering unnecessary pfctl operations and ADR-12 hooks.
    FAILS on pre-Phase-3 code; PASSES after the fix.
    """
    token = "p3idem"
    marker = h.hook_marker_path(token, "post")
    fed_ip = "192.0.2.201"
    feed_file = "smoke_adr40_idem.txt"

    # Set up: install the env-dump hook and configure a local feed with one IP.
    h.set_update_hooks(adr40_vm, [h.env_dump_hook(token, "post")])
    feed_url = h.write_local_feed(adr40_vm, feed_file, f"{fed_ip}\n")
    ip_spec = h.IpCase(
        aliasname="smokeadr40idem",
        feed_url=feed_url,
        header="smokeadr40idem",
    )
    h.inject(adr40_vm, ip_spec)

    # First update: settle the feed.  The alias WILL appear in
    # PFB_CHANGED_IP_ALIASES on this pass (mirror absent on first load →
    # pfb_alias_set_different() returns TRUE).  Assert it to prove the hook
    # fires and the first-load path works before testing the idempotence path.
    h.clear_hook_markers(adr40_vm, token)
    h.reload(adr40_vm, "update")
    env_first = h.read_hook_env(adr40_vm, marker)
    assert env_first is not None, "post hook did not fire on the settling update"
    assert ip_spec.alias in (env_first.get("PFB_CHANGED_IP_ALIASES") or ""), (
        "first update: alias should appear in PFB_CHANGED_IP_ALIASES "
        "(mirror absent → new set → content gate fires): "
        f"got {env_first.get('PFB_CHANGED_IP_ALIASES')!r}"
    )

    # Before-state: pf table is populated with the settled IP.
    # Use wait_pfctl_table — filter_configure is async after pfblockerng.php returns;
    # a bare pfctl_table_members read can race and miss the table.
    members_before = h.wait_pfctl_table(adr40_vm, ip_spec.alias)
    assert any(fed_ip in m for m in members_before), (
        f"before-state: pf table {ip_spec.alias} does not contain {fed_ip}: {members_before}"
    )

    # Second update: SAME feed content, no changes — but defeat the download-reuse
    # cache first (issue #582): without this, an unchanged .txt with no .update/.fail
    # marker takes the REUSE fork (inc:10211-10222), which never re-populates
    # $pfb_alias_lists at all, so pfb_alias_set_different() is never even called — an
    # empty PFB_CHANGED_IP_ALIASES would then prove nothing about the content gate.
    # force_ip_refetch forces the re-download/re-parse fork on this SAME content so the
    # gate is genuinely exercised and found FALSE.
    h.force_ip_refetch(adr40_vm, f"{ip_spec.header}_{ip_spec.family}")
    h.clear_hook_markers(adr40_vm, token)
    h.reload(adr40_vm, "update")
    env_second = h.read_hook_env(adr40_vm, marker)
    assert env_second is not None, "post hook did not fire on the idempotence update"

    changed = env_second.get("PFB_CHANGED_IP_ALIASES") or ""
    assert ip_spec.alias not in changed, (
        f"ADR-40 P3 idempotence FAILED: alias {ip_spec.alias!r} appeared in "
        f"PFB_CHANGED_IP_ALIASES on an update with no feed content change.\n"
        f"Expected PFB_CHANGED_IP_ALIASES to be empty or not contain the alias; "
        f"got {changed!r}\n"
        "Pre-Phase-3 symptom: the download loop added the alias regardless of content; "
        "Phase 3 fix: pfb_alias_set_different() gates the write loop, which is the "
        "sole populator of $pfb_alias_lists."
    )

    # Pf table must still hold the IP — no phantom flush from a skipped reload.
    members_after = h.pfctl_table_members(adr40_vm, ip_spec.alias)
    assert any(fed_ip in m for m in members_after), (
        f"after idempotent update: pf table {ip_spec.alias} lost {fed_ip} — "
        f"a flush ran even though no pfctl -T replace was needed: {members_after}"
    )

    h.clear_update_hooks(adr40_vm)


# --------------------------------------------------------------------------- #
# 2) Surgical reload on content change
# --------------------------------------------------------------------------- #


def test_adr40_content_gate_fires_on_change(adr40_vm: SmokeVM) -> None:
    """When feed content CHANGES, the alias appears in PFB_CHANGED_IP_ALIASES.

    Scenario B (ADR-40 §2): content-addressed reload triggers on genuine delta.

    **Given** a local feed is settled (one IP: 192.0.2.202); the post hook fires;
    the pf table holds only the OLD IP (before-state assertion).

    **When** the feed file is rewritten with a DIFFERENT IP (192.0.2.203) and
    ``force_ip_refetch`` invalidates the reuse cache, then ``reload('update')`` runs.

    **Then** the alias appears in ``PFB_CHANGED_IP_ALIASES`` (the content-gate
    returned TRUE), AND the pf table now contains ONLY the NEW IP (pfctl -T replace
    ran with the updated canonical set and the old IP is gone).

    This is the complementary ON-branch to ``test_adr40_content_gate_idempotence``
    — together they prove ``pfb_alias_set_different()`` is a real two-sided gate,
    not an always-false or always-true no-op.
    """
    token = "p3chng"
    marker = h.hook_marker_path(token, "post")
    old_ip = "192.0.2.202"
    new_ip = "192.0.2.203"
    feed_file = "smoke_adr40_chng.txt"

    h.set_update_hooks(adr40_vm, [h.env_dump_hook(token, "post")])
    feed_url = h.write_local_feed(adr40_vm, feed_file, f"{old_ip}\n")
    ip_spec = h.IpCase(
        aliasname="smokeadr40chng",
        feed_url=feed_url,
        header="smokeadr40chng",
    )
    h.inject(adr40_vm, ip_spec)

    # Settle with the OLD IP.
    h.clear_hook_markers(adr40_vm, token)
    h.reload(adr40_vm, "update")
    env_settle = h.read_hook_env(adr40_vm, marker)
    assert env_settle is not None, "post hook did not fire on the settling update"

    # Before-state: only old_ip in the table; new_ip absent.
    # Use wait_pfctl_table — filter_configure is async after pfblockerng.php returns.
    members_before = h.wait_pfctl_table(adr40_vm, ip_spec.alias)
    assert any(old_ip in m for m in members_before), (
        f"before-state: pf table {ip_spec.alias} missing {old_ip}: {members_before}"
    )
    assert not any(new_ip in m for m in members_before), (
        f"before-state: pf table {ip_spec.alias} already contains {new_ip}: {members_before}"
    )

    # Change: rewrite feed with a DIFFERENT IP; invalidate the reuse cache so
    # pfBlockerNG re-reads the file (force_ip_refetch touches the .update marker).
    # Pass the full on-disk header including the family suffix (e.g. "smokeadr40chng_v4");
    # force_ip_refetch creates {header}.update and the IP loop checks {header}_v4.update.
    h.write_local_feed(adr40_vm, feed_file, f"{new_ip}\n")
    h.force_ip_refetch(adr40_vm, f"{ip_spec.header}_{ip_spec.family}")

    h.clear_hook_markers(adr40_vm, token)
    # Capture the log size BEFORE the change reload so the "Updating:" formatting check below
    # inspects ONLY this reload's output, not the session-accumulated log (order-independent).
    log_len_before = len(adr40_vm.ssh("cat", h.PFB_LOG).stdout)
    h.reload(adr40_vm, "update")
    env_changed = h.read_hook_env(adr40_vm, marker)
    assert env_changed is not None, "post hook did not fire after feed content change"

    changed = env_changed.get("PFB_CHANGED_IP_ALIASES") or ""
    assert ip_spec.alias in changed, (
        f"ADR-40 P3 content-change gate FAILED: alias {ip_spec.alias!r} absent from "
        f"PFB_CHANGED_IP_ALIASES after feed content changed from {old_ip!r} to {new_ip!r}.\n"
        f"Got PFB_CHANGED_IP_ALIASES={changed!r}\n"
        "pfb_alias_set_different() should have returned TRUE (sets differ)."
    )

    # After-state: pf table holds new_ip only; old_ip removed.
    members_after = h.pfctl_table_members(adr40_vm, ip_spec.alias)
    assert any(new_ip in m for m in members_after), (
        f"after content change: pf table {ip_spec.alias} missing new IP {new_ip}: {members_after}"
    )
    assert not any(old_ip in m for m in members_after), (
        f"after content change: pf table {ip_spec.alias} still contains old IP {old_ip}: {members_after}"
    )

    # The content change ran the no-rule-change reload path, which logs:
    #   "Alias table changes detected, updating:\n"
    # immediately followed by per-alias " Updating: <alias>" lines, all CONTIGUOUS (one per
    # line, no blank lines between them). The sub-header is the anchor; without it the block
    # reads as a contradiction after "No changes to Firewall rules".
    reload_log = adr40_vm.ssh("cat", h.PFB_LOG).stdout[log_len_before:]
    assert "Alias table changes detected, updating:" in reload_log, (
        "expected 'Alias table changes detected, updating:' sub-header in the reload log "
        f"after a content change (no-rule-change path):\n{reload_log[-1500:]}"
    )
    assert " Updating:" in reload_log, (
        f"expected a per-alias ' Updating:' line in the reload log after a content change:\n{reload_log[-1500:]}"
    )
    assert "\n\n Updating:" not in reload_log, (
        "per-alias ' Updating:' log lines are blank-separated (a leading newline in the log "
        f"format) — they must be contiguous:\n{reload_log[-1500:]}"
    )

    h.clear_update_hooks(adr40_vm)


# --------------------------------------------------------------------------- #
# ADR-12 helper — set pfb_alias_delta_mode via CFG_IP_SETTINGS
# --------------------------------------------------------------------------- #


def _set_delta_mode(vm: h.SmokeVM, mode: str, *, timeout: float = 60.0) -> None:
    """Persist ``pfb_alias_delta_mode`` in the IP-settings config section.

    Mirrors the UI save path (pfblockerng_ip.php POST → PfbConfig::write).
    Valid stored values: ``'auto'`` / ``'delta'`` / ``'replace'``.  An empty
    string is the absent-default for existing installs (reads to ``'auto'``
    via the PfbAliasDeltaMode adapter); the tests write the explicit token so
    the stored value is unambiguous.

    Call BEFORE the reload under test.  The next ``reload()`` reads this value
    once per pass via ``PfbConfig::read('pfb_alias_delta_mode')``.
    """
    snippet = (
        f"$ip = config_get_path({h._php_str(h.CFG_IP_SETTINGS)}, array());\n"
        f"$ip['pfb_alias_delta_mode'] = {h._php_str(mode)};\n"
        f"config_set_path({h._php_str(h.CFG_IP_SETTINGS)}, $ip);\n"
        "write_config('pfBlockerNG smoke: set pfb_alias_delta_mode');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_set_delta_mode({mode!r}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


# --------------------------------------------------------------------------- #
# 3) Delta apply — small-churn change applies as -T add/-T delete, not replace
# --------------------------------------------------------------------------- #


def test_adr40_delta_apply_small_churn(adr40_vm: h.SmokeVM) -> None:
    """A one-IP change in delta mode applies as -T add/-T delete; end-state == new feed.

    Scenario C (ADR-40 §2 Phase 4): forward-delta apply for small churn.

    **Given** a single IPv4 feed settled with one IP (192.0.2.210, RFC 5737);
    mode=delta forced; the pf table holds only the OLD IP (before-state assertion).

    **When** the feed is rewritten with a DIFFERENT single IP (192.0.2.211) and
    ``force_ip_refetch`` invalidates the reuse cache, then ``reload('update')`` runs.

    **Then** the alias appears in ``PFB_CHANGED_IP_ALIASES`` — the content-gate
    fired (the sets differ); AND the pf table contains ONLY the NEW IP (the delta
    add/delete produced the correct end-state); AND the OLD IP is absent (the
    delete side ran).

    This is the end-state invariant (ADR-40 §2 contract 1): after a delta apply,
    ``pfctl -t <t> -T show`` membership equals the canonical desired set —
    identical to what a full ``-T replace`` would produce.

    Together with ``test_adr40_delta_replace_mode`` (which uses mode=replace and
    asserts the same end-state) this proves the two apply paths are equivalent.

    issue #722: the end-state invariant alone does NOT distinguish delta from replace
    — ``test_adr40_delta_replace_mode`` produces the identical pf-table end-state, so a
    regression that silently routed this "delta" run through -T replace would pass every
    assertion above unnoticed. ``pfb_apply_alias_delta()`` now logs a
    " ADR-40 apply [ <table> ]: delta +N/-M" / "…: replace" marker naming the actual
    apply path taken (pfblockerng.inc ~4711-4736) — the ONLY on-box signal that
    discriminates the two (``pfb_pfctl_table_op()`` itself logs only on error). This test
    asserts the DELTA marker fired for this table and the REPLACE marker did NOT.
    """
    token = "p4delta"
    marker = h.hook_marker_path(token, "post")
    old_ip = "192.0.2.210"
    new_ip = "192.0.2.211"
    feed_file = "smoke_adr40_delta.txt"

    _set_delta_mode(adr40_vm, "delta")
    try:
        h.set_update_hooks(adr40_vm, [h.env_dump_hook(token, "post")])
        feed_url = h.write_local_feed(adr40_vm, feed_file, f"{old_ip}\n")
        ip_spec = h.IpCase(
            aliasname="smokeadr40delta",
            feed_url=feed_url,
            header="smokeadr40delta",
        )
        h.inject(adr40_vm, ip_spec)

        # Settle with OLD IP.
        h.clear_hook_markers(adr40_vm, token)
        h.reload(adr40_vm, "update")
        env_settle = h.read_hook_env(adr40_vm, marker)
        assert env_settle is not None, "post hook did not fire on settling update"

        # Before-state: old_ip in table, new_ip absent.
        # Use wait_pfctl_table — filter_configure is async after pfblockerng.php returns.
        members_before = h.wait_pfctl_table(adr40_vm, ip_spec.alias)
        assert any(old_ip in m for m in members_before), (
            f"before-state: pf table {ip_spec.alias} missing {old_ip}: {members_before}"
        )
        assert not any(new_ip in m for m in members_before), (
            f"before-state: pf table {ip_spec.alias} already has {new_ip}: {members_before}"
        )

        # issue #722: capture the apply-path markers for THIS table right before the change
        # reload, isolating its own delta/replace decision from the settling reload above
        # (which force-replaces on first creation) and from any other table in the run.
        delta_marker = f" ADR-40 apply [ {ip_spec.alias} ]: delta "
        replace_marker = f" ADR-40 apply [ {ip_spec.alias} ]: replace"
        delta_before = h.count_log_marker(adr40_vm, h.PFB_LOG, delta_marker)
        replace_before = h.count_log_marker(adr40_vm, h.PFB_LOG, replace_marker)

        # Change the feed; invalidate the reuse cache.
        h.write_local_feed(adr40_vm, feed_file, f"{new_ip}\n")
        h.force_ip_refetch(adr40_vm, f"{ip_spec.header}_{ip_spec.family}")

        h.clear_hook_markers(adr40_vm, token)
        h.reload(adr40_vm, "update")
        env_changed = h.read_hook_env(adr40_vm, marker)
        assert env_changed is not None, "post hook did not fire after feed content change (delta mode)"

        changed = env_changed.get("PFB_CHANGED_IP_ALIASES") or ""
        assert ip_spec.alias in changed, (
            f"ADR-40 P4 delta FAILED: alias {ip_spec.alias!r} absent from PFB_CHANGED_IP_ALIASES.\n"
            f"Got PFB_CHANGED_IP_ALIASES={changed!r}\n"
            f"Feed changed from {old_ip!r} to {new_ip!r}; content-gate should have fired."
        )

        # issue #722: the apply-path oracle — DELTA marker fired for this table, REPLACE did
        # NOT. Without this, a regression silently routing delta -> replace would pass every
        # end-state assertion below unnoticed (both paths converge on the same pf-table
        # membership).
        delta_after = h.count_log_marker(adr40_vm, h.PFB_LOG, delta_marker)
        replace_after = h.count_log_marker(adr40_vm, h.PFB_LOG, replace_marker)
        assert delta_after > delta_before, (
            f"ADR-40 P4 delta FAILED: expected a new {delta_marker!r} log line "
            f"(before={delta_before}, after={delta_after}) — delta apply path not observed"
        )
        assert replace_after == replace_before, (
            f"ADR-40 P4 delta FAILED: expected NO new {replace_marker!r} log line "
            f"(before={replace_before}, after={replace_after}) — mode=delta silently used replace"
        )

        # End-state: exact table contents must equal the new feed (new_ip only; old_ip gone).
        # This is the ADR-40 end-state invariant: delta apply == replace apply in membership.
        members_after = h.pfctl_table_members(adr40_vm, ip_spec.alias)
        assert any(new_ip in m for m in members_after), (
            f"ADR-40 P4 delta end-state FAILED: pf table {ip_spec.alias} missing {new_ip}.\n"
            f"Expected end-state: [{new_ip}] (canonical desired set = new feed content).\n"
            f"Got: {members_after}"
        )
        assert not any(old_ip in m for m in members_after), (
            f"ADR-40 P4 delta end-state FAILED: pf table {ip_spec.alias} still has {old_ip}.\n"
            f"The delta delete (-T delete) should have removed the old IP.\n"
            f"Expected end-state: [{new_ip}]; got: {members_after}"
        )
        # Exact membership: table holds exactly the one new IP (single-IP feed).
        non_new = [m for m in members_after if new_ip not in m]
        assert not non_new, (
            f"ADR-40 P4 delta end-state FAILED: unexpected entries in table {ip_spec.alias}.\n"
            f"Expected exactly [{new_ip}]; extra entries: {non_new}"
        )
    finally:
        _set_delta_mode(adr40_vm, "auto")
        h.clear_update_hooks(adr40_vm)


# --------------------------------------------------------------------------- #
# 4) Replace mode — mode=replace forces a full replace; end-state still correct
# --------------------------------------------------------------------------- #


def test_adr40_delta_replace_mode(adr40_vm: h.SmokeVM) -> None:
    """mode=replace forces a full -T replace; pf table end-state equals the new feed.

    Scenario D (ADR-40 §2 Phase 4): replace-mode override.

    **Given** a single IPv4 feed settled with one IP (192.0.2.220); mode=replace
    forced; pf table holds only OLD IP (before-state assertion).

    **When** the feed is rewritten with a different IP (192.0.2.221) and
    ``reload('update')`` runs.

    **Then** the alias appears in ``PFB_CHANGED_IP_ALIASES`` (the content-gate
    fired); AND the pf table contains ONLY the NEW IP; AND the OLD IP is absent.

    This is the complementary branch to ``test_adr40_delta_apply_small_churn``:
    both prove the ADR-40 end-state invariant (contract 1) — ``pfctl -T show``
    membership equals the canonical desired set — irrespective of whether the
    delta or replace path was taken.  Together they make the delta/replace
    equivalence provable from smoke alone.

    issue #722: the mirror of the ``test_adr40_delta_apply_small_churn`` apply-path
    assertion — same end-state-only gap, opposite direction. Asserts the REPLACE
    marker fired for this table and the DELTA marker did NOT, proving branch coverage
    both ways (a regression that silently routed replace -> delta would otherwise pass
    every end-state assertion below unnoticed).
    """
    token = "p4repl"
    marker = h.hook_marker_path(token, "post")
    old_ip = "192.0.2.220"
    new_ip = "192.0.2.221"
    feed_file = "smoke_adr40_repl.txt"

    _set_delta_mode(adr40_vm, "replace")
    try:
        h.set_update_hooks(adr40_vm, [h.env_dump_hook(token, "post")])
        feed_url = h.write_local_feed(adr40_vm, feed_file, f"{old_ip}\n")
        ip_spec = h.IpCase(
            aliasname="smokeadr40repl",
            feed_url=feed_url,
            header="smokeadr40repl",
        )
        h.inject(adr40_vm, ip_spec)

        # Settle.
        h.clear_hook_markers(adr40_vm, token)
        h.reload(adr40_vm, "update")
        env_settle = h.read_hook_env(adr40_vm, marker)
        assert env_settle is not None, "post hook did not fire on settling update"

        # Before-state: old_ip in table, new_ip absent.
        # Use wait_pfctl_table — filter_configure is async after pfblockerng.php returns.
        members_before = h.wait_pfctl_table(adr40_vm, ip_spec.alias)
        assert any(old_ip in m for m in members_before), (
            f"before-state: pf table {ip_spec.alias} missing {old_ip}: {members_before}"
        )
        assert not any(new_ip in m for m in members_before), (
            f"before-state: pf table {ip_spec.alias} already has {new_ip}: {members_before}"
        )

        # issue #722: capture the apply-path markers for THIS table right before the change
        # reload (the settling reload above already force-replaces on first creation, so it
        # must NOT be counted as evidence of this change's own decision).
        delta_marker = f" ADR-40 apply [ {ip_spec.alias} ]: delta "
        replace_marker = f" ADR-40 apply [ {ip_spec.alias} ]: replace"
        delta_before = h.count_log_marker(adr40_vm, h.PFB_LOG, delta_marker)
        replace_before = h.count_log_marker(adr40_vm, h.PFB_LOG, replace_marker)

        # Change the feed; invalidate the reuse cache.
        h.write_local_feed(adr40_vm, feed_file, f"{new_ip}\n")
        h.force_ip_refetch(adr40_vm, f"{ip_spec.header}_{ip_spec.family}")

        h.clear_hook_markers(adr40_vm, token)
        h.reload(adr40_vm, "update")
        env_changed = h.read_hook_env(adr40_vm, marker)
        assert env_changed is not None, "post hook did not fire after feed change (replace mode)"

        changed = env_changed.get("PFB_CHANGED_IP_ALIASES") or ""
        assert ip_spec.alias in changed, (
            f"ADR-40 P4 replace-mode FAILED: alias {ip_spec.alias!r} absent from "
            f"PFB_CHANGED_IP_ALIASES.\nGot {changed!r}"
        )

        # issue #722: the apply-path oracle — REPLACE marker fired for this table, DELTA did
        # NOT. Mirror of the delta-mode assertion above: proves branch coverage both ways.
        delta_after = h.count_log_marker(adr40_vm, h.PFB_LOG, delta_marker)
        replace_after = h.count_log_marker(adr40_vm, h.PFB_LOG, replace_marker)
        assert replace_after > replace_before, (
            f"ADR-40 P4 replace-mode FAILED: expected a new {replace_marker!r} log line "
            f"(before={replace_before}, after={replace_after}) — replace apply path not observed"
        )
        assert delta_after == delta_before, (
            f"ADR-40 P4 replace-mode FAILED: expected NO new {delta_marker!r} log line "
            f"(before={delta_before}, after={delta_after}) — mode=replace silently used delta"
        )

        # End-state: exact table contents must equal the new feed (new_ip only; old_ip gone).
        members_after = h.pfctl_table_members(adr40_vm, ip_spec.alias)
        assert any(new_ip in m for m in members_after), (
            f"ADR-40 P4 replace-mode end-state FAILED: pf table {ip_spec.alias} missing {new_ip}.\n"
            f"Expected end-state: [{new_ip}]; got: {members_after}"
        )
        assert not any(old_ip in m for m in members_after), (
            f"ADR-40 P4 replace-mode end-state FAILED: pf table {ip_spec.alias} still has {old_ip}.\n"
            f"Expected end-state: [{new_ip}]; got: {members_after}"
        )
        # Exact membership: table holds exactly the one new IP (single-IP feed).
        non_new = [m for m in members_after if new_ip not in m]
        assert not non_new, (
            f"ADR-40 P4 replace-mode end-state FAILED: unexpected entries in table {ip_spec.alias}.\n"
            f"Expected exactly [{new_ip}]; extra entries: {non_new}"
        )
    finally:
        _set_delta_mode(adr40_vm, "auto")
        h.clear_update_hooks(adr40_vm)


def test_pfctl_table_count_absent_table_no_bare_error(adr40_vm: SmokeVM) -> None:
    """Reading an absent pf table reports 0 entries and leaks NO bare 'pfctl: Table does not exist'.

    The mutation wrapper pfb_pfctl_table_op() attributes add/delete/replace/kill failures in the
    log, but the table-SIZE reads were unwrapped and did not redirect pfctl's stderr — so reading
    an alias whose kernel table does not exist yet (as mid-reload, right after the previous version
    flushed it during a package update) leaked a bare 'pfctl: Table does not exist' into the update
    / Software-page output. pfb_pfctl_table_count() now reads with pfctl's OWN stderr suppressed and
    counts in PHP, so an absent table is simply 0 entries — no leak.

    Red→green: pfb_pfctl_table_count() does not exist before the change, so the snippet fatals (no
    COUNT marker emitted); green after.
    """
    absent = "pfB_smoke_absent_xyzzy_v4"  # a table name that is never created on the box
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
        f"echo '<<<CNT>>>' . pfb_pfctl_table_count('{absent}') . '<<<END>>>';"
    )
    result = h.php_eval(adr40_vm, snippet)
    combined = result.stdout + result.stderr

    # A read of an absent table is "0 entries", not a failure.
    assert "<<<CNT>>>0<<<END>>>" in result.stdout, (
        f"expected 0 entries for an absent table; rc={result.returncode} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # ...and emits no bare pfctl 'Table does not exist' anywhere (stdout or stderr).
    assert "Table does not exist" not in combined, (
        f"bare 'pfctl: Table does not exist' leaked despite the read helper: {combined!r}"
    )


def test_ip_orig_pruned_only_when_feed_unconfigured(adr40_vm: SmokeVM) -> None:
    """origdir/*.orig is reclaimed iff the feed is no longer CONFIGURED -- not merely missing a .txt.

    The IPv4/6 'Last Updated List Summary' lists every *.orig in origdir. A feed the user
    un-subscribed used to leave its <header>.orig behind forever -- the IP side lacked the
    orphan-prune the DNSBL side has -- so removed feeds kept appearing in the summary. The prune
    keys on CONFIG, not on .txt presence: the .orig is the cached download the reuse/reparse path
    re-reads, and a configured feed can legitimately have no .txt this pass (reuse/reparse, an
    empty or all-filtered result), so it MUST be kept; only a removed feed's .orig is deleted.

    Branch coverage (both sides of the keep/prune decision):
      * configured feed, even with its .txt deleted (the reuse/reparse case) -> KEPT;
      * unconfigured header (a feed removed from config)                      -> PRUNED.

    Red->green: before the fix the IP side had no prune, so the unconfigured orphan survived.
    """
    origdir = "/var/db/pfblockerng/original"

    # Given: one configured IPv4 deny feed, settled on disk (its .orig written by the download).
    feed_url = h.write_local_feed(adr40_vm, "smoke_origprune.txt", "203.0.113.7\n")
    ip_spec = h.IpCase(aliasname="smokeorigprune", feed_url=feed_url, header="smokeorigprune")
    h.inject(adr40_vm, ip_spec)
    h.reload(adr40_vm, "update")
    # IP feeds carry a _v4/_v6 family suffix in the stored header, the .orig, and $existing,
    # so the download lands at <header>_v4.orig (the v4-only feed above).
    kept = f"{origdir}/smokeorigprune_v4.orig"
    assert "PRESENT" in adr40_vm.ssh(f"test -f {kept} && echo PRESENT || echo MISSING").stdout, (
        f"setup failed: configured feed's .orig not created at {kept}"
    )

    # And: the change-detect probe file for the SAME configured feed. It shares the *.orig glob
    # via its legacy .md5 infix ({header}.md5.orig), so it must be kept too -- asserting this pins
    # the .md5-infix strip (without it the probe basename would read as an unknown header).
    kept_probe = f"{origdir}/smokeorigprune_v4.md5.orig"
    adr40_vm.ssh(f"echo '203.0.113.7' > {kept_probe}")

    # And: delete that feed's parsed .txt -- the reuse/reparse/empty case where keying on .txt
    # would wrongly delete a still-configured feed's cached .orig.
    adr40_vm.ssh("rm -f /var/db/pfblockerng/deny/smokeorigprune*")

    # And: an unconfigured orphan .orig (a feed removed from config in some prior pass).
    orphan = f"{origdir}/zzz_orphan_xyzzy.orig"
    adr40_vm.ssh(f"echo '198.51.100.0/24' > {orphan}")

    # When: a reload runs the IP list reconciliation.
    h.reload(adr40_vm, "update")

    # Then: the configured feed's .orig (and its .md5 probe) are KEPT; the orphan is PRUNED.
    kept_state = adr40_vm.ssh(f"test -f {kept} && echo PRESENT || echo GONE").stdout
    probe_state = adr40_vm.ssh(f"test -f {kept_probe} && echo PRESENT || echo GONE").stdout
    orphan_state = adr40_vm.ssh(f"test -f {orphan} && echo PRESENT || echo GONE").stdout
    assert "PRESENT" in kept_state, (
        "configured feed's .orig wrongly pruned -- the prune must key on config, not .txt.\n"
        f"  expected: {kept} PRESENT\n  actual:   {kept_state!r}"
    )
    assert "PRESENT" in probe_state, (
        "configured feed's .md5.orig probe wrongly pruned -- the .md5 infix must be stripped so it "
        f"maps back to its header.\n  expected: {kept_probe} PRESENT\n  actual:   {probe_state!r}"
    )
    assert "GONE" in orphan_state, (
        f"unconfigured orphan .orig not pruned.\n  expected: {orphan} GONE\n  actual:   {orphan_state!r}"
    )
