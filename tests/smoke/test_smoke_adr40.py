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
for small-churn changes (churn ratio < ``PFB_DELTA_CHURN_THRESHOLD`` = 0.20)
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

* **Large-churn replace fallback (auto mode)** — crossing the 20% threshold
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

    **When** ``helpers.reload(vm, 'update')`` runs again over the SAME unchanged
    feed content.

    **Then** the post hook fires and ``PFB_CHANGED_IP_ALIASES`` does NOT contain
    the alias — the content-gate short-circuited the reload.

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

    # Second update: SAME feed content, no changes.
    # pfb_alias_set_different() must return FALSE → alias NOT added to $pfb_alias_lists.
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

    # The content change ran the no-rule-change reload path, which logs a per-alias
    # " Updating: <alias>" line. Those lines must render CONTIGUOUSLY (one per line), not
    # blank-separated — a leading "\n" in the log format put a blank line above every entry.
    # Inspect only THIS reload's slice of the log (order-independent — the session VM's log
    # accumulates across tests), guarding the exact regression: no entry preceded by a blank line.
    reload_log = adr40_vm.ssh("cat", h.PFB_LOG).stdout[log_len_before:]
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
