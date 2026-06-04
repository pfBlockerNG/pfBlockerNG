"""ADR-04 Phase 5 — the first landed smoke matrix (a THIN vertical slice).

This is NOT the broad knob space (SafeSearch/TLD/GeoIP/full-AAAA are out of scope,
ADR §2). The one knob added beyond the original thin slice is the **HSTS VIP→null
override** (``test_dnsbl_hsts_*``): an HSTS-preload name on a VIP-mode list blocks
NULL, not the VIP — a load-bearing default branch (``pfb_hsts``) the rest of the
matrix deliberately avoids. It is the minimum that proves the Phase-4 harness asserts
REAL pfBlockerNG behaviour end-to-end on BOTH paths — the IP path (``pfctl``
alias table + rule) and the DNS path (``dig`` rcode/record shape) — hermetically
(mock feeds + baked Unbound ``local-data`` only) and guarded against false-green.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Every expected answer is pinned to the REAL matcher semantics in
``src/usr/local/pkg/pfblockerng/pfb_unbound.py`` + ``pfblockerng.inc`` (verified
against source, not guessed):

* DNSBL **python** mode (the ONLY mode on ``next``): the feed is written to
  ``pfb_py_data.txt`` as EXACT entries (``inc:8966-8970``; zone files are only
  produced by the out-of-scope TLD feature). ``evaluate_domain``
  (``pfb_unbound.py:evaluate_domain``) looks the name up in ``dataDB`` EXACTLY.
  The response shape is:

  - ``logging='enabled'`` → ``logging_type='1'`` → ``null_blocking=False``
    → NOERROR + A = DNSBL VIP (``pfb_dnsvip4``). (**VIP** shape.)
  - ``logging='disabled'`` → ``logging_type='2'`` → ``null_blocking=True``
    → NOERROR + A = ``0.0.0.0`` / AAAA = ``::0``. (**NULL** shape.)

  A matched subdomain is NOT in ``dataDB`` and is NOT blocked (exact match only).
  NXDOMAIN is NEVER the response for a normal feed match (verified on the live
  box); the only NXDOMAIN path is SafeSearch.

  Probed ON-BOX (``drill @127.0.0.1`` over SSH): verified on a live box that
  python-mode DNSBL has NO localhost exemption — a blocked name returns its block
  shape even for a 127.0.0.1 query. (The QEMU SLIRP WAN-hostfwd path, unlike a real
  LAN client, is not answered in CI — so we don't use it.)

  Two domain constraints, both load-bearing (see ``helpers.unique_domain``):
  test names must NOT use RFC 6761 TLDs (``.test`` / ``.example`` / …) — Unbound's
  built-in ``local-zone``s shadow them (NXDOMAIN/NODATA) before DNSBL — and must
  NOT be HSTS-preload — with HSTS on (the default ``pfb_hsts``), a preload domain's
  VIP block is forced to NULL. A random ``uuid-*.com`` satisfies both.
* WHITELIST (``suppression``): ``whitelist_check_domain`` short-circuits before
  any block shape, so a suppressed name resolves via its control ``local-data``.
* DNSBL-IP dual-stack (``action != 'Disabled'``): IP literals in the DNSBL feed
  split by family into ``<header>_v4.ip``/``_v6.ip`` (``inc:8596-8617``,
  ``8688-8702``), merged into ``DNSBLIP_v4.txt``/``_v6.txt`` (``inc:8869-8931``),
  loaded into the per-family alias tables ``pfB_DNSBLIP_v4`` AND
  ``pfB_DNSBLIP_v6`` (``inc:9306``); each holds only its own family.

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps; without them they skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _MockFeedServer, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the matrix; the per-case egress block is
    managed by ``CaseContext``, NOT here.

    Egress stays OPEN during a pfBlockerNG reload (the DNSBL update path needs a
    working resolver/network) and ``CaseContext`` blocks it only for the per-case
    DNS probe. The probe stays hermetic because every name the matrix asserts
    resolves LOCALLY — a blocked name is intercepted by the python module before
    the forwarder, and a control/whitelist name answers from its injected host
    override — so the probe never needs the real internet. A not-blocked,
    no-control name resolves via the runner-side stub (``use_stub_upstream``), the
    sole controlled upstream — a known sentinel, AND recorded, so "was it blocked?"
    is read off the upstream, not inferred from a SERVFAIL. deploy() needs no
    egress for dependencies either — the pre-baked image ships pfBlockerNG's
    RUN_DEPENDS, so ``pkg add`` resolves them from the local pkg db offline.
    unblock on teardown as a safety net.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    # Snapshot the DNSBL-OFF unbound.conf so dump_diagnostics can diff what the
    # DNSBL reload changes (incl. whether it drops custom access-control).
    h.snapshot_unbound_conf(smoke_vm)
    h.snap_state(smoke_vm, "deployed")
    # DNSBL force-disables itself without a VIP (pfb_validate_vips); by default
    # pfBlockerNG does NOT auto-create one (pfb_dnsvip_auto OFF; pfb_manage_dnsbl_vip
    # auto-creates it when ON — ADR-13). The image does NOT bake one, so inject the
    # lo0 sinkhole VIP once for the matrix. dns_probe queries on-box (drill
    # @127.0.0.1) — no localhost exemption — so no WAN/ACL plumbing is needed.
    h.ensure_dnsbl_vip(smoke_vm)
    # Point Unbound's sole upstream at the controlled stub BEFORE any per-test
    # unbound-config snapshot (test_dnsbl_unbound_config_immutable), so the stub
    # forward-zone is part of the baseline and the DNSBL reload still adds only python.
    h.use_stub_upstream(smoke_vm)
    h.snap_state(smoke_vm, "vip")
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        # ALWAYS collect a full guest snapshot (all /var/log, dmesg, pf, unbound,
        # scrubbed config.xml) for the workflow to upload — for this debug and for
        # after-the-fact analysis. Best-effort; never masks a test result.
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# 1) IP path — alias-table membership (positive + negative) + rule reference
# --------------------------------------------------------------------------- #


def test_ip_alias_table_and_rule(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A fed IP is a table member, a non-fed IP is NOT, and a rule references it.

    Positive + negative member on the real ``pfctl`` path: the fed
    ``198.51.100.5`` must be in ``pfB_<alias>`` and the never-fed
    ``198.51.100.99`` must be absent (a table that swallowed everything, or a
    stale table, would fail the negative). A loaded pf rule must reference the
    alias (proves the table is actually wired into the ruleset, not orphaned).
    """
    fed_ip = "198.51.100.5"
    non_fed = "198.51.100.99"
    feed_url = h.write_local_feed(deployed_vm, "smoke_ip_matrix.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="smokeipmtx", feed_url=feed_url, header="smokeipmtx")
    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, fed_ip), f"{fed_ip} not in {spec.alias}: {members}"
        assert not h.member_present(members, non_fed), f"{non_fed} unexpectedly in {spec.alias}: {members}"
        assert h.rule_references(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


# --------------------------------------------------------------------------- #
# 2) DNSBL path — the response-shape matrix (pinned to pfb_unbound.py)
# --------------------------------------------------------------------------- #


def test_dnsbl_unbound_config_immutable(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """pfBlockerNG DNSBL reload only adds python-module config to unbound.conf.

    When DNSBL is enabled, pfBlockerNG is allowed to make exactly ONE class of
    change to Unbound's configuration: adding the python iterator module directives
    (``module-config``, ``python-script``, and pfBlockerNG managed ``include``
    lines, plus the DNSBL VIP ``interface:`` entry).  No other configuration —
    access-control, forward-zones, server tuning — may be removed or altered.

    This guards against pfBlockerNG silently clobbering custom Unbound config
    (e.g. the DNS-Resolver ACLs in access_lists.conf) during a reload.
    """
    # Baseline the EFFECTIVE unbound config (unbound.conf + all *.conf includes,
    # so access_lists.conf etc. are covered) AND the live ACLs, BEFORE DNSBL is
    # applied. The case carries no control records, so the only legitimate delta
    # is pfBlockerNG's python-module config.
    h.snapshot_unbound_effective(deployed_vm)
    acls_before = h.unbound_access_control(deployed_vm)
    domain = h.unique_domain("cfgimmut")
    feed_url = h.write_local_feed(deployed_vm, "smoke_cfgimmut.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokecfgimmut", feed_url=feed_url, header="smokecfgimmut")
    with h.CaseContext(deployed_vm, spec):
        h.assert_unbound_adds_only_python_config(deployed_vm)
        # Authoritative ACL check via the daemon itself (unbound-control), not a
        # file grep: the DNSBL reload must not drop/alter the resolver ACLs.
        acls_after = h.unbound_access_control(deployed_vm)
        assert acls_after == acls_before, (
            f"DNSBL reload changed Unbound ACLs: before={sorted(acls_before)} after={sorted(acls_after)}"
        )


def test_dnsbl_python_exact_vip(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Python-mode exact block: NOERROR + VIP for the listed domain; subdomain passes.

    Verified on the live box: python mode writes the feed to ``pfb_py_data.txt``
    as EXACT entries.  ``evaluate_domain`` looks the name up in ``dataDB`` EXACTLY
    — ``logging='enabled'`` → ``null_blocking=False`` → NOERROR + A = DNSBL VIP.
    A subdomain is NOT in ``dataDB`` and resolves normally (exact, not wildcard).
    Probed on-box (``drill @127.0.0.1``); python-mode has no localhost exemption,
    so the block shows there. Domain is a unique non-RFC-6761 ``.com`` so no
    Unbound local-zone shadows it.
    """
    domain = h.unique_domain("blocked")
    sub = f"x.{domain}"
    sub_ip = "198.51.100.40"
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_exact.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokeexact",
        feed_url=feed_url,
        header="smokeexact",
        mode=h.DnsblMode.VIP,
        control_local_data={sub: {"A": sub_ip}},
    )
    with h.CaseContext(deployed_vm, spec):
        blocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(blocked), f"{domain} expected VIP {h.DEFAULT_DNSBL_VIP4}, got {blocked}"
        # EXACT match: subdomain NOT in dataDB, resolves to its control answer.
        passed = h.dns_probe(deployed_vm, sub, "A")
        assert h.resolves_to(passed, sub_ip), f"{sub} should resolve to {sub_ip} (exact != wildcard), got {passed}"
        assert not h.is_vip(passed), f"{sub} wrongly VIP-blocked (exact match, not wildcard): {passed}"


def test_dnsbl_exact_null(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Python-mode null sinkhole: NOERROR + 0.0.0.0/::0 for a logging='disabled' feed.

    ``logging='disabled'`` → ``logging_type='2'`` → ``null_blocking=True`` →
    pfb_unbound.py answers NOERROR + A 0.0.0.0 / AAAA ::0. The domain is a unique
    non-HSTS-preload ``.com`` so HSTS (on by default) does not also force NULL —
    NULL here is purely the per-list ``logging='disabled'`` path.
    """
    domain = h.unique_domain("null")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_null.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokenull",
        feed_url=feed_url,
        header="smokenull",
        mode=h.DnsblMode.NULL,
    )
    with h.CaseContext(deployed_vm, spec):
        a = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_null_ip(a), f"{domain} A expected {h.NULL_IP4}, got {a}"
        aaaa = h.dns_probe(deployed_vm, domain, "AAAA")
        assert h.is_null_ip(aaaa, null_ip="::0") or not aaaa.records, (
            f"{domain} AAAA expected ::0 (or no AAAA), got {aaaa}"
        )


def test_dnsbl_hsts_override_forces_null(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """HSTS override: a VIP-mode block on an HSTS-preload name is forced to NULL.

    The load-bearing branch the rest of the matrix deliberately avoids. For a
    ``logging='enabled'`` (VIP, ``log_type == '1'``) list, ``evaluate_domain``
    sets ``null_blocking=False`` (→ VIP) ONLY when the name is NOT in HSTS; an
    HSTS-preload name keeps ``null_blocking=True`` → NULL (``0.0.0.0`` / ``::0``).
    HSTS is on by default (``pfb_hsts`` → ini ``python_hsts``); we set it
    explicitly. Rationale: a browser refuses the plaintext VIP sinkhole for an
    HSTS host, so NULL is the correct block.

    Self-contained: we pin a unique ``.com`` into the in-chroot HSTS set
    (``add_hsts_name``) rather than depend on the shipped preload list. The case's
    first reload (in ``CaseContext``) recreates ``pfb_py_hsts.txt`` from the shipped
    list; we then append our name and reload again — copy-if-missing leaves the now-
    existing file alone, so the module reloads hstsDB WITH our name. Paired with
    ``test_dnsbl_hsts_disabled_keeps_vip`` (same name, same VIP list, HSTS off →
    VIP) to prove this is the override, not an always-null path.
    """
    domain = h.unique_domain("hstsnull")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_hsts.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokehsts",
        feed_url=feed_url,
        header="smokehsts",
        mode=h.DnsblMode.VIP,  # logging='enabled' → would be VIP UNLESS HSTS forces NULL
        hsts=True,  # pfb_hsts on — the override under test
    )
    with h.CaseContext(deployed_vm, spec):
        # hstsDB after enter = shipped list (no our name). Pin it, reload so the
        # module re-reads, and confirm it is in the effective set before probing.
        h.add_hsts_name(deployed_vm, domain)
        h.reload(deployed_vm, "updatednsbl")
        h.assert_hsts_loaded(deployed_vm, domain)
        a = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_null_ip(a), f"HSTS override should force A=0.0.0.0, got {a} (VIP leak?)"
        assert not h.is_vip(a), f"HSTS-preload VIP-list block must NOT be the VIP {h.DEFAULT_DNSBL_VIP4}: {a}"
        aaaa = h.dns_probe(deployed_vm, domain, "AAAA")
        assert h.is_null_ip(aaaa, null_ip="::0") or not aaaa.records, (
            f"{domain} AAAA expected ::0 (or no AAAA), got {aaaa}"
        )


def test_dnsbl_hsts_disabled_keeps_vip(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Non-tautology guard: the SAME VIP-list HSTS-listed name, HSTS OFF → VIP.

    With ``pfb_hsts`` off → ini ``python_hsts=off``, pfb_unbound.py never loads
    hstsDB (``cfg["hstsDB"]`` False), so ``in_hsts`` stays False and the
    ``logging='enabled'`` (VIP) list yields the VIP even for a name we pinned into
    ``pfb_py_hsts.txt``. The name IS added to the HSTS file (then ignored) so the
    ONLY difference from ``test_dnsbl_hsts_override_forces_null`` is the toggle —
    proving that test exercises the HSTS branch, not an always-null path.
    """
    domain = h.unique_domain("hstsvip")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_hstsoff.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokehstsoff",
        feed_url=feed_url,
        header="smokehstsoff",
        mode=h.DnsblMode.VIP,
        hsts=False,  # pfb_hsts off → HSTS branch disabled
    )
    with h.CaseContext(deployed_vm, spec):
        # Pin the name into the HSTS file too — with HSTS off it is IGNORED, so the
        # only delta vs the positive case is pfb_hsts.
        h.add_hsts_name(deployed_vm, domain)
        h.reload(deployed_vm, "updatednsbl")
        blocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(blocked), f"HSTS off: VIP-list block should be the VIP {h.DEFAULT_DNSBL_VIP4}, got {blocked}"
        assert not h.is_null_ip(blocked), f"HSTS off must NOT force NULL: {blocked}"


def test_dnsbl_whitelist_passthrough(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """WHITELIST: a domain on the whitelist AND in the block feed RESOLVES.

    ``suppression`` short-circuits before any block shape, so the name resolves
    via its control ``local-data`` (a true pass) — NOT NXDOMAIN/null/VIP.
    """
    domain = h.unique_domain("allowed")
    pass_ip = "198.51.100.77"
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_white.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokewhite",
        feed_url=feed_url,
        header="smokewhite",
        mode=h.DnsblMode.VIP,
        whitelist=[domain],
        control_local_data={domain: {"A": pass_ip}},
    )
    with h.CaseContext(deployed_vm, spec):
        answer = h.dns_probe(deployed_vm, domain, "A")
        assert h.resolves_to(answer, pass_ip), f"whitelisted {domain} should resolve to {pass_ip}, got {answer}"
        assert not h.is_vip(answer), f"whitelisted {domain} wrongly VIP-blocked: {answer}"
        assert not h.is_null_ip(answer), f"whitelisted {domain} wrongly null-IP: {answer}"


def test_dnsbl_resolve_block_unlock_relock_lifecycle(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """#51 FULL lifecycle, asserting the ACTUAL resolution at every transition:

      (a) BEFORE any list  -> the domain RESOLVES (forwarded to the stub sentinel);
      (b) added to a feed  -> BLOCKED (VIP), no longer resolves;
      (c) temporary Unlock -> RESOLVES again (forwarded to the stub sentinel);
      (d) re-Lock          -> BLOCKED again (VIP).

    Proving the domain resolves in (a) and again in (c) rules out a false-green: the
    VIP in (b)/(d) genuinely comes from the feed block, and the pass in (c) genuinely
    comes from the Unlock. The Unlock/Lock drives the real python-mode
    pfblockerng_alerts.php ``dnsbl_remove`` sequence (toggle the ``pfb_unlock`` store ->
    regenerate ``config.user_unlock`` -> RESTART Unbound, whose python ``init_standard``
    re-reads the manifest). Before the #51 fix step (c) was a NO-OP (it wrote files the
    manifest build no longer reads), so the domain stayed VIP-blocked.

    NOTE: NO ``control_local_data`` host override on the name. A host override is served
    by Unbound as ``local-data`` BEFORE the python module runs, so it would shadow the
    DNSBL block (the name would resolve to the override even in step (b)). An *allowed*
    name therefore resolves via the controlled stub upstream (``STUB_DNS_A``) — exactly
    how ``test_dns_probe_absent_resolves_via_stub`` proves a real pass. Egress is left
    OPEN in the body so the allowed probes reach the (SLIRP-local, controlled) stub;
    the block probes return the VIP locally, so there is no false-green from egress.
    """
    domain = h.unique_domain("unlock")

    # (a) BEFORE any blocklist: forwarded to the controlled stub -> resolves to the
    #     sentinel (a real, observable baseline — not yet on any feed, not blocked).
    before = h.dns_probe(deployed_vm, domain, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{domain} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_vip(before) and not h.is_null_ip(before), f"{domain} unexpectedly blocked before any feed: {before}"

    # (b) Now put it on a DNSBL feed -> the SAME domain is now BLOCKED (VIP).
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_unlock.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokeunlock", feed_url=feed_url, header="smokeunlock", mode=h.DnsblMode.VIP)
    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()  # the allowed probes (a-shape) must reach the controlled stub
        blocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(blocked), f"{domain} expected VIP block once listed, got {blocked}"
        assert not h.resolves_to(blocked, STUB_DNS_A), f"{domain} still resolving after block: {blocked}"

        # (c) Temporary Unlock -> resolves again (forwarded to the stub sentinel).
        #     A VIP here would be the #51 no-op (unlock never reaching the build).
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "unlock")
        unlocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.resolves_to(unlocked, STUB_DNS_A), f"unlocked {domain} should resolve via stub, got {unlocked}"
        assert not h.is_vip(unlocked), f"unlocked {domain} still VIP-blocked (the #51 no-op): {unlocked}"

        # (d) Re-Lock -> the temporary allow is removed: blocked again (VIP).
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "lock")
        relocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(relocked), f"re-locked {domain} expected VIP block again, got {relocked}"
        assert not h.resolves_to(relocked, STUB_DNS_A), f"re-locked {domain} still resolving: {relocked}"


def test_dnsbl_temp_unlock_cleared_by_force_update(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """#51: a temporary Unlock is re-locked by a Cron/Force update — even with NO feed
    change (parity with main).

    A pending temporary-unlock store forces the reload path regardless of feed changes
    (``inc:8806`` ``|| file_exists($pfb['dnsbl_unlock'])``); that path drops the store
    and clears the manifest's ``config.user_unlock`` (``inc:3451`` ->
    ``pfb_unbound_python_sources_unlock``), so Unbound's ``init_standard`` re-reads a
    cleared whiteDB and the domain is re-blocked. On ``main`` the equivalent re-lock is
    the ungated whitelist regeneration; before this fix devel only cleared ``user_unlock``
    on a feed-change rebuild, so a no-change Force left the unlock live (the regression
    this run caught). A plain ``update`` over the UNCHANGED feed is therefore enough.
    """
    domain = h.unique_domain("unlocktmp")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_unlocktmp.txt", f"{domain}\n")
    # No host override on the name — it would shadow the DNSBL block (served as
    # local-data before the python module); an allowed name resolves via the stub.
    spec = h.DnsblCase(aliasname="smokeunlocktmp", feed_url=feed_url, header="smokeunlocktmp", mode=h.DnsblMode.VIP)
    with h.CaseContext(deployed_vm, spec):
        # Egress OPEN: the update path deadlocks under a dark egress, and the allowed
        # (unlock) probe must reach the controlled stub. The block probes return the VIP
        # locally, so there is no false-green from leaving egress open.
        h.unblock_egress()
        # Blocked by the feed -> VIP (the "before" of the Unlock operation).
        blocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(blocked), f"{domain} expected VIP block, got {blocked}"
        # Unlock -> resolves again (forwarded to the stub sentinel).
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "unlock")
        unlocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.resolves_to(unlocked, STUB_DNS_A), f"unlocked {domain} should resolve via stub, got {unlocked}"
        assert not h.is_vip(unlocked), f"unlocked {domain} still VIP-blocked: {unlocked}"
        # A Cron/Force update over the UNCHANGED feed re-locks it: the pending unlock
        # store forces the reload + clears the manifest's user_unlock.
        h.reload(deployed_vm, "update")
        relocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(relocked), f"Cron/Force update should re-lock {domain} -> VIP, got {relocked}"
        assert not h.resolves_to(relocked, STUB_DNS_A), f"re-locked {domain} still resolving: {relocked}"


# --------------------------------------------------------------------------- #
# 3) DNSBL-IP dual-stack — two distinct pf tables, partitioned by family
# --------------------------------------------------------------------------- #


def test_dnsblip_dual_stack_partition(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A DNSBL feed with BOTH families -> pfB_DNSBLIP_v4 AND pfB_DNSBLIP_v6.

    ADR §2 contract: with the DNSBL-IP feature on and a feed carrying both an
    IPv4 and an IPv6 literal, pfBlockerNG must populate TWO distinct alias tables
    (the hardcoded ``DNSBLIP`` base name is suffixed per family ``_v4``/``_v6``,
    inc:9306) — each holding ONLY its own family, never merged onto one table.
    The inet/inet6 rules must reference the matching table.

    DEFERRED: ``pfB_DNSBLIP_v4`` / ``pfB_DNSBLIP_v6`` are not present when
    ``pfctl_tables()`` runs — the tables appear in teardown diagnostics, showing
    that ``filter_configure`` populates them asynchronously after
    ``pfblockerng.php update`` exits.  The assertion needs a polling helper (like
    ``rule_references``).  Re-deferred; the IP-firewall path itself is already
    proven by ``test_ip_alias_table_and_rule``.
    Tracked: https://github.com/andrebrait/pfBlockerNG/issues/35
    """
    pytest.skip(
        "pfB_DNSBLIP_v4/v6 populated async by filter_configure; needs poll-based "
        "assertion — deferred (see docstring; un-skip: #35)"
    )
    v4 = "203.0.113.7"  # RFC 5737 documentation range
    v6 = "2001:db8:5::7"  # RFC 3849 documentation range
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsblip_dual.txt", f"{v4}\n{v6}\n")
    # The feed is reached by a DNSBL list; the embedded IPs feed the DNSBLIP
    # tables once the DNSBL-IP feature (action) is enabled. update covers both
    # the domain DB and the IP tables.
    spec = h.DnsblCase(
        aliasname="smokedualip",
        feed_url=feed_url,
        header="smokedualip",
        mode=h.DnsblMode.NULL,
        dnsbl_ip_action="Deny_Both",
    )
    with h.CaseContext(deployed_vm, spec, scope="update"):
        tables = h.pfctl_tables(deployed_vm)
        assert "pfB_DNSBLIP_v4" in tables, f"pfB_DNSBLIP_v4 missing: {tables}"
        assert "pfB_DNSBLIP_v6" in tables, f"pfB_DNSBLIP_v6 missing: {tables}"

        v4_members = h.pfctl_table_members(deployed_vm, "pfB_DNSBLIP_v4")
        v6_members = h.pfctl_table_members(deployed_vm, "pfB_DNSBLIP_v6")

        # Each table holds ONLY its own family (no collision / merge).
        assert h.member_present(v4_members, v4), f"{v4} not in pfB_DNSBLIP_v4: {v4_members}"
        assert not any(":" in m for m in v4_members), f"IPv6 leaked into pfB_DNSBLIP_v4: {v4_members}"
        assert any(":" in m for m in v6_members), f"no IPv6 in pfB_DNSBLIP_v6: {v6_members}"
        assert not any(_is_v4_literal(m) for m in v6_members), f"IPv4 leaked into pfB_DNSBLIP_v6: {v6_members}"

        # inet/inet6 rules reference the matching per-family table.
        assert h.rule_references(deployed_vm, "pfB_DNSBLIP_v4"), "no rule references pfB_DNSBLIP_v4"
        assert h.rule_references(deployed_vm, "pfB_DNSBLIP_v6"), "no rule references pfB_DNSBLIP_v6"


def _is_v4_literal(member: str) -> bool:
    """True iff a pfctl table member looks like an IPv4 address/CIDR."""
    head = member.split("/", 1)[0]
    parts = head.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# --------------------------------------------------------------------------- #
# 3b) DNSBL auto-VIP (ADR-13) — create on enable, remove on disable
# --------------------------------------------------------------------------- #


def test_dnsbl_autovip_lifecycle(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-13 'Create VIPs automatically': provision a marked sinkhole VIP on
    enable, sink a block to it, remove ONLY it on disable.

    Full before/after lifecycle (CLAUDE.md test-coverage rules — assert the
    before-state, then prove the transition caused the change):

    * BEFORE: no package-owned ``pfB_AUTO_VIP_v4`` exists, and the listed name is
      NOT blocked (it forwards to the stub upstream, so it resolves to a non-VIP
      address).
    * ENABLE (``pfb_dnsvip_auto`` on + DNSBL on): the package creates an IP-Alias
      VIP at ``10.10.10.53/32`` on ``lo0`` (live in ``ifconfig``), points
      ``pfb_dnsvip4`` at it, and the listed name now sinks to ``10.10.10.53`` —
      the AUTO address, NOT the harness's manual ``10.10.10.1`` VIP.
    * DISABLE: the marked VIP is removed from config AND ``lo0``.

    The matrix's manual VIP at ``10.10.10.1`` is present throughout and is never
    touched (only marker-owned VIPs are managed). Teardown restores the manual
    VIP + auto-off so the rest of the matrix runs against its own baseline.

    Auto-create picks ``10.10.10.53`` precisely because the manual VIP holds
    ``10.10.10.1`` — the first free ``.53`` candidate — so the two coexist and
    this case needs no second VM. Uses ``scope='update'`` (a full Force Update)
    so ``pfb_create_dnsbl`` -> ``pfb_manage_dnsbl_vip`` actually runs.
    """
    vm = deployed_vm
    domain = h.unique_domain("autovip")
    feed_url = h.write_local_feed(vm, "smoke_autovip.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokeautovip", feed_url=feed_url, header="smokeautovip", mode=h.DnsblMode.VIP)
    try:
        # BEFORE: no auto VIP yet, and the name is not blocked to the auto address.
        assert h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4) == "", (
            "pfB_AUTO_VIP_v4 present before auto-create was ever enabled"
        )
        pre = h.dns_probe(vm, domain, "A")
        assert pre.records, f"{domain} did not resolve before listing: {pre}"
        assert not h.is_vip(pre, vip=h.AUTO_VIP_IP4), f"{domain} already sinks to the auto VIP before enable: {pre}"

        # ENABLE auto-create; the CaseContext's Force Update lists the name and
        # runs pfb_create_dnsbl('enabled') -> the VIP is created + applied.
        h.set_dnsvip_auto(vm, True)
        with h.CaseContext(vm, spec, scope="update"):
            assert h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4) == h.AUTO_VIP_IP4, (
                f"auto VIP not created at {h.AUTO_VIP_IP4}: got {h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4)!r}"
            )
            assert h.vip_alias_live(vm, h.AUTO_VIP_IP4), f"auto VIP {h.AUTO_VIP_IP4} not live on lo0 (ifconfig)"
            assert h.dnsvip4_address(vm) == h.AUTO_VIP_IP4, (
                f"pfb_dnsvip4 does not point at the auto VIP: {h.dnsvip4_address(vm)!r}"
            )
            blocked = h.dns_probe(vm, domain, "A")
            assert h.is_vip(blocked, vip=h.AUTO_VIP_IP4), f"{domain} expected auto VIP {h.AUTO_VIP_IP4}, got {blocked}"
            assert not h.is_vip(blocked, vip=h.DEFAULT_DNSBL_VIP4), (
                f"block leaked to the manual VIP {h.DEFAULT_DNSBL_VIP4} instead of the auto VIP: {blocked}"
            )

        # DISABLE DNSBL -> mode 'disabled' -> remove ONLY the marked + IP-matched VIP.
        h.set_dnsbl_enabled(vm, False)
        h.reload(vm, "update")
        assert h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4) == "", "auto VIP not removed from config on disable"
        assert not h.vip_alias_live(vm, h.AUTO_VIP_IP4), f"auto VIP {h.AUTO_VIP_IP4} still live on lo0 after disable"
    finally:
        # Restore the matrix baseline: auto off, DNSBL on, manual VIP repointed.
        h.set_dnsvip_auto(vm, False)
        h.set_dnsbl_enabled(vm, True)
        h.ensure_dnsbl_vip(vm)
        h.reset(vm)


# --------------------------------------------------------------------------- #
# 4) FALSE-GREEN GUARD — a deliberately-wrong expectation MUST go red
# --------------------------------------------------------------------------- #


@pytest.mark.xfail(strict=True, reason="deliberately-wrong expectation: a real VIP block is NOT a pass")
def test_false_green_guard_vm(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """STRICT-xfail guard: assert a real block RESOLVES — it must NOT.

    Blocks a unique domain (VIP) then asserts it resolves to a pass IP.
    That assertion is FALSE on a working harness, so the test fails -> the
    ``strict=True`` xfail turns the failure into the expected outcome (green
    overall). If a broken/lenient harness silently let the block "pass", this
    test would PASS unexpectedly and ``strict=True`` would flip the suite RED —
    catching a false-green at the VM level (on top of the pure-Python guard in
    test_smoke_helpers.py::test_false_green_guard).
    """
    domain = h.unique_domain("guard")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_guard.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokeguard",
        feed_url=feed_url,
        header="smokeguard",
        mode=h.DnsblMode.VIP,
    )
    with h.CaseContext(deployed_vm, spec):
        answer = h.dns_probe(deployed_vm, domain, "A")
        # WRONG on purpose: a VIP block does not resolve to a pass IP.
        assert h.resolves_to(answer, "198.51.100.250"), "expected (wrongly) to resolve — must fail"
