"""Live-VM smoke for the SafeSearch CNAME redirect — fully hermetic (issue #238).

The test is driven entirely against the in-process stub DNS server with egress
BLOCKED.  No live third-party DNS is contacted; all source and target names are
fabricated with :func:`~helpers.unique_domain` (``uuid-*.com``) and served by
the stub with distinct RFC 5737 / RFC 3849 fixture IPs.

Mechanism under test: pfBlockerNG plants a synthetic ``src -> CNAME -> target``
redirect in Unbound's message cache (via ``safesearch_cname_redirect`` in
``pfb_unbound.py``) and restarts the iterator so the iterator chases the target
name.  The stub serves the target's address, so ``src`` resolves to that address
(#1 chase outcome).  When the target resolves with NO address (NODATA), the module
falls back to the baked IP embedded in the CSV row (#2 baked-fallback outcome).

Both resolver modes are covered (the fixture is parametrized):

* **recursive** — Unbound recurses; a catch-all ``forward-zone`` in
  ``custom_options`` redirects all queries to the stub.
* **forwarding** — Unbound forwards to ``192.168.89.2`` (SLIRP host alias → stub).

All heavy setup (Unbound reconfigure + pfBlockerNG reloads) lives in the fixture
so the 30 s per-test-body cap (``smoke-single.yml: timeout_func_only``) does not bite.

This replaces the former live-DNS dependency on real ``duckduckgo.com`` /
``pixabay.com`` redirects, which drifted and made the test flaky (issue #238).
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterator
from typing import NamedTuple

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer

pytestmark = [pytest.mark.smoke, pytest.mark.safesearch]


class _SSFixture(NamedTuple):
    """Everything the SafeSearch tests need, yielded by :func:`safesearch_vm`."""

    vm: SmokeVM
    client_vm: SmokeVM
    forwarding_on: bool
    src_chase: str  # the CNAME-redirect source name for the #1 chase test
    target_chase: str  # the CNAME target name served with SS_TARGET_A/AAAA by the stub
    src_fallback: str  # the CNAME-redirect source name for the #2 baked-fallback test
    before: h.DnsAnswer  # sentinel answer for src_chase BEFORE the redirect is active


@pytest.fixture(scope="module")
def _ss_deployed(smoke_vm: SmokeVM, client_vm: SmokeVM) -> Iterator[tuple[SmokeVM, SmokeVM]]:
    """One-time deploy + DNSBL VIP (shared by both resolver-mode parametrizations)."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    yield smoke_vm, client_vm


@pytest.fixture(scope="module", params=[False, True], ids=["recursive", "forwarding"])
def safesearch_vm(
    _ss_deployed: tuple[SmokeVM, SmokeVM],
    stub_dns: _StubDnsServer,
    request: pytest.FixtureRequest,
) -> Iterator[_SSFixture]:
    """Wire Unbound to the stub, inject fabricated SafeSearch CNAME rows, yield fixture.

    Parametrized on ``forwarding_on``.  Egress is BLOCKED for the duration so the
    test is hermetic; the stub is reachable via the SLIRP ``192.168.89.2`` loopback path
    regardless.

    Sequence:

    1. Block egress (hermeticity gate).
    2. Fabricate source + target names via :func:`~helpers.unique_domain`.
    3. Wire Unbound to the stub (:func:`~helpers.use_stub_for_safesearch`) — this
       strips the pfb python module from ``unbound.conf``.
    4. Enable DNSBL with a dummy local feed so the pfb python module is reloaded
       into ``unbound.conf``.  SafeSearch is NOT enabled via config — rows are
       injected directly so the package's real ddg/pixabay rows are irrelevant.
    5. Register stub records: ``target_chase`` → SS_TARGET_A/AAAA; ``target_fallback``
       → NODATA (no families registered → the chase yields no address → baked fallback).
    6. Capture the BEFORE answer for ``src_chase`` (stub sentinel — distinct from the
       post-redirect SS_TARGET_A so the before/after mandate is provable).
    7. Inject the fabricated CSV rows and bounce Unbound to reload ``safeSearchDB``.
    8. Flush the Unbound cache (the BEFORE probe cached the sentinel; clear it so the
       AFTER probe is evaluated fresh through the module).
    9. Yield the :class:`_SSFixture`.
    10. Teardown: drop stub records, restore egress, collect diagnostics.
    """
    vm, cvm = _ss_deployed
    forwarding_on: bool = request.param

    # Step 1: block egress — all DNS must route through the stub.
    h.block_egress()

    # Step 2: fabricate source + target names (must be unique_domain — never RFC-6761
    # TLDs or HSTS-preload names; SafeSearch redirects have no localhost exemption).
    src_chase = h.unique_domain("ss-src")
    target_chase = h.unique_domain("ss-tgt")
    src_fallback = h.unique_domain("ss-fb-src")
    target_fallback = h.unique_domain("ss-fb-tgt")

    try:
        # Step 3: wire Unbound to the stub (strips pfb python module from unbound.conf).
        h.use_stub_for_safesearch(vm, forwarding_on)

        # Step 4: enable DNSBL with a dummy local feed — reloads pfb python module into
        # unbound.conf so safeSearchDB and the CNAME redirect logic are active.
        # SafeSearch is left DISABLED in config; we inject rows directly below.
        feed = h.write_local_feed(vm, "smoke_ss_dummy.txt", f"{h.unique_domain('ssdummy')}\n")
        spec = h.DnsblCase(aliasname="smokess", feed_url=feed, header="smokess")
        h.inject(vm, spec)
        h.reload(vm, "update")

        # Step 5: register stub records.
        # Chase target: stub serves SS_TARGET_A/AAAA — DISTINCT from the sentinel so
        # the test can tell "chase reached the target" from "sentinel default".
        stub_dns.set_records(target_chase, a=(h.SS_TARGET_A,), aaaa=(h.SS_TARGET_AAAA,))
        # Fallback target: NODATA (no families) — chase yields only a bare CNAME with no
        # address, so the module answers src_fallback with the baked IP from the CSV row.
        stub_dns.set_records(target_fallback)

        # Step 6: capture the BEFORE answer (redirect not active yet).
        # src_chase is an unregistered name -> stub sentinel STUB_DNS_A.
        # This is DISTINCT from SS_TARGET_A so the before≠after transition is provable.
        before = h.dns_probe_client(cvm, src_chase, "A")

        # Step 7: inject the fabricated SafeSearch CNAME rows and bounce Unbound.
        h.inject_safesearch_cname_entries(
            vm,
            [
                h.SafeSearchEntry(src_chase, target_chase),
                h.SafeSearchEntry(src_fallback, target_fallback, h.SS_BAKED_A, h.SS_BAKED_AAAA),
            ],
        )

        # Step 8: flush the cache — the BEFORE probe cached the sentinel; clearing it
        # ensures the AFTER probe is evaluated fresh through the pfb python module.
        h.flush_unbound_cache(vm)

        yield _SSFixture(
            vm=vm,
            client_vm=cvm,
            forwarding_on=forwarding_on,
            src_chase=src_chase,
            target_chase=target_chase,
            src_fallback=src_fallback,
            before=before,
        )

    finally:
        # Drop all fabricated stub records so they do not leak to later test modules.
        stub_dns.clear_cname()
        h.unblock_egress()
        h.collect_host_diagnostics(vm)


def test_safesearch_cname_redirect_takes_effect(safesearch_vm: _SSFixture) -> None:
    """The gate: enabling SafeSearch REDIRECTS src_chase away from its sentinel default.

    Scenario: SafeSearch CNAME redirect changes the on-box answer.

    Background:
        Given a fabricated source name with no SafeSearch entry active.

    Given the BEFORE answer is the stub sentinel (SafeSearch-off baseline):
        The source name resolves to STUB_DNS_A — confirming no redirect is active yet.
    When the SafeSearch CNAME row is injected and Unbound is bounced.
    Then the on-box answer is a clean NOERROR with records, is NOT SERVFAIL (which
        would mean the synthesized CNAME hop went DNSSEC-bogus), and DIFFERS from the
        BEFORE sentinel — proving the redirect CAUSED the change.
    """
    vm, cvm, forwarding_on, src_chase, _target_chase, _src_fallback, before = safesearch_vm

    # Given: assert the before-state (sentinel) so green proves the redirect CAUSED the change.
    assert h.resolves_to(before, STUB_DNS_A), (
        f"[forwarding={forwarding_on}] BEFORE: {src_chase} should resolve to sentinel "
        f"{STUB_DNS_A} (no redirect yet); got {before}"
    )

    # When: redirect is active (injected in the fixture).
    after = h.dns_probe_client(cvm, src_chase, "A")

    # Then: NOERROR with records, not SERVFAIL, and different from the sentinel before-state.
    assert after.rcode != "SERVFAIL", (
        f"[forwarding={forwarding_on}] {src_chase} SERVFAIL after redirect — "
        f"synthesized CNAME hop may be DNSSEC-bogus: {after}"
    )
    assert after.rcode == "NOERROR" and after.records, (
        f"[forwarding={forwarding_on}] {src_chase} should still resolve after redirect; got {after}"
    )
    assert set(after.records) != set(before.records), (
        f"[forwarding={forwarding_on}] {src_chase} answer unchanged after SafeSearch injection — "
        f"redirect did not take effect (before={before.records}, after={after.records})"
    )


def test_safesearch_cname_chase_reaches_target(safesearch_vm: _SSFixture) -> None:
    """#1 chase: src_chase resolves to the stub-served fixture address of target_chase.

    Scenario: CNAME iterator chase reaches the stub target address.

    Background:
        Given the stub serves SS_TARGET_A / SS_TARGET_AAAA for target_chase.
        Given pfBlockerNG plants src_chase -> CNAME -> target_chase in the message cache.

    When the iterator chases src_chase.
    Then src_chase A resolves to SS_TARGET_A and src_chase AAAA resolves to SS_TARGET_AAAA
        (the stub-served fixture address — DISTINCT from the sentinel so the assertion
        proves the chase, not a stub default).
    And a direct lookup of target_chase returns the same fixture address (cache-population
        / chase-consistency check: the iterator populated target_chase's cache entry).
    """
    vm, cvm, forwarding_on, src_chase, target_chase, _src_fallback, _before = safesearch_vm

    for rtype, expected in (("A", h.SS_TARGET_A), ("AAAA", h.SS_TARGET_AAAA)):
        redirected = h.dns_probe_client(cvm, src_chase, rtype)
        assert redirected.rcode == "NOERROR" and redirected.records, (
            f"[forwarding={forwarding_on}] {src_chase} {rtype} did not resolve after redirect: {redirected}"
        )
        # Compare IPv6 by value (:: == ::0) via ipaddress.ip_address normalisation.
        normalised_records = {str(ipaddress.ip_address(r)) for r in redirected.records}
        assert str(ipaddress.ip_address(expected)) in normalised_records, (
            f"[forwarding={forwarding_on}] {src_chase} {rtype}: expected {expected} "
            f"(chase target address); got {redirected.records}"
        )

        # Cache-population check: target_chase itself resolves to the same fixture address.
        target_ans = h.dns_probe_client(cvm, target_chase, rtype)
        assert target_ans.rcode == "NOERROR" and target_ans.records, (
            f"[forwarding={forwarding_on}] {target_chase} {rtype} did not resolve "
            f"(expected cache hit from the chase): {target_ans}"
        )
        normalised_target = {str(ipaddress.ip_address(r)) for r in target_ans.records}
        assert normalised_records & normalised_target, (
            f"[forwarding={forwarding_on}] {src_chase} {rtype} address does not overlap "
            f"{target_chase} {rtype} — CNAME chase did not reach the target: "
            f"{src_chase}={redirected.records} vs {target_chase}={target_ans.records}"
        )


def test_safesearch_cname_fallback_to_baked_ip(safesearch_vm: _SSFixture) -> None:
    """#2 baked fallback: src_fallback (NODATA target) resolves to the baked CSV IP.

    Scenario: baked-fallback fires when the CNAME chase yields no address.

    Background:
        Given the stub serves NODATA for target_fallback (no A or AAAA registered).
        Given pfBlockerNG plants src_fallback -> CNAME -> target_fallback; the baked
        IPs SS_BAKED_A / SS_BAKED_AAAA are embedded in the CSV row.

    When the iterator chases src_fallback and finds only a bare CNAME with no address.
    Then the module answers src_fallback with the baked IPs (SS_BAKED_A / SS_BAKED_AAAA).
    And the answer does NOT contain SS_TARGET_A or the stub sentinel — proving the baked
        fallback fired, not the chase (#1) and not the stub default.

    This test pairs with test_safesearch_cname_chase_reaches_target to prove #1 (chase)
    and #2 (baked fallback) are DISTINCT real branches — not the same code path.
    """
    vm, cvm, forwarding_on, _src_chase, _target_chase, src_fallback, _before = safesearch_vm

    for rtype, expected, not_expected_label, not_expected in (
        ("A", h.SS_BAKED_A, "chase/sentinel", {h.SS_TARGET_A, STUB_DNS_A}),
        ("AAAA", h.SS_BAKED_AAAA, "chase/sentinel", {h.SS_TARGET_AAAA}),
    ):
        ans = h.dns_probe_client(cvm, src_fallback, rtype)
        assert ans.rcode == "NOERROR" and ans.records, (
            f"[forwarding={forwarding_on}] {src_fallback} {rtype} should resolve via baked "
            f"fallback (NODATA target); got {ans}"
        )
        normalised = {str(ipaddress.ip_address(r)) for r in ans.records}
        assert str(ipaddress.ip_address(expected)) in normalised, (
            f"[forwarding={forwarding_on}] {src_fallback} {rtype}: expected baked fallback "
            f"address {expected}; got {ans.records}"
        )
        for bad in not_expected:
            assert str(ipaddress.ip_address(bad)) not in normalised, (
                f"[forwarding={forwarding_on}] {src_fallback} {rtype}: found {not_expected_label} "
                f"address {bad} — baked fallback did not fire (got {ans.records})"
            )
