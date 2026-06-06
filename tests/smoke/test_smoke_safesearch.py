"""Live-VM smoke for the SafeSearch CNAME redirect (issue #149).

SafeSearch ships two CNAME redirects — ``duckduckgo.com -> safe.duckduckgo.com``
and ``pixabay.com -> safesearch.pixabay.com`` — every other SafeSearch entry is a
plain A/AAAA rewrite. Before #149 those two rode a residual native-Unbound
``local-zone`` include (the last sliver ADR-02 left behind); now pfb_unbound.py does
the redirect itself: it plants the synthetic CNAME in Unbound's cache and restarts
the iterator so the iterator chases the target (working around NLnetLabs/unbound
#976 — a module-handed CNAME is not chased), re-stamping DNSSEC so the synthesized
hop is not bogus. A #2 baked-IP fallback (resolved at list-build, kept fresh by the
15-min cron) answers if the chase ever yields no address.

This is the make-or-break gate for the #1 live-chase mechanism, which can only be
proven on a real Unbound. To make the proof deterministic AND hermetic, the two
CNAME targets are pinned to RFC-5737 TEST-NET addresses via DNS-Resolver Host
Overrides: a working chase lands on those exact IPs. (The targets are unsigned in
real DNS, so the chase has no DNSSEC angle here regardless.)

Probed ON-BOX (``drill @127.0.0.1``); SafeSearch redirects have no localhost
exemption, so the redirect shows there.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

# Marked ``smoke`` (runs under the full ``-m smoke`` matrix) AND ``safesearch`` (so a
# focused ``-m safesearch`` dispatch runs just this CNAME-redirect case).
pytestmark = [pytest.mark.smoke, pytest.mark.safesearch]

# The two shipped CNAME-SafeSearch names and their redirect targets.
DDG = "duckduckgo.com"
DDG_TARGET = "safe.duckduckgo.com"
PIX = "pixabay.com"
PIX_TARGET = "safesearch.pixabay.com"

# Controlled addresses the targets are pinned to (RFC 5737 / RFC 3849 test ranges),
# so a working chase resolves the SafeSearch name to a KNOWN value rather than a
# live CDN IP. A #2 baked fallback would instead serve the real (extdns-resolved)
# target IP, so the controlled IP is also what distinguishes #1 from #2.
DDG_V4, DDG_V6 = "198.51.100.50", "2001:db8::50"
PIX_V4, PIX_V6 = "198.51.100.51", "2001:db8::51"

CONTROL = {
    DDG_TARGET: {"A": DDG_V4, "AAAA": DDG_V6},
    PIX_TARGET: {"A": PIX_V4, "AAAA": PIX_V6},
}


@pytest.fixture(scope="module")
def safesearch_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[tuple[SmokeVM, h.DnsAnswer, h.DnsAnswer]]:
    """Deploy, enable DNSBL with SafeSearch, and capture the BEFORE answers.

    RECURSIVE mode (deliberately NOT use_system_dns_upstream): a catch-all
    ``forward-zone: "."`` re-forwards the SOURCE name on the iterator restart, which
    defeats the cache-planted CNAME chase — and pfSense's default resolver is
    recursive anyway, which is what the #1 mechanism targets. The redirect TARGET
    (safe.duckduckgo.com / safesearch.pixabay.com) is pinned to a TEST-NET IP via a
    Host Override (local-data), so the chase resolves it LOCALLY — the proof needs no
    real internet. Egress stays open so the SafeSearch-off BEFORE probe can resolve
    the real site and the #2 bake can run, but the AFTER redirect does not depend on
    it.

    Yields ``(vm, ddg_before, pix_before)`` — the pre-redirect answers, so each test
    can prove the redirect CHANGED them (no false green from a name that already
    resolved to the target).
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.unblock_egress()  # recursive resolution for the BEFORE probe + the #2 bake

    # Enable DNSBL (so the python module is loaded) with a dummy feed; pin the CNAME
    # targets to the controlled TEST-NET IPs. SafeSearch is still OFF here.
    feed = h.write_local_feed(smoke_vm, "smoke_ss_dummy.txt", f"{h.unique_domain('ssdummy')}\n")
    spec = h.DnsblCase(aliasname="smokess", feed_url=feed, header="smokess", control_local_data=CONTROL)
    h.set_safesearch_enabled(smoke_vm, False)
    h.inject(smoke_vm, spec)
    h.reload(smoke_vm, "update")

    # BEFORE: with SafeSearch off, the CNAME names resolve normally (recursive); in CI
    # recursion can be flaky, so this is a best-effort baseline (tests only require it
    # is NOT already the controlled target, not that it succeeded).
    ddg_before = h.dns_probe(smoke_vm, DDG, "A")
    pix_before = h.dns_probe(smoke_vm, PIX, "A")

    # WHEN: enable SafeSearch and rebuild -> the redirect rows enter pfb_py_ss.txt and
    # pfb_unbound.py reloads safeSearchDB on the unbound restart (issue #149 forces the
    # restart, since the data swap alone does not reload safeSearchDB).
    h.set_safesearch_enabled(smoke_vm, True)
    h.reload(smoke_vm, "update")
    # The BEFORE probe cached the real site answer; clear it so the AFTER probe is
    # evaluated fresh through the module (belt-and-braces; the config-change reload
    # already restarts Unbound).
    h.flush_unbound_cache(smoke_vm)

    try:
        yield smoke_vm, ddg_before, pix_before
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


def test_safesearch_cname_redirect_takes_effect(
    safesearch_vm: tuple[SmokeVM, h.DnsAnswer, h.DnsAnswer],
) -> None:
    """The gate: enabling SafeSearch REDIRECTS duckduckgo.com to the safe target.

    When SafeSearch is enabled, Then the on-box answer becomes a clean NOERROR with
    records, is NOT a SERVFAIL (which would mean the synthesized hop went
    DNSSEC-bogus), and DIFFERS from the SafeSearch-off baseline — the redirect took
    effect. The baseline is only required to NOT already be the controlled target (CI
    recursion can be flaky, so we do not require it to have resolved).
    """
    vm, ddg_before, _ = safesearch_vm

    # Baseline must not already be the SafeSearch target (else "changed" is vacuous).
    assert not h.resolves_to(ddg_before, DDG_V4), "baseline must not already be the SafeSearch target"

    after = h.dns_probe(vm, DDG, "A")
    assert after.rcode != "SERVFAIL", f"{DDG} SERVFAIL after redirect (synthesized hop went bogus?) — {after}"
    assert after.rcode == "NOERROR" and after.records, f"{DDG} should still resolve after redirect, got {after}"
    assert set(after.records) != set(ddg_before.records), (
        f"{DDG} answer unchanged by SafeSearch — redirect did not take effect "
        f"(before={ddg_before.records}, after={after.records})"
    )


def test_safesearch_cname_chase_reaches_target(
    safesearch_vm: tuple[SmokeVM, h.DnsAnswer, h.DnsAnswer],
) -> None:
    """#1 live chase: the redirect resolves to the CONTROLLED target address.

    The targets are pinned to TEST-NET IPs via Host Overrides, so a working iterator
    chase of our planted CNAME lands EXACTLY on them. This is the proof that #1 (plant
    CNAME -> restart iterator -> chase) works on real Unbound — if instead the #2 baked
    fallback answered, the IP would be the real (extdns-resolved) target, not the
    controlled one, and this asserts the difference. Covers both A and AAAA, and a
    second CNAME name (pixabay) so it is not a single-name fluke.
    """
    vm, _, pix_before = safesearch_vm

    ddg_a = h.dns_probe(vm, DDG, "A")
    assert h.resolves_to(ddg_a, DDG_V4), f"{DDG} A should chase to controlled {DDG_V4} (#1), got {ddg_a}"

    ddg_aaaa = h.dns_probe(vm, DDG, "AAAA")
    assert h.resolves_to(ddg_aaaa, DDG_V6), f"{DDG} AAAA should chase to controlled {DDG_V6} (#1), got {ddg_aaaa}"

    # A second CNAME-SafeSearch name proves the redirect is general, not duckduckgo-special.
    assert not h.resolves_to(pix_before, PIX_V4), f"baseline {PIX} must not already be the target, got {pix_before}"
    pix_a = h.dns_probe(vm, PIX, "A")
    assert h.resolves_to(pix_a, PIX_V4), f"{PIX} A should chase to controlled {PIX_V4} (#1), got {pix_a}"
