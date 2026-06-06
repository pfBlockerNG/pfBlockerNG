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
proven on a real Unbound. The resolver runs RECURSIVE (pfSense's default and what
the chase targets) — deliberately NOT use_system_dns_upstream, whose catch-all
``forward-zone: "."`` re-forwards the SOURCE name on the iterator restart and
defeats the cache-planted chase. The chase therefore resolves the real
``safe.duckduckgo.com`` / ``safesearch.pixabay.com`` (unsigned in DNS, so no DNSSEC
angle), and the test asserts ``duckduckgo.com`` ends up at that same address.

Probed ON-BOX (``drill @127.0.0.1``); SafeSearch redirects have no localhost
exemption, so the redirect shows there.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = [pytest.mark.smoke, pytest.mark.safesearch]

# The two shipped CNAME-SafeSearch names and their redirect targets.
DDG = "duckduckgo.com"
DDG_TARGET = "safe.duckduckgo.com"
PIX = "pixabay.com"
PIX_TARGET = "safesearch.pixabay.com"


@pytest.fixture(scope="module")
def safesearch_vm(smoke_vm: SmokeVM) -> Iterator[tuple[SmokeVM, h.DnsAnswer, h.DnsAnswer]]:
    """Deploy, enable DNSBL + SafeSearch (recursive resolver), capture the BEFORE answers.

    Egress stays OPEN: the resolver is recursive, so the redirect chase resolves the
    real SafeSearch target, and the SafeSearch-off BEFORE probe resolves the real site.

    Yields ``(vm, ddg_before, pix_before)`` — the pre-redirect answers, so each test
    proves the redirect CHANGED them.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.unblock_egress()  # recursive resolution for the chase + the BEFORE probe
    # Force recursive mode: a prior matrix module on the SHARED VM may have set
    # use_system_dns_upstream (catch-all forward-zone), which re-forwards the source
    # name on the iterator restart and defeats the cache-planted chase (issue #149).
    h.use_recursive_resolver(smoke_vm)

    # Enable DNSBL (so the python module is loaded) with a dummy local feed. SafeSearch
    # is still OFF here, so the CNAME names resolve to their real sites.
    feed = h.write_local_feed(smoke_vm, "smoke_ss_dummy.txt", f"{h.unique_domain('ssdummy')}\n")
    spec = h.DnsblCase(aliasname="smokess", feed_url=feed, header="smokess")
    h.set_safesearch_enabled(smoke_vm, False)
    h.inject(smoke_vm, spec)
    h.reload(smoke_vm, "update")

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
    """The gate: enabling SafeSearch REDIRECTS duckduckgo.com away from its real site.

    When SafeSearch is enabled, Then the on-box answer becomes a clean NOERROR with
    records, is NOT a SERVFAIL (which would mean the synthesized hop went
    DNSSEC-bogus), and DIFFERS from the SafeSearch-off baseline — the redirect took
    effect.
    """
    vm, ddg_before, _ = safesearch_vm

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
    """#1 live chase: duckduckgo.com resolves to safe.duckduckgo.com's own address.

    The redirect plants ``duckduckgo.com -> CNAME -> safe.duckduckgo.com`` and the
    iterator chases it, so the queried name ends up at the TARGET's address. Proven by
    comparing duckduckgo.com's answer to a direct lookup of safe.duckduckgo.com: the
    chase populated the target's cache entry, so the direct lookup is a cache hit and
    the two share an address (rotation-proof). A second CNAME name (pixabay) shows the
    redirect is general, not duckduckgo-special.
    """
    vm, _, _ = safesearch_vm

    for name, target in ((DDG, DDG_TARGET), (PIX, PIX_TARGET)):
        redirected = h.dns_probe(vm, name, "A")
        assert redirected.rcode == "NOERROR" and redirected.records, (
            f"{name} did not resolve after redirect: {redirected}"
        )
        target_ans = h.dns_probe(vm, target, "A")  # cache hit from the chase above
        assert set(redirected.records) & set(target_ans.records), (
            f"{name} should resolve to {target}'s address (CNAME chase); "
            f"{name}={redirected.records} vs {target}={target_ans.records}"
        )
