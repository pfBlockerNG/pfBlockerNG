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

Run in BOTH resolver modes (the fixture is parametrized on ``unbound/forwarding``):
RECURSIVE and FORWARDING to a real upstream. The redirect works in both — the
iterator checks the message cache (where the module plants the CNAME) before it
forwards/recurses, then chases the TARGET. Forwarding uses a REAL upstream so the
SafeSearch target resolves to its own distinct address (the mock stub answers every
name identically and would mask the result; that — NOT a broken chase — is why the
smoke must not run against the stub). Targets are unsigned in DNS, so no DNSSEC angle.

The slow per-mode setup (Unbound reconfigure + pfBlockerNG reloads) lives in the
FIXTURE, so the 30s per-test-body cap (smoke.yml: ``timeout_func_only``) does not bite
and no per-test timeout override is needed.

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
def _ss_deployed(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """One-time deploy + DNSBL VIP (shared by both resolver-mode parametrizations)."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    yield smoke_vm


@pytest.fixture(scope="module", params=[False, True], ids=["recursive", "forwarding"])
def safesearch_vm(
    _ss_deployed: SmokeVM, request: pytest.FixtureRequest
) -> Iterator[tuple[SmokeVM, bool, h.DnsAnswer, h.DnsAnswer]]:
    """Enable DNSBL + SafeSearch in one resolver mode; capture the pre-redirect answers.

    Parametrized on ``forwarding`` — the ONLY difference between the two runs is
    ``unbound/forwarding`` off (recursive) vs on (forward to a real upstream). Egress
    stays open so both recursion and the real-upstream forward resolve. All reloads are
    here in the fixture (not the test body), so no per-test timeout override is needed.

    Yields ``(vm, forwarding_on, ddg_before, pix_before)`` — the SafeSearch-off answers,
    so each test proves the redirect CHANGED them.
    """
    vm = _ss_deployed
    forwarding_on: bool = request.param
    h.unblock_egress()

    # The single toggled variable. services_unbound_configure here regenerates the base
    # unbound.conf WITHOUT pfBlockerNG's python module; the reloads below re-add it.
    h.set_unbound_forwarding(vm, on=forwarding_on)

    # Enable DNSBL (python module loaded) with a dummy local feed; SafeSearch still OFF,
    # so the CNAME names resolve to their real sites for the BEFORE capture.
    feed = h.write_local_feed(vm, "smoke_ss_dummy.txt", f"{h.unique_domain('ssdummy')}\n")
    spec = h.DnsblCase(aliasname="smokess", feed_url=feed, header="smokess")
    h.set_safesearch_enabled(vm, False)
    h.inject(vm, spec)
    h.reload(vm, "update")

    ddg_before = h.dns_probe(vm, DDG, "A")
    pix_before = h.dns_probe(vm, PIX, "A")

    # WHEN: enable SafeSearch and rebuild -> the redirect rows enter pfb_py_ss.txt and
    # pfb_unbound.py reloads safeSearchDB on the unbound restart (issue #149 forces the
    # restart, since the data swap alone does not reload safeSearchDB).
    h.set_safesearch_enabled(vm, True)
    h.reload(vm, "update")
    # The BEFORE probe cached the real site answer; clear it so the AFTER probe is
    # evaluated fresh through the module (belt-and-braces; the reload already restarted).
    h.flush_unbound_cache(vm)

    try:
        yield vm, forwarding_on, ddg_before, pix_before
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(vm)


def test_safesearch_cname_redirect_takes_effect(
    safesearch_vm: tuple[SmokeVM, bool, h.DnsAnswer, h.DnsAnswer],
) -> None:
    """The gate: enabling SafeSearch REDIRECTS duckduckgo.com away from its real site.

    When SafeSearch is enabled, Then the on-box answer becomes a clean NOERROR with
    records, is NOT a SERVFAIL (which would mean the synthesized hop went
    DNSSEC-bogus), and DIFFERS from the SafeSearch-off baseline — the redirect took
    effect. Asserted in BOTH recursive and forwarding mode (the fixture parametrization).
    """
    vm, forwarding_on, ddg_before, _ = safesearch_vm

    after = h.dns_probe(vm, DDG, "A")
    assert after.rcode != "SERVFAIL", f"[forwarding={forwarding_on}] {DDG} SERVFAIL after redirect — {after}"
    assert after.rcode == "NOERROR" and after.records, (
        f"[forwarding={forwarding_on}] {DDG} should still resolve after redirect, got {after}"
    )
    assert set(after.records) != set(ddg_before.records), (
        f"[forwarding={forwarding_on}] {DDG} answer unchanged by SafeSearch — redirect did not take "
        f"effect (before={ddg_before.records}, after={after.records})"
    )


def test_safesearch_cname_chase_reaches_target(
    safesearch_vm: tuple[SmokeVM, bool, h.DnsAnswer, h.DnsAnswer],
) -> None:
    """#1 live chase: duckduckgo.com resolves to safe.duckduckgo.com's own address.

    The redirect plants ``duckduckgo.com -> CNAME -> safe.duckduckgo.com`` and the
    iterator chases it, so the queried name ends up at the TARGET's address. Proven by
    comparing duckduckgo.com's answer to a direct lookup of safe.duckduckgo.com: the
    chase populated the target's cache entry, so the direct lookup is a cache hit and
    the two share an address (rotation-proof). A second CNAME name (pixabay) shows the
    redirect is general, not duckduckgo-special. Asserted in BOTH recursive and
    forwarding mode (the fixture parametrization).
    """
    vm, forwarding_on, _, _ = safesearch_vm

    for name, target in ((DDG, DDG_TARGET), (PIX, PIX_TARGET)):
        redirected = h.dns_probe(vm, name, "A")
        assert redirected.rcode == "NOERROR" and redirected.records, (
            f"[forwarding={forwarding_on}] {name} did not resolve after redirect: {redirected}"
        )
        target_ans = h.dns_probe(vm, target, "A")  # cache hit from the chase above
        assert set(redirected.records) & set(target_ans.records), (
            f"[forwarding={forwarding_on}] {name} should resolve to {target}'s address (CNAME chase); "
            f"{name}={redirected.records} vs {target}={target_ans.records}"
        )
