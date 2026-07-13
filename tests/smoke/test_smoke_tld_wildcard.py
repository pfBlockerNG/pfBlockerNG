"""Live-VM smoke for issue #1255 -- DNSBL Wildcard Blocking (TLD) toggle.

``pfb_tld`` (ini ``python_tld_wildcard``) gates whether ``pfb_unbound.py``'s
``classify()`` opens the shipped public-suffix oracle (``pfb_py_tld.txt``, staged
from ``dnsbl_tld`` by ``dnsbl_cache_stage()``, mirroring HSTS). ON: a listed 2-label
registrable domain (e.g. ``label-<uuid>.com``) classifies into a wildcard ZONE, which
blocks the domain AND every sub-domain at any depth. OFF: the oracle is never opened
(``tlds`` is empty), so ``classify()`` forces EXACT DATA for every domain -- only the
literally-listed name blocks; an unlisted sub-domain resolves normally.

The toggle applies on the NEXT NORMAL Update (``reload(vm, "update")`` -- scope=both
force=false trigger=cron), NOT a Force Reload: ``pfb_unbound_python()`` rewrites the
ini, the ini content differs, ``$pfbpython = TRUE``, and ``pfb_update_unbound()``
restarts the DNSBL python integration re-reading it.

Probed via a real LAN client (``dns_probe_client``, mirrors ``test_smoke_dnsbl_control.py``):
a not-blocked sub-domain must RESOLVE to a KNOWN, observable answer, not just "not
VIP" -- ``use_system_dns_upstream`` + the ``stub_dns`` server give a deterministic
``STUB_DNS_A`` sentinel for anything pfSense forwards (ADR-16 Part C's RESOLVE-PROOF
pattern), so a false-green from a real-DNS NXDOMAIN/timeout is impossible.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def tld_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[tuple[SmokeVM, str]]:
    """Deploy once with DNSBL Wildcard Blocking (TLD) ON and one 2-label domain listed.

    A single local feed pins a unique registrable domain (``label-<uuid>.com``) to a
    VIP block; ``tld_enabled=True`` on the case writes ``pfb_tld = on`` at inject time
    (``inject()``'s DNSBL-settings replace, same as ``control``/``hsts`` -- #588).
    System DNS is pointed at the controlled stub so a not-blocked probe has a known
    answer. Yields ``(vm, domain)``.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)

    domain = h.unique_domain("tldwild")
    feed = h.write_local_feed(smoke_vm, "smoke_tldwild_feed.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smoketldwild", feed_url=feed, header="smoketldwild", mode=h.DnsblMode.VIP, tld_enabled=True
    )
    h.inject(smoke_vm, spec)
    h.reload(smoke_vm, "update")
    # No assert_tld_wildcard_ini guard here (unlike sibling assert_control_ini
    # fixtures): the ini key is BRAND-NEW (#1255) -- a hard guard would abort setup
    # on pre-fix code, masking the test's own (deferred) red discriminator.
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    try:
        yield smoke_vm, domain
    finally:
        h.unblock_egress()
        try:
            h.clear_dnsbl_settings(smoke_vm)
        except Exception as cleanup_exc:  # noqa: BLE001
            print(f"[smoke] clear_dnsbl_settings failed on tld-wildcard teardown (suppressed): {cleanup_exc!r}")
        h.collect_host_diagnostics(smoke_vm)


def test_tld_wildcard_toggle_governs_subdomain_blocking(tld_vm: tuple[SmokeVM, str], client_vm: SmokeVM) -> None:
    """Scenario: the TLD-Wildcard toggle governs sub-domain blocking, not the listed name.

    Background: DNSBL Wildcard Blocking (TLD) is ON (the fixture baseline) and
    ``domain`` (a 2-label registrable ``uuid-*.com``) is feed-listed; ``sub`` (a fresh
    label prepended to ``domain``) is never itself listed.
    Given TLD-Wildcard ON, ``domain`` is VIP-blocked AND ``sub`` is ALSO VIP-blocked --
    the wildcard ZONE covers it (the before-state, so the toggle's effect below is
    provably causal, not a pre-existing accident).
    When TLD-Wildcard is turned OFF and a NORMAL Update runs (``reload(vm, "update")``
    -- force=false, NOT a Force Reload),
    Then ``domain`` STAYS VIP-blocked (the exact DATA entry survives the toggle) but
    ``sub`` now RESOLVES via the controlled stub upstream -- proving OFF collapses to
    exact-only matching, no wildcard.
    """
    vm, domain = tld_vm
    sub = "x." + domain

    # GIVEN: TLD-Wildcard ON -- domain AND its never-listed sub-domain both VIP-blocked.
    before_domain = h.dns_probe_client(client_vm, domain, "A")
    assert h.is_vip(before_domain), f"{domain} expected VIP block with TLD-Wildcard on, got {before_domain}"
    before_sub = h.dns_probe_client(client_vm, sub, "A")
    assert h.is_vip(before_sub), f"{sub} expected VIP block (wildcard ZONE) with TLD-Wildcard on, got {before_sub}"

    # WHEN: TLD-Wildcard OFF + a NORMAL Update (scope=update -> force=false; never Force Reload).
    h.set_dnsbl_tld_wildcard(vm, False)
    h.reload(vm, "update")
    # Defend against a stale cached answer surviving the reload regardless of whether
    # it took the restart or in-place-reinit path -- flush before the after-state probes.
    h.flush_unbound_cache(vm)

    # THEN: domain (the exact DATA entry) is UNCHANGED -- still VIP-blocked.
    after_domain = h.dns_probe_client(client_vm, domain, "A")
    assert h.is_vip(after_domain), (
        f"{domain} should STAY VIP-blocked (exact DATA) with TLD-Wildcard off, got {after_domain}"
    )

    # AND: sub now resolves via the stub -- the PRIMARY discriminator (the wildcard
    # zone no longer applies). This is the assertion that must fail on pre-fix code.
    after_sub = h.dns_probe_client(client_vm, sub, "A")
    assert h.resolves_to(after_sub, STUB_DNS_A), (
        f"{sub} should resolve via the stub with TLD-Wildcard off, got {after_sub}"
    )
    assert not h.is_vip(after_sub), f"{sub} unexpectedly still VIP-blocked with TLD-Wildcard off: {after_sub}"
    assert not h.is_null_ip(after_sub), f"{sub} unexpectedly NULL-blocked with TLD-Wildcard off: {after_sub}"

    # Attribution (reached only once the behavioural transition above is proven): the
    # ini reflects the OFF state -- a real config-write, not an accidental resolve.
    h.assert_tld_wildcard_ini(vm, on=False)
