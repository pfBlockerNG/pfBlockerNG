"""Issue #361 — live-VM smoke for pfb_collect_localip() IPv6 locality recognition.

Before the fix, ``pfb_collect_localip()`` did not enumerate runtime IPv6 addresses
for interfaces whose ``ipaddrv6`` config key stores a dynamic-mode keyword
(``track6``, ``dhcp6``, ``slaac``, etc.) rather than a static address.  As a
result, a local destination's IPv6 was not recognised as local and
``pfb_daemon_filterlog()`` misidentified it as the external ``$host``, running
GeoIP/ASN lookups on the local machine's own address.

The fix adds a ``get_configured_ipv6_addresses()`` enumeration pass to
``pfb_collect_localip()`` so the *runtime* IPv6 address is collected regardless
of how the config keyword is stored.

These tests call the REAL ``pfb_collect_localip()`` on a booted pfSense VM:

* Configure a static RFC 3849 IPv6 address (``2001:db8:51:1::1/64``) on the
  LAN interface so the address is unconditionally present at probe time.
* Call ``collect_localip(vm)`` to obtain the ``(pfb_local, pfb_localsub)``
  structures from the live box.
* Assert every locality invariant — before and after — so a regression would
  produce a red test, not a vacuous green.

Test domains and IPs are RFC 3849 / RFC 5737: inert, non-routable, never
HSTS-preloaded.

These tests are DESELECTED from the default ``python -m pytest`` run.  Run via::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

A live VM (``smoke_vm``) and a built package (``SMOKE_PKG``) are required; both
fixtures skip cleanly when absent.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke


# ---------------------------------------------------------------------------
# Module-scoped deploy fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ipv6_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once; yield the VM for the locality tests.

    No DNSBL config is required — ``pfb_collect_localip()`` runs before any
    reload and has no dependency on the DNSBL pipeline being active.  The
    package is installed (so pfblockerng.inc is present on disk) and the VM is
    otherwise in its default state.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _read_ipv6_config(vm: SmokeVM, iface: str) -> dict[str, str]:
    """Read the stored IPv6 config keys for ``iface`` from config.xml.

    Returns ``{"ipaddrv6": <value-or-empty>, "subnetv6": <value-or-empty>}``
    without writing anything to config.xml.  Used to capture the pre-test
    state so it can be restored in the test's ``finally`` block.
    """
    snippet = (
        f"$iface = config_get_path({h._php_str('interfaces/' + iface)}, array());\n"
        f"echo {h._php_str(h._CFG_VAL_OPEN)}"
        " . ($iface['ipaddrv6'] ?? '')"
        f" . {h._php_str('|||')}"
        " . ($iface['subnetv6'] ?? '')"
        f" . {h._php_str(h._CFG_VAL_CLOSE)};"
    )
    result = h.php_eval(vm, snippet, timeout=30.0)
    out = result.stdout
    start = out.find(h._CFG_VAL_OPEN)
    end = out.find(h._CFG_VAL_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(
            f"_read_ipv6_config({iface}): no delimited value in output: rc={result.returncode} out={out!r}"
        )
    inner = out[start + len(h._CFG_VAL_OPEN) : end]
    parts = inner.split("|||", 1)
    return {"ipaddrv6": parts[0], "subnetv6": parts[1] if len(parts) > 1 else ""}


# ---------------------------------------------------------------------------
# Locality smoke test
# ---------------------------------------------------------------------------


def test_collect_localip_recognises_ipv6_address_and_subnet(
    ipv6_vm: SmokeVM,
) -> None:
    """Scenario: pfb_collect_localip() recognises a static IPv6 on the LAN interface.

    Background:
        The LAN interface (never the WAN — that carries the SLIRP-NAT SSH path)
        is configured with the RFC 3849 address ``2001:db8:51:1::1/64``.
        ``pfb_collect_localip()`` is called on the live box.

    Given the LAN interface has NO static IPv6 configured (before state):
        ``pfb_local`` does NOT contain ``2001:db8:51:1::1``.
        ``pfb_localsub`` does NOT contain ``2001:db8:51:1::/64``.
        ``ip_in_localsub(IPV6_LOCAL_HOST, pfb_localsub)`` returns False.

    When the static IPv6 ``2001:db8:51:1::1/64`` is applied to the LAN interface:

    Then (after state):
        ``pfb_local`` CONTAINS ``2001:db8:51:1::1`` (exact-match recognised).
        ``pfb_localsub`` CONTAINS a subnet covering ``2001:db8:51:1::/64``
            (subnet recognised).
        ``ip_in_localsub(IPV6_LOCAL_HOST, pfb_localsub)`` returns True — a
            host inside the /64 is classified as local.
        ``ip_in_localsub(IPV6_FOREIGN, pfb_localsub)`` returns False — a host
            in a different /32 block is NOT classified as local.

    And the IPv4 path is unaffected:
        The LAN IPv4 runtime address is NOT empty AND IS present in ``pfb_local``
            (proves the IPv6 pass did not break IPv4 enumeration).
    """
    vm = ipv6_vm
    iface = h.IPV6_LOCAL_IFACE
    addr = h.IPV6_LOCAL_ADDR
    bits = h.IPV6_LOCAL_BITS
    local_host = h.IPV6_LOCAL_HOST
    foreign = h.IPV6_FOREIGN

    # ------------------------------------------------------------------
    # Save the original IPv6 config for restore in finally (read-only —
    # no config.xml mutation at this point).
    # ------------------------------------------------------------------
    original_ipv6_config = _read_ipv6_config(vm, iface)

    try:
        # ------------------------------------------------------------------
        # GIVEN: Clear any static IPv6 from the LAN interface so the
        # before-state is clean, then read collect_localip().
        # restore_interface_ipv6 with empty ipaddrv6 removes the keys and
        # calls interface_configure() to remove the OS-level address.
        # ------------------------------------------------------------------
        h.restore_interface_ipv6(vm, iface, {"ipaddrv6": "", "subnetv6": ""}, timeout=120.0)

        before_local, before_localsub = h.collect_localip(vm)

        # GIVEN assertions: the target address is absent before we add it.
        assert addr not in before_local, (
            f"GIVEN violated: {addr!r} already in pfb_local before set_interface_ipv6 — "
            f"cannot assert causal before/after.  pfb_local={before_local!r}"
        )
        assert not h.ip_in_localsub(addr, before_localsub), (
            f"GIVEN violated: {addr!r} already in a pfb_localsub subnet — pfb_localsub={before_localsub!r}"
        )
        assert not h.ip_in_localsub(local_host, before_localsub), (
            f"GIVEN violated: in-subnet host {local_host!r} already matched pfb_localsub — "
            f"pfb_localsub={before_localsub!r}"
        )

        # ------------------------------------------------------------------
        # WHEN: Apply the static IPv6 address on the LAN interface.
        # set_interface_ipv6 polls until get_configured_ipv6_addresses() confirms
        # the address is live on the OS, so probes after this call are authoritative.
        # ------------------------------------------------------------------
        h.set_interface_ipv6(vm, iface, addr, bits, timeout=120.0)

        # WHEN: Call pfb_collect_localip() on the live box.
        after_local, after_localsub = h.collect_localip(vm)

        # ------------------------------------------------------------------
        # THEN: Local IPv6 is recognised.
        # ------------------------------------------------------------------
        assert addr in after_local, (
            f"THEN violated: {addr!r} NOT in pfb_local after set_interface_ipv6 — "
            f"fix for issue #361 not effective.  pfb_local={after_local!r}"
        )

        # THEN: The /64 subnet is recognised.
        assert h.ip_in_localsub(addr, after_localsub), (
            f"THEN violated: configured address {addr!r} not matched by any "
            f"pfb_localsub subnet.  pfb_localsub={after_localsub!r}"
        )

        # THEN: A host INSIDE the /64 is recognised as local.
        assert h.ip_in_localsub(local_host, after_localsub), (
            f"THEN violated: in-subnet host {local_host!r} NOT matched by pfb_localsub — "
            f"fix for issue #361 not effective.  pfb_localsub={after_localsub!r}"
        )

        # THEN: A FOREIGN address (outside the /64) is NOT recognised as local.
        assert not h.ip_in_localsub(foreign, after_localsub), (
            f"THEN violated: foreign address {foreign!r} IS matched by pfb_localsub — "
            f"over-broad subnet or wrong prefix.  pfb_localsub={after_localsub!r}"
        )

        # AND: The IPv4 path is unaffected.
        lan_ipv4 = h.get_live_ipv4(vm, iface)
        assert lan_ipv4, (
            "AND violated: get_live_ipv4(lan) returned empty — the IPv6 pass may have broken IPv4 enumeration."
        )
        assert lan_ipv4 in after_local, (
            f"AND violated: LAN IPv4 {lan_ipv4!r} NOT in pfb_local — "
            f"IPv4 enumeration broken after IPv6 change.  pfb_local={after_local!r}"
        )

    finally:
        # Always restore the original IPv6 config regardless of assertion outcome.
        h.restore_interface_ipv6(vm, iface, original_ipv6_config, timeout=120.0)
