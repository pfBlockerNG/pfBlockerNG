"""Live-VM smoke for the DoH/DoT-block NXDOMAIN path (issue #740) — fully hermetic.

Issue #740: the shipped ``pfb_dnsbl.doh.conf`` carried a malformed Yandex entry
(``yandex.dns`` — not a real hostname), so enabling the "Yandex DoH/DoT" option could
never block anything. A prior step replaced it with 9 real Yandex DoH/DoT endpoints
(``dns.yandex.ru``, ``common.dot.dns.yandex.net``, ...) under one UI key
(``dns.yandex``). This module is the live-VM proof that the FIXED conf data actually
blocks: the real Yandex hostnames are the subject under test on purpose (the bug was
in the shipped hostnames themselves, so a fabricated name would prove nothing about
it). The run stays hermetic despite probing real-world names: the in-process stub DNS
answers every query (including these) with a fixed sentinel, and egress is BLOCKED for
the test's duration, so nothing ever reaches the real Yandex network — the
``unique_domain()`` fabricated-name rule (for feed content that must not collide with
a real domain) does not apply to these probe SUBJECTS, only to control/scoping names.

Mechanism under test: pfBlockerNG's SafeSearch DoH/DoT block (``safesearch_doh`` +
``safesearch_doh_list``) uncomments the selected endpoints' lines in the shipped
``pfb_dnsbl.doh.conf``, feeds them into the SafeSearch CSV (``pfb_py_ss.txt``) as
``domain,nxdomain,nxdomain`` rows, and ``pfb_unbound.py`` answers a matched query with
RCODE NXDOMAIN (pfblockerng.inc:14148-14224, pfb_unbound.py:6140-6143) — the
SafeSearch-only NXDOMAIN block shape (never used for a DNSBL feed match).

Both endpoint FAMILIES are probed with one host each: ``safe.dns.yandex.ru`` (the
``.ru`` DoH/DoT family) and ``common.dot.dns.yandex.net`` (the ``.net`` DoT family) —
proving the single ``dns.yandex`` UI key's substring match reaches conf lines across
BOTH families, not just one.

A SafeSearch CSV change is loaded ONLY at python-module init (issue #149 —
``safeSearchDB`` is populated once in ``init()``, never by the data-only reload path),
so pfBlockerNG's own reload forces the config-change/RESTART path whenever the CSV
changes (``$safesearch_update`` -> ``$pfbpython = TRUE``, pfblockerng.inc:14040 /
15845-15858) instead of the ADR-10 zero-downtime data swap. The production
``pfblockerng.php pfb_trigger`` reload (:func:`~tests.smoke.helpers.reload`) already
takes this path, so no raw Unbound bounce is needed here (contrast
``inject_safesearch_cname_entries``, which bypasses the PHP reload entirely by writing
the CSV directly and therefore DOES need a raw bounce).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import NamedTuple

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer

pytestmark = [pytest.mark.smoke, pytest.mark.safesearch]

# The two real Yandex DoH/DoT endpoints probed — one per conf "family" (issue #740's
# fix added 9 entries total; these two prove both families are covered by one UI key).
DOH_RU_HOST = "safe.dns.yandex.ru"  # the .ru DoH/DoT family
DOH_NET_HOST = "common.dot.dns.yandex.net"  # the .net DoT family
DOH_YANDEX_KEY = "dns.yandex"  # the pfblockerng_dnsbl.php safesearch_doh_list option key


class _DohFixture(NamedTuple):
    """Everything the DoH-block tests need, yielded by :func:`doh_block_vm`."""

    vm: SmokeVM
    client_vm: SmokeVM
    control_name: str  # a fabricated, never-blocked name — proves the block is SCOPED
    before_ru: h.DnsAnswer  # sentinel answer for DOH_RU_HOST BEFORE the block is active
    before_net: h.DnsAnswer  # sentinel answer for DOH_NET_HOST BEFORE the block is active


@pytest.fixture(scope="module")
def _doh_deployed(smoke_vm: SmokeVM, client_vm: SmokeVM) -> Iterator[tuple[SmokeVM, SmokeVM]]:
    """One-time deploy + DNSBL VIP (mirrors ``_ss_deployed`` in test_smoke_safesearch.py)."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    yield smoke_vm, client_vm


@pytest.fixture(scope="module")
def doh_block_vm(
    _doh_deployed: tuple[SmokeVM, SmokeVM],
    stub_dns: _StubDnsServer,
) -> Iterator[_DohFixture]:
    """Wire Unbound to the stub, enable DNSBL, capture BEFORE probes, enable the DoH block, yield.

    Egress is BLOCKED for the duration so the test is hermetic; the stub is reachable
    via the SLIRP ``192.168.89.2`` loopback path regardless (see ``use_stub_for_safesearch``).
    Recursive mode only (unlike the CNAME-redirect module, the NXDOMAIN synthesis in
    ``pfb_unbound.py`` does not depend on forwarding vs. recursion — it fires on the
    pre-resolution NEW pass before either path runs).

    Sequence:

    1. Block egress (hermeticity gate).
    2. Wire Unbound to the stub in RECURSIVE mode (:func:`~helpers.use_stub_for_safesearch`)
       — this strips the pfb python module from ``unbound.conf``.
    3. Enable DNSBL with a dummy local feed so the pfb python module is reloaded into
       ``unbound.conf``. The DoH block is NOT enabled yet.
    4. Capture the BEFORE answers for both probe hosts — unregistered names at the stub,
       so both resolve to the sentinel (STUB_DNS_A), proving the block is not yet active.
    5. Enable the DoH block for the ``dns.yandex`` key and reload — the production path
       (`$safesearch_update` -> restart) reloads `safeSearchDB` with the new NXDOMAIN rows.
    6. Flush the Unbound cache (the BEFORE probes cached the sentinel; clear it so the
       AFTER probes are evaluated fresh through the pfb python module).
    7. Yield the :class:`_DohFixture`.
    8. Teardown: disable the DoH block + reload (drops the CSV rows), restore egress,
       collect diagnostics.
    """
    vm, cvm = _doh_deployed

    # Step 1: block egress — all DNS must route through the stub.
    h.block_egress()

    # A fabricated control name — never appears in any DoH conf, so it must resolve
    # to the stub sentinel both before AND after the block is enabled (scoping proof).
    control_name = h.unique_domain("dohctrl")

    try:
        # Step 2: wire Unbound to the stub (strips pfb python module from unbound.conf).
        h.use_stub_for_safesearch(vm, False)

        # Step 3: enable DNSBL with a dummy local feed — reloads pfb python module into
        # unbound.conf so safeSearchDB and the DoH-block NXDOMAIN logic are active.
        feed = h.write_local_feed(vm, "smoke_doh_dummy.txt", f"{h.unique_domain('dohdummy')}\n")
        spec = h.DnsblCase(aliasname="smokedoh", feed_url=feed, header="smokedoh")
        h.inject(vm, spec)
        h.reload(vm, "update")

        # Step 4: capture the BEFORE answers (DoH block not active yet).
        # Both hosts are unregistered at the stub -> sentinel STUB_DNS_A.
        before_ru = h.dns_probe_client(cvm, DOH_RU_HOST, "A")
        before_net = h.dns_probe_client(cvm, DOH_NET_HOST, "A")

        # Step 5: enable the DoH block for the Yandex family and reload. The production
        # reload path detects the SafeSearch CSV change and forces the restart path
        # (see module docstring), so safeSearchDB is guaranteed fresh afterwards.
        h.set_safesearch_doh(vm, True, DOH_YANDEX_KEY)
        h.reload(vm, "update")

        # Step 6: flush the cache — the BEFORE probes cached the sentinel; clearing it
        # ensures the AFTER probes are evaluated fresh through the pfb python module.
        h.flush_unbound_cache(vm)

        yield _DohFixture(
            vm=vm,
            client_vm=cvm,
            control_name=control_name,
            before_ru=before_ru,
            before_net=before_net,
        )

    finally:
        # Drop the DoH block so it does not leak to later test modules.
        h.set_safesearch_doh(vm, False, "")
        h.reload(vm, "update")
        h.unblock_egress()
        h.collect_host_diagnostics(vm)


def test_doh_block_yandex_returns_nxdomain(doh_block_vm: _DohFixture) -> None:
    """Enabling the Yandex DoH/DoT block turns real Yandex endpoints into NXDOMAIN.

    Scenario: the #740 fix makes the shipped Yandex DoH/DoT conf entries actually block.

    Background:
        Given the malformed pre-fix entry (``yandex.dns``) could never match a real
        query, so this scenario is void unless the shipped conf now carries real
        hostnames AND the enable path wires them into ``safeSearchDB``.

    Given the BEFORE answers for both probe hosts are the stub sentinel (block-off
        baseline):
        ``safe.dns.yandex.ru`` and ``common.dot.dns.yandex.net`` resolve to STUB_DNS_A
        — confirming no block is active yet.
    When the ``dns.yandex`` DoH/DoT block key is enabled and Unbound reloads.
    Then BOTH hosts — one from each conf "family" (.ru DoH/DoT and .net DoT) — return
        NXDOMAIN with NO answer records, proving the single UI key's substring match
        reached conf lines in both families, and that the SafeSearch-only NXDOMAIN
        shape (never NOERROR/VIP/NULL, which are DNSBL-feed shapes) is what fires.
    """
    vm, cvm, _control_name, before_ru, before_net = doh_block_vm

    # Given: assert the before-state (sentinel) so green proves the block CAUSED the change.
    assert h.resolves_to(before_ru, STUB_DNS_A), (
        f"BEFORE: {DOH_RU_HOST} should resolve to sentinel {STUB_DNS_A} (no DoH block yet); got {before_ru}"
    )
    assert h.resolves_to(before_net, STUB_DNS_A), (
        f"BEFORE: {DOH_NET_HOST} should resolve to sentinel {STUB_DNS_A} (no DoH block yet); got {before_net}"
    )

    # When: the DoH block is active (enabled in the fixture). Then: both families NXDOMAIN.
    for host in (DOH_RU_HOST, DOH_NET_HOST):
        after = h.dns_probe_client(cvm, host, "A")
        assert after.rcode == "NXDOMAIN", (
            f"{host}: expected NXDOMAIN (SafeSearch DoH-block shape) after enabling "
            f"the {DOH_YANDEX_KEY!r} key; got rcode={after.rcode!r} records={after.records}"
        )
        assert not after.records, f"{host}: NXDOMAIN answer should carry NO records; got {after.records}"


def test_doh_block_scoped_not_global(doh_block_vm: _DohFixture) -> None:
    """The DoH block targets only the selected endpoints — it is not a resolver-wide NXDOMAIN.

    Scenario: the DoH/DoT block does not blanket-NXDOMAIN every query.

    Given a fabricated control name that appears in no DoH conf entry.
    When the ``dns.yandex`` DoH/DoT block is active (same fixture state as the
        NXDOMAIN test above).
    Then the control name still resolves NOERROR to the stub sentinel — proving the
        block is scoped to the DoH/DoT endpoint list, not a global NXDOMAIN override.
    """
    vm, cvm, control_name, _before_ru, _before_net = doh_block_vm

    ans = h.dns_probe_client(cvm, control_name, "A")
    assert ans.rcode == "NOERROR" and h.resolves_to(ans, STUB_DNS_A), (
        f"{control_name}: expected NOERROR/{STUB_DNS_A} (unaffected by the DoH block, "
        f"which must be scoped to the selected endpoints only); got rcode={ans.rcode!r} "
        f"records={ans.records}"
    )
