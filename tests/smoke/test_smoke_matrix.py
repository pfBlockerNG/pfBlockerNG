"""ADR-04 Phase 5 — the first landed smoke matrix (a THIN vertical slice).

This is NOT the broad knob space (SafeSearch/regex/HSTS/TLD/GeoIP/full-AAAA are
out of scope, ADR §2). It is the minimum that proves the Phase-4 harness asserts
REAL pfBlockerNG behaviour end-to-end on BOTH paths — the IP path (``pfctl``
alias table + rule) and the DNS path (``dig`` rcode/record shape) — hermetically
(mock feeds + baked Unbound ``local-data`` only) and guarded against false-green.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Every expected answer is pinned to the REAL matcher semantics in
``src/usr/local/pkg/pfblockerng/pfb_unbound.py`` + ``pfblockerng.inc`` (verified
against source, not guessed):

* DNSBL **python** mode (``dnsbl_python`` + ``pfb_py_block``): the whole feed is
  written to ``pfb_py_data.txt`` as EXACT entries (``inc:8966-8970``; zone files
  are only produced by the out-of-scope TLD feature). ``evaluate_domain``
  (``pfb_unbound.py:1707``) looks the name up in ``dataDB`` EXACTLY — a matched
  name yields NXDOMAIN; a SUBDOMAIN of it is NOT in ``dataDB`` and is NOT blocked.
* DNSBL **unbound** mode (``dnsbl_unbound``): each domain becomes an Unbound
  ``local-zone: "<d>" redirect`` (``inc:3069``/feed path ``inc:8670``), which is
  a WILDCARD — it answers for ``<d>`` AND every subdomain. ``logging='disabled'``
  sinkholes to ``0.0.0.0``/``::0`` (NULL); ``logging='enabled'`` sinkholes to the
  DNSBL VIP (``pfb_dnsvip4``).
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

import pytest

from . import helpers as h
from .conftest import SmokeVM, _MockFeedServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> SmokeVM:
    """Deploy the branch .pkg once for the whole matrix module."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    return smoke_vm


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
    feed_url = mock_feeds.register("smoke_ip_matrix.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="smokeipmtx", feed_url=feed_url, header="smokeipmtx")
    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, fed_ip), f"{fed_ip} not in {spec.alias}: {members}"
        assert not h.member_present(members, non_fed), f"{non_fed} unexpectedly in {spec.alias}: {members}"
        assert h.rule_references(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


# --------------------------------------------------------------------------- #
# 2) DNSBL path — the response-shape matrix (pinned to pfb_unbound.py)
# --------------------------------------------------------------------------- #


def test_dnsbl_exact_nxdomain(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """EXACT + NXDOMAIN: ``<d>`` is NXDOMAIN; a subdomain ``x.<d>`` is NOT blocked.

    Python mode writes the feed as EXACT ``dataDB`` entries, so ``evaluate_domain``
    matches ``blocked-exact.pfb.test`` (NXDOMAIN) but NOT ``x.blocked-exact...``.
    The subdomain is given a control ``local-data`` so its non-block is provable
    hermetically: a true pass to ``198.51.100.40``, not any block shape.
    """
    domain = "blocked-exact.pfb.test"
    sub = f"x.{domain}"
    sub_ip = "198.51.100.40"
    feed_url = mock_feeds.register("smoke_dnsbl_exact.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokeexact",
        feed_url=feed_url,
        header="smokeexact",
        mode=h.DnsblMode.NXDOMAIN,
        control_local_data={sub: {"A": sub_ip}},
    )
    with h.CaseContext(deployed_vm, spec):
        blocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_nxdomain(blocked), f"{domain} expected NXDOMAIN, got {blocked}"
        # EXACT does NOT block the subdomain: it resolves to its control answer.
        passed = h.dns_probe(deployed_vm, sub, "A")
        assert h.resolves_to(passed, sub_ip), f"{sub} should resolve to {sub_ip} (exact != wildcard), got {passed}"
        assert not h.is_nxdomain(passed), f"{sub} wrongly blocked as NXDOMAIN: {passed}"


def test_dnsbl_exact_null(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """NULL mode: ``<d>`` returns the null sinkhole (A ``0.0.0.0`` / AAAA ``::0``).

    Unbound mode + per-list ``logging='disabled'`` -> the domain's redirect zone
    sinkholes to ``0.0.0.0`` (and ``::0`` for AAAA, inc:3000/8668).
    """
    domain = "blocked-null.pfb.test"
    feed_url = mock_feeds.register("smoke_dnsbl_null.txt", f"{domain}\n")
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


def test_dnsbl_wildcard_zone(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """WILDCARD (Unbound redirect zone): blocks ``<d>`` AND a deep subdomain.

    Unbound mode writes ``local-zone: "<d>" redirect`` — a wildcard that answers
    for the zone apex itself AND any depth of subdomain. Probe both the apex and
    ``a.b.<d>`` (VIP mode here, so each returns the DNSBL VIP).
    """
    domain = "blocked-wild.pfb.test"
    deep = f"a.b.{domain}"
    feed_url = mock_feeds.register("smoke_dnsbl_wild.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokewild",
        feed_url=feed_url,
        header="smokewild",
        mode=h.DnsblMode.VIP,
        wildcard=True,
    )
    with h.CaseContext(deployed_vm, spec):
        apex = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(apex), f"{domain} (apex) expected VIP {h.DEFAULT_DNSBL_VIP4}, got {apex}"
        sub = h.dns_probe(deployed_vm, deep, "A")
        assert h.is_vip(sub), f"{deep} (deep subdomain) expected VIP {h.DEFAULT_DNSBL_VIP4}, got {sub}"


def test_dnsbl_whitelist_passthrough(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """WHITELIST: a domain on the whitelist AND in the block feed RESOLVES.

    ``suppression`` short-circuits before any block shape, so the name resolves
    via its control ``local-data`` (a true pass) — NOT NXDOMAIN/null/VIP.
    """
    domain = "allowed.pfb.test"
    pass_ip = "198.51.100.77"
    feed_url = mock_feeds.register("smoke_dnsbl_white.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokewhite",
        feed_url=feed_url,
        header="smokewhite",
        mode=h.DnsblMode.NXDOMAIN,
        whitelist=[domain],
        control_local_data={domain: {"A": pass_ip}},
    )
    with h.CaseContext(deployed_vm, spec):
        answer = h.dns_probe(deployed_vm, domain, "A")
        assert h.resolves_to(answer, pass_ip), f"whitelisted {domain} should resolve to {pass_ip}, got {answer}"
        assert not h.is_nxdomain(answer), f"whitelisted {domain} wrongly NXDOMAIN: {answer}"
        assert not h.is_null_ip(answer), f"whitelisted {domain} wrongly null-IP: {answer}"


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
    """
    v4 = "203.0.113.7"  # RFC 5737 documentation range
    v6 = "2001:db8:5::7"  # RFC 3849 documentation range
    feed_url = mock_feeds.register("smoke_dnsblip_dual.txt", f"{v4}\n{v6}\n")
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
# 4) FALSE-GREEN GUARD — a deliberately-wrong expectation MUST go red
# --------------------------------------------------------------------------- #


@pytest.mark.xfail(strict=True, reason="deliberately-wrong expectation: a real NXDOMAIN block is NOT a pass")
def test_false_green_guard_vm(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """STRICT-xfail guard: assert a real block RESOLVES — it must NOT.

    Blocks ``guard.pfb.test`` (NXDOMAIN) then asserts it resolves to a pass IP.
    That assertion is FALSE on a working harness, so the test fails -> the
    ``strict=True`` xfail turns the failure into the expected outcome (green
    overall). If a broken/lenient harness silently let the block "pass", this
    test would PASS unexpectedly and ``strict=True`` would flip the suite RED —
    catching a false-green at the VM level (on top of the pure-Python guard in
    test_smoke_helpers.py::test_false_green_guard).
    """
    domain = "guard.pfb.test"
    feed_url = mock_feeds.register("smoke_dnsbl_guard.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokeguard",
        feed_url=feed_url,
        header="smokeguard",
        mode=h.DnsblMode.NXDOMAIN,
    )
    with h.CaseContext(deployed_vm, spec):
        answer = h.dns_probe(deployed_vm, domain, "A")
        # WRONG on purpose: a NXDOMAIN block does not resolve to a pass IP.
        assert h.resolves_to(answer, "198.51.100.250"), "expected (wrongly) to resolve — must fail"
