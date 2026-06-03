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
from .conftest import SmokeVM, _MockFeedServer, _StubDnsServer

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
    override — so the probe never needs upstream egress. (``configure_upstream``
    is intentionally NOT called: the baked image already forwards on its own;
    injecting a second ``forward-zone "."`` broke Unbound.) deploy() needs no
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
    # DNSBL force-disables itself without a VIP (pfb_validate_vips); pfBlockerNG
    # never auto-creates one and the image does NOT bake one, so inject the lo0
    # sinkhole VIP once for the matrix. dns_probe queries on-box (drill
    # @127.0.0.1) — no localhost exemption — so no WAN/ACL plumbing is needed.
    h.ensure_dnsbl_vip(smoke_vm)
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
    """
    pytest.skip(
        "pfB_DNSBLIP_v4/v6 populated async by filter_configure; needs poll-based assertion — deferred (see docstring)"
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
