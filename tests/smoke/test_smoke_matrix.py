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
  - ``logging='nxdomain_log'`` → ``logging_type='3'`` → ``operate()`` returns a
    bare ``RCODE_NXDOMAIN`` (no records). (**NXDOMAIN** shape, issue #31.)

  A matched subdomain is NOT in ``dataDB`` and is NOT blocked (exact match only).
  Before issue #31 NXDOMAIN was reachable only via SafeSearch; it is now also a
  user-selectable DNSBL block response (the ``nxdomain``/``nxdomain_log`` modes).

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
import time
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
    no-control name resolves via the runner-side mock (``use_system_dns_upstream``:
    pfSense forwards to the SLIRP host alias 10.0.2.2, which libslirp NATs to the mock) — a known
    answer, AND recorded, so "was it blocked?" is read off the upstream, not inferred
    from a SERVFAIL. deploy() needs no egress for dependencies either — the pre-baked
    image ships pfBlockerNG's RUN_DEPENDS, so ``pkg add`` resolves them from the local
    pkg db offline. unblock on teardown as a safety net.
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
    # Point pfSense at the controlled mock via its System-DNS path BEFORE any per-test
    # unbound-config snapshot (test_dnsbl_unbound_config_immutable), so the forwarding
    # config is part of the baseline and the DNSBL reload still adds only python.
    h.use_system_dns_upstream(smoke_vm)
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


def test_dnsbl_exact_nxdomain(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Python-mode NXDOMAIN block (issue #31): a bare NXDOMAIN, no records.

    ``logging='nxdomain_log'`` → ``logging_type='3'`` → ``operate()`` returns
    ``RCODE_NXDOMAIN`` with no DNSMessage (neither the VIP nor the 0.0.0.0 null
    shape). The rcode is name-level, so BOTH the A and AAAA queries answer
    NXDOMAIN. A unique non-HSTS-preload ``.com`` is used so the result is the
    NXDOMAIN block path itself, not an Unbound built-in ``local-zone`` shadowing
    an RFC-6761 TLD (which would also NXDOMAIN, ahead of DNSBL). Contrast the
    VIP/null cases above: same feed match, different per-list ``logging`` →
    different response shape, proving '3' is a distinct, live branch.
    """
    domain = h.unique_domain("nxdomain")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_nxdomain.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokenxd",
        feed_url=feed_url,
        header="smokenxd",
        mode=h.DnsblMode.NXDOMAIN,
    )
    with h.CaseContext(deployed_vm, spec):
        a = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_nxdomain(a), f"{domain} A expected NXDOMAIN (no records), got {a}"
        assert not h.is_vip(a) and not h.is_null_ip(a), f"{domain} must be a bare NXDOMAIN, not a VIP/null record: {a}"
        aaaa = h.dns_probe(deployed_vm, domain, "AAAA")
        assert h.is_nxdomain(aaaa), f"{domain} AAAA expected NXDOMAIN (no records), got {aaaa}"


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


# IDN homoglyph protection — Confusable mode (ADR-08). The block comes from the
# matcher's TR39 mixed-script analyzer (pfb_unbound.py classify_idn), NOT a feed
# entry — the feed below is one innocuous filler so the DNSBL list/alias is real and
# python mode is active; ``idn_mode='confusable'`` is what arms the analyzer.


def test_dnsbl_idn_confusable_blocks_homoglyph_resolves_legit(
    deployed_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """Confusable mode blocks a cross-script homoglyph (VIP) but resolves a legit IDN.

    Scenario: ``pfb_idn='confusable'`` + ``block_malicious`` ON (default). The
    matcher decodes each ``xn--`` label, runs the TR39 analyzer per-label, and:
      * ``xn--pple-43d`` (аpple — Cyrillic U+0430 + Latin) is a confusable Latin+
        Cyrillic mix → MALICIOUS → blocked as feed ``Homoglyph`` (log_type '1',
        not HSTS) → NOERROR + the DNSBL VIP.
      * ``xn--mnchen-3ya`` (münchen — single-script Latin) is legit → NO IDN action,
        so it resolves to its control answer (the before-state: green proves the
        analyzer is the cause of the block, not an always-block path).
    Probed on-box (``drill @127.0.0.1``); python-mode has no localhost exemption.
    """
    homoglyph = "xn--pple-43d.com"  # аpple — Latin+Cyrillic confusable → MALICIOUS
    legit = "xn--mnchen-3ya.com"  # münchen — single-script Latin → legit
    legit_ip = "198.51.100.60"
    feed_url = h.write_local_feed(deployed_vm, "smoke_idn_confusable.txt", f"{h.unique_domain('idnfiller')}\n")
    spec = h.DnsblCase(
        aliasname="smokeidn",
        feed_url=feed_url,
        header="smokeidn",
        mode=h.DnsblMode.VIP,
        idn_mode="confusable",
        idn_block_malicious=True,
        idn_escalate_suspicious=False,
        control_local_data={legit: {"A": legit_ip}},
    )
    with h.CaseContext(deployed_vm, spec):
        # Before-state: the legit single-script IDN is NOT blocked — it resolves.
        legit_ans = h.dns_probe(deployed_vm, legit, "A")
        assert h.resolves_to(legit_ans, legit_ip), f"legit IDN {legit} should resolve to {legit_ip}, got {legit_ans}"
        assert not h.is_vip(legit_ans), f"legit IDN {legit} must NOT be homoglyph-blocked (FALSE POSITIVE): {legit_ans}"
        # The confusable homograph blocks with the DNSBL VIP.
        blocked = h.dns_probe(deployed_vm, homoglyph, "A")
        assert h.is_vip(blocked), (
            f"homoglyph {homoglyph} (Latin+Cyrillic) expected VIP {h.DEFAULT_DNSBL_VIP4}, got {blocked}"
        )


def test_dnsbl_idn_confusable_block_malicious_off_alerts_only(
    deployed_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """The ``block_malicious`` sub-toggle is a real branch: OFF → the SAME homograph
    only alerts (resolves), not blocks.

    Same confusable ``xn--pple-43d`` (аpple) as the positive case, but with
    ``block_malicious`` OFF: ``idn_confusable_action`` maps MALICIOUS → ALERT, so
    ``is_found`` stays False and the name resolves to its control answer. Paired with
    the block-on case above (same input, toggle flipped) this proves it is the toggle,
    not an always-resolve path.
    """
    homoglyph = "xn--pple-43d.com"  # аpple — MALICIOUS, but block_malicious is OFF
    homoglyph_ip = "198.51.100.61"
    feed_url = h.write_local_feed(deployed_vm, "smoke_idn_alert.txt", f"{h.unique_domain('idnfiller')}\n")
    spec = h.DnsblCase(
        aliasname="smokeidnalert",
        feed_url=feed_url,
        header="smokeidnalert",
        mode=h.DnsblMode.VIP,
        idn_mode="confusable",
        idn_block_malicious=False,  # malicious → ALERT only (no block)
        control_local_data={homoglyph: {"A": homoglyph_ip}},
    )
    with h.CaseContext(deployed_vm, spec):
        ans = h.dns_probe(deployed_vm, homoglyph, "A")
        assert h.resolves_to(ans, homoglyph_ip), (
            f"block_malicious OFF: {homoglyph} should resolve to {homoglyph_ip}, got {ans}"
        )
        assert not h.is_vip(ans), f"block_malicious OFF must NOT block the homograph (alert only): {ans}"


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


# ADR-10: several bounded wait-for-apply round-trips per case (each swap blocks PHP
# until the watcher confirms the applied generation -- seconds, not the old async poll)
# plus per-case setup exceed the smoke harness's 30s per-test cap; override it.
@pytest.mark.timeout(120)
def test_dnsbl_resolve_block_unlock_relock_lifecycle(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """#51 FULL lifecycle, asserting the ACTUAL resolution at every transition:

      (a) BEFORE any list  -> the domain RESOLVES (forwarded to the stub sentinel);
      (b) added to a feed  -> BLOCKED (VIP), no longer resolves;
      (c) temporary Unlock -> RESOLVES again (forwarded to the stub sentinel);
      (d) re-Lock          -> BLOCKED again (VIP).

    Proving the domain resolves in (a) and again in (c) rules out a false-green: the
    VIP in (b)/(d) genuinely comes from the feed block, and the pass in (c) genuinely
    comes from the Unlock. The Unlock/Lock drives the real python-mode
    ``pfblockerng_alerts.php`` ``dnsbl_remove`` sequence (toggle the ``pfb_unlock`` store
    -> regenerate ``config.user_unlock`` -> reload Unbound).

    ZERO-DOWNTIME (ADR-10, #51): the reload takes the no-restart DATA FAST PATH — PHP
    patches the manifest, flips the generation sentinel, and the in-module watcher rebuilds
    + atomically swaps the snapshot (a Lock additionally targeted-flushes that one name from
    the C-cache; an Unlock needs none since #43 stopped C-caching blocks). Unbound is NOT
    restarted, so its **pid is captured before and asserted UNCHANGED after** the whole
    Unlock/Lock sequence — proving the #51 flips apply with no restart. (Before the #51 fix
    step (c) was a NO-OP — it wrote files the manifest build no longer reads — so the domain
    stayed VIP-blocked; here it must resolve again.) The unlock/lock transitions use
    ``dns_probe_until`` (the async-swap analog of the authoritative probe): the swapped
    decision lands within a bounded window without a restart.

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
        # Listing the name is the feed/swap allow->block direction: the module already
        # mounted (a prior case), so first-enable applies via the no-restart swap, which
        # by design does NOT flush the C-cache for a feed/cron delta (TTL-bounded,
        # RESULTS/05 SS3). Step (a) above pre-resolved the name (stub TTL 60s), so that
        # cached real answer would serve past the swap; clear that one name (mirroring a
        # #51 Lock's targeted delta-flush) then poll until the swapped VIP block lands.
        h.flush_unbound_name(deployed_vm, domain)
        blocked = h.dns_probe_until(deployed_vm, domain, h.is_vip)
        assert not h.resolves_to(blocked, STUB_DNS_A), f"{domain} still resolving after block: {blocked}"

        # NO-RESTART invariant: capture Unbound's pid before the #51 Unlock/Lock flips.
        # Each flip takes the ADR-10 zero-downtime fast path, so the pid must NOT change.
        pid_before = h.unbound_pid(deployed_vm)

        # (c) Temporary Unlock -> resolves again (forwarded to the stub sentinel).
        #     A VIP here would be the #51 no-op (unlock never reaching the build).
        #     The swap is async, so poll until the decision flips (bounded; raises on
        #     timeout) — the block->allow direction is immediate (blocks not cached, #43).
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "unlock")
        unlocked = h.dns_probe_until(deployed_vm, domain, lambda a: h.resolves_to(a, STUB_DNS_A))
        assert not h.is_vip(unlocked), f"unlocked {domain} still VIP-blocked (the #51 no-op): {unlocked}"

        # (d) Re-Lock -> the temporary allow is removed: blocked again (VIP). allow->block
        #     here clears the prior resolved answer via the production targeted C-cache
        #     delta-flush inside pfb_reload_unbound, so the VIP block is observable.
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "lock")
        relocked = h.dns_probe_until(deployed_vm, domain, h.is_vip)
        assert not h.resolves_to(relocked, STUB_DNS_A), f"re-locked {domain} still resolving: {relocked}"

        # The whole Unlock/Lock sequence applied with NO restart: pid unchanged.
        pid_after = h.unbound_pid(deployed_vm)
        assert pid_after == pid_before, (
            f"#51 Unlock/Lock must apply via the no-restart zero-downtime swap, but Unbound "
            f"restarted: pid {pid_before} -> {pid_after}"
        )


@pytest.mark.timeout(120)  # ADR-10: multiple wait-for-apply round-trips > the 30s smoke cap.
def test_dnsbl_temp_unlock_cleared_by_force_update(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """#51: a temporary Unlock is re-locked by a Cron/Force update — even with NO feed
    change (parity with main).

    A pending temporary-unlock store forces the reload path regardless of feed changes
    (``inc:8806`` ``|| file_exists($pfb['dnsbl_unlock'])``); that path drops the store
    and clears the manifest's ``config.user_unlock`` (``inc:3451`` ->
    ``pfb_unbound_python_sources_unlock``), so the re-read whiteDB no longer allows the
    domain and it is re-blocked. On ``main`` the equivalent re-lock is the ungated
    whitelist regeneration; before this fix devel only cleared ``user_unlock`` on a
    feed-change rebuild, so a no-change Force left the unlock live (the regression this
    run caught). A plain ``update`` over the UNCHANGED feed is therefore enough.

    ZERO-DOWNTIME (ADR-10): both the #51 Unlock AND the config-clean Force ``update`` are
    pure DNSBL-DATA updates in python mode, so each takes the no-restart fast path (flip
    the sentinel -> the watcher rebuilds + atomically swaps). Unbound's **pid is captured
    before and asserted UNCHANGED after** both operations — proving the re-lock applies with
    no restart. The Force update is driven with ``data_path=True`` so the helper waits on
    the swap-applied log line (not restart readiness), and the re-lock decision is observed
    via ``dns_probe_until`` (the Force update's allow->block re-lock clears the prior
    resolved answer because the pending-unlock-store reload path re-applies the feed block).
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

        # NO-RESTART invariant: capture pid before the Unlock + Force-update re-lock.
        pid_before = h.unbound_pid(deployed_vm)

        # Unlock -> resolves again (forwarded to the stub sentinel). Async swap: poll until
        # the block->allow flip lands (immediate direction since blocks aren't C-cached, #43).
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "unlock")
        unlocked = h.dns_probe_until(deployed_vm, domain, lambda a: h.resolves_to(a, STUB_DNS_A))
        assert not h.is_vip(unlocked), f"unlocked {domain} still VIP-blocked: {unlocked}"

        # A Cron/Force update over the UNCHANGED feed re-locks it: the pending unlock store
        # forces the reload + clears the manifest's user_unlock. It is a config-clean
        # DNSBL-data update -> the no-restart fast path (data_path=True waits on the swap).
        h.reload(deployed_vm, "update", data_path=True)
        # The Force-update re-lock is the feed/cron allow->block direction: PHP passes no
        # targeted C-cache flush (TTL-bounded by design, RESULTS/05 SS3), so the domain's
        # prior resolved answer (cached by the unlock probe above) would serve until TTL.
        # Clear it, then observe the swapped re-block (mirrors test_dnsbl_feed_update).
        h.flush_unbound_name(deployed_vm, domain)
        relocked = h.dns_probe_until(deployed_vm, domain, h.is_vip)
        assert not h.resolves_to(relocked, STUB_DNS_A), f"re-locked {domain} still resolving: {relocked}"

        # Both the Unlock and the Force-update re-lock applied with NO restart: pid unchanged.
        pid_after = h.unbound_pid(deployed_vm)
        assert pid_after == pid_before, (
            f"#51 Unlock + Cron/Force re-lock must apply via the no-restart swap, but Unbound "
            f"restarted: pid {pid_before} -> {pid_after}"
        )


# --------------------------------------------------------------------------- #
# 2b) ADR-10 zero-downtime DNSBL — no-restart data path, config-restart fork,
#     fail-closed. Automates the §7 maintainer smoke checklist. The hard proof is
#     Unbound's pid: UNCHANGED across a DATA update (the swap reuses the running
#     process), CHANGED across a CONFIG update (the restart fork). Each case asserts
#     the BEFORE-state and the pid invariant (CLAUDE.md test-coverage rules).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(120)  # ADR-10: setup restart + a wait-for-apply swap > the 30s smoke cap.
def test_dnsbl_feed_update_no_restart(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A feed-content DNSBL update applies WITHOUT restarting Unbound (ADR-10 zero-downtime).

    Branch-coverage partner of ``test_dnsbl_config_change_restarts`` (data fork vs config
    fork). Full before/after with the pid invariant:

    * BEFORE: a name NOT in the feed RESOLVES (forwarded to the stub sentinel) — the
      list is live but does not yet contain it. (Asserted, so the later block is proven
      to come from the feed edit, not a pre-existing state.)
    * APPLY: add the name to the SAME local feed file and force a full ``update``. Feeds
      are cached and re-fetched only on a force (the ``reset``/force-update precedent —
      see ``test_dnsbl_temp_unlock_cleared_by_force_update``). A config-clean feed/cron
      update in python mode routes through the no-restart data fast path
      (``pfb_update_unbound`` -> ``pfb_reload_unbound($mode, TRUE, $pfbpython, !$pfbpython)``,
      inc:4151), so PHP flips the sentinel and the watcher swaps the snapshot.
    * AFTER: the name is BLOCKED (VIP), Unbound's pid is UNCHANGED (no restart), and the
      pfBlockerNG log gained a ``zero-downtime swap`` fast-path line.

    NO-FALLBACK NOTE: a config-clean feed-content re-fetch IS reliably the no-restart path
    (the brief's primary route), so this exercises a genuine feed update — not the #51 lock
    substitute. The feed/cron allow->block direction passes no targeted C-cache flush (it is
    TTL-bounded by design, RESULTS/05 SS3), so the name's prior resolved answer is explicitly
    flushed (``flush_unbound_name`` — the same targeted clear a #51 Lock does on the box)
    before observing the swapped block within the test window; ``dns_probe_until`` then polls
    until the VIP decision lands (the swap is async — "briefly stale by design").
    """
    domain = h.unique_domain("feedupd")
    other = h.unique_domain("feedupd-filler")
    # Start with a feed that does NOT contain the target (only an unrelated filler line),
    # so the list is live but the target is not yet blocked.
    feed_name = "smoke_dnsbl_feedupd.txt"
    feed_url = h.write_local_feed(deployed_vm, feed_name, f"{other}\n")
    spec = h.DnsblCase(aliasname="smokefeedupd", feed_url=feed_url, header="smokefeedupd", mode=h.DnsblMode.VIP)
    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()  # the allowed (before-state) probe must reach the controlled stub

        # BEFORE: the target is not on the feed yet -> it RESOLVES via the stub sentinel.
        before = h.dns_probe(deployed_vm, domain, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{domain} should resolve via stub BEFORE the feed edit, got {before}"
        assert not h.is_vip(before), f"{domain} unexpectedly VIP-blocked before being listed: {before}"

        # NO-RESTART invariant + fast-path-log proof: capture pid and the swap-log baseline.
        pid_before = h.unbound_pid(deployed_vm)
        swap_before = h.count_log_marker(deployed_vm, h.PFB_LOG, h.SWAP_LOG_MARKER)

        # APPLY: add the target to the feed and force a full update (re-fetches the edited
        # local feed). data_path=True -> the no-restart fast path; the helper waits on the
        # swap-applied log line and RAISES if the restart fallback was taken instead.
        h.write_local_feed(deployed_vm, feed_name, f"{other}\n{domain}\n")
        # Invalidate the per-feed cache so the full update RE-READS the edited local feed
        # (pfBlockerNG reuses the cached '.txt' otherwise -> the edit never reaches the
        # manifest and no swap fires). This is the config-clean data update the swap targets.
        h.force_dnsbl_refetch(deployed_vm, spec.header)
        h.reload(deployed_vm, "update", data_path=True)

        # Clear the target's TTL-bounded prior resolved answer (feed/cron allow->block is
        # not targeted-flushed by PHP — RESULTS/05 SS3), then observe the swapped block.
        h.flush_unbound_name(deployed_vm, domain)
        blocked = h.dns_probe_until(deployed_vm, domain, h.is_vip)
        assert not h.resolves_to(blocked, STUB_DNS_A), f"{domain} still resolving after the feed block: {blocked}"

        # AFTER: pid unchanged (no restart) AND a fresh fast-path swap line was logged.
        pid_after = h.unbound_pid(deployed_vm)
        assert pid_after == pid_before, (
            f"a feed DNSBL update must take the no-restart zero-downtime swap, but Unbound "
            f"restarted: pid {pid_before} -> {pid_after}"
        )
        swap_after = h.count_log_marker(deployed_vm, h.PFB_LOG, h.SWAP_LOG_MARKER)
        assert swap_after > swap_before, (
            f"no new '{h.SWAP_LOG_MARKER}' fast-path line logged for the feed update "
            f"(before={swap_before}, after={swap_after}) — the data fast path did not run"
        )


@pytest.mark.timeout(120)  # ADR-10: two full Unbound restarts (disable + enable) > the 30s cap.
def test_dnsbl_config_change_restarts(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A CONFIG change DOES restart Unbound — the other fork of the data/config split.

    Branch-coverage partner of ``test_dnsbl_feed_update_no_restart``: ADR-10 keeps the
    restart for a config change (unbound.conf/ini/mode regenerated), only DNSBL DATA is
    zero-downtime. Disabling then re-enabling the DNSBL component toggles
    ``pfb_dnsbl``/the python integration, which regenerates Unbound's config and forces a
    restart (``$pfbpython`` TRUE -> ``$datapath`` FALSE -> ``pfb_stop_start_unbound``).
    The proof is the pid CHANGING.

    Before/after with the pid invariant:

    * BEFORE: DNSBL is live with the name blocked (VIP) — capture Unbound's pid.
    * CONFIG CHANGE: disable DNSBL (``pfb_dnsbl`` off) + ``updatednsbl`` (regenerates
      unbound.conf without the python module -> restart), then re-enable + ``updatednsbl``
      (regenerates WITH it -> restart). Both are config changes, so each restarts.
    * AFTER: Unbound's pid has CHANGED at least once (a genuine restart happened), proving
      the config fork does NOT take the no-restart data path. The name blocks again (the
      list is restored).

    Teardown (``CaseContext.__exit__`` -> ``reset``) restores ``pfb_dnsbl`` on via the
    normal config, so the rest of the matrix runs against its baseline.
    """
    domain = h.unique_domain("cfgrestart")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_cfgrestart.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokecfgrestart", feed_url=feed_url, header="smokecfgrestart", mode=h.DnsblMode.VIP)
    with h.CaseContext(deployed_vm, spec):
        # BEFORE: the name is blocked (VIP) and DNSBL is live. Capture the running pid.
        blocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(blocked), f"{domain} expected VIP block before the config change, got {blocked}"
        pid_before = h.unbound_pid(deployed_vm)

        # CONFIG CHANGE: disable DNSBL -> regenerates unbound.conf (drops the python
        # module) -> restart. These reloads are NOT data_path: a config change keeps the
        # restart, so wait on restart readiness (the default reload() path).
        h.set_dnsbl_enabled(deployed_vm, False)
        h.reload(deployed_vm, "updatednsbl")
        pid_mid = h.unbound_pid(deployed_vm)
        assert pid_mid != pid_before, (
            f"disabling DNSBL is a config change and MUST restart Unbound, but pid was "
            f"unchanged ({pid_before}) — the config fork wrongly took the no-restart path"
        )

        # Re-enable DNSBL -> regenerates unbound.conf WITH the python module -> restart.
        h.set_dnsbl_enabled(deployed_vm, True)
        h.reload(deployed_vm, "updatednsbl")
        pid_after = h.unbound_pid(deployed_vm)
        assert pid_after != pid_mid, (
            f"re-enabling DNSBL is a config change and MUST restart Unbound, but pid was unchanged ({pid_mid})"
        )
        # The list is restored: the name blocks again after the config round-trip.
        reblocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(reblocked), f"{domain} expected VIP block after re-enabling DNSBL, got {reblocked}"


@pytest.mark.timeout(120)  # ADR-10: setup + a watcher build-fail observation window > the 30s cap.
def test_dnsbl_fail_closed_broken_manifest(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A broken manifest does NOT swap — the last-good lists keep serving (ADR-10 fail-closed).

    The ADR-10 safety contract: if a rebuild fails (bad/partial manifest), the watcher keeps
    the OLD snapshot live and never swaps to an empty/partial set ("never fail open to no
    blocking"). Before/after with the pid invariant:

    * BEFORE: the name is BLOCKED (VIP) — the last-good snapshot. Capture Unbound's pid and
      the py_error.log baseline.
    * CORRUPT + TRIGGER: overwrite ``/var/unbound/pfb_py_sources.json`` with invalid JSON
      (preserving unbound:unbound ownership so the chrooted module can still OPEN it — the
      failure must be a PARSE failure, not a permission one), then bump the generation
      sentinel (``/var/unbound/pfb_py_reload`` -> current+1) to trigger the watcher. The
      build fails (``dnsbl_build_from_manifest`` logs "Failed to load DNSBL manifest" and
      returns None -> ``rebuild_and_swap`` keeps the old snapshot).
    * AFTER: the name STILL BLOCKS (old snapshot kept), Unbound is still UP (``unbound-control
      status`` ok) with its pid UNCHANGED (no restart, no crash), and py_error.log gained a
      ``Failed to load DNSBL manifest`` (or ``keeping current snapshot``) line.

    Teardown restores a clean state: a real ``reset`` (clear* + forced ``update``) rewrites a
    valid manifest, so the next case starts from the baseline.
    """
    domain = h.unique_domain("failclosed")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_failclosed.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokefailclosed", feed_url=feed_url, header="smokefailclosed", mode=h.DnsblMode.VIP)
    with h.CaseContext(deployed_vm, spec):
        # BEFORE: the name is blocked (VIP) by the last-good snapshot.
        blocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(blocked), f"{domain} expected VIP block before corrupting the manifest, got {blocked}"
        pid_before = h.unbound_pid(deployed_vm)
        pyerr_before = h.count_log_marker(deployed_vm, h.PY_ERROR_LOG, "Failed to load DNSBL manifest")

        # CORRUPT the manifest + bump the sentinel via PHP (pfSsh.php) — NOT a raw SSH shell
        # string: pfSense's root login shell is tcsh, which lacks POSIX ``$(...)``/``case``/
        # ``$((…))``; PHP gives deterministic file ops and ownership. Write invalid JSON
        # (a PARSE error, not a permission one), keep unbound:unbound ownership so the
        # chrooted module can still OPEN it, then write generation current+1 into the
        # sentinel (the watcher swaps only on a STRICT advance) to trigger the failing build.
        snippet = (
            "$m = '/var/unbound/pfb_py_sources.json';\n"
            "file_put_contents($m, '{ this is not valid json');\n"
            "@chown($m, 'unbound'); @chgrp($m, 'unbound');\n"
            "$s = '/var/unbound/pfb_py_reload';\n"
            "$raw = @file_get_contents($s);\n"
            '$cur = ($raw !== FALSE) ? (int) strtok($raw, "\\n") : 0;\n'
            'file_put_contents($s, ($cur + 1) . "\\n");\n'
            "@chown($s, 'unbound'); @chgrp($s, 'unbound');\n"
            "echo 'OK';"
        )
        res = h.php_eval(deployed_vm, snippet, timeout=60)
        assert "OK" in res.stdout, f"failed to corrupt manifest / bump sentinel: rc={res.returncode} {res.stderr!r}"

        # Give the watcher a bounded window to wake, fail the build, and log it — then assert
        # the fail-closed outcome. py_error.log gaining the manifest-load failure line proves
        # the build was attempted AND failed (not silently skipped).
        def _pyerr_logged(_a: h.DnsAnswer) -> bool:
            now = h.count_log_marker(deployed_vm, h.PY_ERROR_LOG, "Failed to load DNSBL manifest")
            return now > pyerr_before

        # dns_probe_until polls the (still-blocked) name; the predicate also confirms the
        # py_error line appeared — both must hold within the window (raises otherwise).
        still = h.dns_probe_until(
            deployed_vm,
            domain,
            lambda a: h.is_vip(a) and _pyerr_logged(a),
            timeout=45.0,
        )
        assert h.is_vip(still), f"fail-closed: {domain} must STILL block on the old snapshot, got {still}"

        # Unbound is still UP and was NOT restarted by the failed build.
        h.wait_unbound_ready(deployed_vm)
        pid_after = h.unbound_pid(deployed_vm)
        assert pid_after == pid_before, (
            f"a failed (fail-closed) build must keep the running resolver: Unbound pid changed "
            f"{pid_before} -> {pid_after}"
        )
        pyerr_after = h.count_log_marker(deployed_vm, h.PY_ERROR_LOG, "Failed to load DNSBL manifest")
        assert pyerr_after > pyerr_before, (
            f"expected a 'Failed to load DNSBL manifest' line in {h.PY_ERROR_LOG} "
            f"(before={pyerr_before}, after={pyerr_after}) — the broken-manifest build was not logged"
        )


# --------------------------------------------------------------------------- #
# 3) DNSBL-IP dual-stack — two distinct pf tables, partitioned by family
# --------------------------------------------------------------------------- #


def test_dnsblip_dual_stack_partition(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A DNSBL feed with BOTH families -> pfB_DNSBLIP_v4 AND pfB_DNSBLIP_v6.

    Scenario: a DNSBL-IP feed carrying BOTH families partitions onto two tables.
      Given a feed file with exactly one IPv4 literal and one IPv6 literal
        And a DNSBL list referencing it with the DNSBL-IP action 'Deny_Both' on
      When a Force Update builds the domain DB and the IP firewall tables
      Then pfBlockerNG populates TWO distinct alias tables, pfB_DNSBLIP_v4 and
           pfB_DNSBLIP_v6 (the hardcoded ``DNSBLIP`` base name suffixed per family,
           inc:9306) — each holding ONLY its own family, never merged onto one
        And the inet/inet6 rules each reference the matching per-family table.

    ADR §2 contract; on the maintainer's §7 manual checklist. The IP-firewall path
    itself is already proven synchronously by ``test_ip_alias_table_and_rule``; what
    this pins is specifically the dual-stack PARTITION (families never collide on one
    table).

    ``pfB_DNSBLIP_v4`` / ``pfB_DNSBLIP_v6`` are populated ASYNC — ``filter_configure``
    lands them slightly after ``pfblockerng.php update`` returns (absent on a sync read
    right after the reload, present in teardown diagnostics — issue #35). So the table
    read goes through the bounded :func:`~helpers.wait_pfctl_table` poll, mirroring the
    ``rule_references`` reload-lag pattern; a real miss surfaces as an assertion on the
    empty list (with diagnostics uploaded), never a hang.
    """
    # Given: a feed carrying exactly one literal per family.
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
        # When: read each per-family table through the bounded async-population poll.
        # Then: both tables exist and are non-empty (empty list -> clear assertion).
        v4_members = h.wait_pfctl_table(deployed_vm, "pfB_DNSBLIP_v4")
        v6_members = h.wait_pfctl_table(deployed_vm, "pfB_DNSBLIP_v6")
        assert v4_members, "pfB_DNSBLIP_v4 never appeared/populated within the poll window"
        assert v6_members, "pfB_DNSBLIP_v6 never appeared/populated within the poll window"

        # Then: each table holds ONLY its own family (the partition — no collision / merge).
        assert h.member_present(v4_members, v4), f"{v4} not in pfB_DNSBLIP_v4: {v4_members}"
        assert not any(":" in m for m in v4_members), f"IPv6 leaked into pfB_DNSBLIP_v4: {v4_members}"
        assert h.member_present(v6_members, v6), f"{v6} not in pfB_DNSBLIP_v6: {v6_members}"
        assert any(":" in m for m in v6_members), f"no IPv6 in pfB_DNSBLIP_v6: {v6_members}"
        assert not any(_is_v4_literal(m) for m in v6_members), f"IPv4 leaked into pfB_DNSBLIP_v6: {v6_members}"

        # Then: inet/inet6 rules reference the matching per-family table.
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


# --------------------------------------------------------------------------- #
# ADR-03 — persistent log handle: a VIP block reaches dnsbl.log under real Unbound.
# The off-box golden harness pins byte-identical log CONTENT; this pins that the
# persistent WatchedFileHandler/QueueListener path actually WRITES the line live —
# the one thing the off-box harness cannot prove (the chrooted Python loader's file IO).
# --------------------------------------------------------------------------- #


def _dnsbl_log_hits(vm: SmokeVM, needle: str, *, timeout: float = 30.0) -> int:
    """Count ``dnsbl.log`` lines containing ``needle`` on the guest (host + chroot paths).

    ``pfb_unbound.py`` runs chrooted at ``/var/unbound``, so its
    ``/var/log/pfblockerng/dnsbl.log`` open resolves inside the chroot; grep BOTH the host
    and the chroot path so the assertion is independent of which one the line lands in.
    ``grep -hcF`` prints one integer per file (filename suppressed); a missing file is
    skipped (its error goes to stderr), so summing the integer tokens is robust.
    """
    res = vm.ssh(
        "grep",
        "-hcF",
        "--",
        needle,
        "/var/log/pfblockerng/dnsbl.log",
        "/var/unbound/var/log/pfblockerng/dnsbl.log",
        timeout=timeout,
    )
    return sum(int(tok) for tok in res.stdout.split() if tok.isdigit())


def test_dnsbl_block_writes_persistent_log_line(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-03: a VIP (``log_type='1'``) block is written to ``dnsbl.log`` via the persistent handle.

    Scenario: ADR-03 replaced per-call open/close with a persistent ``WatchedFileHandler``
    behind a ``QueueListener``. The off-box golden harness pins byte-identical log content;
    this pins that — under REAL Unbound (the chrooted python loader) — a block decision
    actually reaches ``dnsbl.log`` through that persistent path.

    Given a unique domain not yet listed, ``dnsbl.log`` names it zero times (before-state).
    When it is listed VIP (per-list logging enabled -> ``log_type='1'``) and queried once,
    Then a ``dnsbl.log`` line naming it appears (the persistent logging IO path wrote it). A
      NULL / non-logged block (``log_type`` ``'2'``/``'4'``) writes nothing, so the line is
      real evidence of the ``log_type='1'`` write path, not mere execution.
    """
    domain = h.unique_domain("adr03log")
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr03_log.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokeadr03", feed_url=feed_url, header="smokeadr03", mode=h.DnsblMode.VIP)

    # BEFORE: the unique domain has never been blocked -> no dnsbl.log line names it.
    assert _dnsbl_log_hits(deployed_vm, domain) == 0, f"{domain} already in dnsbl.log before listing"

    with h.CaseContext(deployed_vm, spec):
        blocked = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(blocked), f"{domain} expected VIP block, got {blocked}"
        # The log write rides the async QueueListener -> poll briefly for the line.
        deadline = time.monotonic() + 20.0
        hits = 0
        while time.monotonic() < deadline:
            hits = _dnsbl_log_hits(deployed_vm, domain)
            if hits >= 1:
                break
            time.sleep(1.0)
        assert hits >= 1, f"no dnsbl.log line for {domain} after a VIP block (ADR-03 persistent log handle)"
