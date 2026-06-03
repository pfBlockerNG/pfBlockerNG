"""ADR-07 — the ABP DNSBL smoke matrix (live pfSense VM).

Proves the **full Adblock-Plus DNS decision logic** (``@@`` exceptions, cross-feed
``@@``, ``$important`` / ``$badfilter`` precedence, regex block/allow + admitted
count, whitelist sovereignty, and the opt-in regex static cap) holds END-TO-END on
a real resolver — what the pure ADR-07 unit oracle (``tests/test_adr07_*``) cannot:
it models ``decide()`` in Python, but only a live Unbound + ``pfb_unbound.py`` loader
proves the manifest build + matcher agree with that model on the box.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

ABP feed delivery (see ``helpers.abp_feed`` / ``write_local_feed``): a feed whose
body STARTS with ``[Adblock Plus 2.0]`` is header-sniffed by pfBlockerNG
(``pfblockerng.inc:7934``), tagged ``format_hint='abp'`` in the per-feed manifest
(``inc:8414``), and its RAW lines flow to the Python ABP parser (``parse_abp``);
the old PHP lite parser is gone (ADR-07 P8). Detection is CONTENT-based, so each
DNSBL row's ``format`` stays ``auto``.

Every expected answer is pinned to the REAL semantics in
``src/usr/local/pkg/pfblockerng/pfb_unbound.py`` (verified against source):

* ``||domain^`` / ``@@||domain^`` / hosts / bare-domain are **wildcard** rules —
  they cover the domain AND its subdomains (``parse_abp`` ``wildcard=True``,
  pfb_unbound.py:2161/2186/2206); a block lands in zoneDB (suffix match).
* The 6-band precedence (``_dnsbl_rule_band`` / ``PRIO_*``): feed-block **1**,
  feed-allow **2**, feed-block+``$important`` **3**, feed-allow+``$important`` **4**,
  user-block **5**, user-allow **6**. A matched block STANDS iff
  ``block_band > allow_band`` (``_resolve_numeric_allow`` returns
  ``allow_band >= block_band`` == "resolves"). Loading any feed ``@@`` / feed regex /
  ``$important`` sets ``important_rules=True`` so the numeric branch runs.
* Block SHAPE is unchanged from ADR-04: per-list ``logging='enabled'`` →
  ``log_type='1'`` → NOERROR + DNSBL VIP; a **regex** block forces ``log_type='1'``
  (VIP) at pfb_unbound.py:3545. NXDOMAIN is NEVER an ABP feed-match shape.
* The DNSBL_Regex alias count (``/var/unbound/pfb_py_regex_count``) is
  ``len(regexDB)+len(allowRegexDB)`` AFTER the static cap drops over-cap patterns —
  the **admitted** count (pfb_unbound.py:755), which shrinks by design with the cap on.

HERMETIC PROBE NOTE (load-bearing, inherited from the ADR-04 matrix): during the
per-case probe ``CaseContext`` blocks the runner's egress, so a name that is NOT
blocked only answers if it has a control Host-Override (``control_local_data``);
otherwise it would hang (no upstream). Every "resolves" expectation here therefore
injects a control A record and asserts that exact pass IP — never a loose
"not blocked".

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps; without them they skip cleanly.

Items the harness does NOT automate (run by hand on a live box — see ADR.md
"Live smoke"): the runtime regex warn→evict timing (no config key writes the
warn/evict ceilings; the trip is CPU-bound and flaky in CI), the ABP×DNSBL-TLD
live mode, and the async DNSBL-IP table populate (the ADR-04 matrix already defers
``test_dnsblip_dual_stack_partition`` for the same reason).
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _MockFeedServer, _StubDnsServer

pytestmark = pytest.mark.smoke

# TEST-NET-2 (RFC 5737) control answers for names a case expects to RESOLVE.
PASS_IP = "198.51.100.60"
PASS_IP2 = "198.51.100.61"


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the ABP matrix (mirrors the ADR-04 matrix).

    Egress is managed per-case by ``CaseContext``; the DNSBL VIP is injected once
    (DNSBL force-disables itself without one). A full guest snapshot is collected on
    teardown for the workflow to upload.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# 1) @@ exception un-blocks (same feed) — checklist "`@@` exception un-blocks"
# --------------------------------------------------------------------------- #


def test_abp_exception_unblocks(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """An ABP feed that blocks ``||base^`` and exempts ``@@||good.base^``:
    ``good.base`` resolves; ``base`` and a non-exempt subdomain stay VIP-blocked.

    ``||base^`` is a wildcard block (zoneDB suffix; covers base + subdomains).
    ``@@||good.base^`` is a wildcard feed-allow (band 2). For ``good.base``:
    block_band 1, allow_band 2 → ``1 > 2`` false → allow wins → resolves (to its
    control IP). For ``base`` / ``bad.base``: no allow match → block stands → VIP.
    Loading the feed ``@@`` sets ``important_rules`` so the numeric branch runs.
    """
    base = h.unique_domain("abpexc")
    good = f"good.{base}"
    bad = f"bad.{base}"
    body = h.abp_feed(f"||{base}^", f"@@||{good}^")
    feed_url = h.write_local_feed(deployed_vm, "smoke_abp_exc.txt", body)
    spec = h.DnsblCase(
        aliasname="smokeabpexc",
        feed_url=feed_url,
        header="smokeabpexc",
        mode=h.DnsblMode.VIP,
        control_local_data={good: {"A": PASS_IP}},
    )
    with h.CaseContext(deployed_vm, spec):
        ans_base = h.dns_probe(deployed_vm, base, "A")
        assert h.is_vip(ans_base), f"{base} expected VIP block, got {ans_base}"
        ans_bad = h.dns_probe(deployed_vm, bad, "A")
        assert h.is_vip(ans_bad), f"{bad} (non-exempt subdomain) expected VIP block, got {ans_bad}"
        ans_good = h.dns_probe(deployed_vm, good, "A")
        assert h.resolves_to(ans_good, PASS_IP), f"exempted {good} should resolve to {PASS_IP}, got {ans_good}"
        assert not h.is_vip(ans_good), f"exempted {good} wrongly VIP-blocked: {ans_good}"


# --------------------------------------------------------------------------- #
# 2) Cross-feed @@ — an exception in feed B un-blocks a block in feed A
# --------------------------------------------------------------------------- #


def test_abp_cross_feed_exception(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Feed A blocks ``||base^``; feed B exempts ``@@||base^`` → ``base`` resolves.

    The two feeds are two ROWS of ONE DNSBL group (each header-sniffed ABP
    independently); the Python build MERGES their rules. Cross-feed global ``@@`` is
    intended ABP semantics (ADR.md): feed-allow band 2 ≥ feed-block band 1 → resolves.
    """
    base = h.unique_domain("abpxfeed")
    feed_a = h.write_local_feed(deployed_vm, "smoke_abp_xfeed_a.txt", h.abp_feed(f"||{base}^"))
    feed_b = h.write_local_feed(deployed_vm, "smoke_abp_xfeed_b.txt", h.abp_feed(f"@@||{base}^"))
    spec = h.DnsblCase(
        aliasname="smokeabpxf",
        feed_url=feed_a,
        header="smokeabpxfa",
        mode=h.DnsblMode.VIP,
        extra_rows=[("smokeabpxfb", feed_b)],
        control_local_data={base: {"A": PASS_IP}},
    )
    with h.CaseContext(deployed_vm, spec):
        ans = h.dns_probe(deployed_vm, base, "A")
        assert h.resolves_to(ans, PASS_IP), f"cross-feed @@ should un-block {base} -> {PASS_IP}, got {ans}"
        assert not h.is_vip(ans), f"{base} wrongly VIP-blocked despite cross-feed @@: {ans}"


# --------------------------------------------------------------------------- #
# 3) $important / $badfilter precedence
# --------------------------------------------------------------------------- #


def test_abp_important_block_beats_feed_allow(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Feed ``||x^$important`` (band 3) beats a feed ``@@||x^`` (band 2): x stays blocked.

    block_band 3 > allow_band 2 → block wins → VIP. (The ``@@`` makes the numeric
    branch run; ``$important`` is what raises the block above the feed allow.)
    """
    x = h.unique_domain("abpimp")
    body = h.abp_feed(f"||{x}^$important", f"@@||{x}^")
    feed_url = h.write_local_feed(deployed_vm, "smoke_abp_important.txt", body)
    spec = h.DnsblCase(aliasname="smokeabpimp", feed_url=feed_url, header="smokeabpimp", mode=h.DnsblMode.VIP)
    with h.CaseContext(deployed_vm, spec):
        ans = h.dns_probe(deployed_vm, x, "A")
        assert h.is_vip(ans), f"{x}: $important block must beat feed @@ (VIP), got {ans}"


def test_abp_badfilter_prunes_feed_block(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Feed ``||y^$badfilter`` prunes the matching feed ``||y^`` → y resolves.

    ``$badfilter`` removes every FEED rule with the matching signature (``(y, ())``),
    including the badfilter rule itself — so y has no surviving block and resolves
    (to its control IP). Sovereignty caveat is covered separately: a user rule's
    signature is NOT pruned.
    """
    y = h.unique_domain("abpbad")
    body = h.abp_feed(f"||{y}^", f"||{y}^$badfilter")
    feed_url = h.write_local_feed(deployed_vm, "smoke_abp_badfilter.txt", body)
    spec = h.DnsblCase(
        aliasname="smokeabpbad",
        feed_url=feed_url,
        header="smokeabpbad",
        mode=h.DnsblMode.VIP,
        control_local_data={y: {"A": PASS_IP}},
    )
    with h.CaseContext(deployed_vm, spec):
        ans = h.dns_probe(deployed_vm, y, "A")
        assert h.resolves_to(ans, PASS_IP), f"$badfilter should prune the block on {y} -> {PASS_IP}, got {ans}"
        assert not h.is_vip(ans), f"{y} wrongly VIP-blocked despite $badfilter: {ans}"


# --------------------------------------------------------------------------- #
# 4) Regex — block + @@ allow (irreducible) and the admitted count
# --------------------------------------------------------------------------- #


def test_abp_regex_block_and_allow(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """An ABP feed regex blocks a matching name; an ``@@/re/`` allow un-blocks an
    also-matching name.

    Block ``/badword/`` (irreducible substring regex → compiled into regexDB, band 1,
    forced ``log_type='1'`` → VIP). Allow ``@@/goodword/`` (allowRegexDB, band 2). A
    name carrying ONLY ``badword`` is VIP-blocked; a name carrying BOTH matches the
    allow (band 2 ≥ block band 1) → resolves.
    """
    uid = h.unique_domain("abprx").split(".", 1)[0]  # the uuid label only
    blocked = f"xbadwordx-{uid}.com"
    unblocked = f"goodwordbadword-{uid}.com"
    body = h.abp_feed("/badword/", "@@/goodword/")
    feed_url = h.write_local_feed(deployed_vm, "smoke_abp_regex.txt", body)
    spec = h.DnsblCase(
        aliasname="smokeabprx",
        feed_url=feed_url,
        header="smokeabprx",
        mode=h.DnsblMode.VIP,
        control_local_data={unblocked: {"A": PASS_IP}},
    )
    with h.CaseContext(deployed_vm, spec):
        ans_block = h.dns_probe(deployed_vm, blocked, "A")
        assert h.is_vip(ans_block), f"regex-matched {blocked} expected VIP, got {ans_block}"
        ans_allow = h.dns_probe(deployed_vm, unblocked, "A")
        assert h.resolves_to(ans_allow, PASS_IP), f"@@ regex should un-block {unblocked} -> {PASS_IP}, got {ans_allow}"


def test_abp_regex_admitted_count(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """The DNSBL_Regex count reflects ADMITTED regex, and the static cap shrinks it.

    Two USER regex patterns — one benign (``ads[0-9]+``), one nested-quantifier
    (``(a+)+evil``, which ``_regex_exceeds_static_cap`` flags). With the cap OFF both
    are admitted (count 2); with the cap ON the over-cap pattern is dropped at load
    (count 1). A minimal plain feed is present so the DNSBL build runs and emits the
    count file. (allowRegexDB is empty here, so the count is purely regexDB.)
    """
    domain = h.unique_domain("abpcnt")
    feed_url = h.write_local_feed(deployed_vm, "smoke_abp_cnt.txt", f"{domain}\n")
    patterns = [r"ads[0-9]+", r"(a+)+evil"]

    spec_off = h.DnsblCase(
        aliasname="smokeabpcnt", feed_url=feed_url, header="smokeabpcnt", mode=h.DnsblMode.VIP, user_regex=patterns
    )
    with h.CaseContext(deployed_vm, spec_off):
        n_off = h.regex_admitted_count(deployed_vm)
    assert n_off == 2, f"cap OFF: both user regex admitted, expected 2, got {n_off!r}"

    spec_on = h.DnsblCase(
        aliasname="smokeabpcnt",
        feed_url=feed_url,
        header="smokeabpcnt",
        mode=h.DnsblMode.VIP,
        user_regex=patterns,
        regex_cap=True,
    )
    with h.CaseContext(deployed_vm, spec_on):
        n_on = h.regex_admitted_count(deployed_vm)
    assert n_on == 1, f"cap ON: nested-quantifier dropped at load, expected admitted 1, got {n_on!r}"
    assert n_on < n_off, f"cap must shrink the admitted count: off={n_off} on={n_on}"


# --------------------------------------------------------------------------- #
# 5) User sovereignty — the whitelist beats any feed rule (incl. $important)
# --------------------------------------------------------------------------- #


def test_abp_whitelist_sovereign_over_important(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A whitelisted name resolves even against a feed ``||w^$important``.

    The settings whitelist (``suppression``) loads into whiteDB as a user allow
    (``important=True`` → band 6, ``_white_entry_band``). vs feed block+``$important``
    band 3: allow_band 6 ≥ block_band 3 → resolves (to its control IP). This is the
    one UNAMBIGUOUS sovereign user lever in DNSBL python mode. (User *regex* load at
    feed band 1, not the oracle's user band 5 — see ADR.md "Live smoke" note — so
    user-regex band-sovereignty is intentionally NOT asserted here.)
    """
    w = h.unique_domain("abpwl")
    body = h.abp_feed(f"||{w}^$important")
    feed_url = h.write_local_feed(deployed_vm, "smoke_abp_wl.txt", body)
    spec = h.DnsblCase(
        aliasname="smokeabpwl",
        feed_url=feed_url,
        header="smokeabpwl",
        mode=h.DnsblMode.VIP,
        whitelist=[w],
        control_local_data={w: {"A": PASS_IP}},
    )
    with h.CaseContext(deployed_vm, spec):
        ans = h.dns_probe(deployed_vm, w, "A")
        assert h.resolves_to(ans, PASS_IP), f"whitelisted {w} must resolve to {PASS_IP} despite $important, got {ans}"
        assert not h.is_vip(ans), f"whitelisted {w} wrongly VIP-blocked: {ans}"


def test_user_regex_blocks(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A user "Python Regex List" pattern blocks a matching name (VIP shape).

    The user regex loads into regexDB (bare compiled pattern); a regex block forces
    ``log_type='1'`` → VIP. This pins user-regex *functionality* end-to-end (a
    sovereign whitelist still wins, proven above); a minimal plain feed is present so
    the DNSBL build runs.
    """
    uid = h.unique_domain("abpurx").split(".", 1)[0]
    blocked = f"trackerx-{uid}.com"
    plain = h.unique_domain("abpurxfeed")
    feed_url = h.write_local_feed(deployed_vm, "smoke_user_regex.txt", f"{plain}\n")
    spec = h.DnsblCase(
        aliasname="smokeurx",
        feed_url=feed_url,
        header="smokeurx",
        mode=h.DnsblMode.VIP,
        user_regex=[r"trackerx-"],
    )
    with h.CaseContext(deployed_vm, spec):
        ans = h.dns_probe(deployed_vm, blocked, "A")
        assert h.is_vip(ans), f"user-regex-matched {blocked} expected VIP block, got {ans}"


# --------------------------------------------------------------------------- #
# 6) No regression — a plain (non-ABP) feed still blocks; pfb_py_count renders
# --------------------------------------------------------------------------- #


def test_abp_no_regression_plain_feed(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A plain (non-ABP) feed blocks exactly as before and pfb_py_count renders.

    The body carries no ABP header, so it is NOT tagged ABP — it takes the ADR-06
    plain path (exact dataDB entry). The loaded-count file must render a positive
    integer (the UI alias). This guards the fast path stays intact alongside ABP.
    """
    domain = h.unique_domain("abpnoreg")
    feed_url = h.write_local_feed(deployed_vm, "smoke_plain_noreg.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokenoreg", feed_url=feed_url, header="smokenoreg", mode=h.DnsblMode.VIP)
    with h.CaseContext(deployed_vm, spec):
        ans = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_vip(ans), f"plain feed {domain} expected VIP block (no regression), got {ans}"
        count = h.py_loaded_count(deployed_vm)
        assert count is not None and count >= 1, f"pfb_py_count must render >=1, got {count!r}"
