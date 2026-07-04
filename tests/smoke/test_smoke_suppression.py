"""ADR-53 live-VM smoke: the PERSISTED suppression engines carve a live-loaded
member set, both families -- the §4.1 acceptance requirement's update-time
proof.

Two independent mechanisms exist for the same set-subtraction invariant:

* The **update-time engine** (this module): ``pfblockerng.sh suppress()``
  (``iprange --except``, v4) and ``pfb_suppress_file_v6()`` (pure-PHP CIDR
  set-diff, v6), wired into the alias-build loop and driven by a config
  ``v4suppression``/``v6suppression`` entry + a reload.
* The **Alerts "+" live punch** (``pfb_live_punch_plan()``,
  ``tests/smoke/ui/test_alerts.py``'s ``test_addsuppress_*_carves_containing_range_*``
  tests, ADR-53 Phase 8): a DIFFERENT code path that mutates the live pf table
  directly from a single web click, independent of any reload.

This module covers the FIRST mechanism only -- config -> reload -> engine ->
pf table -- so it does not duplicate Phase 8's UI e2e coverage.

``$pfb['supp_update']`` unlocks BOTH the v4 AND v6 suppression sub-passes for
a given reload. An adversarial-review pass on this ADR (finding A) caught that
it was originally flipped TRUE only from inside a v4-only dedup/reputation
block (``pfblockerng.inc`` ~16550-16558), so a v6-only Deny deployment could
never fire v6 suppression in isolation -- fixed via the pure
``pfb_supp_update_active()`` helper (family-agnostic: any feed-changed
Deny-folder alias unlocks it), pinned by ``AliasContentGateTest.php``'s
Scenario H. Scenario B below still injects a companion v4 Deny alias alongside
the v6 target -- now exercising the MIXED-family case (both families active
in the same pass), not working around the fixed bug.

Scenarios D and E cover a THIRD mechanism gated by the same Suppression checkbox
(``$pfb['supp'] == 'on'``) but otherwise unrelated to the carve engines above --
``sanitize_ipaddr()``/``sanitize_ipaddr_v6()``'s per-line reserved-class drop and
the per-category IPv6 CIDR floor (issue #760 §1/§3). They reuse this module's
``deployed_vm``/``_clean_suppression`` infra (the Suppression checkbox + the
``IpCase``/``inject_ip_lists`` plumbing) rather than a new module, since that
infra is exactly what they need and duplicating it would buy nothing.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run via the smoke workflow or locally::

    python -m pytest tests/smoke/test_smoke_suppression.py -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``);
without it the module fixture skips cleanly. Pure IP-side (no DNSBL, no DNS
probe) -- mirrors the minimal ``test_smoke_714_asn_geoip.py`` deploy shape.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import FIXTURES_DIR, SmokeVM

pytestmark = pytest.mark.smoke

CFG_IP_SETTINGS = h.CFG_IP_SETTINGS
DENYDIR = f"{h.PFB_DBDIR}/deny"

# The two bare hosts each fixture carries, in both notations iprange/the v6
# engine may render a lone covering host (bare, or explicitly masked) -- used
# to filter "untouched sibling" lines out of a covering-CIDR count.
#
# NOTE (issue #760): these used to be RFC 5737/3849 documentation addresses, matching
# the smoke-fixture convention (tests/smoke/fixtures/README.md). Every test in this
# module runs with the global Suppression checkbox ON (``_set_suppression``), and
# issue #760 §1 made ``sanitize_ipaddr()``/``sanitize_ipaddr_v6()`` drop documentation
# space UNCONDITIONALLY whenever Suppression is on -- so RFC 5737/3849 fixture data
# would now be silently dropped before ever reaching the pf table, breaking every
# BEFORE-state assertion in this module. Switched to public, non-reserved space
# (Cloudflare/Google/Quad9 exemplar addresses) instead; ``ip_suppress_v4.txt`` /
# ``ip_suppress_v6.txt`` were updated to match (see their in-file comments).
V4_BARE_HOSTS = ("9.9.9.9", "8.8.8.8")
V6_BARE_HOSTS = ("2606:4700:99::10", "2606:4700:aa::20")


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the ADR-53 persisted-suppression-engine module.

    Pure IP-side: the engines under test run inside the IP-scope reload path
    only (no DNSBL, no DNS probe needed) -- mirrors the minimal
    ``test_smoke_714_asn_geoip.py`` shape (no DNSBL VIP, no client_vm, no stub_dns).
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def _set_suppression(vm: SmokeVM, *, v4: list[str] | None = None, v6: list[str] | None = None) -> None:
    """Enable the master "Enable Suppression" toggle and set BOTH customlists.

    ``v4``/``v6`` are raw textarea lines (e.g. ``"1.1.3.4/32"``) -- every
    suppression line MUST carry an explicit mask: ``pfb_validate_suppression_line``
    rejects a bare host (``is_subnetv4()``/``is_subnetv6()`` both require
    ``/bits``). ``None``/empty clears that family's list. Same base64/CRLF
    TEXTAREA shape as every other pfBlockerNG customlist (``helpers._b64_textarea``).
    """
    snippet = (
        f"$ip = config_get_path({h._php_str(CFG_IP_SETTINGS)}, array());\n"
        "$ip['suppression'] = 'on';\n"
        f"$ip['v4suppression'] = {h._php_str(h._b64_textarea(v4 or []))};\n"
        f"$ip['v6suppression'] = {h._php_str(h._b64_textarea(v6 or []))};\n"
        f"config_set_path({h._php_str(CFG_IP_SETTINGS)}, $ip);\n"
        "write_config('pfBlockerNG smoke: ADR-53 suppression');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_suppression failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _wipe_suppression(vm: SmokeVM) -> None:
    """Force BOTH suppression customlists empty and confirm the write actually took.

    Self-encapsulated per-test baseline (CLAUDE.md test-coverage mandate): a
    stale v4suppression/v6suppression entry left by one test must never leak
    into the NEXT test's BEFORE-state assertion. Fails LOUDLY -- never a
    silent best-effort -- if the readback disagrees with what was just written.
    """
    _set_suppression(vm, v4=[], v6=[])
    v4_after = h.config_get(vm, f"{CFG_IP_SETTINGS}/v4suppression")
    v6_after = h.config_get(vm, f"{CFG_IP_SETTINGS}/v6suppression")
    if v4_after or v6_after:
        raise AssertionError(
            "wipe of v4suppression/v6suppression did not take -- expected both empty, "
            f"got v4suppression={v4_after!r} v6suppression={v6_after!r}"
        )


def _set_suppression_cidr_v6(vm: SmokeVM, value: str) -> None:
    """Set the per-category ``suppression_cidr_v6`` floor (issue #760 §3) on the SINGLE
    v6 list-group the module's own ``h.inject()``/``h.inject_ip_lists()`` just wrote
    (index 0 -- both write a fresh single-element list-group array per family root, so
    this always targets the right row without a lookup). ``value`` is a mask-width
    string (``'1'``..``'64'``) or ``'Disabled'``.
    """
    snippet = (
        f"$lists = config_get_path({h._php_str(h.CFG_IP_V6_LISTS)}, array());\n"
        f"$lists[0]['suppression_cidr_v6'] = {h._php_str(value)};\n"
        f"config_set_path({h._php_str(h.CFG_IP_V6_LISTS)}, $lists);\n"
        "write_config('pfBlockerNG smoke: issue #760 v6 CIDR floor');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_set_suppression_cidr_v6 failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


@pytest.fixture(autouse=True)
def _clean_suppression(deployed_vm: SmokeVM) -> Iterator[None]:
    """Wipe both suppression customlists before AND after every test in this module.

    Each test injects its OWN uniquely-named alias, so there is no pf-table
    collision between tests; the v4suppression/v6suppression config nodes are
    the only state that could otherwise leak test-to-test. Teardown also drops
    the finishing test's derived pf/sqlite state (``helpers.reset``) so the
    next test's BEFORE-state assertion starts from a genuinely clean table.
    """
    _wipe_suppression(deployed_vm)
    yield
    _wipe_suppression(deployed_vm)
    h.reset(deployed_vm)


def _member_lines(vm: SmokeVM, on_disk_header: str) -> list[str]:
    """Non-blank lines of a deny-folder member file (the post-suppression content)."""
    result = vm.ssh("cat", f"{DENYDIR}/{on_disk_header}.txt")
    return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]


def _has_entry(lines: list[str], ip: str) -> bool:
    """True iff ``ip`` appears in ``lines`` bare, or with an explicit /32 or /128 mask.

    iprange renders a lone covering host WITHOUT a mask suffix (confirmed:
    ``tests/shell/pfblockerng_suppress_spec.sh``'s ``'10.9.8.5'`` sample); this
    tolerates either rendering rather than pinning one exact notation.
    """
    return ip in lines or f"{ip}/32" in lines or f"{ip}/128" in lines


def _carved_only(lines: list[str], bare_hosts: tuple[str, ...]) -> list[str]:
    """``lines`` with every KNOWN untouched bare-host fixture entry filtered out.

    Isolates the covering-CIDR entries the suppression engine actually
    produced from the fixture's own untouched sibling hosts, in EITHER
    notation (see :func:`_has_entry`).
    """
    excluded = set(bare_hosts) | {f"{ip}/32" for ip in bare_hosts} | {f"{ip}/128" for ip in bare_hosts}
    return [ln for ln in lines if ln not in excluded]


# --------------------------------------------------------------------------- #
# Scenario A -- v4 containing-range carve (the §4.1 headline case)
# --------------------------------------------------------------------------- #


def test_suppression_v4_carves_containing_range_spares_sibling(deployed_vm: SmokeVM) -> None:
    """The persisted v4 engine (``suppress()``, ``iprange --except``) carves a
    live-loaded /16 down to covering CIDRs -- ADR-53 §4.1's headline acceptance
    requirement, proven via the update-time path.

    Given: the v4 fixture feed (``1.1.0.0/16`` + two bare hosts) is loaded
    as a Deny list; suppression is enabled but empty; a settling update runs.

    When: v4suppression is set to the target host's exact /32 and a second
    update runs.

    Then: BEFORE the config change, both the target (inside the /16) and an
    unrelated sibling (a bare-host feed entry) match the live pf table. AFTER,
    the target no longer matches (the /16 was carved into covering CIDRs --
    never a 65536-host explosion); the sibling still matches; the member file
    holds exactly 16 covering-CIDR entries for the /16 minus the /32.
    """
    feed_body = (FIXTURES_DIR / "ip_suppress_v4.txt").read_text()
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr53_v4a.txt", feed_body)
    spec = h.IpCase(aliasname="adr53v4a", feed_url=feed_url, header="adr53v4a")
    # Same relative host-in-block position (octet3=3, octet4=4 inside a /16) as
    # the real-iprange-verified vector in tests/shell/pfblockerng_suppress_spec.sh
    # ("10.0.3.4" inside "10.0.0.0/16" -> 16 covering CIDRs incl. ".0.0/23" and
    # ".128.0/17") -- the covering-CIDR count/shape is invariant to the network
    # prefix, so this grounds the assertions below in an already-proven result.
    target = "1.1.3.4"
    sibling = "9.9.9.9"
    host_entry = f"{target}/32"

    h.inject(deployed_vm, spec)
    # updateip (scope=ip force=true) sets $pfb['reuse']='on' for the WHOLE pass
    # (pfblockerng.inc ~13243), which defeats the per-file "already parsed,
    # skip" cache for EVERY Deny alias -- so a LATER, content-unchanged
    # updateip call genuinely re-parses this alias with no marker-touch
    # needed (unlike the ADR-40 tests, which use the force=false 'update'
    # verb and must call force_ip_refetch explicitly).
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    # BEFORE: both addresses match the freshly-loaded, UNSUPPRESSED table.
    members = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert members, f"pf table {spec.alias} never populated after the settling update"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, target)
    assert matched, f"expected {target} to MATCH {spec.alias} before suppression; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, sibling)
    assert matched, f"expected {sibling} to MATCH {spec.alias} before suppression; pfctl said: {raw!r}"

    # WHEN: configure suppression for the target host only, then re-run.
    _set_suppression(deployed_vm, v4=[host_entry])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    # THEN: the target is carved out; the sibling -- an unrelated feed entry -- is untouched.
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, target)
    assert not matched, f"expected {target} to NO LONGER match {spec.alias} after suppression; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, sibling)
    assert matched, f"expected {sibling} to STILL match {spec.alias} after suppression; pfctl said: {raw!r}"

    # AND: the member file holds covering CIDRs, never a host explosion.
    lines = _member_lines(deployed_vm, f"{spec.header}_v4")
    carved = _carved_only(lines, V4_BARE_HOSTS)
    assert len(carved) == 16, (
        "expected 16 covering-CIDR entries for a /16 minus a /32 (ADR-53 §1.2's "
        f"measured bound); got {len(carved)}: {carved}\nfull member file ({len(lines)} lines): {lines}"
    )
    assert "1.1.0.0/23" in carved and "1.1.128.0/17" in carved, (
        "expected representative covering CIDRs '1.1.0.0/23' and '1.1.128.0/17' "
        f"(the same relative shape as the real-iprange-verified 10.0.0.0/16-10.0.3.4 vector); got {carved}"
    )


# --------------------------------------------------------------------------- #
# Scenario B -- v6 containing-range carve (v6 had NO carve mechanism before ADR-53)
# --------------------------------------------------------------------------- #


def test_suppression_v6_carves_containing_range_spares_sibling(deployed_vm: SmokeVM) -> None:
    """The persisted v6 engine (``pfb_suppress_file_v6()``, pure-PHP CIDR
    set-diff) carves a live-loaded /64 down to covering CIDRs -- v6 had NO
    carve mechanism at all before ADR-53.

    A trivial companion v4 Deny alias is injected alongside the v6 target to
    exercise the mixed-family case (see the module docstring: this used to be a
    workaround for a v6-only $pfb['supp_update'] gating bug, now fixed).

    Given: the v6 fixture feed (``2606:4700:53::/64`` + two bare hosts) is
    loaded as a Deny list, alongside the v4 companion; suppression enabled but
    empty; a settling update runs.

    When: v6suppression is set to the target host's exact /128 and a second
    update runs.

    Then: BEFORE, the target and a sibling both match; AFTER, the target no
    longer matches (the /64 was carved into covering CIDRs); the sibling still
    matches; the member file holds exactly 64 covering-CIDR entries for the
    /64 minus the /128 (ADR-53 §1.2's measured bound; also the exact vector
    ``pfb_cidr_subtract_v6()`` is unit-pinned against in
    ``tests/php/V6CidrSubtractTest.php``).
    """
    feed_body = (FIXTURES_DIR / "ip_suppress_v6.txt").read_text()
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr53_v6b.txt", feed_body)
    v6spec = h.IpCase(aliasname="adr53v6b", feed_url=feed_url, header="adr53v6b", family="v6")

    companion_url = h.write_local_feed(deployed_vm, "smoke_adr53_v6companion.txt", "5.5.5.5\n")
    companion_spec = h.IpCase(aliasname="adr53v6bcompanion", feed_url=companion_url, header="adr53v6bcompanion")

    target = "2606:4700:53::42"
    sibling = "2606:4700:99::10"
    host_entry = f"{target}/128"

    h.inject_ip_lists(deployed_vm, [companion_spec, v6spec])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    members = h.wait_pfctl_table(deployed_vm, v6spec.alias)
    assert members, f"pf table {v6spec.alias} never populated after the settling update"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, v6spec.alias, target)
    assert matched, f"expected {target} to MATCH {v6spec.alias} before suppression; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, v6spec.alias, sibling)
    assert matched, f"expected {sibling} to MATCH {v6spec.alias} before suppression; pfctl said: {raw!r}"

    # WHEN: configure v6 suppression, then re-run BOTH aliases -- the v6
    # alias's own re-parse now flips $pfb['supp_update'] on its own (fixed);
    # the companion v4 alias re-parses alongside it, exercising the
    # mixed-family case in the same pass.
    _set_suppression(deployed_vm, v6=[host_entry])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    matched, raw = h.pfctl_table_test_raw(deployed_vm, v6spec.alias, target)
    assert not matched, f"expected {target} to NO LONGER match {v6spec.alias} after suppression; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, v6spec.alias, sibling)
    assert matched, f"expected {sibling} to STILL match {v6spec.alias} after suppression; pfctl said: {raw!r}"

    lines = _member_lines(deployed_vm, f"{v6spec.header}_v6")
    carved = _carved_only(lines, V6_BARE_HOSTS)
    assert len(carved) == 64, (
        "expected 64 covering-CIDR entries for a /64 minus a /128 (ADR-53 §1.2's measured "
        f"bound, unit-pinned in V6CidrSubtractTest.php); got {len(carved)}: {carved}\n"
        f"full member file ({len(lines)} lines): {lines}"
    )


# --------------------------------------------------------------------------- #
# Scenario C -- whole-token + legacy-shape upgrade parity (§2.2)
# --------------------------------------------------------------------------- #


def test_suppression_v4_bare_host_removed(deployed_vm: SmokeVM) -> None:
    """A masked suppression entry over a BARE FEED HOST removes just that
    token; a /16 entry it never intersects is left byte-identical -- proving
    the engine only carves entries that actually contain a hole, and that a
    plain host suppression keeps working identically to the pre-ADR-53
    mechanism (upgrade parity, ADR-53 §2.2).

    Given: the v4 fixture feed, settled; BEFORE a host inside the /16 and
    BOTH bare hosts match.

    When: v4suppression is set to ONE bare host's exact /32 (no intersection
    with the /16 at all).

    Then: that bare host no longer matches; the OTHER bare host and a host
    inside the untouched /16 still match; the member file holds exactly the
    /16 line plus the surviving bare host (2 lines) -- never a carve of an
    entry the suppression list never touched.
    """
    feed_body = (FIXTURES_DIR / "ip_suppress_v4.txt").read_text()
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr53_v4c1.txt", feed_body)
    spec = h.IpCase(aliasname="adr53v4c1", feed_url=feed_url, header="adr53v4c1")
    inside_16 = "1.1.3.4"
    removed_host = "8.8.8.8"
    kept_host = "9.9.9.9"
    host_entry = f"{removed_host}/32"

    h.inject(deployed_vm, spec)
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    members = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert members, f"pf table {spec.alias} never populated after the settling update"
    for ip in (inside_16, removed_host, kept_host):
        matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, ip)
        assert matched, f"expected {ip} to MATCH {spec.alias} before suppression; pfctl said: {raw!r}"

    _set_suppression(deployed_vm, v4=[host_entry])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, removed_host)
    assert not matched, f"expected {removed_host} to be REMOVED from {spec.alias}; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, kept_host)
    assert matched, f"expected {kept_host} to still match {spec.alias}; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, inside_16)
    assert matched, (
        f"expected {inside_16} (inside the untouched /16) to STILL match {spec.alias} -- "
        f"a bare-host suppression must never touch an unrelated /16 entry; pfctl said: {raw!r}"
    )

    lines = _member_lines(deployed_vm, f"{spec.header}_v4")
    assert len(lines) == 2, f"expected exactly 2 member-file lines (untouched /16 + surviving bare host); got {lines}"
    assert "1.1.0.0/16" in lines, f"expected the untouched /16 line verbatim (never carved); got {lines}"
    assert _has_entry(lines, kept_host), f"expected the surviving bare host {kept_host}; got {lines}"
    assert not _has_entry(lines, removed_host), f"expected {removed_host} removed; got {lines}"


def test_suppression_v4_subnet_mask_carves_at_granularity(deployed_vm: SmokeVM) -> None:
    """A /24-mask suppression entry (not just /32) carves the containing /16
    at /24 granularity -- proves the engine is mask-agnostic (ADR-53 §2.1's
    UI mask lift to /8-/32) for a wider suppression range, not just a host.

    Given: the v4 fixture feed, settled; BEFORE a host inside the target /24
    and a sibling /24 (both inside the /16) match.

    When: v4suppression is set to the CONTAINING /24 (not a /32).

    Then: the target /24 no longer matches anywhere inside it; a sibling /24
    (a different /24 inside the same /16) still matches; the member file
    holds exactly 8 covering-CIDR entries for the /16 minus the /24
    (24-16=8 -- the same prefix-length-difference bound the shellspec proves
    for /24-/32=8, here applied one level up the /16).
    """
    feed_body = (FIXTURES_DIR / "ip_suppress_v4.txt").read_text()
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr53_v4c2.txt", feed_body)
    spec = h.IpCase(aliasname="adr53v4c2", feed_url=feed_url, header="adr53v4c2")
    hole_ip = "1.1.5.9"
    sibling_ip = "1.1.9.9"
    hole_subnet = "1.1.5.0/24"

    h.inject(deployed_vm, spec)
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    members = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert members, f"pf table {spec.alias} never populated after the settling update"
    for ip in (hole_ip, sibling_ip):
        matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, ip)
        assert matched, f"expected {ip} to MATCH {spec.alias} before suppression; pfctl said: {raw!r}"

    _set_suppression(deployed_vm, v4=[hole_subnet])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, hole_ip)
    assert not matched, (
        f"expected {hole_ip} (inside the suppressed /24) to NO LONGER match {spec.alias}; pfctl said: {raw!r}"
    )
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, sibling_ip)
    assert matched, f"expected {sibling_ip} (a different /24) to STILL match {spec.alias}; pfctl said: {raw!r}"

    lines = _member_lines(deployed_vm, f"{spec.header}_v4")
    carved = _carved_only(lines, V4_BARE_HOSTS)
    assert len(carved) == 8, (
        "expected 8 covering-CIDR entries for a /16 minus a /24 (24-16=8, the same "
        f"prefix-length-difference bound the shellspec proves for /24-/32=8); got {len(carved)}: {carved}\n"
        f"full member file ({len(lines)} lines): {lines}"
    )


# --------------------------------------------------------------------------- #
# Scenario D -- reserved-class entries never reach the pf table (issue #760 §1)
# --------------------------------------------------------------------------- #


def test_suppression_drops_reserved_classes_keeps_public(deployed_vm: SmokeVM) -> None:
    """Under Suppression, a feed's RESERVED-CLASS entries (documentation, multicast,
    NAT64, CGN) are dropped OUTRIGHT at parse time -- issue #760 §1's "IPv6
    suppression is thinner" gap. Unlike Scenarios A-C, this is not the
    suppression-LIST carve engine: ``sanitize_ipaddr()``/``sanitize_ipaddr_v6()``
    (``pfblockerng.inc`` ~8018-8028 v4, ~8090-8097 v6) drop these classes
    unconditionally whenever Suppression is on, with no suppression-list entry
    needed.

    Given: a v6 feed mixing one public (non-reserved) entry with a documentation
    (2001:db8::1), a multicast (ff02::1) and a NAT64 (64:ff9b::1) entry, plus a
    companion v4 feed mixing one public entry with a CGN (100.64.0.1) entry;
    Suppression is enabled with both suppression lists empty (this module's
    default) -- these are unconditional drops, not suppression-list carves.

    When: a force update loads both feeds in one pass.

    Then: each family's public entry IS in its pf table (proves the feed
    genuinely loaded -- a false pass otherwise); every reserved-class entry is
    ABSENT from its table.
    """
    v6_body = (FIXTURES_DIR / "ip_suppress_reserved_v6.txt").read_text()
    v6_url = h.write_local_feed(deployed_vm, "smoke_issue760_reserved_v6.txt", v6_body)
    v6spec = h.IpCase(aliasname="issue760resv6", feed_url=v6_url, header="issue760resv6", family="v6")

    # Trivial inline v4 companion (not a committed fixture -- mirrors Scenario B's
    # companion alias): pins the v4 side of the same drop (issue #760 §1) cheaply.
    v4_url = h.write_local_feed(deployed_vm, "smoke_issue760_reserved_v4.txt", "1.1.1.1\n100.64.0.1\n")
    v4spec = h.IpCase(aliasname="issue760resv4", feed_url=v4_url, header="issue760resv4")

    public_v6 = "2606:4700:7777::1111"
    dropped_v6 = ("2001:db8::1", "ff02::1", "64:ff9b::1")
    public_v4 = "1.1.1.1"
    dropped_v4 = "100.64.0.1"

    h.inject_ip_lists(deployed_vm, [v4spec, v6spec])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    members_v6 = h.wait_pfctl_table(deployed_vm, v6spec.alias)
    assert members_v6, f"pf table {v6spec.alias} never populated after the update"
    members_v4 = h.wait_pfctl_table(deployed_vm, v4spec.alias)
    assert members_v4, f"pf table {v4spec.alias} never populated after the update"

    matched, raw = h.pfctl_table_test_raw(deployed_vm, v6spec.alias, public_v6)
    assert matched, f"expected the public v6 entry {public_v6} to load into {v6spec.alias}; pfctl said: {raw!r}"
    for ip in dropped_v6:
        matched, raw = h.pfctl_table_test_raw(deployed_vm, v6spec.alias, ip)
        assert not matched, f"expected reserved-class {ip} to be DROPPED from {v6spec.alias}; pfctl said: {raw!r}"

    matched, raw = h.pfctl_table_test_raw(deployed_vm, v4spec.alias, public_v4)
    assert matched, f"expected the public v4 entry {public_v4} to load into {v4spec.alias}; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, v4spec.alias, dropped_v4)
    assert not matched, f"expected CGN entry {dropped_v4} to be DROPPED from {v4spec.alias}; pfctl said: {raw!r}"


# --------------------------------------------------------------------------- #
# Scenario E -- v6 Suppression CIDR floor clamps a wide range (issue #760 §3)
# --------------------------------------------------------------------------- #


def test_suppression_cidr_v6_floor_clamps_wide_cidr_to_bare_host(deployed_vm: SmokeVM) -> None:
    """The per-category IPv6 "Suppression CIDR Limit" (``suppression_cidr_v6``,
    issue #760 §3) clamps a feed CIDR narrower than the floor down to a bare
    host -- never a silent full-range load -- while an unrelated host entry is
    left untouched.

    Given: a v6 feed with a network-aligned /48 (``2606:4700:aaaa::/48``) and a
    separate bare host (``2606:4700:bbbb::99``) in a different /48; Suppression
    is enabled (module default) with ``suppression_cidr_v6`` left at its absent
    default (``Disabled``) for the settling update.

    When: BEFORE -- the floor is absent, so the /48 loads as-is (an address
    inside it matches). AFTER -- ``suppression_cidr_v6`` is set to 56 (wider
    than the feed's /48) and a second update runs.

    Then: the address that matched inside the /48 no longer matches (the range
    collapsed); the /48's own base address now matches as a BARE host (clamped,
    no prefix span -- never a 2^80-host explosion); the sibling host is
    unaffected throughout.
    """
    feed_body = (FIXTURES_DIR / "ip_suppress_cidr_floor_v6.txt").read_text()
    feed_url = h.write_local_feed(deployed_vm, "smoke_issue760_cidrfloor_v6.txt", feed_body)
    spec = h.IpCase(aliasname="issue760cidrv6", feed_url=feed_url, header="issue760cidrv6", family="v6")

    inside_cidr = "2606:4700:aaaa::1234"
    cidr_base = "2606:4700:aaaa::"
    sibling = "2606:4700:bbbb::99"

    h.inject(deployed_vm, spec)
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    # BEFORE: the floor is absent (Disabled) -- the /48 loads unclamped.
    members = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert members, f"pf table {spec.alias} never populated after the settling update"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, inside_cidr)
    assert matched, f"expected {inside_cidr} (inside the un-floored /48) to MATCH {spec.alias}; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, sibling)
    assert matched, f"expected {sibling} to MATCH {spec.alias} before the floor is set; pfctl said: {raw!r}"

    # WHEN: set the floor above the feed's /48, then re-run.
    _set_suppression_cidr_v6(deployed_vm, "56")
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    # THEN: the /48 collapsed to its bare base address -- the wide span no longer matches...
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, inside_cidr)
    assert not matched, (
        f"expected {inside_cidr} to NO LONGER match {spec.alias} once the /48 is floor-clamped; pfctl said: {raw!r}"
    )
    # ...but the clamped bare host itself is still loaded (never silently dropped outright).
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, cidr_base)
    assert matched, f"expected the clamped bare host {cidr_base} to STILL match {spec.alias}; pfctl said: {raw!r}"
    matched, raw = h.pfctl_table_test_raw(deployed_vm, spec.alias, sibling)
    assert matched, f"expected {sibling} to remain unaffected by the CIDR floor; pfctl said: {raw!r}"
