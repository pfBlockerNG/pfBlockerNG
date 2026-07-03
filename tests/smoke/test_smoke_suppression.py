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

Non-obvious wiring fact this module's Scenario B works around (and flags for
the maintainer): ``$pfb['supp_update']`` -- the flag that unlocks BOTH the v4
AND v6 suppression sub-passes for a given reload -- is set TRUE only by a v4
Deny alias's own genuine reparse (``pfblockerng.inc`` ~16550-16558, inside
``if ($pfbadv && $list['vtype'] == '_v4')``). An install with ONLY v6 Deny
lists configured would never flip it, so v6 suppression would never fire in
isolation. Scenario B injects a trivial companion v4 Deny alias alongside the
v6 target for exactly this reason -- exercising the wiring as shipped, the
way a production box with both families configured would.

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
V4_BARE_HOSTS = ("203.0.113.60", "198.51.100.77")
V6_BARE_HOSTS = ("2001:db8:99::10", "2001:db8:aa::20")


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

    ``v4``/``v6`` are raw textarea lines (e.g. ``"198.18.3.4/32"``) -- every
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


def _pfctl_test(vm: SmokeVM, table: str, ip: str) -> tuple[bool, str]:
    """Run ``pfctl -t <table> -T test <ip>`` ONCE; return (matched, raw output).

    Same "1/1 addresses match" substring test as ``helpers.pfctl_table_test``,
    but also returns pf's own rendered output so a failing assertion can print
    it (CLAUDE.md "expected vs actual" -- never a bare derived boolean).
    ``pfctl -T test`` prints the match line on STDERR (verified live on
    FreeBSD), so both streams are combined -- stdout alone is always empty.
    """
    result = vm.ssh(h.PFCTL, "-t", table, "-T", "test", ip)
    raw = (result.stdout + result.stderr).strip()
    return "1/1 addresses match" in raw, raw


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

    Given: the v4 fixture feed (``198.18.0.0/16`` + two bare hosts) is loaded
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
    target = "198.18.3.4"
    sibling = "203.0.113.60"
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
    matched, raw = _pfctl_test(deployed_vm, spec.alias, target)
    assert matched, f"expected {target} to MATCH {spec.alias} before suppression; pfctl said: {raw!r}"
    matched, raw = _pfctl_test(deployed_vm, spec.alias, sibling)
    assert matched, f"expected {sibling} to MATCH {spec.alias} before suppression; pfctl said: {raw!r}"

    # WHEN: configure suppression for the target host only, then re-run.
    _set_suppression(deployed_vm, v4=[host_entry])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    # THEN: the target is carved out; the sibling -- an unrelated feed entry -- is untouched.
    matched, raw = _pfctl_test(deployed_vm, spec.alias, target)
    assert not matched, f"expected {target} to NO LONGER match {spec.alias} after suppression; pfctl said: {raw!r}"
    matched, raw = _pfctl_test(deployed_vm, spec.alias, sibling)
    assert matched, f"expected {sibling} to STILL match {spec.alias} after suppression; pfctl said: {raw!r}"

    # AND: the member file holds covering CIDRs, never a host explosion.
    lines = _member_lines(deployed_vm, f"{spec.header}_v4")
    carved = _carved_only(lines, V4_BARE_HOSTS)
    assert len(carved) == 16, (
        "expected 16 covering-CIDR entries for a /16 minus a /32 (ADR-53 §1.2's "
        f"measured bound); got {len(carved)}: {carved}\nfull member file ({len(lines)} lines): {lines}"
    )
    assert "198.18.0.0/23" in carved and "198.18.128.0/17" in carved, (
        "expected representative covering CIDRs '198.18.0.0/23' and '198.18.128.0/17' "
        f"(the same relative shape as the real-iprange-verified 10.0.0.0/16-10.0.3.4 vector); got {carved}"
    )


# --------------------------------------------------------------------------- #
# Scenario B -- v6 containing-range carve (v6 had NO carve mechanism before ADR-53)
# --------------------------------------------------------------------------- #


def test_suppression_v6_carves_containing_range_spares_sibling(deployed_vm: SmokeVM) -> None:
    """The persisted v6 engine (``pfb_suppress_file_v6()``, pure-PHP CIDR
    set-diff) carves a live-loaded /64 down to covering CIDRs -- v6 had NO
    carve mechanism at all before ADR-53.

    A trivial companion v4 Deny alias is injected alongside the v6 target: see
    the module docstring for why ($pfb['supp_update'] is a v4-only trigger).

    Given: the v6 fixture feed (``2001:db8:53::/64`` + two bare hosts) is
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

    companion_url = h.write_local_feed(deployed_vm, "smoke_adr53_v6companion.txt", "203.0.113.90\n")
    companion_spec = h.IpCase(aliasname="adr53v6bcompanion", feed_url=companion_url, header="adr53v6bcompanion")

    target = "2001:db8:53::42"
    sibling = "2001:db8:99::10"
    host_entry = f"{target}/128"

    h.inject_ip_lists(deployed_vm, [companion_spec, v6spec])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    members = h.wait_pfctl_table(deployed_vm, v6spec.alias)
    assert members, f"pf table {v6spec.alias} never populated after the settling update"
    matched, raw = _pfctl_test(deployed_vm, v6spec.alias, target)
    assert matched, f"expected {target} to MATCH {v6spec.alias} before suppression; pfctl said: {raw!r}"
    matched, raw = _pfctl_test(deployed_vm, v6spec.alias, sibling)
    assert matched, f"expected {sibling} to MATCH {v6spec.alias} before suppression; pfctl said: {raw!r}"

    # WHEN: configure v6 suppression, then re-run BOTH aliases -- the
    # companion's own re-parse is what flips $pfb['supp_update'] this pass.
    _set_suppression(deployed_vm, v6=[host_entry])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    matched, raw = _pfctl_test(deployed_vm, v6spec.alias, target)
    assert not matched, f"expected {target} to NO LONGER match {v6spec.alias} after suppression; pfctl said: {raw!r}"
    matched, raw = _pfctl_test(deployed_vm, v6spec.alias, sibling)
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
    inside_16 = "198.18.3.4"
    removed_host = "198.51.100.77"
    kept_host = "203.0.113.60"
    host_entry = f"{removed_host}/32"

    h.inject(deployed_vm, spec)
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    members = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert members, f"pf table {spec.alias} never populated after the settling update"
    for ip in (inside_16, removed_host, kept_host):
        matched, raw = _pfctl_test(deployed_vm, spec.alias, ip)
        assert matched, f"expected {ip} to MATCH {spec.alias} before suppression; pfctl said: {raw!r}"

    _set_suppression(deployed_vm, v4=[host_entry])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    matched, raw = _pfctl_test(deployed_vm, spec.alias, removed_host)
    assert not matched, f"expected {removed_host} to be REMOVED from {spec.alias}; pfctl said: {raw!r}"
    matched, raw = _pfctl_test(deployed_vm, spec.alias, kept_host)
    assert matched, f"expected {kept_host} to still match {spec.alias}; pfctl said: {raw!r}"
    matched, raw = _pfctl_test(deployed_vm, spec.alias, inside_16)
    assert matched, (
        f"expected {inside_16} (inside the untouched /16) to STILL match {spec.alias} -- "
        f"a bare-host suppression must never touch an unrelated /16 entry; pfctl said: {raw!r}"
    )

    lines = _member_lines(deployed_vm, f"{spec.header}_v4")
    assert len(lines) == 2, f"expected exactly 2 member-file lines (untouched /16 + surviving bare host); got {lines}"
    assert "198.18.0.0/16" in lines, f"expected the untouched /16 line verbatim (never carved); got {lines}"
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
    hole_ip = "198.18.5.9"
    sibling_ip = "198.18.9.9"
    hole_subnet = "198.18.5.0/24"

    h.inject(deployed_vm, spec)
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    members = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert members, f"pf table {spec.alias} never populated after the settling update"
    for ip in (hole_ip, sibling_ip):
        matched, raw = _pfctl_test(deployed_vm, spec.alias, ip)
        assert matched, f"expected {ip} to MATCH {spec.alias} before suppression; pfctl said: {raw!r}"

    _set_suppression(deployed_vm, v4=[hole_subnet])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    matched, raw = _pfctl_test(deployed_vm, spec.alias, hole_ip)
    assert not matched, (
        f"expected {hole_ip} (inside the suppressed /24) to NO LONGER match {spec.alias}; pfctl said: {raw!r}"
    )
    matched, raw = _pfctl_test(deployed_vm, spec.alias, sibling_ip)
    assert matched, f"expected {sibling_ip} (a different /24) to STILL match {spec.alias}; pfctl said: {raw!r}"

    lines = _member_lines(deployed_vm, f"{spec.header}_v4")
    carved = _carved_only(lines, V4_BARE_HOSTS)
    assert len(carved) == 8, (
        "expected 8 covering-CIDR entries for a /16 minus a /24 (24-16=8, the same "
        f"prefix-length-difference bound the shellspec proves for /24-/32=8); got {len(carved)}: {carved}\n"
        f"full member file ({len(lines)} lines): {lines}"
    )
