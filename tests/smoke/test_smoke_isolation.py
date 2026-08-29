"""Live-VM coverage for the smoke-harness ISOLATION keystone (helpers.reset_pfb_baseline
+ the DNSBL settings replace-not-merge).

The session VM is ONE long-lived boot whose copy-on-write disk persists across every test
and module, and ``helpers.reset()`` clears only the pf tables/sqlite — NOT ``config.xml`` —
so injected feeds / settings / global toggles / Host Overrides bleed into the next module
along collection order. ``reset_pfb_baseline`` is the missing clean slate; the autouse
``_pfb_module_baseline`` teardown in ``conftest.py`` runs it after every smoke module.

These two tests pin the keystone's behaviour (red→green vs the old ``reset()``):

* ``test_reset_pfb_baseline_clears_injected_config`` — the wipe deletes the injected IP list
  config, unsets ``enable_cb``, AND removes the smoke control Host Override. ``reset()`` would
  LEAVE all three (it keeps ``config.xml`` and only drops/rebuilds the pf tables), so each
  assertion fails on the old path and passes on the new one. (The derived-state teardown —
  tables/sqlite/pf rules — is ``reset()``'s existing ``clearip``/``cleardnsbl`` path, already
  covered; the NEW behaviour proved here is the config deletion.)
* ``test_dnsbl_inject_replaces_leaked_toggle`` — a later DNSBL case's settings are EXACTLY what
  it declares: a prior case's ``pfb_hsts`` does not survive (replace-not-merge), while the
  VIP/port infrastructure ``ensure_dnsbl_vip`` set IS preserved (so DNSBL is not force-disabled).
  A plain ``array_merge`` leaves ``pfb_hsts=on`` leaked → the first ``Then`` fails on the old path.

Two more (issue #1214), same keystone family:

* ``test_inject_ip_lists_resets_untouched_family`` — a family absent from an
  ``inject_ip_lists`` call is reset to empty, not left holding a PRIOR call's list group.
* ``test_reset_pfb_baseline_clears_geoip_dataset`` — ``reset_pfb_baseline`` removes every
  ``seed_geoip_dataset`` artifact (CSVs, mmdb, generated GUI pages), so a later module never
  reads a fake GeoIP corpus a prior module seeded.

One more (issue #1456), the single-case sibling of the #1214 fix:

* ``test_inject_resets_untouched_family`` — a family absent from a single-case ``inject()``
  call is reset to empty too, not left holding a PRIOR call's list group.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

# host_entries.conf is the Unbound-included file pfSense generates from the DNS-Resolver Host
# Overrides (unbound/hosts). A smoke control name lands here after set_control_records and must
# be GONE after reset_pfb_baseline removes the row + regenerates the resolver config.
HOST_ENTRIES_CONF = "/var/unbound/host_entries.conf"


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg + the DNSBL VIP baseline for the isolation tests.

    No stub DNS / client VM / feed fetch: these tests assert at the config + host_entries.conf
    level, so they never load a feed or resolve a name. ``ensure_dnsbl_vip`` is what sets the
    VIP/port infra keys the replace-not-merge test asserts are preserved.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def _host_entry_present(vm: SmokeVM, name: str) -> bool:
    """True iff ``name`` is a line in the live host_entries.conf (the resolver's view)."""
    return vm.ssh("grep", "-Fq", name, HOST_ENTRIES_CONF).returncode == 0


_COUNT_OPEN, _COUNT_CLOSE = "<<PFBCOUNT>>", "<</PFBCOUNT>>"


def _section_count(vm: SmokeVM, path: str) -> int:
    """Number of elements in a config section (0 when absent), read via the config API."""
    snippet = f"echo '{_COUNT_OPEN}' . count((array) config_get_path('{path}', array())) . '{_COUNT_CLOSE}';"
    out = h.php_eval(vm, snippet).stdout
    start, end = out.find(_COUNT_OPEN), out.find(_COUNT_CLOSE)
    assert start != -1 and end != -1, f"could not read element count for {path}: {out!r}"
    return int(out[start + len(_COUNT_OPEN) : end])


def test_reset_pfb_baseline_clears_injected_config(deployed_vm: SmokeVM) -> None:
    """reset_pfb_baseline DELETES the injected list config, unsets enable_cb, AND removes the
    control Host Override — the three config surfaces reset() would LEAVE behind (it keeps
    config.xml and only touches the pf tables). This is what makes the next module start clean.

    Scenario:
      Given a clean box (no IP list config, the control override absent),
      When an IP list + a smoke control Host Override are injected,
      Then the IP list section is populated, enable_cb is 'on', and the override is live;
      When reset_pfb_baseline runs,
      Then the IP list section is gone, enable_cb is unset, and the override is gone.
    """
    vm = deployed_vm
    # The feed_url is never fetched — inject() only WRITES config; we assert config, no reload.
    spec = h.IpCase(aliasname="smokeisoip4", feed_url="http://192.168.89.2/ip_plain_cidr.txt", header="smokeisoip4")
    control_name = h.unique_domain()
    enable_cb_key = h.CFG_GLOBAL + "/enable_cb"

    # GIVEN a clean baseline: no IP list config, the control name not in host_entries.conf.
    assert _section_count(vm, h.CFG_IP_V4_LISTS) == 0, "IP list section non-empty before any inject"
    assert not _host_entry_present(vm, control_name), f"{control_name} in host_entries.conf before it was added"

    # WHEN we inject an IP list + a smoke control Host Override.
    h.set_control_records(vm, {control_name: {"A": "203.0.113.9"}}, {})
    h.inject(vm, spec)

    # THEN all three config surfaces are LIVE (the before-state the wipe below must clear).
    assert _section_count(vm, h.CFG_IP_V4_LISTS) == 1, "inject did not write the IP list section"
    assert h.config_get(vm, enable_cb_key) == "on", "inject did not set enable_cb — fixture broken"
    assert _host_entry_present(vm, control_name), f"{control_name} not in host_entries.conf after set_control_records"

    # WHEN the clean-baseline reset runs.
    h.reset_pfb_baseline(vm)

    # THEN every injected config surface is gone (reset() would keep all three).
    surviving = _section_count(vm, h.CFG_IP_V4_LISTS)
    assert surviving == 0, f"IP list section survived reset_pfb_baseline ({surviving} rows; reset() keeps it)"
    leftover_cb = h.config_get(vm, enable_cb_key)
    assert leftover_cb == "", f"enable_cb survived reset_pfb_baseline: {leftover_cb!r} (reset() leaves it 'on')"
    assert not _host_entry_present(vm, control_name), f"{control_name} survived reset_pfb_baseline in host_entries.conf"


def test_dnsbl_inject_replaces_leaked_toggle(deployed_vm: SmokeVM) -> None:
    """A DNSBL case's settings are EXACTLY what it declares: a prior case's pfb_hsts does not
    leak into a later one (replace-not-merge), while the VIP/port infrastructure is preserved.

    Scenario:
      Given the DNSBL VIP infra is set (deployed_vm ran ensure_dnsbl_vip),
      When a case with HSTS-null blocking is injected,
      Then pfb_hsts is 'on';
      When a later case WITHOUT hsts is injected (reset() between cases never clears config, so a
        plain array_merge would keep pfb_hsts=on),
      Then pfb_hsts is gone AND the VIP infra key is still present (DNSBL stays enabled).
    """
    vm = deployed_vm
    hsts_key = h.CFG_DNSBL_SETTINGS + "/pfb_hsts"
    vip_key = h.CFG_DNSBL_SETTINGS + "/pfb_dnsvip4"
    # The feed_url is never fetched here — inject() only WRITES config; we read it back, no reload.
    feed = "http://192.168.89.2/dnsbl_plain.txt"

    # GIVEN the VIP infrastructure is in place. Establish it HERE (idempotent), not via the
    # module fixture alone: a sibling test's reset_pfb_baseline wipes CFG_DNSBL_SETTINGS (incl.
    # pfb_dnsvip4), so this test owns its own precondition rather than depending on test order.
    h.ensure_dnsbl_vip(vm)
    assert h.config_get(vm, vip_key) != "", "precondition: ensure_dnsbl_vip should set pfb_dnsvip4"

    # WHEN a case that enables HSTS-null blocking is injected, THEN pfb_hsts is written 'on'.
    h.inject(vm, h.DnsblCase(aliasname="smokeisohsts", feed_url=feed, header="smokeisohsts", hsts=True))
    assert h.config_get(vm, hsts_key) == "on", "inject(hsts=True) did not set pfb_hsts=on"

    # WHEN a later case WITHOUT hsts is injected in the same module.
    h.inject(vm, h.DnsblCase(aliasname="smokeisoplain", feed_url=feed, header="smokeisoplain"))

    # THEN the leaked toggle is gone (replace, not merge) ...
    leaked = h.config_get(vm, hsts_key)
    assert leaked == "", f"pfb_hsts leaked across DNSBL cases: {leaked!r} (array_merge would keep 'on')"
    # ... and the VIP infrastructure key is PRESERVED (a naive config_del would force-disable DNSBL).
    assert h.config_get(vm, vip_key) != "", "replace dropped pfb_dnsvip4 — would force-disable DNSBL"


def test_inject_ip_lists_resets_untouched_family(deployed_vm: SmokeVM) -> None:
    """A family absent from an inject_ip_lists() call is reset to empty, not left holding a
    PRIOR call's list group (issue #1214) -- proved in BOTH directions.

    Scenario:
      Given a v6 IP list injected via inject_ip_lists,
      When a LATER inject_ip_lists call in the same module injects only a v4 spec,
      Then the v6 list-config root is EMPTY (not the leaked-forward v6 list) and the v4
        root holds exactly the new spec (the issue's reported shape);
      When a THIRD call injects only a v6 spec (the mirror direction),
      Then the now-untouched v4 root is EMPTY too, and the v6 root holds the newest spec.
    """
    vm = deployed_vm
    feed_url = "http://192.168.89.2/ip_plain_cidr.txt"
    v6spec = h.IpCase(aliasname="smokeisoipv6", feed_url=feed_url, header="smokeisoipv6", family="v6")
    v4spec = h.IpCase(aliasname="smokeisoipv4", feed_url=feed_url, header="smokeisoipv4")
    v6spec2 = h.IpCase(aliasname="smokeisoipv6b", feed_url=feed_url, header="smokeisoipv6b", family="v6")

    # GIVEN a v6-only inject_ip_lists call.
    h.inject_ip_lists(vm, [v6spec])
    assert _section_count(vm, h.CFG_IP_V6_LISTS) == 1, "inject_ip_lists did not write the v6 list section"

    # WHEN a LATER call injects only a v4 spec.
    h.inject_ip_lists(vm, [v4spec])

    # THEN the untouched v6 root is reset to empty (not left holding the prior v6 list) ...
    leaked = _section_count(vm, h.CFG_IP_V6_LISTS)
    assert leaked == 0, f"v6 list root leaked forward from a prior inject_ip_lists call ({leaked} rows)"
    # ... and the v4 root holds exactly the new spec.
    assert _section_count(vm, h.CFG_IP_V4_LISTS) == 1, "inject_ip_lists did not write the v4 list section"

    # WHEN a THIRD call injects only a v6 spec (the mirror direction).
    h.inject_ip_lists(vm, [v6spec2])

    # THEN the now-untouched v4 root is reset to empty too ...
    leaked_v4 = _section_count(vm, h.CFG_IP_V4_LISTS)
    assert leaked_v4 == 0, f"v4 list root leaked forward from a prior inject_ip_lists call ({leaked_v4} rows)"
    # ... and the v6 root holds exactly the newest spec.
    assert _section_count(vm, h.CFG_IP_V6_LISTS) == 1, "inject_ip_lists did not write the v6 list section (3rd call)"


def test_inject_resets_untouched_family(deployed_vm: SmokeVM) -> None:
    """A family absent from a single-case inject() call is reset to empty, not left holding a
    PRIOR call's list group (issue #1456, the ``inject_ip_lists``/#1214 fix's single-case
    sibling: ``_ip_inject_snippet`` only wrote its OWN family's root) -- proved in BOTH
    directions.

    Scenario:
      Given a v6 IP list injected via inject(),
      When a LATER inject() call in the same module injects only a v4 spec,
      Then the v6 list-config root is EMPTY (not the leaked-forward v6 list) and the v4
        root holds exactly the new spec (the issue's reported shape);
      When a THIRD call injects only a v6 spec (the mirror direction),
      Then the now-untouched v4 root is EMPTY too, and the v6 root holds the newest spec.
    """
    vm = deployed_vm
    feed_url = "http://192.168.89.2/ip_plain_cidr.txt"
    v6spec = h.IpCase(aliasname="smokeisoinjv6", feed_url=feed_url, header="smokeisoinjv6", family="v6")
    v4spec = h.IpCase(aliasname="smokeisoinjv4", feed_url=feed_url, header="smokeisoinjv4")
    v6spec2 = h.IpCase(aliasname="smokeisoinjv6b", feed_url=feed_url, header="smokeisoinjv6b", family="v6")

    # GIVEN a v6-only inject() call.
    h.inject(vm, v6spec)
    assert _section_count(vm, h.CFG_IP_V6_LISTS) == 1, "inject did not write the v6 list section"

    # WHEN a LATER call injects only a v4 spec.
    h.inject(vm, v4spec)

    # THEN the untouched v6 root is reset to empty (not left holding the prior v6 list) ...
    leaked = _section_count(vm, h.CFG_IP_V6_LISTS)
    assert leaked == 0, f"v6 list root leaked forward from a prior inject() call ({leaked} rows)"
    # ... and the v4 root holds exactly the new spec.
    assert _section_count(vm, h.CFG_IP_V4_LISTS) == 1, "inject did not write the v4 list section"

    # WHEN a THIRD call injects only a v6 spec (the mirror direction).
    h.inject(vm, v6spec2)

    # THEN the now-untouched v4 root is reset to empty too ...
    leaked_v4 = _section_count(vm, h.CFG_IP_V4_LISTS)
    assert leaked_v4 == 0, f"v4 list root leaked forward from a prior inject() call ({leaked_v4} rows)"
    # ... and the v6 root holds exactly the newest spec.
    assert _section_count(vm, h.CFG_IP_V6_LISTS) == 1, "inject did not write the v6 list section (3rd call)"


def test_reset_pfb_baseline_clears_geoip_dataset(deployed_vm: SmokeVM) -> None:
    """reset_pfb_baseline undoes seed_geoip_dataset's on-box footprint: a later module must
    not inherit a fake GeoIP corpus a prior module seeded (issue #1214).

    Scenario:
      Given the MaxMind-DB test corpus is seeded (CSVs, mmdb, generated GUI pages),
      When reset_pfb_baseline runs,
      Then every seeded/generated GeoIP artifact is gone.
    """
    vm = deployed_vm
    mmdb_path = f"{h.GEOIP_SHARE_DIR}/GeoLite2-Country.mmdb"
    a_page = f"{h.PFB_WWW_DIR}/{h.GEOIP_CONTINENT_PAGES[0]}"

    # GIVEN the GeoIP corpus is seeded.
    h.seed_geoip_dataset(vm)
    assert vm.ssh("test", "-f", mmdb_path).returncode == 0, "seed_geoip_dataset did not write the mmdb fixture"
    assert vm.ssh("test", "-f", a_page).returncode == 0, "seed_geoip_dataset did not generate the Africa page"

    # WHEN the clean-baseline reset runs.
    h.reset_pfb_baseline(vm)

    # THEN every seeded/generated GeoIP artifact is gone.
    assert vm.ssh("test", "-f", mmdb_path).returncode != 0, "mmdb fixture survived reset_pfb_baseline"
    assert vm.ssh("test", "-f", a_page).returncode != 0, "generated Africa page survived reset_pfb_baseline"
