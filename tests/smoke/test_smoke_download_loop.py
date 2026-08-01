"""Live-VM smoke coverage for the download-loop cluster fixes (#709 / #710 / #712).

Four related bugs were fixed in ``sync_package_pfblockerng()``'s download/apply
loops (commit "pfblockerng: fix IP/DNSBL download-loop cluster …").  The two pure
helpers (#709 ``pfb_list_section_for_vtype`` / #711 ``pfb_prune_failed_bl_lists``)
are red->green unit-pinned off-box in ``tests/php/DownloadLoopHelpersTest.php``.
This module proves the CALLER-LEVEL behaviour that only a live pfBlockerNG update
pass exhibits — the part a pure unit test cannot reach:

* **#709 — a v4 IP list with "Invert src/dst" lands its members in its pf table.**
  The download loop runs AFTER the ``$ip_types`` collection loop, so ``$ip_type``
  was left stale at ``'pfblockernglistsv6'``.  A v4 list with the Advanced
  ``autoaddrnot_in='on'`` flag (which forces Alias-Native) therefore had its member
  file written to ``denydir`` (the stale-section read missed the invert flag and
  kept the Deny folder) while the Configure-Aliases loop — which recomputes the
  section correctly — read ``nativedir``.  The two disagreed, so the v4 list's IPs
  never reached its ``pfB_<alias>_v4`` table (empty table).  The fix derives the
  section from the list's OWN vtype (``pfb_list_section_for_vtype($list['vtype'])``).

* **#710 — the DNSBLIP auto firewall rule keeps its configured Invert.**  In the
  Configure-Aliases loop the synthetic DNSBLIP entry sits at foreach index N (= the
  number of configured IP lists) but its advanced settings live on the
  ``pfblockerngdnsblsettings`` config/0 singleton.  Passing the raw foreach index
  made ``pfb_determine_list_detail()`` read config/N and miss the invert (plus PHP
  8.3 undefined-key warnings), so the ``pfB_DNSBLIP_v4`` rule lost its ``!``
  negation.  The bug is MASKED when the index is 0 — so this test configures ≥1 v4
  IP list on purpose, pushing DNSBLIP to index 1.  The fix passes
  ``$list['key'] ?? $key`` (DNSBLIP carries key=0).

* **#712 — a DNSBL group's configured Source Interface is honoured on download.**
  ``$srcint`` was undefined at the top of the DNSBL group loop (only assigned later
  in the IP loop), so ``CURLOPT_INTERFACE`` was never set for a DNSBL feed and the
  ``"…will be downloaded via interface: <srcint>"`` log line (pfb_download, emitted
  only when ``$srcint`` is truthy) never appeared.  The fix sets
  ``$srcint = $list['srcint'] ?? '' ?: FALSE`` at the loop top.

Each test is a RED->GREEN oracle: against ``origin/devel`` (the pre-fix baseline —
the cluster fix is not yet on ``devel``) it FAILS for the exact documented reason;
against this branch it PASSES.

**#711 is DELIBERATELY not smoke-tested here (out-of-CI limitation).**  The #711
prune (a healthy already-downloaded Blacklist category dropped when a later feed
404s) exercises the LEGACY pre-defined "Blacklist" category download path
(``pfblockerng_download_extras`` + the ``pfblockerng.php bls`` child), NOT the
user-feed path the smoke harness drives.  Reproducing a mid-batch 404 in that
child on a live box is not cleanly achievable in the harness, and a contrived
approximation would be coverage theater.  #711 is fully red->green covered off-box
by ``tests/php/DownloadLoopHelpersTest.php`` (the helper is exercised against the
old positional-unset logic), which is the authoritative gate for that fix.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).  Run
via the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the smoke deps; without them these tests skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _MockFeedServer

pytestmark = pytest.mark.smoke

# The SLIRP WAN host-alias net the mock feed server rides (192.168.89.2).  The
# default-ON feed-host SSRF guard (pfb_feed_internal_filter) would reject the mock's
# RFC1918 address; allowlisting the net keeps the filter ON yet lets the mock fetch
# through — needed only by #712 (its DNSBL feed is fetched over HTTP so pfb_download
# takes the cURL path where the srcint log line lives).
SLIRP_FEED_NET = "192.168.89.0/24"

# A full set of per-direction "Advanced" fields, GUI defaults, so
# pfb_determine_list_detail() reads every key it expects (autoproto/autonot/
# autoaddrnot/agateway + autoports/autoaddr) with NO PHP 8.3 undefined-key warning —
# exactly the shape pfblockerng_category_edit.php persists.  A test overlays the one
# field it exercises (autoaddrnot_in/out) on top of this baseline.
_ADVANCED_FIELD_DEFAULTS: dict[str, str] = {
    "autoaddrnot_in": "",
    "autoaddrnot_out": "",
    "autoports_in": "",
    "autoports_out": "",
    "autoaddr_in": "",
    "autoaddr_out": "",
    "autonot_in": "",
    "autonot_out": "",
    "autoproto_in": "any",
    "autoproto_out": "any",
    "agateway_in": "default",
    "agateway_out": "default",
}


# --------------------------------------------------------------------------- #
# Module fixture — deploy once, plus a per-test clean slate
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def download_loop_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the download-loop module.

    Egress stays OPEN (``pkg add`` + the DNSBL feed fetch need a reachable
    network / the SLIRP mock).  The DNSBL VIP is injected (DNSBL force-disables
    itself without one) and the SLIRP mock net is allowlisted through the SSRF
    guard so #712's HTTP DNSBL feed downloads.  A full guest snapshot is collected
    on teardown for the workflow to upload.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.set_feed_internal_allowlist(smoke_vm, SLIRP_FEED_NET)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


@pytest.fixture(autouse=True)
def _clean_slate(download_loop_vm: SmokeVM) -> Iterator[None]:
    """Give every test an EMPTY pfBlockerNG config + the shared infra, before it runs.

    The module VM is one long-lived boot whose disk persists across tests, so a
    prior test's injected feeds/settings would bleed forward (e.g. a leftover v4 IP
    list would perturb #710's DNSBLIP index arithmetic — a false green).
    ``reset_pfb_baseline`` wipes the config to empty; it also drops the DNSBL VIP
    and the SSRF allowlist (both live in wiped sections), so re-establish them here
    so each test starts from an identical known baseline.
    """
    h.reset_pfb_baseline(download_loop_vm)
    h.ensure_dnsbl_vip(download_loop_vm)
    h.set_feed_internal_allowlist(download_loop_vm, SLIRP_FEED_NET)
    yield


# --------------------------------------------------------------------------- #
# Small on-box helpers
# --------------------------------------------------------------------------- #


def _file_present(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> bool:
    """True iff ``path`` exists on the guest (a plain ``test -f``)."""
    return vm.ssh("/bin/test", "-f", path, timeout=timeout).returncode == 0


def _read_file(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> str:
    """Return the guest file's text, or '' if it does not exist."""
    result = vm.ssh("cat", path, timeout=timeout)
    return result.stdout if result.returncode == 0 else ""


def _set_row_advanced_fields(
    vm: SmokeVM, section: str, rowid: str, fields: dict[str, str], *, timeout: float = 60.0
) -> None:
    """Merge ``fields`` into an ``installedpackages/<section>/config/<rowid>`` row.

    Mirrors how pfblockerng_category_edit.php persists a feed row's Advanced
    settings — a per-key ``config_set_path`` overlay — but done as one merge so the
    rest of the row (aliasname/action/row[]) written by ``inject`` is preserved.
    Written AFTER ``inject`` (which replaces its whole section) so the fields survive.
    """
    path = f"installedpackages/{section}/config/{rowid}"
    snippet = (
        f"$row = config_get_path({h._php_str(path)}, array());\n"
        f"$row = array_merge($row, {h._php_kv_array(fields)});\n"
        f"config_set_path({h._php_str(path)}, $row);\n"
        "write_config('pfBlockerNG smoke: set advanced feed fields');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_set_row_advanced_fields({section}/{rowid}) failed: "
            f"rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


# --------------------------------------------------------------------------- #
# #709 — a v4 Invert-src/dst list's members reach its pf table
# --------------------------------------------------------------------------- #


def test_709_invert_v4_list_members_reach_pf_table(download_loop_vm: SmokeVM) -> None:
    """A v4 Deny list with Invert-src/dst lands its feed IP in its pf table (not an empty one).

    Scenario (#709): the download loop must derive the per-list config section from
    the list's OWN vtype, not the stale ``$ip_type`` left over from the collection
    loop.

    **Given** exactly ONE v4 Deny IP list whose feed carries an RFC 5737 IP and whose
    Advanced ``autoaddrnot_in='on'`` (Invert src/dst) forces Alias-Native, and NO v6
    lists (so the stale ``$ip_type`` = ``'pfblockernglistsv6'`` reads a section that
    does not exist),

    **When** a full ``update`` runs,

    **Then** the member file lands in ``nativedir`` (Alias-Native's folder) — NOT
    ``denydir`` — so the Configure-Aliases loop (which also computes ``nativedir``)
    reads it; the last-applied alias mirror carries the fed IP; and the fed IP is a
    member of ``pfB_<alias>_v4``.

    Pre-fix (origin/devel): the stale-section read misses the invert flag, keeps the
    Deny folder, and writes the member file to ``denydir`` while the alias loop reads
    the empty ``nativedir`` — so the mirror is never written and the pf table is
    empty.  FAILS before the fix on all three checks; PASSES after.
    """
    vm = download_loop_vm
    fed_ip = "203.0.113.9"  # RFC 5737 TEST-NET-3
    header = "smokeinvert"
    spec = h.IpCase(aliasname="smokeinvert", feed_url="", header=header, action="Deny_Both", family="v4")

    # Given: the v4 Deny list + its local feed, with Invert-src/dst forcing Alias-Native.
    spec.feed_url = h.write_local_feed(vm, "smoke709_invert.txt", f"{fed_ip}\n")
    h.inject(vm, spec)
    fields = dict(_ADVANCED_FIELD_DEFAULTS)
    fields["autoaddrnot_in"] = "on"
    _set_row_advanced_fields(vm, "pfblockernglistsv4", "0", fields)

    # When: a full update runs.
    h.reload(vm, "update")
    h.apply_filter_sync(vm)

    native_member = f"{h.PFB_DBDIR}/native/{header}_v4.txt"
    deny_member = f"{h.PFB_DBDIR}/deny/{header}_v4.txt"
    mirror = f"/var/db/aliastables/{spec.alias}.txt"
    in_native = _file_present(vm, native_member)
    in_deny = _file_present(vm, deny_member)
    mirror_body = _read_file(vm, mirror)
    members = h.pfctl_table_members(vm, spec.alias)

    def _report() -> str:
        return (
            "  #709 — v4 Invert-src/dst list member routing:\n"
            f"    Expected member file : {native_member} PRESENT (Alias-Native folder)\n"
            f"    Expected NOT present : {deny_member} (the stale-section Deny folder)\n"
            f"    Expected mirror      : {mirror} contains {fed_ip}\n"
            f"    Expected pf table    : {spec.alias} contains {fed_ip}\n"
            f"  Actual:\n"
            f"    native member file present : {in_native}\n"
            f"    deny   member file present : {in_deny}\n"
            f"    mirror body                : {mirror_body.strip()!r}\n"
            f"    pf table members           : {members}"
        )

    # Then: the member file landed in nativedir (the section fix), not denydir.
    assert in_native, "member file NOT in nativedir — the download loop wrote to the wrong section\n" + _report()
    assert not in_deny, "member file ALSO in denydir — the stale v6-section read routed it wrong\n" + _report()
    # And: the alias mirror (pf's source of truth) carries the fed IP.
    assert fed_ip in mirror_body, "alias mirror missing the fed IP — the alias loop read an empty folder\n" + _report()
    # And: the fed IP actually reached the kernel pf table (the user-facing symptom).
    assert h.member_present(members, fed_ip), f"fed IP {fed_ip} not in {spec.alias} — empty table\n" + _report()


# --------------------------------------------------------------------------- #
# #710 — the DNSBLIP auto rule keeps its configured Invert (index != 0)
# --------------------------------------------------------------------------- #


def _dnsblip_rule_lines(vm: SmokeVM, *, timeout: float = 30.0) -> list[str]:
    """Return the ``pfctl -sr`` rule lines that reference ``pfB_DNSBLIP_v4``."""
    result = vm.ssh(h.PFCTL, "-sr", timeout=timeout)
    if result.returncode != 0:
        return []
    return [ln.strip() for ln in result.stdout.splitlines() if "pfB_DNSBLIP_v4" in ln]


def test_710_dnsblip_auto_rule_keeps_configured_invert(download_loop_vm: SmokeVM) -> None:
    """With ≥1 IP list present, the pfB_DNSBLIP_v4 auto rule carries its configured Invert.

    Scenario (#710): the synthetic DNSBLIP entry must read its advanced settings from
    the ``pfblockerngdnsblsettings`` config/0 singleton, not from config/N where N is
    its foreach index.

    **Given** DNSBL enabled with ``dnsbl_ip`` action = ``Deny_Both`` and Advanced
    ``autoaddrnot_in='on'`` + ``autoaddrnot_out='on'`` (Invert) set on the DNSBL-IP
    settings, AND exactly ONE configured v4 IP list — so the DNSBLIP synthetic entry
    sits at foreach index 1, not 0 (index 0 MASKS the bug: config[0] is the right
    singleton by luck, giving a false green),

    **When** a full ``update`` runs and the filter reload is applied,

    **Then** a loaded ``pfB_DNSBLIP_v4`` rule exists AND carries the ``!`` negation
    (the configured Invert reached the rule).

    Pre-fix (origin/devel): ``pfb_determine_list_detail`` is handed the foreach index
    (1) instead of the DNSBLIP key (0) and reads the non-existent config/1.  Observed
    live effect: the mis-read advanced settings drop the ``pfB_DNSBLIP_v4`` auto-rule
    ENTIRELY — pf loads NO v4 DNSBLIP rule at all (``pfB_DNSBLIP_v6``, built with the
    right index, is unaffected and still carries its ``!``).  So the test fails at the
    "rule exists" check before the fix; after the fix the rule is present AND carries
    the ``!`` invert.  (The bug's headline is "loses its Invert"; the live severity is
    stronger — the whole v4 rule vanishes.)
    """
    vm = download_loop_vm

    # Given: one plain v4 Deny IP list (occupies index 0, pushing DNSBLIP to index 1).
    ip_feed = h.write_local_feed(vm, "smoke710_ip.txt", "198.51.100.20\n")
    ip_spec = h.IpCase(aliasname="smoke710ip", feed_url=ip_feed, header="smoke710ip", action="Deny_Both", family="v4")
    h.inject(vm, ip_spec)

    # Given: a DNSBL group with DNSBL-IP = Deny_Both (so pfB_DNSBLIP_v4 is a rule-creating
    # alias).  Its feed carries a domain + an embedded IP so DNSBLIP_v4.txt is populated.
    dnsbl_feed = h.write_local_feed(vm, "smoke710_dnsbl.txt", f"{h.unique_domain()}\n203.0.113.42\n")
    dnsbl_spec = h.DnsblCase(
        aliasname="smoke710dnsbl",
        feed_url=dnsbl_feed,
        header="smoke710dnsbl",
        mode=h.DnsblMode.VIP,
        dnsbl_ip_action="Deny_Both",
    )
    h.inject(vm, dnsbl_spec)

    # Given: the Invert (autoaddrnot) advanced fields on the DNSBL-IP settings singleton
    # (config/0 of pfblockerngdnsblsettings) — the settings pfb_determine_list_detail must
    # read via the DNSBLIP key, not the foreach index.
    fields = dict(_ADVANCED_FIELD_DEFAULTS)
    fields["autoaddrnot_in"] = "on"
    fields["autoaddrnot_out"] = "on"
    _set_row_advanced_fields(vm, "pfblockerngdnsblsettings", "0", fields)

    # When: a full update runs; make the pf ruleset authoritative (filter_configure is async).
    h.reload(vm, "update")
    h.apply_filter_sync(vm)

    lines = _dnsblip_rule_lines(vm)

    def _report() -> str:
        body = "\n".join(f"      {ln}" for ln in lines) if lines else "      (no rule references pfB_DNSBLIP_v4)"
        return (
            "  #710 — pfB_DNSBLIP_v4 auto-rule Invert:\n"
            "    Expected: a loaded rule referencing pfB_DNSBLIP_v4 that carries the '!' negation\n"
            "              (source/dest inverted — the configured autoaddrnot_in/out='on').\n"
            f"  Actual pfB_DNSBLIP_v4 rules (pfctl -sr):\n{body}"
        )

    # First red symptom: pre-fix the wrong-index read drops the v4 DNSBLIP rule ENTIRELY,
    # so pf loads no rule referencing pfB_DNSBLIP_v4.  This is NOT a setup problem — the
    # IDENTICAL setup builds the rule once the fix reads config/0 (proven by the green leg).
    assert lines, "no pf rule references pfB_DNSBLIP_v4 — the v4 DNSBLIP auto-rule was not created\n" + _report()
    # Second check (post-fix regression guard): the rebuilt rule carries the invert negation,
    # so a future regression that keeps the rule but drops the '!' is still caught.
    assert any("!" in ln for ln in lines), (
        "the pfB_DNSBLIP_v4 rule lost its configured Invert (no '!' negation) — "
        "the DNSBLIP advanced settings were read from the wrong config index\n" + _report()
    )


# --------------------------------------------------------------------------- #
# #712 — a DNSBL group's Source Interface is honoured on download
# --------------------------------------------------------------------------- #


def test_712_dnsbl_source_interface_used_on_download(download_loop_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A DNSBL group configured with a Source Interface downloads its feed via that interface.

    Scenario (#712): ``$srcint`` must be set at the top of the DNSBL group loop so a
    DNSBL feed's cURL download binds ``CURLOPT_INTERFACE`` — mirroring the IP loop.

    **Given** a DNSBL group whose feed is served over HTTP (so pfb_download takes the
    cURL path, where the source-interface log line lives) and whose ``srcint`` is set
    to the box's real WAN interface, with the feed forced to re-download (no reuse),

    **When** a DNSBL ``update`` runs,

    **Then** the pfBlockerNG log gains a NEW ``"…will be downloaded via interface:
    <realif>"`` line for this feed — pfb_download only logs it when ``$srcint`` is
    truthy.

    Pre-fix (origin/devel): ``$srcint`` is undefined in the DNSBL loop (only assigned
    later in the IP loop) → falsy → ``CURLOPT_INTERFACE`` unset and the log line never
    written.  The before/after log-count delta is 0 before the fix, ≥1 after.
    """
    vm = download_loop_vm

    # The box's real WAN interface — what the GUI stores in 'srcint' (the realif key of
    # get_configured_interface_list_by_realif); WAN is the interface that reaches the
    # SLIRP mock at 192.168.89.2, so the bound download still succeeds.
    realif = h._php_read_scalar(vm, "", "get_real_interface('wan')").strip()
    if not realif:
        pytest.skip("could not resolve the WAN real interface for the srcint test")

    header = "smoke712dl"
    # Serve the DNSBL feed over HTTP so pfb_download takes the cURL branch (a local-file
    # feed never reaches the srcint log line, which lives only in the cURL path).
    feed_url = mock_feeds.register("smoke712_dnsbl.txt", f"{h.unique_domain()}\n")
    spec = h.DnsblCase(aliasname="smoke712dnsbl", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)
    h.inject(vm, spec)

    # Set the DNSBL group's Source Interface (srcint lives on the DNSBL list row, config/0).
    _set_row_advanced_fields(vm, "pfblockerngdnsbl", "0", {"srcint": realif})

    # Force a real re-download (defeat the reuse gate) so pfb_download runs this pass.
    h.force_dnsbl_refetch(vm, header)

    marker = f"will be downloaded via interface: {realif}"
    before = h.count_log_marker(vm, h.PFB_LOG, marker)
    h.reload(vm, "updatednsbl")
    after = h.count_log_marker(vm, h.PFB_LOG, marker)

    log_tail = _read_file(vm, h.PFB_LOG)[-1500:]
    assert after > before, (
        "  #712 — DNSBL Source Interface on download:\n"
        f"    Expected: a NEW '{marker}' line in {h.PFB_LOG} after the DNSBL update\n"
        f"              (pfb_download logs it only when $srcint is truthy).\n"
        f"    Actual:   marker count before={before}, after={after} (no new line)\n"
        f"    srcint (WAN realif) = {realif!r}\n"
        f"  Log tail:\n{log_tail}"
    )
