"""Tier-A HTTP render-smoke sweep over every pfBlockerNG page (ADR-14 Phase 2).

Marker ``ui_render`` -- collected only by the smoke/ui workflow
(``pytest tests/smoke -m ui_render --override-ini="addopts="``); the whole
``tests/smoke`` tree is ``--ignore``d in the default ``python -m pytest`` run, so
this never affects the default suite.

Every authenticated pfBlockerNG webConfigurator page (:data:`PAGE_TABLE`) is
GET via the reused Phase-1 :class:`~tests.smoke.ui.webui.WebUI` session and run
through the real oracle (:func:`~tests.smoke.ui.render_oracle.evaluate_render`):
HTTP 200 + no PHP diagnostic in the body + a page-specific marker present, AND
(sweep-level) the on-box ``php_error.log`` gained no new line during the sweep
(:class:`~tests.smoke.ui.render_oracle.PhpErrorLogGuard`). A bare 200 never
passes -- proven by ``test_render_oracle.py`` feeding the oracle a broken body.

Hermeticity (ADR §2 "Hermetic where it claims to be"): every page in the table
renders from local config alone -- none triggers a feed download to produce its
chrome. The GeoIP/Reputation per-continent pages ``pfblockerng_geoip.inc`` WRITES
when invoked by the ``pfblockerng.php`` CLI dispatcher via its credential-free,
network-free `ugc` verb are generated after MaxMind's public test corpus is seeded
(:func:`~tests.smoke.helpers.seed_geoip_dataset`, wired into
:data:`~tests.smoke.ui.conftest.deployed_vm`) and included in the table below. Only
the DNSBL-VIP sinkhole pages (served by a separate lighttpd, unreachable from this
authenticated session) are recorded in :data:`EXCLUDED_FROM_TIER_A` with the reason
and the access note for Phase 5, NOT silently dropped.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from tests._workflow_steps import extract_between

from .. import helpers, pkg_identity
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_category import _snapshot_node
from .test_category_edit import CFG_DNSBL, CFG_IPV4, _del_rowid, _free_rowid
from .webui import row_containing, scrape_form_fields

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render


@dataclass(frozen=True)
class Page:
    """One Tier-A page: a webConfigurator path + the markers that prove it rendered.

    ``markers`` are stable strings drawn from the page's real ``$pgtitle``
    breadcrumb crumb and/or a ``Form_Section`` panel title (rendered verbatim
    into the HTML). ``hermetic`` is documentary -- every entry here is hermetic;
    a non-hermetic page lives in :data:`EXCLUDED_FROM_TIER_A` instead.
    """

    name: str
    path: str
    markers: tuple[str, ...]
    hermetic: bool = True


# The authenticated main-webConfigurator pages under src/usr/local/www/pfblockerng/.
# Markers verified against each file's $pgtitle / Form_Section('...') title.
#
# Multi-mode pages are probed in EACH mode they expose via a query parameter, so
# both branches of the page's mode switch are exercised (CLAUDE.md branch
# coverage): pfblockerng_category.php and _category_edit.php render an IP view by
# default and a DNSBL view under ?type=dnsbl; both are listed.
PAGE_TABLE: tuple[Page, ...] = (
    # "Advanced Text Editor" is the issue #1888 label of the pfb_syntax_highlight checkbox
    # (renamed from "Syntax Highlighting") — a third marker for the rendered field label.
    # The reorg-introduced label is pinned by test_general_private_address_label_renders,
    # not added here: the oracle matches markers with any(), so a fifth marker beside four
    # already-present ones would gate nothing.
    Page(
        "general",
        "/pfblockerng/pfblockerng_general.php",
        ("pfBlockerNG", "General Settings", "Scheduling", "Advanced Text Editor"),
    ),
    # "Aggregated Aliases" is the ADR-11 pfb_agg_types multi-select label (rendered
    # verbatim) — a third marker so the gate also proves that field renders on the IP page.
    # "IPv6 Suppression" is the ADR-53 Phase 6 section title (the v6 sibling of the
    # pre-existing "IPv4 Suppression" section) — proves the new section renders.
    Page(
        "ip",
        "/pfblockerng/pfblockerng_ip.php",
        (
            "IP Configuration",
            "IP Interface/Rules Configuration",
            "ASN configuration",
            "Advanced Settings",
            "Aggregated Aliases",
            "Alias Table Apply Mode",
            "IPv6 Suppression",
        ),
    ),
    # "DNS Redirect" is the ADR-36 section title added to this page (Phase 3).
    # "DoT/DoQ Block" is the ADR-37 section title added to this page (Phase 3).
    # "Permit Firewall Rules" + "Interface(s)" are the two field labels of the #478
    # stacked layout (the toggle and the interface selector now render as separate
    # rows) -- the markers prove both fields render; the *visual* stacking is the
    # ui_browser/maintainer tier. "no-AAAA" is the #480 label/section text (verbatim
    # hyphenated form, guarding the #480 text against a casing/hyphen regression).
    Page(
        "dnsbl",
        "/pfblockerng/pfblockerng_dnsbl.php",
        (
            "DNSBL Webserver Configuration",
            "DNS Caching",
            "AdBlock suffix handling",
            "TLD Allow list",
            "DNS Redirect",
            "DoT/DoQ Block",
            "Permit Firewall Rules",
            "Interface(s)",
            "no-AAAA",
            "pfb_dnsbl_nonat",  # issue-#381 NAT opt-out checkbox (name= attr in rendered HTML)
            # issue #1255: corrected Wildcard Blocking (TLD) help — no more stale "Force
            # Reload required" claim; toggling now applies on the next DNSBL update.
            "Enabling or disabling this option takes effect on the next DNSBL update",
            "pfB_DNSBLIP_v4",  # DNSBL IPs help text names the real alias (was stale 'pfB_DNSBL_IP')
            # Permit-rules help renders as one flowing sentence — a stray <br /> split
            # "...to access<br />the DNSBL Webserver", so this space-joined phrase is the
            # red→green guard (absent with the <br />, present once it is a space).
            "Selected Interface(s) to access the ",
            # issue #1669 slice C: the vendored CodeMirror 6 bundle include -- proves the
            # pfb_regex_list live-highlighting asset is wired on the page. Present because
            # the gating pfb_syntax_highlight toggle defaults on for a fresh box.
            "vendor/codemirror/cm-regex.min.js",
            # issue #1541: the renamed PSL-era controls and both PRIVATE-policy
            # toggles render with their outcome-based labels.
            "Wildcard Blocking",
            "Recognize Shared-Hosting Suffixes (PSL PRIVATE)",
            "Allow Only Selected Domain Suffixes",
            "Allow Shared-Hosting Suffixes (PSL PRIVATE)",
            # issue #2371 Step 3: the two feed-at-suffix policy selects render with
            # their labels and (one representative) option text.
            "Feed entries at shared-hosting suffixes (PSL PRIVATE)",
            "Feed entries at public suffixes (ICANN)",
            "Block the suffix apex only",
            # Enable DNSBL infoblock: v4 evaluate_domain() order (not the v3 pfb_py_block text).
            "DNSBL evaluation order",
            "first match wins",
        ),
    ),
    # feeds.php is split into IPv4/IPv6/DNSBL ?type sub-tabs (ADR-16 Phase 3). Each type
    # is probed; the type-specific marker is the active type's "Feed Settings" alias-name
    # StaticText label ("IPv4 Alias name(s):" etc.), which renders ONLY for the active
    # type -- so it distinguishes the three views (the panel title is shared by all). The
    # coverage guard strips "?", so all three collapse to the one base path.
    Page(
        "feeds_ipv4",
        "/pfblockerng/pfblockerng_feeds.php?type=ipv4",
        ("Pre-defined Alias/Group/Feeds", "IPv4 Alias name(s):"),
    ),
    Page(
        "feeds_ipv6",
        "/pfblockerng/pfblockerng_feeds.php?type=ipv6",
        ("Pre-defined Alias/Group/Feeds", "IPv6 Alias name(s):"),
    ),
    Page(
        "feeds_dnsbl",
        "/pfblockerng/pfblockerng_feeds.php?type=dnsbl",
        ("Pre-defined Alias/Group/Feeds", "DNSBL Alias name(s):"),
    ),
    Page("alerts", "/pfblockerng/pfblockerng_alerts.php", ("Alert Settings",)),
    # The Reports sub-tabs are the same page under ?view=; the stats views (IP Block
    # Stats + DNSBL Block Stats, issue #387) traverse the view switch + the per-stat-type
    # two-column render path. The sub-tab nav label is rendered on every view
    # (data-independent), so it is the marker. The pie panels themselves are alert-data
    # gated, and the responsive-layout + print-stylesheet *visual* correctness added for
    # #387 is an ADR-14 out-of-CI item (ui_browser tier + maintainer), not asserted here;
    # these entries guard the stats view-handler paths against a PHP render regression.
    Page("alerts_ip_block_stat", "/pfblockerng/pfblockerng_alerts.php?view=ip_block_stat", ("IP Block Stats",)),
    Page("alerts_dnsbl_stat", "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat", ("DNSBL Block Stats",)),
    Page("log", "/pfblockerng/pfblockerng_log.php", ("Log/File Browser selections",)),
    Page("sync", "/pfblockerng/pfblockerng_sync.php", ("XMLRPC Sync Settings",)),
    Page("safesearch", "/pfblockerng/pfblockerng_safesearch.php", ("SafeSearch settings", "DNSBL SafeSearch")),
    Page(
        "update",
        "/pfblockerng/pfblockerng_update.php",
        ("Update Settings", "Schedule"),
    ),
    # blacklist.php is always the DNSBL Category view; the long info line is a stable literal.
    Page(
        "blacklist",
        "/pfblockerng/pfblockerng_blacklist.php",
        ("DNSBL Category Feeds are processed first", "DNSBL Category"),
    ),
    # category.php: default IP view (?type=ipv4) AND the DNSBL view (?type=dnsbl).
    Page("category_ip", "/pfblockerng/pfblockerng_category.php?type=ipv4", ("Summary", "pfBlockerNG")),
    Page("category_dnsbl", "/pfblockerng/pfblockerng_category.php?type=dnsbl", ("Summary", "DNSBL")),
    # GeoIP summary: the IP-tab credentials pointer is always rendered (not gated on
    # a missing key), so it is a stable marker even on a box that already has MaxMind.
    Page(
        "category_geoip",
        "/pfblockerng/pfblockerng_category.php?type=geoip",
        ("Summary", "MaxMind Account ID and License Key"),
    ),
    # category_edit.php: default IP view AND the DNSBL view. "Override Default Schedule"
    # is unique to this page now that the IP tab also has an Advanced Settings section.
    Page(
        "category_edit_ip",
        "/pfblockerng/pfblockerng_category_edit.php?type=ipv4",
        (
            "Override Default Schedule",
            "schedule_override",
            "schedule_weekday",
            "schedule_hour",
            "schedule_minute",
        ),
    ),
    # issue #1926: the DNSBL-only pre-script warning (script_pre help text) must render
    # on the dnsbl view. Markers assert presence only, so the IP view's tuple simply
    # omits it; the DNSBL-only conditioning is pinned server-side by
    # DnsblListScriptWiringTest's help-note test.
    Page(
        "category_edit_dnsbl",
        "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl",
        (
            "A DNSBL pre-process script must not remove",
            "Override Default Schedule",
            "schedule_override",
            "schedule_weekday",
            "schedule_hour",
            "schedule_minute",
        ),
    ),
    # ?type=ipv6 renders the issue-#760 §3 "Suppression CIDR Limit" select block (gated
    # `if ($gtype == 'ipv6')`, a code path the ipv4/dnsbl entries above never exercise) --
    # this entry guards it against a PHP render regression.
    Page(
        "category_edit_ipv6",
        "/pfblockerng/pfblockerng_category_edit.php?type=ipv6",
        (
            "Suppression CIDR Limit",
            "Override Default Schedule",
            "schedule_override",
            "schedule_weekday",
            "schedule_hour",
            "schedule_minute",
        ),
    ),
    # issue #1211: the fresh add/addgroup-row $pconfig block (:868-914) reads keys a
    # fresh row never populates. This GET exercises that exact path (no config write --
    # act=addgroup/atype without $_POST['save'] never persists). NOTE: this tier CANNOT
    # observe the "Undefined array key" defect class itself -- the smoke guest runs at
    # error_reporting E_ALL ^ (E_WARNING|E_NOTICE|E_DEPRECATED) with display_errors=off
    # (issue #1218), so a regression here would only be caught by a FATAL (a bad `??`
    # default that breaks rendering). CategoryEditFreshRowPconfigTest (PHPUnit, full
    # error_reporting) is the oracle for the guard itself; this entry is render-hermeticity
    # coverage only.
    Page(
        "category_edit_fresh_addgroup_whitelist",
        "/pfblockerng/pfblockerng_category_edit.php?type=ipv4&act=addgroup&atype=Whitelist%7C192.0.2.55%7Csmoke-1211",
        ("Override Default Schedule",),
    ),
    # threats.php REQUIRES a host/domain/port param -- with none it print_info_box()es and exit()s
    # before rendering $pgtitle. A syntactically-valid param renders the lookup page chrome; the
    # threat links it draws are <a href> only (no server-side network call), so it stays hermetic.
    # All THREE positive views ($title is 'Source IP'/'Domain'/'Port' -> the "Threat <title> Lookup"
    # breadcrumb + "Threat <title>:" panel) are probed (CLAUDE.md branch coverage); the reject /
    # no-request branches are covered by test_threats_rejects_malformed_lookup below. The {domain}
    # placeholder is filled per run with helpers.unique_domain() (uuid-*.com) -- the smoke-domain
    # rule (never a fixed/RFC-6761 name); host/port use a documentation IP (TEST-NET-3) + a valid
    # port (no network coupling either way).
    Page("threats_domain", "/pfblockerng/pfblockerng_threats.php?domain={domain}", ("Threat Domain", "Source IP")),
    Page(
        "threats_host", "/pfblockerng/pfblockerng_threats.php?host=203.0.113.5", ("Threat Source IP", "Threat Lookups")
    ),
    Page("threats_port", "/pfblockerng/pfblockerng_threats.php?port=8443", ("Threat Port",)),
    # ADR-12 Update Hooks (pre/post update-command list). Reached as the Update -> Hooks sub-tab;
    # the markers are the Form_Section titles ('Update Hooks (Pre/Post Update Scripts)' + 'Hook
    # Entries'), stable regardless of the tab restructure. The sub-tab nav itself is pinned by
    # test_update_hooks_subtab_relocation.
    Page(
        "hooks",
        "/pfblockerng/pfblockerng_hooks.php",
        ("Update Hooks", "Hook Entries", "dependency-derived", "versioned interpreter"),
    ),
    # issue #1669 Part B / ADR-12 post-acceptance addendum: the gated "Edit Hooks" hook-script
    # authoring editor, the Update sub-tab directly after Hooks. The smoke session is always
    # authenticated as admin, so the in-page isAllowedPage('diag_command.php') secondary gate's
    # uid-0 short-circuit passes and the page renders (the gate's OWN behaviour -- redirecting a
    # non-privileged user -- is pinned off-box by EditHooksPageWiringTest, not here; building a
    # restricted-user smoke session is disproportionate, same call as SoftwareAddTabTest's
    # documented limitation). Markers: the "Advanced Users Only" root-warning banner heading (the
    # load-bearing manual equivalent of diag_command.php's own callout, since this page is
    # deliberately absent from pfblockerng.priv.inc so the generic WARN-tag mechanism never fires
    # here) and the "Edit Hooks" tab/breadcrumb label plus the picker section title.
    Page(
        "edit_hooks",
        "/pfblockerng/pfblockerng_edit_hooks.php",
        (
            "Advanced Users Only",
            "Edit Hooks",
            "Load an Existing Hook Script",
            # issue #1669 Part B slice B2: the vendored CodeMirror 6 hook-editor bundle
            # include -- proves the pfb_hook_editor_content live-highlighting asset is
            # wired on the page. Present because the gating pfb_syntax_highlight toggle
            # defaults on for a fresh box (same rationale as the "dnsbl" entry above).
            "vendor/codemirror/cm-hooks.min.js",
        ),
    ),
    # The dashboard widget (auth-gated; $nocsrf=true). A direct GET renders the alias-table panel
    # whose hidden inputs (id="pfblockerngack") are a stable marker; the AJAX getNew* paths need a
    # query param, so the plain GET exercises the full-render branch. "Show Aggregated Aliases" is
    # the #494 settings checkbox label (rendered in the widget's settings panel), proving the new
    # toggle renders.
    Page(
        "widget",
        "/widgets/widgets/pfblockerng.widget.php",
        ('id="pfblockerngack"', "Alias", "Show Aggregated Aliases"),
    ),
    # pfblockerng.php dispatches `ugc`; pfblockerng_geoip.inc writes these nine
    # continent/category pages and the Reputation page from local MaxMind-schema CSVs.
    # The deployed_vm fixture seeds the corpus and runs `ugc` before rendering them.
    # Libya is the corpus's ONLY African country, and it has v6 networks only -- its v4 select
    # renders (0) and its v6 select (1).
    Page(
        "geoip_africa",
        "/pfblockerng/pfblockerng_Africa.php",
        ("Continent - Africa", "Libya [2215636] LY (1)"),
    ),
    # The corpus has NO Antarctic/Oceanian/South American networks (tests/smoke/fixtures/
    # README.md), so every country on these three pages renders (0) -- the page still builds.
    Page(
        "geoip_antarctica",
        "/pfblockerng/pfblockerng_Antarctica.php",
        ("Continent - Antarctica", "Antarctica [6697173] AQ (0)"),
    ),
    Page(
        "geoip_asia",
        "/pfblockerng/pfblockerng_Asia.php",
        ("Continent - Asia", "Bhutan [1252634] BT (1)"),
    ),
    Page(
        "geoip_europe",
        "/pfblockerng/pfblockerng_Europe.php",
        ("Continent - Europe", "United Kingdom [2635167] GB (5)"),
    ),
    Page(
        "geoip_north_america",
        "/pfblockerng/pfblockerng_North_America.php",
        ("Continent - North America", "United States [6252001] US (3)"),
    ),
    Page(
        "geoip_oceania",
        "/pfblockerng/pfblockerng_Oceania.php",
        ("Continent - Oceania", "Australia [2077456] AU (0)"),
    ),
    Page(
        "geoip_south_america",
        "/pfblockerng/pfblockerng_South_America.php",
        ("Continent - South America", "Brazil [3469034] BR (0)"),
    ),
    # The A1/A2 ISOs themselves are synthesized unconditionally (pfblockerng.php:929-932), so
    # 'value="A1"' is structural chrome, unique to this page. Real GeoLite2 -- this corpus
    # included -- carries no flagged rows at all (issue #1221), so both aggregates render (0);
    # the data test pins that shape.
    Page(
        "geoip_proxy_and_satellite",
        "/pfblockerng/pfblockerng_Proxy_and_Satellite.php",
        ("Continent - Proxy and Satellite", 'value="A1"'),
    ),
    # Top Spammers rows use the hardcoded $top_20 ISO list (pfblockerng.php:883-884); the
    # format is "(id)" not the continent pages' "[id]" -- a real rendering-path difference.
    Page(
        "geoip_top_spammers",
        "/pfblockerng/pfblockerng_Top_Spammers.php",
        ("Continent - Top Spammers", "United Kingdom (2635167) GB (5)"),
    ),
    # Reputation is written unconditionally by pfb_build_reputation_tab() in
    # pfblockerng_geoip.inc -- no MaxMind/network dependency either.
    Page(
        "geoip_reputation",
        "/pfblockerng/pfblockerng_reputation.php",
        ("IPv4 Reputation", "Individual List Reputation"),
    ),
)


@dataclass(frozen=True)
class ExcludedPage:
    """A pfBlockerNG page deliberately kept OUT of the hermetic Tier-A sweep.

    Recorded (ADR §2 "don't silently drop") with why it is non-hermetic / not
    reachable via the authenticated webConfigurator session, and how Phase 5/CI
    should reach it instead.
    """

    name: str
    path: str
    reason: str
    access_note: str
    markers: tuple[str, ...] = field(default_factory=tuple)


# Pages NOT in the hermetic Tier-A sweep, with the reason + the Phase-5 access note.
# issue #1219: the GeoIP continent + Reputation pages moved OUT of this table and INTO
# PAGE_TABLE above -- `ugc` (the local CSV-conversion verb) needs no MaxMind credential or
# network access, so seeding synthetic CSVs makes them hermetically renderable after all.
EXCLUDED_FROM_TIER_A: tuple[ExcludedPage, ...] = (
    ExcludedPage(
        name="dnsbl_vip_sinkhole_pages",
        path="/index.php and /dnsbl_default.php under www/ (DNSBL VIP webserver)",
        reason=(
            "www/index.php + dnsbl_default.php are served by the DNSBL sinkhole lighttpd on the "
            "DNSBL VIP, NOT the main webConfigurator: no guiconfig auth, and index.php exit()s "
            "unless HTTP_HOST is a valid hostname and REQUEST_URI=='/' (otherwise it returns a "
            "1x1 GIF). dnsbl_default.php is a template INCLUDED by dnsbl_active.php, never served "
            "standalone. The authenticated session on :8080 cannot reach them. issue #1013: the "
            "sinkhole listens on ports 80/443, NOT the configured dnsbl_port/dnsbl_port_ssl "
            "(8081/8443 by default) -- those are the NAT local-port pfb_create_lighttpd() binds "
            "127.0.0.1 to on a real interface (pfblockerng.inc:5459-5460); on lo0 (this harness's "
            "VIP mode) NAT is skipped entirely (pfb_dnsbl_nat_enabled()) and lighttpd binds the "
            "VIP directly on 80/443 -- either way the externally-reachable port is 80/443."
        ),
        access_note=(
            "Phase 5: fetch the VIP sinkhole directly -- http://<DNSBL_VIP>/ (port 80, NOT the "
            "configured dnsbl_port) with a Host header set to a blocked hostname and REQUEST_URI "
            "'/' to get the DNSBL-Full block page; the marker is 'Site blocked via DNSBL' "
            "(dnsbl_default.php <title>). No webConfigurator login."
        ),
        markers=("Site blocked via DNSBL",),
    ),
)


@pytest.fixture(scope="module")
def php_error_log_guard(smoke_vm: SmokeVM, webui: WebUI) -> Iterator[PhpErrorLogGuard]:  # noqa: ARG001
    """Snapshot ``php_error.log`` once before the sweep, assert no growth after.

    Module-scoped so it brackets the WHOLE parametrized sweep (oracle condition
    (d)): a new error line written by ANY page during the sweep fails the
    teardown. ``webui`` is requested only to order this after login / VM
    readiness; the diff itself is read over the ``smoke_vm`` SSH path.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    yield guard
    guard.assert_no_growth()


@pytest.mark.parametrize("page", PAGE_TABLE, ids=lambda p: p.name)
def test_page_renders_clean(page: Page, webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """Each pfBlockerNG page passes the per-page oracle (a)-(c).

    Requesting ``php_error_log_guard`` enrolls this test in the sweep-level (d)
    check: the guard snapshots ``php_error.log`` before the first parametrization
    and asserts no growth after the last, so a page that logs (but does not echo)
    a PHP diagnostic still fails the sweep.
    """
    # Fill the {domain} placeholder (threats page) with a unique uuid-*.com per
    # run; other paths carry no placeholder and pass through unchanged.
    path = page.path.format(domain=helpers.unique_domain()) if "{domain}" in page.path else page.path
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, page.markers)
    assert result.ok, f"render oracle failed for {page.name} ({path}): {result.detail}"


# issue #1217: pfBlockerNG-OWNED external new-tab links that must render with the
# reverse-tabnabbing rel. Scoped to specific pfBlockerNG hrefs on purpose -- the
# pfSense framework chrome (head.inc menu/footer, on every page) carries its own
# out-of-scope target="_blank" links, so a whole-body sweep would false-positive.
# Each url is a stable href in the named page's source.
_NOOPENER_RENDER_CASES: tuple[tuple[str, str], ...] = (
    ("/pfblockerng/pfblockerng_general.php", "https://pfblockerng.com"),
    ("/pfblockerng/pfblockerng_general.php", "https://github.com/BBcan177"),
    ("/pfblockerng/pfblockerng_general.php", "https://github.com/andrebrait"),
    # ?type=geoip: the MaxMind attribution callout only prints in the category page's
    # GeoIP view (source guards it with `$gtype == 'geoip'`).
    ("/pfblockerng/pfblockerng_category.php?type=geoip", "https://www.maxmind.com"),
    ("/pfblockerng/pfblockerng_ip.php", "https://ipinfo.io"),
)


@pytest.mark.parametrize(("path", "url"), _NOOPENER_RENDER_CASES, ids=lambda v: v)
def test_pfblockerng_new_tab_link_renders_with_noopener_rel(path: str, url: str, webui: WebUI) -> None:
    """A pfBlockerNG-owned target="_blank" link renders with rel="noopener noreferrer" (#1217).

    Tier-A render-layer proof that the source tripwire's rel actually reaches the SHIPPED
    HTML. Scoped to pfBlockerNG's OWN external links -- the pfSense framework chrome carries
    its own out-of-scope new-tab links, so a whole-body sweep would false-positive. Asserts
    the link renders (non-vacuity) THEN that its anchor carries the rel adjacent to target.
    """
    body = webui.get(path).text
    assert f'href="{url}"' in body, f"pfBlockerNG link {url} did not render on {path}"
    assert f'target="_blank" rel="noopener noreferrer" href="{url}"' in body, (
        f'link {url} on {path} renders without the adjacent rel="noopener noreferrer"'
    )


# issue #1845: every page that ships pfBlockerNG.js must render the include with an
# mtime cache-buster, and that token must be non-zero. Without the token a browser keeps
# its pre-upgrade copy of the script (the response carries no Expires/Cache-Control, so
# heuristic freshness applies) and the stale copy then throws against the new markup,
# which silently disables every page callback queued behind it in pfSense's unguarded
# `events` drain. A rendered `?v=0` is the same failure wearing a token: it means the
# package installed its files with mtime 0, so the URL never changes between releases.
_PFB_JS_PAGES: tuple[str, ...] = (
    "/pfblockerng/pfblockerng_category_edit.php?type=ipv4",
    "/pfblockerng/pfblockerng_category.php?type=ipv4",
    "/pfblockerng/pfblockerng_ip.php",
    "/pfblockerng/pfblockerng_dnsbl.php",
    # A generated GeoIP continent page: same include, written out from the nowdoc
    # template in pfblockerng_geoip.inc rather than shipped as a page of its own.
    "/pfblockerng/pfblockerng_Europe.php",
)


@pytest.mark.parametrize("path", _PFB_JS_PAGES, ids=lambda v: v)
def test_pfblockerng_js_include_carries_a_nonzero_cache_buster(path: str, webui: WebUI) -> None:
    """The shipped pfBlockerNG.js include renders with a non-zero mtime cache-buster (#1845).

    Tier-A render-layer proof covering BOTH halves of the stale-script defect: the page
    emits the token at all, and the installed package gives it a real value.
    """
    body = webui.get(path).text
    assert 'src="pfBlockerNG.js' in body, f"pfBlockerNG.js is not included on {path} at all"

    match = re.search(r'src="pfBlockerNG\.js\?v=(\d+)"', body)
    assert match is not None, (
        f"{path} renders the pfBlockerNG.js include without a ?v=<mtime> cache-buster; "
        "a browser may keep serving the pre-upgrade script"
    )
    assert int(match.group(1)) > 0, (
        f"{path} renders pfBlockerNG.js?v={match.group(1)}: the installed file's mtime is the "
        "epoch, so the URL is identical for every release and the cache is never invalidated"
    )


# issue #1734: the hook editor's help text is the admin's only signal that the save
# rewrites their script, so it must name every transformation the shared sanitizer
# applies -- not just the line-ending fold it described while the save still used the
# narrower pfb_hook_editor_normalize_content(). A help text that outlives the behaviour
# it describes is how an admin ends up debugging a silently rewritten hook. Substrings
# verified against the real setHelp() copy in pfblockerng_edit_hooks.php.
_EDIT_HOOKS_PAGE = "/pfblockerng/pfblockerng_edit_hooks.php"
_EDIT_HOOKS_SAVE_PROMISE = (
    "line endings are normalized to LF",
    "trailing whitespace is stripped from each line",
    "control characters other than tab are removed",
)


def test_edit_hooks_help_text_names_every_save_transformation(webui: WebUI) -> None:
    """The hook editor's help text names all three transformations the save applies.

    Tier-A render-layer proof, hermetic (the page renders from local state alone).
    Asserts the editor textarea itself rendered (non-vacuity: a page that failed to
    emit the field would otherwise make the substring checks pass trivially on some
    unrelated body), then EACH clause of the promise separately, so dropping any one
    of them fails here rather than degrading silently to a partial description.
    """
    resp = webui.get(_EDIT_HOOKS_PAGE)
    assert resp.status_code == 200, f"GET {_EDIT_HOOKS_PAGE} -> HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert 'id="pfb_hook_editor_content"' in body, (
        f"the hook-editor textarea did not render on {_EDIT_HOOKS_PAGE} -- its help text cannot be pinned"
    )
    for clause in _EDIT_HOOKS_SAVE_PROMISE:
        assert clause in body, (
            f"the hook-editor help text does not state {clause!r} -- the save applies it "
            "(pfb_sanitize_text_area), so an admin reading this page would not know their script is rewritten"
        )


# ADR-11: the IP page's pfb_agg_types multi-select must render with ALL FOUR
# option branches (Deny/Permit/Match/Native) AND its no-rule help caveat. Asserting
# every option proves each branch of the select is emitted (not just the label), and the
# caveat substring proves the help text — the user's only signal that an aggregate is
# reference-only (no firewall rule) — actually rendered. Substrings verified against the
# real pfblockerng_ip.php: the four $options_pfb_agg_types keys render as Form_Select
# option values ('value="<Type>"'), and the setHelp() copy contains "no firewall rule".
_AGG_TYPE_OPTIONS = ("Deny", "Permit", "Match", "Native")
_AGG_HELP_CAVEAT = "no firewall rule"
_GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
_IP_PAGE = "/pfblockerng/pfblockerng_ip.php"


def test_ip_page_renders_aggregate_select(webui: WebUI) -> None:
    """The IP page renders the pfb_agg_types select: all four options + the caveat.

    Hermetic (no network — the IP page renders from local config alone). GET the
    page and assert: (1) the ``pfb_agg_types`` field is present; (2) EACH of the four
    option values (Deny/Permit/Match/Native) is emitted — every branch of the multi-
    select, not just one (CLAUDE.md branch coverage); and (3) the "no firewall rule" help
    caveat — the load-bearing "these are reference-only IP-sets" wording — is present.
    Pairs with the PAGE_TABLE "Aggregated Aliases" label marker (the field's presence) to
    pin both the field and its full option set + help.
    """
    resp = webui.get(_IP_PAGE)
    assert resp.status_code == 200, f"GET {_IP_PAGE} -> HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert "pfb_agg_types" in body, "pfb_agg_types select not present on the IP page"
    missing = [opt for opt in _AGG_TYPE_OPTIONS if f'value="{opt}"' not in body]
    assert not missing, f"pfb_agg_types select missing option value(s) {missing} (each is a branch that must render)"
    assert _AGG_HELP_CAVEAT in body, (
        f"pfb_agg_types help caveat {_AGG_HELP_CAVEAT!r} (the no-rule wording) not rendered on the IP page"
    )


# issue #2895: the Firewall 'Auto' Rule Order help must state the REAL default -- the
# verbatim order_0 label from $options_pass_order -- and must not name the retired
# 'original format' option that no select row offers (a user following that help would
# hunt for a nonexistent choice and be told the wrong rule order is active by default).
_IP_ORDER_DEFAULT_LABEL = "| pfB_Pass/Match/Block/Reject | All other Rules | (Default format)"
_IP_ORDER_RETIRED_OPTION_NAME = "original format"


def test_ip_page_rule_order_help_states_the_order_zero_default(webui: WebUI) -> None:
    """The IP page's 'Auto' Rule Order help states the verbatim order_0 default and
    no longer names the retired 'original format' option (#2895).
    """
    resp = webui.get(_IP_PAGE)
    assert resp.status_code == 200, f"GET {_IP_PAGE} -> HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert _IP_ORDER_DEFAULT_LABEL in body, "the rule-order help no longer states the verbatim order_0 default label"
    assert _IP_ORDER_RETIRED_OPTION_NAME not in body, (
        "the rule-order help still names the retired 'original format' option"
    )


def test_ip_page_renders_v6_suppression_section(webui: WebUI) -> None:
    """The IP page renders the new IPv6 Suppression section (ADR-53 Phase 6).

    Hermetic (no network — the IP page renders from local config alone). GET the
    page and assert: (1) the 'IPv6 Suppression' Form_Section title renders; (2) the
    v6suppression textarea field is present. Pairs with the pre-existing 'IPv4
    Suppression' section (also asserted here, unchanged by this phase) — proving the
    v6 sibling section renders ALONGSIDE it, not instead of it.

    Also pins the corrected drop-set wording (issue #422): before that fix the v6
    section wrongly claimed 'RFC1918' (a v4-only concept); it now names the actual
    v6 drop set. The v4 section's own reserved-class wording (issue #760) is pinned
    alongside it as a sibling text-content guard.
    """
    resp = webui.get(_IP_PAGE)
    assert resp.status_code == 200, f"GET {_IP_PAGE} -> HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert "IPv6 Suppression" in body, "IPv6 Suppression section title not rendered on the IP page"
    assert 'name="v6suppression"' in body, "v6suppression textarea not rendered on the IP page"
    assert "IPv4 Suppression" in body, "IPv4 Suppression section title (existing sibling) missing"
    assert "ULA (fc00::/7)" in body, (
        "v6 Suppression help text missing the corrected 'ULA (fc00::/7)' drop-set wording "
        "(issue #422) -- it previously wrongly claimed 'RFC1918', a v4-only concept"
    )
    assert "benchmarking" in body, (
        "v4 Suppression help text missing the 'benchmarking' reserved-class wording (issue #760)"
    )


_IP_WRITE_ONLY_CREDENTIALS = (
    pytest.param(
        "maxmind_key",
        "installedpackages/pfblockerngipsettings/config/0/maxmind_key",
        "PFBTESTKEY000001",
        id="maxmind-key",
    ),
    pytest.param(
        "asn_token",
        "installedpackages/pfblockerngipsettings/config/0/asn_token",
        "PFBASNTESTTOKEN0001",
        id="asn-token",
    ),
)


# Dual-marked ui_e2e because this test mutates config.xml; the module-level
# ui_render marker keeps both parameter rows in the Tier-A render gate.
@pytest.mark.ui_e2e
@pytest.mark.parametrize(("field", "config_path", "seed_token"), _IP_WRITE_ONLY_CREDENTIALS)
def test_ip_page_never_leaks_write_only_credential(
    field: str,
    config_path: str,
    seed_token: str,
    smoke_vm: SmokeVM,
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,
) -> None:  # noqa: ARG001
    """Stored IP-page credentials stay absent; inputs render blank and password-masked."""
    original = helpers.config_get_state(smoke_vm, config_path)
    try:
        helpers.config_set(smoke_vm, config_path, seed_token)
        assert helpers.config_get(smoke_vm, config_path) == seed_token, (
            f"{field} seed did not take before render assertions"
        )

        resp = webui.get(_IP_PAGE)
        assert resp.status_code == 200, f"GET {_IP_PAGE} -> HTTP {resp.status_code} (expected 200)"
        body = resp.text
        assert seed_token not in body, f"{field} leaked into the IP page body: expected {seed_token!r} to be absent"
        tag = re.search(rf'<input[^>]*\bname="{re.escape(field)}"[^>]*>', body)
        assert tag, f"{field} input not present on the IP page"
        assert 'type="password"' in tag.group(0), (
            f'{field} input must be masked (type="password"): got {tag.group(0)!r}'
        )
        assert scrape_form_fields(body).get(field) == "", f"{field} input must render blank"
    finally:
        helpers.config_restore_state(smoke_vm, config_path, original)


_UPDATE_PAGE = "/pfblockerng/pfblockerng_update.php"
_HOOKS_PAGE = "/pfblockerng/pfblockerng_hooks.php"
_LOG_PAGE = "/pfblockerng/pfblockerng_log.php"


def test_update_hooks_subtab_relocation(webui: WebUI) -> None:
    """Update Hooks moved from a top-level tab to an Update sub-tab row.

    The standalone 'Update Hooks' top tab was replaced by a second display_top_tabs
    row under Update — Run -> the update page, Hooks -> the hooks page, Edit Hooks ->
    the gated editor (the same
    sub-tab idiom the Feeds page uses). Assert the new shape AND that the old
    top-level tab is gone (hermetic — all three pages render from local config).

    Given the restructured tabs,
    When GET pfblockerng_update.php and pfblockerng_hooks.php,
    Then each renders the sub-tab row: 'Run', 'Hooks', and 'Edit Hooks' anchors with
      the expected links.
    And the old standalone 'Update Hooks' tab is gone: it is ABSENT from the update
      page entirely, and from the General witness page (a page that is neither Update
      nor Hooks) — while that page keeps its 'Update' top tab. The absence is the
      before/after guard: 'Update Hooks' was present as a top tab on every page before
      this change, so these assertions would have FAILED then and pass only after the
      move. (The hooks page itself still contains the literal 'Update Hooks' in its
      Form_Section title, so absence is asserted on the update + witness pages, not it.)

    The active-tab-tracks-the-page branch (Run, Hooks, or Edit Hooks active on its page)
    is the Tier-B browser half (test_browser_hooks.py).
    """
    # --- Run page (pfblockerng_update.php): all sub-tabs render; old top tab gone. ---
    body = webui.get(_UPDATE_PAGE).text
    assert ">Run</a>" in body, "update page is missing the 'Run' sub-tab anchor"
    assert ">Hooks</a>" in body, "update page is missing the 'Hooks' sub-tab anchor"
    assert ">Edit Hooks</a>" in body, "update page is missing the 'Edit Hooks' sub-tab anchor"
    assert _HOOKS_PAGE in body, "update page 'Hooks' sub-tab does not link the hooks page"
    assert _EDIT_HOOKS_PAGE in body, "update page 'Edit Hooks' sub-tab does not link the editor page"
    # "Update Hooks" is a tab-nav guard: the removed top tab was the ONLY occurrence of
    # that literal on the update page, so its absence proves the tab is gone. (If future
    # help text on this page ever references the hooks page by that name, narrow this to
    # the nav element rather than the whole body.)
    assert "Update Hooks" not in body, "stale 'Update Hooks' top-level tab still rendered on the update page"

    # --- Hooks page (pfblockerng_hooks.php): all sub-tabs render. ---
    body = webui.get(_HOOKS_PAGE).text
    assert ">Run</a>" in body, "hooks page is missing the 'Run' sub-tab anchor"
    assert ">Hooks</a>" in body, "hooks page is missing the 'Hooks' sub-tab anchor"
    assert ">Edit Hooks</a>" in body, "hooks page is missing the 'Edit Hooks' sub-tab anchor"
    assert _UPDATE_PAGE in body, "hooks page 'Run' sub-tab does not link the update page"
    assert _EDIT_HOOKS_PAGE in body, "hooks page 'Edit Hooks' sub-tab does not link the editor page"

    # --- Witness page (General): the 'Update Hooks' top tab is gone; 'Update' remains. ---
    body = webui.get(_GENERAL_PAGE).text
    assert "Update Hooks" not in body, "'Update Hooks' top-level tab is still present on the General page"
    assert ">Update</a>" in body, "the 'Update' top-level tab was wrongly removed from the General page"
    assert _UPDATE_PAGE in body, "the General page no longer links the Update tab"


def test_update_hooks_help_describes_python_launcher(webui: WebUI) -> None:
    """Hook help distinguishes dependency-derived Python dispatch from shell shebangs.

    Python hooks are launched by the package's versioned interpreter, so their files
    need neither an executable bit nor a usable shebang. Shell hooks still execute
    directly and retain both requirements. This is Tier-A render proof for the
    operator-facing contract; the hook execution behavior is pinned in PHPUnit.
    """
    body = webui.get(_HOOKS_PAGE).text.lower()
    assert "dependency-derived" in body, "hooks help omits dependency-derived Python runtime"
    assert "versioned interpreter" in body, "hooks help omits versioned Python interpreter"
    assert "python hooks do not require" in body, "hooks help does not explain Python executable/shebang exemption"
    assert "shell hooks still require" in body, "hooks help does not preserve shell executable/shebang requirement"
    assert "chmod +x" not in body, "stale blanket chmod +x guidance still claims all hooks need executable bit"


def test_update_page_cron_status_reports_harness_disable_flag(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:  # noqa: ARG001
    """The Update page's cron-status line names the harness's .pfb_cron_disable sentinel (#1204).

    Read-only (no config write) — the flag is deploy()'s always-on harness state, so
    this needs no ``ui_e2e`` isolation. The flag-absent healthy-cron branch is pinned
    off-appliance by UpdateRunNowScheduleOwnershipTest.

    Given the harness flag present (deploy()'s default state),
    When GET pfblockerng_update.php,
    Then the cron-status line names the exact sentinel path.
    """
    flag = helpers.PFB_CRON_DISABLE_PATH
    assert smoke_vm.ssh("test", "-f", flag).returncode == 0, (
        f"precondition: {flag} must be present (deploy() writes it)"
    )

    resp = webui.get(_UPDATE_PAGE)
    result = evaluate_render(_UPDATE_PAGE, resp.status_code, resp.text, ("NEXT Scheduled CRON Event",))
    assert result.ok, f"Update page render oracle failed: {result.detail}"
    assert f"[ Disabled by {flag} ]" in resp.text, (
        f"Update page cron-status line is missing the harness disable banner for {flag}"
    )


def test_geoip_page_renders_current_maxmind_document_link(webui: WebUI) -> None:
    """Generated continent output proves the shared document-link call ran."""
    body = webui.get("/pfblockerng/pfblockerng_Africa.php").text
    assert 'href="https://dev.maxmind.com/geoip/whats-new-in-geoip2/"' in body
    assert "https://dev.maxmind.com/geoip/geoip2/whats-new-in-geoip2/" not in body


def test_geoip_pages_render_the_seeded_csv_rows(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:  # noqa: ARG001
    """Scenario: the GeoIP pages carry the SEEDED data, not just their chrome (issue #1219/#1228).

    Given the UI session seeded MaxMind's official test corpus and ran `ugc`,
    When `ugc` is rerun locally and the GeoIP pages that carry seeded rows are fetched (the
         seven below; the other GeoIP pages are covered for RENDER by PAGE_TABLE),
    Then the rerun adds no ISO-append failure marker and every needle below renders — and each
         one is produced by specific corpus rows, so deleting them (or gutting a whole CSV)
         fails this test.

    These assertions cannot live in ``PAGE_TABLE``: the render oracle matches markers with
    ``any()`` (``render_oracle.py``), and every GeoIP page already carries a data-INDEPENDENT
    "Continent - X" title that pfblockerng.php emits from its hardcoded page list — so a data
    marker added beside it would gate nothing (coverage theater). Same shape as
    ``test_feeds_custom_panel_heading_renders``.

    EVERY needle carries its member COUNT, and that is load-bearing: an ``{ISO}_rep`` entry is
    appended unconditionally for any country that has a direct row (pfblockerng.php:1301-1312),
    so a bare ``GB_rep``/``US_rep`` string still matches — rendering ``(0)`` — even if the
    registered-country computation were deleted outright. Only the count separates a real
    registered-country match from that always-present placeholder.

    The needles, and the rows each one pins:
      * ``GB (5)`` / ``GB (21)`` — the United Kingdom's 5 IPv4 vs. 21 IPv6 networks: the counts
                         differ between the two selects, so the pair proves BOTH Blocks CSVs
                         reached the render (a v6-select fed from the v4 file could not pass)
      * ``GB_rep (1)`` — the registered-country ("exclave") path: 216.160.83.56/29 is a US
                         network registered to GB
      * ``US (3)`` / ``US_rep (4)`` — the United States' 3 direct IPv4 rows, plus the 4 GB
                         networks registered to the US
      * ``LY (1)``     — Libya, the corpus's only African country, has IPv6 networks ONLY, so its
                         count can only come from the IPv6 CSV
      * ``BT (1)``     — Bhutan's 67.43.156.0/24, the row the dMax reputation leg classifies
      * ``Proxy A1 (0)`` — the anonymous-proxy aggregate is EMPTY by data: real GeoLite2 (this
                         corpus included) ships no is_anonymous_proxy/is_satellite_provider rows
                         (issue #1221), so ``(0)`` is the honest, asserted shape — the same holds
                         for the A2 satellite aggregate
      * Top Spammers' ``GB (5)`` — a $top_20 ISO through the "(id)" rendering path
      * Reputation's ``BT (1)`` — the same seeded data through a SEPARATE serialization path
                         (``pfb_build_reputation_tab()``), which the continent pages never touch
    """
    marker = "Failed to append ISO data"
    extras_log = "/var/log/pfblockerng/extras.log"

    def append_failure_count() -> int:
        result = smoke_vm.ssh("grep", "-Fc", marker, extras_log)
        assert result.returncode in (0, 1), (
            f"failed to count {marker!r} in {extras_log}: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )
        return int(result.stdout.strip())

    failures_before = append_failure_count()
    cron_include = "/usr/local/pkg/pfblockerng/pfblockerng_cron.inc"
    installed = smoke_vm.ssh("test", "-f", cron_include)
    assert installed.returncode == 0, f"installed cron include missing at {cron_include}: {installed.stderr!r}"
    ugc = smoke_vm.ssh(helpers.PHP_BIN, helpers.PFB_CLI, "ugc", timeout=600)
    assert ugc.returncode == 0, f"fresh local ugc failed: rc={ugc.returncode} {ugc.stderr!r} {ugc.stdout!r}"
    failures_after = append_failure_count()
    assert failures_after == failures_before, (
        f"fresh local ugc logged an ISO append failure: before={failures_before} after={failures_after}"
    )

    expected: dict[str, tuple[str, ...]] = {
        "/pfblockerng/pfblockerng_Africa.php": ("Libya [2215636] LY (1)",),
        "/pfblockerng/pfblockerng_Asia.php": ("Bhutan [1252634] BT (1)",),
        "/pfblockerng/pfblockerng_Europe.php": (
            "United Kingdom [2635167] GB (5)",
            "United Kingdom [2635167] GB (21)",
            "United Kingdom [2635167] GB_rep (1)",
        ),
        "/pfblockerng/pfblockerng_North_America.php": (
            "United States [6252001] US (3)",
            "United States [6252001] US_rep (4)",
        ),
        "/pfblockerng/pfblockerng_Proxy_and_Satellite.php": ("Proxy A1 (0)",),
        "/pfblockerng/pfblockerng_Top_Spammers.php": ("United Kingdom (2635167) GB (5)",),
        "/pfblockerng/pfblockerng_reputation.php": ("Bhutan [1252634] BT (1)",),
    }
    for path, needles in expected.items():
        resp = webui.get(path)
        body = resp.text
        result = evaluate_render(path, resp.status_code, body, needles)
        assert result.ok, f"{path}: generated GeoIP page failed the render oracle: {result.detail}"
        for needle in needles:
            assert needle in body, (
                f"{path} is missing the seeded-data needle {needle!r} — the GeoIP fixture row it "
                f"pins never reached the render (page rendered, but on empty/incomplete data)"
            )


def test_general_page_keep_help_upgrade_warning(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """The General page's 'Keep Settings' help warns that keep=off wipes settings on a version upgrade (#697).

    Given the General page,
    When GET,
    Then the 'Keep Settings' help text states the wipe also applies to pfSense version upgrades, and
    the removed 'Keep enabled during version upgrades' toggle is gone.

    Fail-before / pass-after: the disclaimer sentence is added in #697 (fails on the pre-#697 page),
    and the removed checkbox must be absent (fails while the old toggle still renders).
    """
    resp = webui.get(_GENERAL_PAGE)
    body = resp.text
    result = evaluate_render(_GENERAL_PAGE, resp.status_code, body, ("General Settings",))
    assert result.ok, f"General page render oracle failed: {result.detail}"
    assert "This also applies to a major pfSense version upgrade" in body, "keep=off upgrade-wipe disclaimer missing"
    assert 'name="pfb_keep_on_upgrade"' not in body, "the removed pfb_keep_on_upgrade toggle still renders (#697)"


def test_general_page_renders_ip_parse_error_log_row(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """issue #1004 Step 1: the General page's Log Settings 'IP' group gains a 'Parse
    Error' row (``log_max_ip_parse_err`` / ``log_max_days_ip_parse_err``), the plumbing
    for the new dedicated ``ip_parsed_error.log`` sink (loop wiring is Step 2).

    Given the General page,
    When GET,
    Then the new Max-lines select (``log_max_ip_parse_err``) and Max-days input
      (``log_max_days_ip_parse_err``) both render.

    Fail-before / pass-after: neither field name exists in the pre-#1004 markup, so
    both assertions fail on that build and pass only once the registry + page wiring land.

    AUTHORED, NOT EXECUTED this session (no live VM) -- run via
    ``pytest tests/smoke/ui -m ui_render --override-ini="addopts="`` on the fan-out VM.
    """
    resp = webui.get(_GENERAL_PAGE)
    body = resp.text
    result = evaluate_render(_GENERAL_PAGE, resp.status_code, body, ("General Settings",))
    assert result.ok, f"General page render oracle failed: {result.detail}"
    assert 'name="log_max_ip_parse_err"' in body, "General page is missing the log_max_ip_parse_err Max-lines select"
    assert 'name="log_max_days_ip_parse_err"' in body, (
        "General page is missing the log_max_days_ip_parse_err Max-days input"
    )


def test_general_page_renders_log_trim_margin_field(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """issue #1109 Step 2: the General page gains a single global ``pfb_log_trim_margin_pct``
    hysteresis-margin field, section-level (outside the per-log-type loop).

    Given the General page,
    When GET,
    Then the new field renders with its help copy, its row label is NOT hidden by the
    desktop ``label.form-label { display: none; }`` media query (its label is the
    Form_Group's own ``control-label``, not a per-control ``label-start``), and the
    pre-existing 3-needle intro wording survives this edit unchanged.

    Fail-before / pass-after: none of these markers exist in the pre-#1109 markup.
    """
    resp = webui.get(_GENERAL_PAGE)
    body = resp.text
    result = evaluate_render(_GENERAL_PAGE, resp.status_code, body, ("General Settings",))
    assert result.ok, f"General page render oracle failed: {result.detail}"

    assert 'name="pfb_log_trim_margin_pct"' in body, "General page is missing the pfb_log_trim_margin_pct field"
    assert "less flash/SSD wear" in body, "General page is missing the Trim Margin help copy"

    # §2d label-class probe: the field's row label must be a Form_Group control-label
    # (visible on desktop), never a per-control label-start (hidden by the media query).
    # Live-rendered markup (verified on-box): '<label class="col-sm-2 control-label">
    # <span>Trim Margin</span></label>' -- no per-input label-start/form-label involved.
    label_re = re.compile(r'<label class="col-sm-2 control-label">\s*<span>Trim Margin</span>\s*</label>')
    assert label_re.search(body), (
        "pfb_log_trim_margin_pct row label is not the expected visible control-label -- "
        "check it is not hidden by the desktop label.form-label media query"
    )

    # the pre-existing intro needles must survive this edit unchanged (behaviour-preserving)
    for needle in ("rolling cap", "trims lines older than", "whichever cap is more restrictive"):
        assert needle in body, f"Log Settings intro wording {needle!r} regressed by the #1109 edit"


def test_general_page_renders_nested_pass_timeout_field(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """issue #2851: the General page gains an Advanced Settings section carrying the one
    global ``pfb_reentry_timeout`` ("Nested pass timeout") control.

    Given the General page,
    When GET,
    Then the field renders as a number input carrying the accepted 60..7200 window and the
    1800-second placeholder, its label is the visible Form_Group ``control-label``, and the
    help copy documents whole-process-tree termination plus the retry path after an expiry.

    Fail-before / pass-after: none of these markers exist in the pre-#2851 markup, where the
    budget was a hardcoded constant with no operator surface at all.
    """
    resp = webui.get(_GENERAL_PAGE)
    body = resp.text
    result = evaluate_render(_GENERAL_PAGE, resp.status_code, body, ("General Settings",))
    assert result.ok, f"General page render oracle failed: {result.detail}"

    assert 'name="pfb_reentry_timeout"' in body, "General page is missing the pfb_reentry_timeout field"
    assert "Advanced Settings" in body, "General page is missing the Advanced Settings section"

    # The browser-side bounds ARE the runtime window -- a drifted attribute would let the
    # form submit a value the backend then silently replaces with the default.
    field_re = re.compile(r'<input[^>]*name="pfb_reentry_timeout"[^>]*>')
    field = field_re.search(body)
    assert field, "pfb_reentry_timeout did not render as an <input>"
    for attr in ('type="number"', 'min="60"', 'max="7200"', 'placeholder="1800"'):
        assert attr in field.group(0), f"pfb_reentry_timeout input is missing {attr}: {field.group(0)}"

    label_re = re.compile(r'<label class="col-sm-2 control-label">\s*<span>Nested pass timeout</span>\s*</label>')
    assert label_re.search(body), (
        "the Nested pass timeout row label is not the expected visible control-label -- "
        "check it is not hidden by the desktop label.form-label media query"
    )

    assert "whole process tree" in body, "the help copy must say the whole process tree is terminated on expiry"
    assert "Force Update" in body, "the help copy must give the retry guidance after an expiry"


def test_hooks_page_documents_lifecycle_env_vars(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """The hooks page lists the PFB_POST_INSTALL / PFB_PRE_UNINSTALL env vars (#684 doc gap, #687).

    Given the hooks page,
    When GET,
    Then the Environment help text names both lifecycle variables so hook authors can react to
        install/upgrade and uninstall passes.

    Fail-before / pass-after: the vars shipped in the previous release without help text; both
    assertions fail on that build and pass once the help text lists them.
    """
    body = webui.get(_HOOKS_PAGE).text
    result = evaluate_render(_HOOKS_PAGE, 200, body, ("Update Hooks",))
    assert result.ok, f"Hooks page render oracle failed: {result.detail}"
    assert "PFB_POST_INSTALL" in body, "hooks page help does not document PFB_POST_INSTALL"
    assert "PFB_PRE_UNINSTALL" in body, "hooks page help does not document PFB_PRE_UNINSTALL"


def test_update_log_textareas_are_readonly(webui: WebUI) -> None:
    """The Update page's two log windows are display-only — they render readonly.

    The 'pfb_status' (progress) and 'pfb_output' (log) textareas are live-tail
    viewers, not input fields; before this change they were plain editable
    textareas, so a user could accidentally cut/type into them (the content is
    harmless — it is repopulated from the log file on refresh — but it is confusing
    and a footgun). Each must now carry the readonly attribute.

    Given the rendered Update page,
    When each log textarea opening tag is located by name,
    Then it contains the readonly attribute. (Pre-fix the tags had no readonly, so
      these assertions FAIL on the old markup and pass only after it.)
    """
    body = webui.get(_UPDATE_PAGE).text
    for name in ("pfb_status", "pfb_output"):
        m = re.search(r"<textarea\b[^>]*\bname=([\"'])" + re.escape(name) + r"\1[^>]*>", body)
        assert m is not None, f"update page is missing the '{name}' textarea"
        tag = m.group(0)
        assert re.search(r"\breadonly\b", tag), f"'{name}' textarea is editable (no readonly): {tag}"


def test_log_page_textarea_is_readonly(webui: WebUI) -> None:
    """The Logs page's file-content viewer is display-only — it renders readonly.

    Same footgun as the Update page's log windows (see
    ``test_update_log_textareas_are_readonly``): 'fileContent' is populated by the
    load AJAX action, not typed into, so an editable textarea let a user
    accidentally cut/type into it with no effect on the underlying file. It must
    carry the readonly attribute.

    Given the rendered Log page,
    When the fileContent textarea opening tag is located,
    Then it contains the readonly attribute. (Pre-fix the tag had no readonly, so
      this assertion FAILS on the old markup and passes only after it.)
    """
    body = webui.get(_LOG_PAGE).text
    m = re.search(r"<textarea\b[^>]*\bname=([\"'])fileContent\1[^>]*>", body)
    assert m is not None, "log page is missing the 'fileContent' textarea"
    tag = m.group(0)
    assert re.search(r"\breadonly\b", tag), f"'fileContent' textarea is editable (no readonly): {tag}"


def test_log_page_lists_ip_parsed_error_log(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """issue #1004 Step 1: the Logs page's default (\"Log Files\") file-selection list
    gains the new dedicated ``ip_parsed_error.log`` detail sink, alongside its DNSBL
    sibling ``dnsbl_parsed_error.log`` (loop wiring that actually populates it is Step 2).

    Given the Log/File Browser page (default 'Log Files' logtype selected),
    When GET,
    Then the ``logFile`` select's option list includes ``ip_parsed_error.log``.

    Fail-before / pass-after: the filename is absent from the pre-#1004 options list, so
    this assertion fails on that build and passes only once the viewer wiring lands.

    AUTHORED, NOT EXECUTED this session (no live VM) -- run via
    ``pytest tests/smoke/ui -m ui_render --override-ini="addopts="`` on the fan-out VM.
    """
    resp = webui.get(_LOG_PAGE)
    body = resp.text
    result = evaluate_render(_LOG_PAGE, resp.status_code, body, ("Log/File Browser selections",))
    assert result.ok, f"Log page render oracle failed: {result.detail}"
    assert "ip_parsed_error.log" in body, "Log page's default file list is missing ip_parsed_error.log"


def test_update_ajax_tail_returns_wellformed_json(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The ?ajax=tail live-log poll endpoint returns well-formed JSON with the poller's contract keys.

    The handler now calls session_write_close() before reading the log so the poll never holds the
    PHP session write-lock — otherwise every 1s poll serialises behind any other same-session
    request, and one such blocked poll freezes the live tail during a long no-output gap (an
    HAProxy graceful-restart drain in an update hook). This guards that early close: it must not
    emit a warning/notice into the response (which would corrupt the JSON) and the endpoint must
    still return the {running, done, offset} contract the client poller consumes.

    Given the Update page's AJAX tail endpoint,
    When it is fetched with no offset (the client's first poll),
    Then the body parses as JSON and carries the running/done/offset keys (done is a bool).
    """
    resp = webui.get(_UPDATE_PAGE + "?ajax=tail")
    assert resp.status_code == 200, f"ajax=tail returned HTTP {resp.status_code}, body={resp.text[:200]!r}"
    # json.loads FAILS if a PHP warning/notice leaked into the body ahead of the JSON — exactly
    # the failure a misplaced session_write_close() (or an un-started session) would produce.
    payload = json.loads(resp.text)
    for key in ("running", "done", "offset"):
        assert key in payload, f"ajax=tail JSON missing the poller-contract key {key!r}: {payload!r}"
    assert isinstance(payload["done"], bool), f"'done' must be a bool for the client stop-check: {payload!r}"


def test_update_revamp_controls_render(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """Update page revamp: new scope + force-mode controls present; old opaque ones gone.

    The opaque Force/Update/Cron/Reload radio trio was replaced with an explicit Run
    Scope radio (ip / dnsbl / both) and a Force radio group (none / parse / download /
    both).  A read-only Schedule section shows last-run and next-due per ledger job.

    Scenario: Update page revamp controls render after Phase 6 + Force-mode addition.
      Background: pfBlockerNG deployed; Update page renders cleanly.

    Given the Update page renders via the clean-render oracle (200, no PHP diagnostic,
      "Update Settings" + "Schedule" section markers present),

    When the body is inspected for the new control ids and the old control ids,

    Then the new scope radio IDs are PRESENT (``pfb_scope_both``, ``pfb_scope_ip``,
      ``pfb_scope_dnsbl``) — proving the scope selector rendered;
    And the Force radio group field name is PRESENT (``pfb_force_mode``) — proving the
      four-mode force selector rendered (none / parse / download / both);
    And ``Run Scope`` and ``Force`` group labels are PRESENT — proving the new form
      groups rendered;
    And ``Schedule`` section text is PRESENT — proving the new section rendered;
    And the old opaque radio IDs are ABSENT (``pfb_force_update``, ``pfb_force_cron``,
      ``pfb_force_reload``, ``pfb_reload_option_all``) — PRESENT before Phase 6 in the
      old Force/Reload radio groups, so their absence is the before/after fail guard;
    And the old ``pfb_run_force`` checkbox name is ABSENT — replaced by ``pfb_force_mode``.

    ``php_error_log_guard`` enrolls this GET in the module-level no-growth sweep.
    """
    resp = webui.get(_UPDATE_PAGE)
    result = evaluate_render(_UPDATE_PAGE, resp.status_code, resp.text, ("Update Settings", "Schedule"))
    assert result.ok, f"Update page render oracle failed: {result.detail}"
    body = resp.text

    # PRESENT: new Run Scope radio control IDs
    for needle in ('id="pfb_scope_both"', 'id="pfb_scope_ip"', 'id="pfb_scope_dnsbl"'):
        assert needle in body, f"Update page missing new scope radio {needle!r}"

    # PRESENT: Force radio group (four-mode: none / parse / download / both)
    assert 'name="pfb_force_mode"' in body, (
        "Update page missing 'pfb_force_mode' Force radio group — "
        "the four-mode force selector (none/parse/download/both) did not render"
    )

    # PRESENT: section / group labels confirming the new design
    for needle in ("Run Scope", "Force", "Schedule"):
        assert needle in body, f"Update page missing new label {needle!r}"

    # ABSENT: old opaque force/reload radio IDs (PRESENT in old code → fail before Phase 6)
    for needle in (
        'id="pfb_force_update"',
        'id="pfb_force_cron"',
        'id="pfb_force_reload"',
        'id="pfb_reload_option_all"',
    ):
        assert needle not in body, f"Update page still has old control {needle!r} — Phase-6 revamp not applied"

    # ABSENT: old single-checkbox force name (replaced by the four-mode radio group)
    assert 'name="pfb_run_force"' not in body, (
        "Update page still has old 'pfb_run_force' checkbox — it must be replaced by the 'pfb_force_mode' radio group"
    )


def test_update_page_schedule_and_help_polish(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """Update-page polish: honest DNSBL-category state, itemized Force help, clean Run-Scope
    help, and spaced Run/View buttons.

    Four user-reported alpha.6 rough edges on the Update page, all guarded here against
    regression (each assertion fails on the pre-fix markup):

    Scenario: the Update page renders the corrected Schedule + help + button markup.
      Background: pfBlockerNG deployed with the DNSBL Category feature NOT configured
      (the suite never enables it), so the category job can never run.

    Given the Update page renders cleanly (200, no PHP diagnostic, section markers),

    When the body is inspected,

    Then the DNSBL Category schedule row reports ``Disabled`` rather than the misleading
      ``Not yet run`` — the bl job only runs (and records a ledger entry) when the feature
      is enabled with a category selected, so an unconfigured install must say why it is
      not scheduled, not pretend a run is pending (pre-fix it showed ``<em>Not yet run</em>``);
    And the Run Scope help no longer carries the stray ``on Run Now`` qualifier;
    And the Force help is itemized per mode (a ``<strong>`` label per None/Parse/Download/Both)
      instead of one run-on sentence (pre-fix there were no ``<strong>`` mode labels);
    And the Run button carries an inline right margin so it is visibly separated from the
      View button on desktop too (pre-fix the column-wrapped buttons sat flush, the gap only
      appearing on mobile).

    ``php_error_log_guard`` enrolls this GET in the module-level no-growth sweep.
    """
    resp = webui.get(_UPDATE_PAGE)
    result = evaluate_render(_UPDATE_PAGE, resp.status_code, resp.text, ("Update Settings", "Schedule"))
    assert result.ok, f"Update page render oracle failed: {result.detail}"
    body = resp.text

    # DNSBL Category row: feature unconfigured ⇒ "Disabled". Scope to THIS row's value cell
    # (the markup right after its label), not the whole body, so unrelated markup can't pass it.
    assert "DNSBL category" in body, "Update page missing the 'DNSBL category' schedule row"
    cat_row = body.split("DNSBL category", 1)[1][:500]
    assert "<em>Disabled</em>" in cat_row, (
        "DNSBL category row should read 'Disabled' when the category feature is off, "
        f"not the misleading 'Not yet run' — row markup was: {cat_row[:200]!r}"
    )

    # Run Scope help: the stray 'on Run Now' qualifier is gone. Match the precise OLD help
    # string (not a bare "on Run Now", which also appears in an unrelated inline JS comment).
    assert "Which lists to sync: Both, IP-only, or DNSBL-only." in body, "Run Scope help text not updated"
    assert "Which lists to sync on Run Now" not in body, "Run Scope help still carries the stray 'on Run Now' qualifier"

    # Force help: itemized with a bold label per mode.
    for needle in (
        "<strong>None:</strong>",
        "<strong>Parse:</strong>",
        "<strong>Download:</strong>",
        "<strong>Both:</strong>",
    ):
        assert needle in body, f"Force help not itemized — missing {needle!r}"

    # Run button: inline right margin (desktop spacing). Scope to the Run Now <button>
    # element itself, not the whole body, so the margin is proven to be ON that button.
    run_btn = next((b for b in re.findall(r"<button\b.*?</button>", body, re.S) if "Run Now" in b), None)
    assert run_btn is not None, "Update page missing the Run Now button"
    assert "margin-right" in run_btn, (
        f"Run button has no inline right margin — it will sit flush against View on desktop: {run_btn!r}"
    )


_LEDGER_DIR = "/var/db/pfblockerng"
_PFB_EXTRA_INC = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"


def _write_ledger_entry(vm: SmokeVM, job_key: str, last_run: int, next_due: int, jitter: int = 0) -> None:
    """Seed one due-ledger job entry via the package's own PHP ledger writer (ADR-43's
    format) -- a hand-written JSON file risks drifting from pfb_due_ledger_write_entry()'s
    own shape. Mirrors tests/smoke/test_smoke_tick.py's local helper of the same shape.
    """
    snippet = (
        f"require_once('{_PFB_EXTRA_INC}');"
        f"pfb_due_ledger_write_entry('{job_key}', array("
        f"'last_run' => {int(last_run)}, 'next_due' => {int(next_due)}, 'jitter' => {int(jitter)}"
        f"), '{_LEDGER_DIR}');"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_write_ledger_entry failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def test_update_page_schedule_shows_seconds_precision(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The Schedule section's Last/Next timestamps now include seconds (ADR-60 P10):
    pfb_ledger_entry_html() switched from 'Y-m-d H:i' to 'Y-m-d H:i:s'.

    Scenario: a due-ledger 'cron' entry with a known last_run/next_due epoch is seeded,
    then the Update page is rendered.

    Given a 'cron' ledger entry with last_run/next_due epochs whose seconds component is
      deliberately non-zero (':45'),
    When the Update page is GET,
    Then the rendered Schedule line shows BOTH timestamps WITH those seconds -- the
      pre-fix minute-only format would have silently dropped them.
    """
    last_run = 1735722045  # 2025-01-01 09:00:45 UTC -- non-zero seconds so a minute-only
    # render (the pre-fix format) would visibly truncate them.
    next_due = last_run + 900  # +15 minutes, still :45s

    _write_ledger_entry(smoke_vm, "cron", last_run, next_due)

    resp = webui.get(_UPDATE_PAGE)
    result = evaluate_render(_UPDATE_PAGE, resp.status_code, resp.text, ("Update Settings", "Schedule"))
    assert result.ok, f"Update page render oracle failed: {result.detail}"

    assert re.search(r"Last:\s*<strong>[\d-]+ \d{2}:\d{2}:45</strong>", resp.text), (
        "Update page Schedule 'Last' timestamp must show seconds precision (':45') -- "
        f"the pre-fix 'Y-m-d H:i' format truncates them; body snippet around 'Last:': "
        f"{resp.text[resp.text.find('Last:') : resp.text.find('Last:') + 80]!r}"
    )
    assert re.search(r"Next:\s*<strong>[\d-]+ \d{2}:\d{2}:45</strong>", resp.text), (
        "Update page Schedule 'Next' timestamp must show seconds precision (':45')"
    )


_CFG_PFB_ENABLE = "installedpackages/pfblockerng/config/0/enable_cb"
_CFG_TICK_INTERVAL = "installedpackages/pfblockerng/config/0/pfb_tick_interval"
_DNSBL_STAT_DB = "/var/unbound/pfb_py_dnsbl.sqlite"
_WIDGET_PAGE = "/widgets/widgets/pfblockerng.widget.php"


# Dual-marked ui_e2e (issue #810, same rationale as test_alerts_unified_log_colour_fields_render):
# this test mutates config.xml (enable_cb + pfb_dnsbl) as setup.
@pytest.mark.ui_e2e
def test_widget_dnsbl_stat_renders_year_bearing_iso_timestamp(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The dashboard widget's per-group DNSBL 'last updated' stat renders a YEAR-bearing
    ISO timestamp (ADR-60 P10 -- dnsbl_stats_update() stores 'Y-m-d H:i:s', not the
    old year-less 'M j H:i:s' that pfb_iso_timestamp() had to guess a year for).

    Seeds the SQLite 'dnsbl' row directly (the widget's own read path, ``SELECT * FROM
    dnsbl``) with a value in the NEW year-bearing shape, then confirms the rendered
    group row shows that exact value -- proving pfb_iso_timestamp()'s round-trip-unchanged
    branch is what actually reaches the page for a fresh (post-fix) stored value.
    """
    helpers.ensure_dnsbl_vip(smoke_vm)
    orig_enable = helpers.config_get(smoke_vm, _CFG_PFB_ENABLE)
    orig_dnsbl = helpers.config_get(smoke_vm, CFG_PFB_DNSBL)
    helpers.php_eval(
        smoke_vm,
        f"config_set_path('{_CFG_PFB_ENABLE}', 'on');\n"
        f"config_set_path('{CFG_PFB_DNSBL}', 'on');\n"
        "write_config('pfBlockerNG smoke: enable DNSBL for the widget stat render check');\n"
        "echo 'OK';",
    )

    group = f"PFB_SMOKE_WIDGETSTAT_{uuid.uuid4().hex[:8]}"
    seed_snippet = (
        f"$db = new SQLite3('{_DNSBL_STAT_DB}');"
        '$db->exec("CREATE TABLE IF NOT EXISTS dnsbl '
        '(groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER);");'
        "$stmt = $db->prepare('INSERT OR REPLACE INTO dnsbl (groupname, timestamp, entries, counter) "
        "VALUES (:g, :t, :e, :c)');"
        f"$stmt->bindValue(':g', '{group}', SQLITE3_TEXT);"
        "$stmt->bindValue(':t', '2025-01-01 09:00:45', SQLITE3_TEXT);"
        "$stmt->bindValue(':e', 42, SQLITE3_INTEGER);"
        "$stmt->bindValue(':c', 0, SQLITE3_INTEGER);"
        "$stmt->execute();"
        "$db->close();"
        "echo 'OK';"
    )
    seed = helpers.php_eval(smoke_vm, seed_snippet)
    assert "OK" in seed.stdout, (
        f"failed to seed the dnsbl stat row: rc={seed.returncode} {seed.stderr!r} {seed.stdout!r}"
    )

    try:
        resp = webui.get(_WIDGET_PAGE)
        result = evaluate_render(_WIDGET_PAGE, resp.status_code, resp.text, ('id="pfblockerngack"',))
        assert result.ok, f"Widget render oracle failed: {result.detail}"
        assert "2025-01-01 09:00:45" in resp.text, (
            f"widget must render the year-bearing ISO stat for group {group!r} unchanged; not found in body"
        )
    finally:
        helpers.php_eval(
            smoke_vm,
            f"$db = new SQLite3('{_DNSBL_STAT_DB}');"
            "$stmt = $db->prepare('DELETE FROM dnsbl WHERE groupname = :g');"
            f"$stmt->bindValue(':g', '{group}', SQLITE3_TEXT);"
            "$stmt->execute();"
            "$db->close();"
            "echo 'OK';",
        )
        helpers.php_eval(
            smoke_vm,
            f"config_set_path('{_CFG_PFB_ENABLE}', '{orig_enable}');\n"
            f"config_set_path('{CFG_PFB_DNSBL}', '{orig_dnsbl}');\n"
            "write_config('pfBlockerNG smoke: restore enable_cb/pfb_dnsbl after widget stat render check');\n"
            "echo 'OK';",
        )


def test_dnsbl_idn_blocking_fields_render(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The ADR-08 'IDN Blocking' selector + its two Confusable sub-toggles render
    cleanly on the DNSBL page — so a regression that drops or breaks the field is
    caught at the render tier (not just by the matcher smoke).

    Asserts the page passes the clean-render oracle AND that the three POST field
    names (``pfb_idn`` select + the two sub-toggle checkboxes) and the 'IDN Blocking'
    / 'Confusable' option labels are present in the body. ``php_error_log_guard``
    enrolls this GET in the module-level no-growth sweep.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    for needle in (
        'name="pfb_idn"',
        'name="pfb_idn_block_malicious"',
        'name="pfb_idn_escalate_suspicious"',
        "IDN Blocking",
        ">Always<",  # the 'all' mode option label (renamed from "All-IDN")
        ">Confusable<",
    ):
        assert needle in body, f"DNSBL page is missing the IDN-mode marker {needle!r}"


def test_dnsbl_control_fields_render(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The DNSBL Control toggle + its deprecated legacy DNS-TXT sub-toggle (PFBL-03) render
    cleanly on the DNSBL page — so a regression that drops or breaks either field is caught
    at the render tier.

    Asserts the page passes the clean-render oracle AND that both POST field names
    (``pfb_control`` + ``pfb_control_legacy``) and their labels are present in the body.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    for needle in (
        'name="pfb_control"',
        'name="pfb_control_legacy"',
        "DNSBL Control",
        "DNSBL Control (legacy DNS TXT)",
    ):
        assert needle in body, f"DNSBL page is missing the control marker {needle!r}"


def test_dnsbl_top1m_source_options_exclude_alexa(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The TOP1M 'Type' select renders the five live sources (Tranco, Cisco
    Umbrella, OpenPageRank, Majestic Million — added ADR-59 Phase 4 — and Cloudflare
    Radar — added ADR-59 Phase 5) — the dead Alexa TOP1M option (#872) is dropped
    from the page (#877), so a regression that resurrects the option, or drops a
    live one, is caught at the render tier. Majestic's CC BY 3.0 and Cloudflare's
    CC BY-NC attribution notes (required by their licences) must also render, along
    with the masked, write-only top1m_token field Cloudflare needs.

    Asserts the page passes the clean-render oracle AND that all five live option
    labels, both attribution notes, and the masked token field are present, while
    the removed 'Alexa TOP1M' label and its ``value="alexa"`` option are absent
    from the body.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    for needle in (
        "Tranco TOP1M",
        "Cisco Umbrella TOP1M",
        "OpenPageRank TOP1M",
        "Majestic Million TOP1M",
        "Cloudflare Radar",
        'name="top1m_enable"',
        'name="top1m_count"',
        'name="top1m_inclusion[]"',
    ):
        assert needle in body, f"DNSBL page is missing the TOP1M settings marker {needle!r}"
    # Self-coupled to Majestic specifically (#892 review) -- the bare substrings "CC BY"
    # and "3.0" are also individually satisfied by Cloudflare's "(CC BY-NC) 4.0" note, so
    # this would pass even if Majestic's own note vanished.
    assert "(CC BY) 3.0" in body, "DNSBL page is missing the Majestic (CC BY) 3.0 attribution note"
    # Exact form, like Majestic's above (#909): the split "CC BY-NC" + "4.0" pair was
    # satisfiable by any unrelated "4.0" elsewhere in the page body.
    assert "(CC BY-NC) 4.0" in body, "DNSBL page is missing the Cloudflare (CC BY-NC) 4.0 attribution note"
    assert 'name="top1m_token"' in body, "DNSBL page is missing the top1m_token field"
    assert 'type="password"' in body, "DNSBL page's top1m_token field must be masked (type=password)"
    for absent in ("Alexa TOP1M", 'value="alexa"'):
        assert absent not in body, f"DNSBL page still renders the dropped Alexa TOP1M option ({absent!r})"


def test_dnsbl_top1m_type_help_says_update_not_force_reload(
    webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The TOP1M 'Type' select's help text says an Update suffices after a type change,
    not the stale 'Force Reload - DNSBL' instruction (#886) — the Save handler preserves
    the cached source and marks TOP1M for reprocessing, so a plain Update reuses or refreshes
    it; a Force Reload was never actually required.

    Asserts the page passes the clean-render oracle AND that the field's help text
    mentions 'Update' while no longer telling the user to run a Force Reload.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    assert "select the type and Save, then run an Update" in body, (
        "DNSBL page's TOP1M Type help no longer tells the user an Update suffices"
    )
    # The old TOP1M Type help's exact wording (distinct from the OTHER, still-accurate
    # Force-Reload help texts elsewhere on this page -- TLD Exclusion / Global-log) --
    # its absence pins that the stale instruction was actually replaced, not just added to.
    assert "select type and Save, followed by a" not in body, (
        "DNSBL page's TOP1M Type help still carries the stale Force-Reload wording"
    )


def test_dnsbl_lenient_parsing_field_renders(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The ADR-22 'Download Schemes' toggle renders cleanly on the DNSBL page — so a
    regression that drops or breaks the field is caught at the render tier (not only by the
    feed-parsing smoke).

    Asserts the page passes the clean-render oracle AND that the POST field name
    (``pfb_dnsbl_lenient``) and its 'Download Schemes' label are present in the body.
    ``php_error_log_guard`` enrolls this GET in the module-level no-growth sweep.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    for needle in (
        'name="pfb_dnsbl_lenient"',
        "Download Schemes",
    ):
        assert needle in body, f"DNSBL page is missing the lenient-parsing marker {needle!r}"


def test_dnsbl_redir_exception_and_fill_fields_render(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The ADR-36/37 DNS-Redirect & DoT/DoQ-Block exception-alias autocomplete + the
    interface quick-fill rewrite render cleanly on the DNSBL page — so a regression that
    drops the autocomplete wiring or reverts the fill helper is caught at the render tier
    (the browser-only behaviours themselves are exercised by the Tier-B browser tests).

    Asserts the page passes the clean-render oracle AND that the markers for all three
    PR-660 fixes are present: the two exception-alias input field names, the autocomplete
    bootstrap function + its alias-name source array, and the ``.val(...)`` fill rewrite
    (the form that replaced the broken per-option ``.prop('selected')`` loop).
    ``php_error_log_guard`` enrolls this GET in the module-level no-growth sweep.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    for needle in (
        # (2) Exception Alias fields + their autocomplete wiring.
        'name="dnsbl_redir_exclude"',
        'name="dnsbl_dot_block_exclude"',
        "pfb_redir_exclude_autocomplete",
        "pfb_alias_names",
        # (3) The fill rewrite — now a single shared pfb_fill_interfaces(selectName, fillSet)
        # helper: the canonical .val([...]).trigger('change') form (not the old .prop() loop),
        # the bracketed-name selector built from the passed-in selectName (a pfSense
        # multi-select renders id/name as "<field>[]", so the fill must target it by name, not
        # the broken bracket-free "#id"), and both onclick call sites wiring the two buttons.
        ".val(fillSet).trigger('change')",
        "select[name=\"' + selectName + '[]\"]",
        "pfb_fill_interfaces('dnsbl_redir_int', pfb_redir_fill_ifaces)",
        "pfb_fill_interfaces('dnsbl_dot_block_int', pfb_dot_block_fill_ifaces)",
    ):
        assert needle in body, f"DNSBL page is missing the redirect/fill marker {needle!r}"


def test_dnsbl_doh_list_select_is_bounded_scrollable(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The 'DoH/DoT/DoQ Blocking List' multi-select renders with a bounded, scrollable
    height instead of expanding to show all ~140 providers at once.

    A ``<select multiple>`` whose ``size`` exceeds its option count shows every row with no
    scrollbar; the field previously carried ``size="140"`` (one row per provider), so the
    list dominated the page. Capping ``size`` below the option count makes the browser render
    a fixed-height, natively scrollable box — matching the TLD multi-select (``size="20"``).

    Pins the change: against the pre-change page the oversized ``size="140"`` was present
    (this fails), against the post-change page it is gone and the field renders with the
    bounded ``size="20"`` (this passes). ``php_error_log_guard`` enrolls this GET in the
    module-level no-growth sweep.

    Also pins issue #740 (the malformed Yandex DoH entry): the option list must render the
    FIXED ``dns.yandex`` key (the real Yandex DoH/DoT endpoints added in its place) and must
    NOT still carry the dead ``yandex.dns`` token — a regression that reintroduced the
    malformed key would fail this Tier-A check without needing a live-VM DNS probe.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    # The field still renders (a pfSense multi-select renders its name as "<field>[]").
    assert 'name="safesearch_doh_list[]"' in body, "DNSBL page is missing the DoH/DoT/DoQ Blocking List select"
    # The oversized, unscrollable height is gone and replaced by the bounded one.
    assert 'size="140"' not in body, "DoH/DoT/DoQ Blocking List select still renders the oversized size='140'"
    assert 'size="20"' in body, "DoH/DoT/DoQ Blocking List select is missing the bounded scrollable size='20'"
    # #740: the fixed Yandex option value renders, and the dead malformed token is gone.
    assert 'value="dns.yandex"' in body, "DNSBL page is missing the fixed Yandex DoH/DoT option 'dns.yandex' (#740)"
    assert "yandex.dns" not in body, "DNSBL page still renders the dead malformed 'yandex.dns' token (#740)"


def test_dnsbl_encrypted_dns_sections_order(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The DNS Redirect and DoT/DoQ Block sections render ABOVE the
    ``DNS over HTTPS/TLS/QUIC`` sub-heading on the DNSBL page.

    The encrypted-DNS controls were reordered so the active interception controls (redirect
    plain DNS, block DoT/DoQ) come first and the provider-name blocklist sits last. This is
    a structural/positional change, so the order of the headings in the rendered HTML is
    the oracle.

    The DoH marker is the subhdr markup (``>DNS over HTTPS/TLS/QUIC<``), not the help
    sentence that also contains that phrase, and not the old Form_Section title that
    ended in ``Blocking``.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    doh_pos = body.find(">DNS over HTTPS/TLS/QUIC<")
    redir_pos = body.find("DNS Redirect")
    dot_pos = body.find("DoT/DoQ Block")
    assert doh_pos != -1, "DNSBL page is missing the 'DNS over HTTPS/TLS/QUIC' sub-heading"
    assert redir_pos != -1, "DNSBL page is missing the 'DNS Redirect' section heading"
    assert dot_pos != -1, "DNSBL page is missing the 'DoT/DoQ Block' section heading"
    assert redir_pos < doh_pos, (
        f"'DNS Redirect' (pos {redir_pos}) must render above 'DNS over HTTPS/TLS/QUIC' (pos {doh_pos})"
    )
    assert dot_pos < doh_pos, (
        f"'DoT/DoQ Block' (pos {dot_pos}) must render above 'DNS over HTTPS/TLS/QUIC' (pos {doh_pos})"
    )


def test_dnsbl_group_policy_section_renders_above_dns_redirect(
    webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The collapsible DNSBL Group Policy panel renders ABOVE the DNS Redirect section.

    The panel was moved up next to the main 'DNSBL' section (which holds its pfb_gp
    enable checkbox) instead of sitting below the encrypted-DNS sections. This is a
    structural/positional change, so the order of the section markup in the rendered
    HTML is the oracle.

    The oracle keys on the section's unique ``Python_Group_Policy`` id, NOT the
    'DNSBL Group Policy' text — that text also appears as the enable-checkbox label
    inside the main 'DNSBL' section (which is always above DNS Redirect), so matching
    it would pass on the pre-change page too.

    Pins the change: pre-change the Group Policy section markup appeared BELOW the
    'DNS Redirect' section heading (so this assertion fails); post-change it appears
    above it.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    gp_pos = body.find("Python_Group_Policy")
    redir_pos = body.find("DNS Redirect")
    assert gp_pos != -1, "DNSBL page is missing the 'Python_Group_Policy' Group Policy section id"
    assert redir_pos != -1, "DNSBL page is missing the 'DNS Redirect' section heading"
    assert gp_pos < redir_pos, (
        f"'DNSBL Group Policy' section (id 'Python_Group_Policy', pos {gp_pos}) must render "
        f"above 'DNS Redirect' (pos {redir_pos})"
    )


# The four TLD Allow picker selects (issue #876) -- built from the IANA-sourced gTLD/ccTLD/
# iTLD arrays + the hand-curated bgTLD array in pfblockerng_dnsbl.php's $tld_list. Each is
# checked for a STABLE, durable TLD rather than a newly-added one -- IANA's TLD set churns
# release to release, so "was just added" is not a safe assertion target, but these have
# existed for years and are extremely unlikely to be retired.
_TLD_STABLE_OPTIONS = {
    "tld_allow_gtld": "com",
    "tld_allow_cctld": "de",
    "tld_allow_itld": "xn--p1ai",  # a punycode (IDN) TLD -- Russia's .рф
    "tld_allow_bgtld": "ovh",
}


def test_dnsbl_page_renders_tld_pickers(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The TLD Allow pickers render populated after the IANA refresh (#876).

    Regression guard against a malformed ``$tld_list`` rewrite by
    ``scripts/misc/update_tld_lists.py``: asserts all four TLD-Allow Form_Select fields
    (gTLD/ccTLD/iTLD/bgTLD) render by name AND each carries a real option -- one stable,
    durable TLD per category (see :data:`_TLD_STABLE_OPTIONS`) so the guard survives IANA's
    routine TLD churn instead of pinning a TLD that could vanish on the next refresh.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL render oracle failed: {result.detail}"
    body = resp.text
    # Each picker is a pfSense multi-select (Form_Select(..., TRUE)), so its name renders
    # with a trailing "[]" (see the safesearch_doh_list[] assertion above).
    missing_selects = [name for name in _TLD_STABLE_OPTIONS if f'name="{name}[]"' not in body]
    assert not missing_selects, f"DNSBL page is missing TLD-Allow select(s) {missing_selects}"
    missing_options = [
        f"{name}(value={value!r})" for name, value in _TLD_STABLE_OPTIONS.items() if f'value="{value}"' not in body
    ]
    assert not missing_options, f"DNSBL page TLD-Allow select(s) missing a stable option: {missing_options}"
    # The "N TLDs available" count is computed from the arrays (number_format($tld_total)),
    # not the old hardcoded "1,546". Assert it rendered a plausible, non-stale total -- this
    # also catches a silently-blanked $tld_list (the count would collapse to a tiny number).
    count_match = re.search(r"\(([\d,]+) TLDs available\)", body)
    assert count_match, "DNSBL page is missing the '(N TLDs available)' help text"
    tld_count = int(count_match.group(1).replace(",", ""))
    assert tld_count >= 1000, f"TLD-Allow count {tld_count} is implausibly low (arrays blanked?)"
    assert count_match.group(1) != "1,546", "TLD-Allow count is still the stale hardcoded 1,546"
    # Aggregate and per-list figures derive from the same $tld_list, so they must agree on
    # the rendered page -- a divergence the ">= 1000" floor cannot see.
    per_list = [int(n) for n in re.findall(r"Total TLD Count: \[(\d+)\]", body)]
    assert len(per_list) == len(_TLD_STABLE_OPTIONS), (
        f"expected {len(_TLD_STABLE_OPTIONS)} per-list TLD counts, found {len(per_list)}: {per_list}"
    )
    assert sum(per_list) == tld_count, (
        f"TLD-Allow aggregate {tld_count} != sum of the rendered per-list counts {per_list} = {sum(per_list)}"
    )


# The DNSBL master-enable toggle -- gates the 'dnsbl'/'upstream'/'reply' rows of the alerts
# page's $uni_defaults Unified-Log colour registry (pfblockerng_alerts.php). Off by default on
# a fresh install, so test_alerts_unified_log_colour_fields_render turns it on for its GET (and
# always restores whatever it read first, so a pre-existing 'on' round-trips as a no-op).
CFG_PFB_DNSBL = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"


# Dual-marked ui_e2e (issue #810): this test MUTATES config.xml (flips pfb_dnsbl on) as
# setup, so it must ride the per-test isolation probe (_ui_pfb_isolation gates on the
# ui_e2e/ui_browser markers); the module-level ui_render marker keeps it in the Tier-A gate.
@pytest.mark.ui_e2e
def test_alerts_unified_log_colour_fields_render(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The Alerts page's Unified-Log colour fields — built by looping over the $uni_defaults
    registry (one pass per light/dark theme) — render cleanly, including the DNSBL-gated rows.

    Asserts the always-present 'block' row (``name="uniblock"``/``"uniblock2"``) AND, with the
    DNSBL master toggle turned on for this GET, the gated 'reply' row (``name="unireply2"``)
    plus its light-only help asymmetry (``'(Resolver only)'`` — the light help text differs from
    the dark help text only for this one row) — so a regression in the loop rewrite (a dropped
    row, a missing gate, or a lost help-text override) is caught at the render tier.

    The config toggle alone is NOT enough: pfb_global force-disables the runtime
    ``$pfb['dnsbl']`` ("DNSBL disabled: no VIP configured", pfblockerng.inc) when
    ``pfb_validate_vips`` finds no sinkhole VIP, and the page's colour-field gate reads that
    downgraded value — so without a VIP the gated ``unireply2`` row never renders and this
    test fails on a bare image. Seed the VIP first (idempotent, the standard harness fixture).
    """
    helpers.ensure_dnsbl_vip(smoke_vm)
    original = helpers.config_get(smoke_vm, CFG_PFB_DNSBL)
    helpers.php_eval(
        smoke_vm,
        f"config_set_path('{CFG_PFB_DNSBL}', 'on');\n"
        "write_config('pfBlockerNG smoke: enable DNSBL for the alerts unified-log render check');\n"
        "echo 'OK';",
    )
    try:
        path = "/pfblockerng/pfblockerng_alerts.php"
        resp = webui.get(path)
        result = evaluate_render(path, resp.status_code, resp.text, ("Alert Settings",))
        assert result.ok, f"Alerts render oracle failed: {result.detail}"
        body = resp.text
        for needle in (
            'name="uniblock"',
            'name="uniblock2"',
            'name="unireply2"',
            "(Resolver only)",
        ):
            assert needle in body, f"Alerts page is missing the unified-log colour marker {needle!r}"
    finally:
        helpers.php_eval(
            smoke_vm,
            f"config_set_path('{CFG_PFB_DNSBL}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore DNSBL toggle');\n"
            "echo 'OK';",
        )


def test_general_private_address_label_renders(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The General reorg renamed the pfb_feed_internal_allowlist textarea label from
    "Internal Feed Host Exemptions" to "Block Private-Address Exceptions".

    A dedicated assertion rather than a PAGE_TABLE marker because the render oracle matches
    markers with ``any()``: a fifth marker beside four that already render would pass whether
    or not the label survives (coverage theater). Asserting the new string present AND the old
    absent gives an unambiguous fail-before / pass-after for the rename.
    """
    path = "/pfblockerng/pfblockerng_general.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("General Settings",))
    assert result.ok, f"General render oracle failed: {result.detail}"
    body = resp.text
    assert "Block Private-Address Exceptions" in body, (
        "General page is missing the 'Block Private-Address Exceptions' textarea label"
    )
    assert "Internal Feed Host Exemptions" not in body, (
        "General page still renders the pre-reorg 'Internal Feed Host Exemptions' label"
    )


def test_feeds_custom_panel_heading_renders(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The second Feeds panel — the one listing user-configured feeds that don't match the
    predefined catalog — is headed "Custom Feeds", not the former "Unknown user defined Feeds".

    The heading is the shared panel title (renders on every ?type sub-tab, outside the
    row-rendering guard), so it is a stable render marker. This is a dedicated assertion rather
    than an entry in PAGE_TABLE because the render oracle matches markers with ``any()``: adding
    "Custom Feeds" to a tuple that already carries a present marker would pass on the old heading
    too (coverage theater). Asserting the new string present AND the old string absent gives an
    unambiguous fail-before / pass-after for the rename.
    """
    path = "/pfblockerng/pfblockerng_feeds.php?type=ipv4"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("Pre-defined Alias/Group/Feeds",))
    assert result.ok, f"Feeds render oracle failed: {result.detail}"
    body = resp.text
    assert "CCT_IP" not in body, "Feeds page still offers the discontinued CCT_IP feed"
    assert "Custom Feeds" in body, "Feeds page is missing the 'Custom Feeds' panel heading"
    assert "Unknown user defined Feeds" not in body, (
        "Feeds page still shows the old 'Unknown user defined Feeds' heading"
    )


# Dual-marked ui_e2e because setup writes one config row; the module-level
# ui_render marker keeps this live render regression in the Tier-A gate.
@pytest.mark.ui_e2e
def test_feeds_non_contiguous_alternate_bucket_renders_every_row(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:  # noqa: ARG001
    """A configured non-first SFS alternate renders it and every later alternate (#1702)."""
    path = "/pfblockerng/pfblockerng_feeds.php?type=ipv4"
    rowid = _free_rowid(smoke_vm, CFG_IPV4)
    base = f"{CFG_IPV4}/{rowid}"
    matched_url = "https://www.stopforumspam.com/downloads/listed_ip_7.zip"
    headers = ("SFS_7d", "SFS_30d", "SFS_90d", "SFS_180d", "SFS_365d")
    try:
        seed = helpers.php_eval(
            smoke_vm,
            f"config_set_path({helpers._php_str(f'{base}/aliasname')}, 'SFS');\n"
            f"config_set_path({helpers._php_str(f'{base}/action')}, 'Deny_Both');\n"
            f"config_set_path({helpers._php_str(f'{base}/row/0/state')}, 'Enabled');\n"
            f"config_set_path({helpers._php_str(f'{base}/row/0/url')}, {helpers._php_str(matched_url)});\n"
            f"config_set_path({helpers._php_str(f'{base}/row/0/header')}, 'SFS_7d');\n"
            "write_config('pfBlockerNG smoke #1702: seed non-first alternate');\n"
            "echo 'OK';",
        )
        assert seed.returncode == 0 and "OK" in seed.stdout, (
            f"failed to seed SFS alternate row: rc={seed.returncode}, stdout={seed.stdout!r}, stderr={seed.stderr!r}"
        )
        assert helpers.config_get(smoke_vm, f"{base}/row/0/url") == matched_url, (
            "non-first alternate setup did not persist"
        )

        resp = webui.get(path)
        result = evaluate_render(path, resp.status_code, resp.text, ("Pre-defined Alias/Group/Feeds",))
        assert result.ok, f"Feeds render oracle failed: {result.detail}"

        markers = [f'value="alt_{header}"' for header in headers]
        positions = [resp.text.find(marker) for marker in markers]
        assert all(position >= 0 for position in positions), (
            f"configured alternate and later rows did not all render: {dict(zip(headers, positions, strict=True))}"
        )
        assert positions == sorted(positions), (
            f"alternate rows did not preserve source order: {dict(zip(headers, positions, strict=True))}"
        )
    finally:
        _del_rowid(smoke_vm, CFG_IPV4, rowid)


def test_dnsbl_cache_flush_option_renders(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """DNSBL page exposes the default-off full-cache trade-off without PHP diagnostics."""
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"DNSBL cache-flush render oracle failed: {result.detail}"
    assert 'name="pfb_cache_flush"' in resp.text, "DNSBL page is missing the cache-flush checkbox"
    assert "When disabled, cached allowed answers remain until their DNS TTL expires" in resp.text, (
        "DNSBL cache-flush help must explain the default-disabled TTL trade-off"
    )


# issue #1907: dnsbl/pfb_cache, dnsbl/pfb_py_reply, dnsbl/pfb_hsts (DNSBL page) and
# ip/suppression (IP page) flipped their registry default to 'on' -- the checkbox must
# render CHECKED with no stored config, and still render UNCHECKED for a present Off token
# for both canonical empty and legacy ``off`` storage.
_ISSUE1907_DNSBL_TOGGLES = (
    ("pfb_cache", "installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache"),
    ("pfb_py_reply", "installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply"),
    ("pfb_hsts", "installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts"),
)
_ISSUE1907_IP_SUPPRESSION_PATH = "installedpackages/pfblockerngipsettings/config/0/suppression"


def _config_path_exists(vm: SmokeVM, path: str) -> bool:
    """Return whether a scalar config path exists, distinguishing missing from empty."""
    return (
        helpers._php_read_scalar(vm, "", f"config_get_path({helpers._php_str(path)}, null) === null ? '0' : '1'") == "1"
    )


def _set_scalar_or_absent(vm: SmokeVM, path: str, value: str | None) -> None:
    """Set ``path`` to ``value``, or delete it entirely when ``value`` is None. Used both
    to seed a fixture's state and to restore whatever state preceded it."""
    op = (
        f"config_del_path({helpers._php_str(path)});"
        if value is None
        else f"config_set_path({helpers._php_str(path)}, {helpers._php_str(value)});"
    )
    result = helpers.php_eval(vm, f"{op}\nwrite_config('pfBlockerNG smoke #1907: toggle render check');\necho 'OK';")
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"failed to set {path!r}: stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_dnsbl_python_gated_toggles_render_checked_when_absent(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """issue #1907: pfb_cache/pfb_py_reply/pfb_hsts render CHECKED with no stored config --
    the registry default flipped to 'on', matching the page's REMOVED
    ``isset(...) ? ... : 'on'`` fallback (PfbConfig::read() now owns the default).
    """
    vm = smoke_vm
    priors = {
        path: helpers.config_get(vm, path) if _config_path_exists(vm, path) else None
        for _name, path in _ISSUE1907_DNSBL_TOGGLES
    }
    for _name, path in _ISSUE1907_DNSBL_TOGGLES:
        _set_scalar_or_absent(vm, path, None)
    try:
        page = "/pfblockerng/pfblockerng_dnsbl.php"
        resp = webui.get(page)
        result = evaluate_render(page, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
        assert result.ok, f"DNSBL render oracle failed: {result.detail}"
        fields = scrape_form_fields(resp.text)
        for name, _path in _ISSUE1907_DNSBL_TOGGLES:
            assert fields.get(name) == "on", (
                f"{name} must render CHECKED with no stored config (issue #1907 default-on), got {fields.get(name)!r}"
            )
    finally:
        for _name, path in _ISSUE1907_DNSBL_TOGGLES:
            _set_scalar_or_absent(vm, path, priors[path])


def test_dnsbl_python_gated_toggles_render_unchecked_when_stored_off(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """Legacy ``off`` and canonical empty Off tokens both render unchecked."""
    vm = smoke_vm
    priors = {
        path: helpers.config_get(vm, path) if _config_path_exists(vm, path) else None
        for _name, path in _ISSUE1907_DNSBL_TOGGLES
    }
    try:
        for stored in ("off", ""):
            for _name, path in _ISSUE1907_DNSBL_TOGGLES:
                _set_scalar_or_absent(vm, path, stored)
            page = "/pfblockerng/pfblockerng_dnsbl.php"
            resp = webui.get(page)
            result = evaluate_render(page, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
            assert result.ok, f"DNSBL render oracle failed for {stored!r}: {result.detail}"
            fields = scrape_form_fields(resp.text)
            for name, _path in _ISSUE1907_DNSBL_TOGGLES:
                assert name not in fields, (
                    f"{name} must render UNCHECKED when stored {stored!r}, got checked with value {fields.get(name)!r}"
                )
    finally:
        for _name, path in _ISSUE1907_DNSBL_TOGGLES:
            _set_scalar_or_absent(vm, path, priors[path])


def test_ip_suppression_renders_checked_when_absent(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """issue #1907: IP page suppression renders CHECKED with no stored config -- the
    registry default flipped to 'on', matching the page's REMOVED
    ``isset(...) ? ... : 'on'`` fallback."""
    vm = smoke_vm
    path = _ISSUE1907_IP_SUPPRESSION_PATH
    prior = helpers.config_get(vm, path) if _config_path_exists(vm, path) else None
    _set_scalar_or_absent(vm, path, None)
    try:
        resp = webui.get(_IP_PAGE)
        result = evaluate_render(_IP_PAGE, resp.status_code, resp.text, ("IP Configuration",))
        assert result.ok, f"IP render oracle failed: {result.detail}"
        fields = scrape_form_fields(resp.text)
        assert fields.get("suppression") == "on", (
            f"suppression must render CHECKED with no stored config (issue #1907 default-on), "
            f"got {fields.get('suppression')!r}"
        )
    finally:
        _set_scalar_or_absent(vm, path, prior)


def test_ip_suppression_renders_unchecked_for_empty_and_legacy_off(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """Canonical empty and legacy ``off`` suppression tokens render unchecked."""
    vm = smoke_vm
    path = _ISSUE1907_IP_SUPPRESSION_PATH
    prior = helpers.config_get(vm, path) if _config_path_exists(vm, path) else None
    try:
        for stored in ("", "off"):
            _set_scalar_or_absent(vm, path, stored)
            resp = webui.get(_IP_PAGE)
            result = evaluate_render(_IP_PAGE, resp.status_code, resp.text, ("IP Configuration",))
            assert result.ok, f"IP render oracle failed for {stored!r}: {result.detail}"
            fields = scrape_form_fields(resp.text)
            assert "suppression" not in fields, (
                f"suppression must render UNCHECKED when stored {stored!r}, "
                f"got checked with value {fields.get('suppression')!r}"
            )
    finally:
        _set_scalar_or_absent(vm, path, prior)


def test_ip_suppression_stays_checked_on_validation_error_rerender(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The validation-error re-render swaps ``$pconfig`` for raw ``$_POST`` strings, so
    the checked-state expression must accept both the enum and the POST string 'on' —
    an enabled box must stay checked through a failed save."""
    resp = webui.post(
        _IP_PAGE,
        {"save": "Save", "ip_placeholder": "not-an-ip", "suppression": "on"},
    )
    assert "Placeholder IP" in resp.text, (
        "expected the Placeholder-IP validation error to fire (the error re-render under test)"
    )
    fields = scrape_form_fields(resp.text)
    assert fields.get("suppression") == "on", (
        f"suppression must stay CHECKED on the validation-error re-render "
        f"(raw POST 'on' in $pconfig), got {fields.get('suppression')!r}"
    )


def test_states_removal_help_references_ip_tab(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The category-edit 'States Removal' help points at the IP tab, where 'Kill States' lives.

    The 'Kill States' (``killstates``) checkbox is on the IP tab (pfblockerng_ip.php), so the
    cross-reference in the IP-alias edit page's 'States Removal' help must read '(IP Tab)', not
    the stale '(General Tab)'.  The field renders only for the IPv4/IPv6 alias type, so this
    probes category_edit with ``?type=ipv4``.

    Fail-before / pass-after: before the fix the States Removal help reads '(General Tab)', so
    the '(IP Tab)' assertion fails; the negative assertion guards against the stale wording
    returning.

    Both needles are scoped to the States Removal sentence ('... you can disable States
    removal') so they cannot be satisfied by the sibling 'Enable Logging' help on the same
    page, which legitimately references the General tab (for the Global Logging override).
    """
    path = "/pfblockerng/pfblockerng_category_edit.php?type=ipv4"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("States Removal",))
    assert result.ok, f"category_edit (ipv4) render oracle failed: {result.detail}"
    body = resp.text
    assert "(IP Tab), you can disable States removal" in body, (
        "States Removal help is missing the corrected '(IP Tab)' cross-reference "
        "(the 'Kill States' option lives on the IP tab)"
    )
    assert "(General Tab), you can disable States removal" not in body, (
        "States Removal help still carries the stale '(General Tab)' cross-reference -- "
        "'Kill States' is on the IP tab, not the General tab"
    )


_CATEGORY_IPV4_PAGE = "/pfblockerng/pfblockerng_category.php?type=ipv4"
_CATEGORY_DNSBL_PAGE = "/pfblockerng/pfblockerng_category.php?type=dnsbl"
_CATEGORY_GEOIP_PAGE = "/pfblockerng/pfblockerng_category.php?type=geoip"


@pytest.mark.parametrize(
    ("path", "expect_reorder_th"),
    (
        pytest.param(_CATEGORY_IPV4_PAGE, True, id="ipv4"),
        pytest.param(_CATEGORY_DNSBL_PAGE, True, id="dnsbl"),
        pytest.param(_CATEGORY_GEOIP_PAGE, False, id="geoip"),
    ),
)
def test_category_page_renders_reorder_wiring(
    path: str, expect_reorder_th: bool, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:  # noqa: ARG001
    """The Category page wires the shared anchor-click reorder component (issue #1147).

    Hermetic. GET the page and assert: (1) ``pfb_reorder_init(`` (the component
    call, ADR-63) is present; (2) the ``pfb_drag_enabled`` boolean var (mirrors
    ``system/webgui/roworderdragging``) is emitted -- both unconditional, so
    they render on every gtype including GeoIP; (3) the reorder ``<th>`` column
    is gated ``$gtype != 'geoip'`` (branch coverage: present on ipv4/dnsbl,
    ABSENT on GeoIP); (4) the row ``class="sortable"`` drag marker is gated the
    same way -- GeoIP rows must NOT carry it, so the GeoIP tab offers no reorder
    (issue #1201: reorder disallowed on GeoIP, whose order never persisted).
    """
    resp = webui.get(path)
    assert resp.status_code == 200, f"GET {path} -> HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert "pfb_reorder_init(" in body, f"pfb_reorder_init( wiring call missing on {path}"
    assert "pfb_drag_enabled" in body, f"pfb_drag_enabled boolean var missing on {path}"
    has_reorder_th = "<!----- Reorder -----></th>" in body
    # The <tr> drag marker rendered as ``class="sortable" id="pfb_rN"`` for a
    # reorderable row (anchored to the id so the table's own
    # ``sortable-theme-bootstrap`` class can't false-match).
    sortable_row = 'class="sortable" id="pfb_r' in body
    if expect_reorder_th:
        assert has_reorder_th, f"reorder <th> column missing on {path}"
    else:
        assert not has_reorder_th, f"GeoIP page must NOT render the reorder <th> column, found on {path}"
        # Non-vacuous: GeoIP always renders built-in continent rows -- assert they
        # exist, then that NONE is a sortable (drag-reorderable) row (issue #1201).
        assert 'id="pfb_r' in body, f"GeoIP page rendered no continent rows on {path}"
        assert not sortable_row, f'GeoIP rows must NOT carry class="sortable" (reorder disallowed, issue #1201): {path}'


# ADR-63 Phase 4 (issue #1147): pfblockerng_category_edit.php's staged reorder
# wiring is gated server-side on sort=='no-sort' -- a fresh (hermetic) box
# always renders sort mode, so the wiring's ABSENCE there is a hermetic check;
# its PRESENCE needs one seeded no-sort row (dual-marked ui_e2e, like the
# maxmind_key never-leak test above -- it mutates config.xml as setup).
_CATEGORY_EDIT_IPV4_PAGE = "/pfblockerng/pfblockerng_category_edit.php?type=ipv4"
_CATEGORY_EDIT_IPV6_PAGE = "/pfblockerng/pfblockerng_category_edit.php?type=ipv6"
_CATEGORY_EDIT_DNSBL_PAGE = "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl"


@pytest.mark.parametrize(
    "path",
    (
        pytest.param(_CATEGORY_EDIT_IPV4_PAGE, id="ipv4"),
        pytest.param(_CATEGORY_EDIT_IPV6_PAGE, id="ipv6"),
        pytest.param(_CATEGORY_EDIT_DNSBL_PAGE, id="dnsbl"),
    ),
)
def test_category_edit_flex_help_states_certificate_verification_disabled(
    path: str, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:  # noqa: ARG001
    """issue #2661: Flex help names what the TLS retry actually disables.

    Given a category-edit Feeds page (IPv4, IPv6, or DNSBL — the State guideline
    is shared across all three),
    When GET,
    Then the Guidelines infoblock says Flex retries with certificate verification
    disabled, and the old 'Downgrade the SSL Connection' wording is gone.

    Fail-before / pass-after: the new phrases are absent and the old sentence is
    present on devel; the production edit inverts both.
    """
    resp = webui.get(path)
    body = resp.text
    result = evaluate_render(path, resp.status_code, body, ("Override Default Schedule",))
    assert result.ok, f"{path}: category-edit render oracle failed: {result.detail}"
    assert "certificate verification disabled" in body, (
        f"{path} is missing Flex help that certificate verification is disabled (issue #2661)"
    )
    assert "widened cipher list" in body, f"{path} is missing Flex help that the cipher list is widened (issue #2661)"
    assert "Not Recommended" in body, f"{path} dropped the Flex 'Not Recommended' framing (issue #2661)"
    assert "unauthenticated" in body, (
        f"{path} is missing Flex help that the feed contents are then unauthenticated (issue #2661)"
    )
    assert "Downgrade the SSL Connection" not in body, (
        f"{path} still uses the unspecific Flex 'Downgrade the SSL Connection' wording (issue #2661)"
    )


@pytest.mark.parametrize(
    "path",
    (
        pytest.param(_CATEGORY_EDIT_IPV4_PAGE, id="ipv4"),
        pytest.param(_CATEGORY_EDIT_DNSBL_PAGE, id="dnsbl"),
    ),
)
def test_category_edit_sort_mode_renders_no_reorder_wiring(
    path: str, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """ADR-63 P4: a fresh (sort-mode, no seeded rows) category-edit page emits NO
    staged-reorder wiring and NO retired Lmove/Xmove markup (issue #1147's old
    mechanism, deleted this phase).

    Hermetic -- a fresh box has no saved alias, so ``$rowdata[$rowid]['sort']``
    is unset (never 'no-sort'), the branch this phase gates the wiring on.
    """
    resp = webui.get(path)
    assert resp.status_code == 200, f"GET {path} -> HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert "pfb_reorder_init(" not in body, f"pfb_reorder_init( must not render in sort mode on {path}"
    assert 'class="pfb-gutter"' not in body, f"pfb-gutter container class must not render in sort mode on {path}"
    assert 'name="Lmove' not in body, f"retired Lmove markup found on {path}"
    assert 'name="Xmove' not in body, f"retired Xmove markup found on {path}"


@pytest.mark.ui_e2e
def test_category_edit_no_sort_mode_renders_reorder_wiring(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:  # noqa: ARG001
    """ADR-63 P4: a no-sort category-edit page emits the staged-reorder wiring +
    the gutter container class, still with zero retired Lmove/Xmove markup.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    try:
        seed = helpers.php_eval(
            vm,
            f"config_set_path({helpers._php_str(f'{base}/aliasname')}, 'pfbrenderns');\n"
            f"config_set_path({helpers._php_str(f'{base}/action')}, 'unbound');\n"
            f"config_set_path({helpers._php_str(f'{base}/sort')}, 'no-sort');\n"
            f"config_set_path({helpers._php_str(f'{base}/row/0/format')}, 'auto');\n"
            f"config_set_path({helpers._php_str(f'{base}/row/0/state')}, 'Disabled');\n"
            f"config_set_path({helpers._php_str(f'{base}/row/0/url')}, '');\n"
            f"config_set_path({helpers._php_str(f'{base}/row/0/header')}, 'pfbrenderns0');\n"
            "write_config('ADR-63 P4 smoke: seed no-sort render row');\n"
            "echo 'OK';",
        )
        assert seed.returncode == 0 and "OK" in seed.stdout, (
            f"failed to seed no-sort category row: rc={seed.returncode}, stdout={seed.stdout!r}, stderr={seed.stderr!r}"
        )

        path = f"/pfblockerng/pfblockerng_category_edit.php?type=dnsbl&rowid={rowid}"
        resp = webui.get(path)
        assert resp.status_code == 200, f"GET {path} -> HTTP {resp.status_code} (expected 200)"
        body = resp.text
        assert "pfb_reorder_init('#sourcedefinitions .panel-body'" in body, (
            f"pfb_reorder_init wiring missing in no-sort mode on {path}"
        )
        assert 'class="pfb-gutter"' in body, f"pfb-gutter container class missing in no-sort mode on {path}"
        assert 'name="Lmove' not in body, f"retired Lmove markup found on {path}"
        assert 'name="Xmove' not in body, f"retired Xmove markup found on {path}"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
def test_corrupt_group_actions_render_repairably(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:  # noqa: ARG001
    """Bogus and array actions fail closed in Alerts and remain repairable.

    Whole IPv4, DNSBL, and Africa GeoIP config nodes are restored exactly.
    """
    vm = smoke_vm

    def node_present(node: str) -> bool:
        pre = (
            "$missing = new stdClass();\n"
            f"$value = config_get_path({helpers._php_str(node)}, $missing);\n"
            "$present = ($value === $missing) ? '0' : '1';"
        )
        return helpers._php_read_scalar(vm, pre, "$present") == "1"

    def file_size(path: str) -> str | None:
        result = vm.ssh("stat", "-f", "%z", path, timeout=15)
        if result.returncode == 0:
            return result.stdout.strip()
        missing = vm.ssh("test", "!", "-e", path, timeout=15)
        if missing.returncode != 0:
            raise RuntimeError(f"stat failed for existing file {path!r}: {result.stderr!r}")
        return None

    geoip_root = "installedpackages/pfblockerngafrica/config"
    dnsbl_was_present = node_present(CFG_DNSBL)
    ipv4_was_present = node_present(CFG_IPV4)
    geoip_was_present = node_present(geoip_root)
    dnsbl_snap = _snapshot_node(vm, CFG_DNSBL)
    ipv4_snap = _snapshot_node(vm, CFG_IPV4)
    geoip_snap = _snapshot_node(vm, geoip_root)
    dnsbl_rowid = _free_rowid(vm, CFG_DNSBL)
    ipv4_rowid = _free_rowid(vm, CFG_IPV4)
    dnsbl_base = f"{CFG_DNSBL}/{dnsbl_rowid}"
    ipv4_base = f"{CFG_IPV4}/{ipv4_rowid}"
    dnsbl_valid_base = f"{CFG_DNSBL}/{dnsbl_rowid + 1}"
    ipv4_valid_base = f"{CFG_IPV4}/{ipv4_rowid + 1}"

    unified_log = "/var/log/pfblockerng/unified.log"
    ip_feed_name = "pfB_RepairActionFeed1346_v4"
    ip_feed = f"/var/db/pfblockerng/deny/{ip_feed_name}.txt"
    unified_size = file_size(unified_log)
    feed_size = file_size(ip_feed)

    ip_host = "198.51.100.134"
    ip_eval = f"{ip_host}/32"
    ip_logged_alias = "pfB_RepairActionDeny1346_v4"
    dns_domain = helpers.unique_domain("repair1346")
    dns_corrupt_action = "CorruptDnsAction1346"
    ip_corrupt_action = "PermitBogus"
    geoip_corrupt_action = "GeoipBogus1346"
    fixed_ts = "Jan 01 00:00:00"
    unified_rows = (
        f"Block,{fixed_ts},100,em0,WAN,block,4,6,TCP,"
        f"{ip_host},10.0.0.134,12345,443,in,US,{ip_logged_alias},{ip_eval},"
        f"{ip_feed_name},Unknown,Unknown,Unknown,,,+\n"
        f"DNS-reply,{fixed_ts},cache,,A,30,{dns_domain},127.0.0.1,203.0.113.134,US\n"
    )

    def assert_action_selected(body: str, path: str, field_name: str, expected: str) -> None:
        select = re.search(rf'<select(?=[^>]*name="{re.escape(field_name)}")[^>]*>(.*?)</select>', body, re.DOTALL)
        assert select is not None, f"action select {field_name!r} missing on {path}"
        selected = re.search(
            rf'<option(?=[^>]*value="{re.escape(expected)}")(?=[^>]*selected(?:=|\s|>))[^>]*>', select.group(1)
        )
        assert selected is not None, (
            f"action {field_name!r} did not render selected {expected!r} on {path}: {select.group(0)!r}"
        )

    def assert_disabled_selected(body: str, path: str) -> None:
        assert_action_selected(body, path, "action", "Disabled")

    def summary_action_field(row: str, path: str) -> str:
        action_field = re.search(r'<select(?=[^>]*name="(action-\d+)")[^>]*>', row)
        assert action_field is not None, f"summary action select missing on {path}: {row!r}"
        return action_field.group(1)

    try:
        seed = helpers.php_eval(
            vm,
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/aliasname')}, 'pfbrepairdns');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/description')}, '');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/action')}, "
            f"array('bogus' => {helpers._php_str(dns_corrupt_action)}));\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/cron')}, 'Never');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/logging')}, 'enabled');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/custom')}, base64_encode('bad.example'));\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/row/0/format')}, 'auto');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/row/0/state')}, 'Disabled');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/row/0/url')}, '');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_base}/row/0/header')}, 'pfbrepairdns0');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_valid_base}/aliasname')}, 'pfbvaliddns1346');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_valid_base}/description')}, '');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_valid_base}/action')}, 'unbound');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_valid_base}/cron')}, 'Never');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_valid_base}/logging')}, 'enabled');\n"
            f"config_set_path({helpers._php_str(f'{dnsbl_valid_base}/custom')}, base64_encode('valid.example'));\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/aliasname')}, 'pfbrepairip');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/description')}, '');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/action')}, {helpers._php_str(ip_corrupt_action)});\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/cron')}, 'Never');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/aliaslog')}, 'enabled');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/custom')}, base64_encode('192.0.2.1'));\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/row/0/format')}, 'auto');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/row/0/state')}, 'Disabled');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/row/0/url')}, '');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_base}/row/0/header')}, 'pfbrepairip0');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_valid_base}/aliasname')}, 'pfbvalidip1346');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_valid_base}/description')}, '');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_valid_base}/action')}, 'Permit_Inbound');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_valid_base}/cron')}, 'Never');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_valid_base}/aliaslog')}, 'enabled');\n"
            f"config_set_path({helpers._php_str(f'{ipv4_valid_base}/custom')}, base64_encode('192.0.2.200'));\n"
            f"$geoip = config_get_path({helpers._php_str(f'{geoip_root}/0')}, array());\n"
            "if (!is_array($geoip)) { $geoip = array(); }\n"
            "$geoip += array('countries4' => '', 'countries6' => '', 'aliaslog' => 'enabled', "
            "'autoaddrnot_in' => '', 'autoports_in' => '', 'aliasports_in' => '', 'autoaddr_in' => '', "
            "'autonot_in' => '', 'aliasaddr_in' => '', 'autoproto_in' => 'any', 'agateway_in' => 'default', "
            "'autoaddrnot_out' => '', 'autoports_out' => '', 'aliasports_out' => '', 'autoaddr_out' => '', "
            "'autonot_out' => '', 'aliasaddr_out' => '', 'autoproto_out' => 'any', 'agateway_out' => 'default');\n"
            f"$geoip['action'] = {helpers._php_str(geoip_corrupt_action)};\n"
            f"config_set_path({helpers._php_str(f'{geoip_root}/0')}, $geoip);\n"
            "write_config('pfBlockerNG smoke: seed corrupt action render rows');\n"
            "echo 'OK';",
        )
        assert seed.returncode == 0 and "OK" in seed.stdout, (
            f"failed to seed corrupt action rows: rc={seed.returncode}, stdout={seed.stdout!r}, stderr={seed.stderr!r}"
        )

        open_marker = "__PFB_ACTION_OPEN__"
        close_marker = "__PFB_ACTION_CLOSE__"
        raw_probe = helpers.php_eval(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc'); "
            f"$raw = config_get_path({helpers._php_str(f'{dnsbl_base}/action')}, NULL); "
            "$normalized = pfb_group_action_valid($raw, 'dnsbl') ? $raw : 'Disabled'; "
            f"echo '{open_marker}' . json_encode(array(gettype($raw), "
            f"pfb_group_action_valid($raw, 'dnsbl'), $normalized)) . '{close_marker}';",
        )
        probe_diag = f"stdout={raw_probe.stdout!r}, stderr={raw_probe.stderr!r}"
        assert raw_probe.returncode == 0, f"DNSBL action raw probe failed rc={raw_probe.returncode}: {probe_diag}"
        assert raw_probe.stdout.count(open_marker) == 1 and raw_probe.stdout.count(close_marker) == 1, (
            f"DNSBL action raw probe markers missing or duplicated: {probe_diag}"
        )
        open_idx = raw_probe.stdout.find(open_marker)
        close_idx = raw_probe.stdout.find(close_marker)
        assert 0 <= open_idx < close_idx, f"DNSBL action raw probe markers out of order: {probe_diag}"
        payload = raw_probe.stdout[open_idx + len(open_marker) : close_idx]
        try:
            raw_state = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"DNSBL action raw probe returned malformed JSON: {probe_diag}") from exc
        assert raw_state == ["array", False, "Disabled"], (
            f"DNSBL action seed/normalization precondition failed: {probe_diag}"
        )

        for directory in (unified_log.rsplit("/", 1)[0], ip_feed.rsplit("/", 1)[0]):
            mkdir = vm.ssh("mkdir", "-p", directory, timeout=15)
            assert mkdir.returncode == 0, (
                f"failed to create alert fixture directory {directory!r}: "
                f"rc={mkdir.returncode}, stderr={mkdir.stderr!r}"
            )

        feed_append = subprocess.run(
            vm.ssh_argv("tee", "-a", ip_feed),
            input=f"{ip_eval}\n",
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert feed_append.returncode == 0, (
            f"failed to append alert fixture feed {ip_feed!r}: "
            f"rc={feed_append.returncode}, stderr={feed_append.stderr!r}"
        )

        alerts_path = "/pfblockerng/pfblockerng_alerts.php?view=unified"
        pre = webui.get(alerts_path)
        pre_result = evaluate_render(alerts_path, pre.status_code, pre.text, ("Alert Settings",))
        assert pre_result.ok, f"Alerts precondition render failed: {pre_result.detail}"
        assert ip_host not in pre.text, f"IP alert fixture host {ip_host!r} already rendered before log append"
        assert dns_domain not in pre.text, (
            f"DNSBL alert fixture domain {dns_domain!r} already rendered before log append"
        )

        log_append = subprocess.run(
            vm.ssh_argv("tee", "-a", unified_log),
            input=unified_rows,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert log_append.returncode == 0, (
            f"failed to append unified alert fixtures: rc={log_append.returncode}, stderr={log_append.stderr!r}"
        )

        alerts_resp = webui.get(alerts_path)
        alerts_result = evaluate_render(alerts_path, alerts_resp.status_code, alerts_resp.text, ("Alert Settings",))
        assert alerts_result.ok, f"Alerts corrupt-action render failed: {alerts_result.detail}"
        ip_row = row_containing(alerts_resp.text, ip_host)
        dns_row = row_containing(alerts_resp.text, dns_domain)
        assert "pfB_pfbvalidip1346_v4" in ip_row, "valid Permit IP alias missing from seeded alert row"
        assert "DNSBL_pfbvaliddns1346" in dns_row, "valid DNSBL alias missing from seeded alert row"
        assert "pfB_pfbrepairip_v4" not in alerts_resp.text, "PermitBogus IP row entered Alerts permit options"
        assert "DNSBL_pfbrepairdns" not in alerts_resp.text, "array DNSBL row entered Alerts custom-list options"

        summary_cases = (
            (
                "ipv4",
                "pfbrepairip",
                ip_corrupt_action,
                "pfbvalidip1346",
                "Permit_Inbound",
            ),
            (
                "dnsbl",
                "pfbrepairdns",
                dns_corrupt_action,
                "pfbvaliddns1346",
                "unbound",
            ),
        )
        effective_rowids: dict[str, int] = {}
        for gtype, bad_alias, corrupt_action, valid_alias, valid_action in summary_cases:
            path = f"/pfblockerng/pfblockerng_category.php?type={gtype}"
            resp = webui.get(path)
            result = evaluate_render(path, resp.status_code, resp.text, ("Summary",))
            assert result.ok, f"Category {gtype} corrupt-action summary render failed: {result.detail}"
            invalid_row = row_containing(resp.text, bad_alias)
            invalid_action_field = summary_action_field(invalid_row, path)
            assert_action_selected(invalid_row, path, invalid_action_field, "Disabled")
            effective_rowids[gtype] = int(invalid_action_field.removeprefix("action-"))
            assert corrupt_action not in resp.text, f"invalid persisted action leaked into summary form on {path}"
            valid_row = row_containing(resp.text, valid_alias)
            assert_action_selected(valid_row, path, summary_action_field(valid_row, path), valid_action)

        path = "/pfblockerng/pfblockerng_Africa.php"
        resp = webui.get(path)
        result = evaluate_render(path, resp.status_code, resp.text, ("Continent - Africa",))
        assert result.ok, f"Generated GeoIP corrupt-action render failed: {result.detail}"
        assert geoip_corrupt_action not in resp.text, f"invalid persisted GeoIP action leaked into form on {path}"
        assert_disabled_selected(resp.text, path)

        path = f"/pfblockerng/pfblockerng_category_edit.php?type=dnsbl&rowid={effective_rowids['dnsbl']}"
        resp = webui.get(path)
        result = evaluate_render(path, resp.status_code, resp.text, ("Override Default Schedule",))
        assert result.ok, f"Category Edit DNSBL corrupt-action render failed: {result.detail}"
        assert_disabled_selected(resp.text, path)

        path = f"/pfblockerng/pfblockerng_category_edit.php?type=ipv4&rowid={effective_rowids['ipv4']}"
        resp = webui.get(path)
        result = evaluate_render(path, resp.status_code, resp.text, ("Override Default Schedule",))
        assert result.ok, f"Category Edit IPv4 corrupt-action render failed: {result.detail}"
        assert "PermitBogus" not in resp.text, f"invalid persisted action leaked into repair form on {path}"
        assert_disabled_selected(resp.text, path)
    finally:
        ipv4_restore = (
            f"config_set_path({helpers._php_str(CFG_IPV4)}, unserialize(base64_decode({helpers._php_str(ipv4_snap)})));"
            if ipv4_was_present
            else f"config_del_path({helpers._php_str(CFG_IPV4)});"
        )
        dnsbl_restore = (
            f"config_set_path({helpers._php_str(CFG_DNSBL)}, "
            f"unserialize(base64_decode({helpers._php_str(dnsbl_snap)})));"
            if dnsbl_was_present
            else f"config_del_path({helpers._php_str(CFG_DNSBL)});"
        )
        geoip_restore = (
            f"config_set_path({helpers._php_str(geoip_root)}, "
            f"unserialize(base64_decode({helpers._php_str(geoip_snap)})));"
            if geoip_was_present
            else f"config_del_path({helpers._php_str(geoip_root)});"
        )
        restore_errors: list[str] = []
        config_fixtures = (
            ("IPv4", CFG_IPV4, ipv4_was_present, ipv4_snap, ipv4_restore),
            ("DNSBL", CFG_DNSBL, dnsbl_was_present, dnsbl_snap, dnsbl_restore),
            ("GeoIP", geoip_root, geoip_was_present, geoip_snap, geoip_restore),
        )
        for label, _node, _was_present, _snap, restore in config_fixtures:
            try:
                config_restore = helpers.php_eval(
                    vm,
                    f"{restore}\n"
                    f"write_config('pfBlockerNG smoke: restore corrupt-action {label} fixture');\n"
                    "echo 'OK';",
                )
            except Exception as exc:  # noqa: BLE001 -- cleanup must attempt every independent restore
                restore_errors.append(f"{label} config: restore command failed: {exc!r}")
                continue
            if config_restore.returncode != 0 or "OK" not in config_restore.stdout:
                restore_errors.append(
                    f"{label} config: rc={config_restore.returncode}, "
                    f"stdout={config_restore.stdout!r}, stderr={config_restore.stderr!r}"
                )

        file_fixtures = ((unified_log, unified_size), (ip_feed, feed_size))
        for file_path, original_size in file_fixtures:
            argv = (
                vm.ssh_argv("/bin/rm", "-f", file_path)
                if original_size is None
                else vm.ssh_argv("/usr/bin/truncate", "-s", original_size, file_path)
            )
            try:
                restored = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                restore_errors.append(f"{file_path}: restore command failed: {exc!r}")
                continue
            if restored.returncode != 0:
                restore_errors.append(f"{file_path}: rc={restored.returncode}, stderr={restored.stderr!r}")

        for label, node, was_present, snap, _restore in config_fixtures:
            try:
                present = node_present(node)
                if present != was_present:
                    restore_errors.append(f"{label} config: presence mismatch (expected {was_present}, got {present})")
                elif was_present and _snapshot_node(vm, node) != snap:
                    restore_errors.append(f"{label} config: restored snapshot was not exact")
            except Exception as exc:  # noqa: BLE001 -- cleanup must verify every independent restore
                restore_errors.append(f"{label} config: verification failed: {exc!r}")

        for file_path, original_size in file_fixtures:
            try:
                restored_size = file_size(file_path)
                if restored_size != original_size:
                    restore_errors.append(
                        f"{file_path}: size/presence mismatch (expected {original_size!r}, got {restored_size!r})"
                    )
            except Exception as exc:  # noqa: BLE001 -- cleanup must verify every independent restore
                restore_errors.append(f"{file_path}: verification failed: {exc!r}")

        assert not restore_errors, f"corrupt-action fixture restore failed: {restore_errors}"


# The V4 wizard submit path reads the shipped legacy feed catalog directly. This source
# assertion lives in the Tier-A module because step4_submitphpaction() is a POST-only path
# that the authenticated GET sweep cannot execute.
def test_wizard_uses_legacy_feed_catalog() -> None:
    """Keep V5's normalized registry out of the V4 setup-wizard submit path."""
    source_path = helpers.SMOKE_DIR.parent.parent / "src/usr/local/www/wizards/pfblockerng_wizard.inc"
    source = source_path.read_text(encoding="utf-8")

    assert "json_decode(@file_get_contents(\"{$pfb['feeds']}\"), TRUE)" in source
    assert "PfbRegistry::" not in source


def test_wizard_schedule_producer_is_canonical() -> None:
    """Issue #2316: the shipped wizard emits only canonical schedule fields."""
    source_path = helpers.SMOKE_DIR.parent.parent / "src/usr/local/www/wizards/pfblockerng_wizard.inc"
    source = source_path.read_text(encoding="utf-8")

    for schedule_field in ("schedule_override", "schedule_weekday", "schedule_hour", "schedule_minute"):
        assert f"$add['{schedule_field}']" in source
    assert "$add['dow']" not in source


# ADR-23: the setup wizard's DNSBL step now surfaces ADR-13's pfb_dnsvip_auto auto-VIP
# toggle. Core wizard.php renders ONE step per GET, indexed by a 0-based `stepid` (verified
# against pfSense upstream wizard.php: `$stepid` defaults to "0" and indexes $pkg['step']
# directly). The DNSBL step is the 4th <step> (<id>4</id>, "DNSBL Component Configuration")
# in pfblockerng_wizard.xml -> stepid=3. The wizard is NOT in PAGE_TABLE (a core-rendered
# www/wizards/ page, not a www/pfblockerng/ one), so it gets its own render assertion.
_WIZARD_DNSBL_STEP = "/wizard.php?xml=pfblockerng_wizard.xml&stepid=3"


def test_group_action_validator_is_strict_on_appliance(smoke_vm: SmokeVM, webui: WebUI) -> None:  # noqa: ARG001
    """Issue #1346: shipped validator rejects cross-group and non-string actions."""
    result = helpers.php_eval(
        smoke_vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc'); "
        "$rows = array("
        "array('Deny_Both', 'ipv4', true), "
        "array('unbound', 'dnsbl', true), "
        "array('unbound', 'ipv4', false), "
        "array('Deny_Both', 'dnsbl', false), "
        "array(array('Deny_Both'), 'ipv4', false), "
        "array(0, 'dnsbl', false)); "
        "foreach ($rows as $row) { if (pfb_group_action_valid($row[0], $row[1]) !== $row[2]) { exit(9); } } "
        "echo 'OK';",
    )
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"group-action validator matrix failed: rc={result.returncode} out={result.stdout!r} err={result.stderr!r}"
    )


# The welcome step carries the second copy of the Support logo (issue #2863); it is the
# first <step> in pfblockerng_wizard.xml, so stepid=0.
_WIZARD_WELCOME_STEP = "/wizard.php?xml=pfblockerng_wizard.xml&stepid=0"


def test_wizard_welcome_step_renders_the_fluid_support_logo(
    webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The wizard's Support logo renders responsively and unclipped (issue #2863).

    The viewBox must contain the circle and the column must be fluid, as shipped.
    """
    resp = webui.get(_WIZARD_WELCOME_STEP)
    # The step's own <title>, not a generic marker: this PR makes the wizard logo markup
    # identical to the General page's, so a stepid mishandling that served General
    # instead would satisfy every other assertion here.
    result = evaluate_render(_WIZARD_WELCOME_STEP, resp.status_code, resp.text, ("pfBlockerNG Setup",))
    assert result.ok, f"wizard welcome step render oracle failed: {result.detail}"
    body = resp.text
    assert 'viewBox="128 172 384 384"' in body, "wizard logo still uses the clipping viewBox"
    assert "col-sm-3" in body, "wizard logo column is not the fluid Bootstrap column"
    assert "width: 25%; height: 170px; float: right;" not in body, (
        "wizard logo still uses the fixed float column that overflows narrow viewports"
    )
    assert "enable-background" not in body, "wizard logo still carries the retired enable-background"


# Step 2 ("pfBlockerNG Components") is the second <step> -> stepid=1.
_WIZARD_COMPONENTS_STEP = "/wizard.php?xml=pfblockerng_wizard.xml&stepid=1"


def test_wizard_components_step_columns_sit_in_rows(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The step-2 callouts render inside Bootstrap rows (issue #2890).

    Without a row parent the columns carry uncancelled negative gutters, which is
    visible only in the shipped markup -- the PHP pin proves the source.
    """
    resp = webui.get(_WIZARD_COMPONENTS_STEP)
    result = evaluate_render(_WIZARD_COMPONENTS_STEP, resp.status_code, resp.text, ("pfBlockerNG Components",))
    assert result.ok, f"wizard components step render oracle failed: {result.detail}"
    body = resp.text
    assert "CAUTION BEFORE PROCEEDING!" in body, "step 2 lost its caution callout"
    caution = body.index("CAUTION BEFORE PROCEEDING!")
    assert 'class="row"' in body[max(0, caution - 400) : caution], (
        "step 2's caution callout is not inside a Bootstrap row"
    )


def test_wizard_dnsbl_step_renders_auto_vip(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """ADR-23: the wizard DNSBL step renders the Auto VIP (pfb_dnsvip_auto) checkbox cleanly.

    The setup wizard exposes ADR-13's auto-create toggle on its DNSBL step so a first-run
    user need not pre-create a sinkhole VIP — a render regression that drops/breaks the field
    (or the wizard step itself) must fail here, not only in the maintainer on-box check. A
    direct authenticated GET renders the step regardless of the first-run dismissal the
    `webui` fixture performs (dismissal only suppresses general.php's auto-launch redirect,
    not wizard.php itself).

    Asserts the step passes the clean-render oracle (200, no PHP diagnostic, the step-title
    Form_Section marker present, not the login form) AND — from three independent wizard.php
    render paths — that the field's POST name (`pfb_dnsvip_auto`), its 'Auto VIP' displayname
    label, and the 'Create VIPs automatically' setHelp() wording are present. The IPv4/IPv6
    manual selectors carry the new "manual mode only" note, asserted too so the mode framing
    that pairs with the checkbox is pinned. `php_error_log_guard` enrolls this GET in the
    module-level no-growth sweep.
    """
    resp = webui.get(_WIZARD_DNSBL_STEP)
    result = evaluate_render(_WIZARD_DNSBL_STEP, resp.status_code, resp.text, ("DNSBL Component Configuration",))
    assert result.ok, f"wizard DNSBL-step render oracle failed: {result.detail}"
    body = resp.text
    for needle in (
        "pfb_dnsvip_auto",  # the checkbox field's POST name (input name/id)
        "Auto VIP",  # the <displayname> label
        "Create VIPs automatically",  # the <description> setHelp() wording
        "manual mode only",  # the pfb_dnsvip4/6 selectors' new mode-dependency note
    ):
        assert needle in body, f"wizard DNSBL step is missing the Auto VIP marker {needle!r}"
    # issue #2869: the step must not name the sweep pool ADR-13 retired -- an admin who
    # reads it goes looking for an address pfb_dnsbl_vip_candidates() never returns.
    # Scoped to the retired claim, not to "10.10.": the harness provisions a manual VIP at
    # DEFAULT_DNSBL_VIP4 (10.10.10.1) which the step's VIP dropdown legitimately lists.
    for retired in ("10.10.X.53", "10.10.x.53", "fd00:X::53"):
        assert retired not in body, f"wizard DNSBL step still advertises the retired {retired} pool"


def test_general_wizard_disable_get_is_state_free(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """Issue #1651: a plain GET of ?wizard=disable writes NO config and still renders General.

    Scenario: forged cross-site request against the wizard-disable action.
    Given:   an authenticated session (the webui fixture already dismissed the wizard
             through the csrf-protected wizard POST, so General renders directly)
    When:    general.php is GET with ?wizard=disable -- the request an attacker page can
             forge, since csrf-magic attaches no token to a GET
    Then:    /conf/config.xml is BYTE-identical before and after (the old handler called
             write_config on every such GET, bumping <revision> even with the flag already
             'on'), and the response still renders the General settings page cleanly

    The raw sha256 (not helpers.pfb_config_digest) is deliberate: the digest helper
    strips the volatile <revision> block, which is exactly where a same-value
    write_config shows up -- stripping it would blind this assertion.
    """
    before = smoke_vm.ssh("sha256", "-q", "/conf/config.xml")
    assert before.returncode == 0 and before.stdout, (
        f"config digest (before) failed: rc={before.returncode} stderr={before.stderr!r}"
    )

    path = _GENERAL_PAGE + "?wizard=disable"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("General Settings",))
    assert result.ok, f"?wizard=disable render oracle failed: {result.detail}"

    after = smoke_vm.ssh("sha256", "-q", "/conf/config.xml")
    assert after.returncode == 0 and after.stdout, (
        f"config digest (after) failed: rc={after.returncode} stderr={after.stderr!r}"
    )
    assert before.stdout == after.stdout, (
        "a plain GET of ?wizard=disable must not write config (issue #1651): "
        f"config.xml changed {before.stdout.strip()!r} -> {after.stdout.strip()!r}"
    )


# threats.php's NEGATIVE branches: each malformed/absent param print_info_box()es
# a specific message and exit()s BEFORE the "$pgtitle" lookup-page chrome. These
# pair with the positive threats_{domain,host,port} entries above (CLAUDE.md
# branch coverage: prove the validators REJECT, not only that valid input renders).
THREATS_PAGE = "/pfblockerng/pfblockerng_threats.php"
# (id, query, expected info-box message) -- messages verified verbatim against
# pfblockerng_threats.php (is_ipaddr / is_port guards + the no-param else).
THREATS_REJECTS: tuple[tuple[str, str, str], ...] = (
    ("invalid_host", "host=not-an-ip", "Invalid IP Address, cannot proceed!"),
    ("invalid_port", "port=99999", "Invalid Port cannot proceed!"),
    ("no_request", "", "No Requests found, cannot proceed!"),
)
# The lookup-page chrome titles ("Threat <title> Lookup") that MUST be absent on a
# reject (the handler exit()s before rendering $pgtitle).
_THREATS_LOOKUP_TITLES = ("Threat Domain Lookup", "Threat Source IP Lookup", "Threat Port Lookup")


@pytest.mark.parametrize(("name", "query", "message"), THREATS_REJECTS, ids=[r[0] for r in THREATS_REJECTS])
def test_threats_rejects_malformed_lookup(name: str, query: str, message: str, webui: WebUI) -> None:
    """A malformed/absent threats lookup renders its info-box, NOT the lookup page.

    HTTP 200 (head.inc is included before the dispatch, so the page still renders
    its header) with the exact info-box message present and the "Threat ... Lookup"
    chrome absent -- proving the validator rejected and exit()ed rather than
    rendering the lookup view. The before-state (a valid param DOES render that
    chrome) is the positive threats_{domain,host,port} entries in PAGE_TABLE.
    """
    path = f"{THREATS_PAGE}?{query}" if query else THREATS_PAGE
    resp = webui.get(path)
    assert resp.status_code == 200, f"{name}: GET {path} -> HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert message in body, f"{name}: expected info-box {message!r} not present in {path} body"
    present = [title for title in _THREATS_LOOKUP_TITLES if title in body]
    assert not present, f"{name}: reject path unexpectedly rendered lookup chrome {present}"


def test_threats_domain_dead_alexa_siteinfo_link_removed(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The domain threat-lookup page no longer links out to alexa.com/siteinfo (#877).

    Alexa.com's siteinfo service shut down in 2022, so the link 404s. Asserts the
    page still passes the clean-render oracle (Threat Domain Lookup chrome intact)
    AND that the dead Alexa link is gone from the body while the sibling domain-intel
    links (Talos, Norton Safe Web) remain -- proving only the one dead link was cut.
    """
    path = f"{THREATS_PAGE}?domain={helpers.unique_domain()}"
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, ("Threat Domain", "Source IP"))
    assert result.ok, f"threats domain render oracle failed: {result.detail}"
    body = resp.text
    assert "alexa.com/siteinfo" not in body, "threats domain page still links to the dead alexa.com/siteinfo service"
    for needle in ("Talos Threat Intelligence", "Norton Safe Web"):
        assert needle in body, f"threats domain page lost an unrelated domain-intel link {needle!r}"


# ADR-19: the "Software" page + tab are PROVENANCE-GATED — present ONLY on a build installed
# from one of OUR repos (pkg %R == pfblockerng / pfblockerng-nightly). The ADR-04 UI harness
# sideloads the branch .pkg with `pkg add -f` (offline), so its %R is empty -> the auto-detect
# HIDES the page and tab (the DEFAULT negative state, proven below). To exercise BOTH states
# deterministically on this same sideload deploy, pfblockerng.inc honours a HIDDEN override
# sentinel (PFB_SOFTWARE_PANEL_OVERRIDE, a file containing 'on'|'off'); software_panel_forced()
# drops/clears it over SSH so we can render the page ENABLED (positive: 200 + the
# 'pfb-software-panel' marker) and DISABLED (negative) without needing an our-repo install. The
# REAL %R-driven behaviour is separately validated by the `repo` flow (test_software_update.py).
_SOFTWARE_PAGE = "/pfblockerng/pfblockerng_software.php"
_SOFTWARE_PANEL_MARKER = "pfb-software-panel"
_SOFTWARE_TAB_HREF = "/pfblockerng/pfblockerng_software.php"
# Mirrors PFB_SOFTWARE_PANEL_OVERRIDE in pfblockerng.inc (the hidden test/support sentinel).
_SOFTWARE_OVERRIDE_NAME = ".pfb_software_panel"
_SOFTWARE_OVERRIDE_FILE = f"{helpers.PFB_DBDIR}/{_SOFTWARE_OVERRIDE_NAME}"


@contextmanager
def software_panel_forced(vm: SmokeVM, state: str) -> Iterator[None]:
    """Force the Software-page gate ``on``/``off`` for the block via the hidden sentinel, then
    remove it so subsequent tests see the default auto-detect. ``state`` is a fixed 'on'/'off'
    literal (never user input).

    The write goes through ``helpers.write_local_feed`` (bare ``mkdir -p`` argv + ``tee`` over
    stdin), NOT ``ssh "/bin/sh -c 'mkdir … && printf … > file'"``: ssh space-joins the remote
    argv and the pfSense root LOGIN shell (tcsh) re-parses it, so the compound ``sh -c`` form
    silently mis-runs (``mkdir`` gets no operand). ``write_local_feed`` already raises on a
    failed write, so a silent failure can't let the forced-off case pass on the default-hidden
    path; the cleanup ``rm`` is checked too so a failure can't leak override state into a later
    test."""
    helpers.write_local_feed(vm, _SOFTWARE_OVERRIDE_NAME, state)
    try:
        yield
    finally:
        clear = vm.ssh("/bin/rm", "-f", _SOFTWARE_OVERRIDE_FILE)
        assert clear.returncode == 0, f"failed to clear software override sentinel: {clear.stderr.strip()}"


def test_software_page_provenance_gate_hides_on_nonour_build(
    webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The Software page's provenance guard hides it on a non-our-repo install.

    Scenario: pfBlockerNG installed via `pkg add -f` (the UI harness), so the
    installed package's repo (`pkg query %R`) is NOT one of our repos.
      Given the standard Tier-A deploy (offline `pkg add -f`),
      When the Software page is GET (redirects NOT followed),
      Then the top-of-file provenance guard redirects to /index.php (a 3xx, not a
           200 panel body), the page-specific 'pfb-software-panel' marker is absent
           from the body, AND no new php_error.log line is produced (the guard is a
           clean redirect+exit, NOT a fatal). The enrolled php_error_log_guard pins
           the no-new-error-line condition over the sweep.
    """
    # Do NOT follow the redirect: assert the guard's 3xx -> /index.php directly, so a
    # broken guard that 200-renders the panel can't pass by following to a clean page.
    resp = webui.get(_SOFTWARE_PAGE, allow_redirects=False)
    assert resp.status_code in (301, 302, 303, 307, 308), (
        f"Software page expected a provenance-guard redirect, got HTTP {resp.status_code}"
    )
    location = resp.headers.get("Location", "")
    assert location.endswith("/index.php"), f"provenance guard should redirect to /index.php, got Location={location!r}"
    assert _SOFTWARE_PANEL_MARKER not in resp.text, (
        "provenance guard must NOT render the Software panel on a non-our-build"
    )


def test_software_tab_absent_on_nonour_build(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The 'Software' tab is absent from a normal pfBlockerNG page on a non-our-build.

    Given the same offline `pkg add -f` deploy (non-our-repo provenance),
    When the General page is GET,
    Then pfb_software_add_tab() appended nothing: the Software tab href is NOT in the
         tab bar. Pairs with the page-gate test above to prove BOTH gated surfaces
         (page + tab) are hidden. The positive (tab PRESENT) state is Phase 5's
         repo-install journey. php_error_log_guard enrolls this GET in the sweep.
    """
    resp = webui.get(_GENERAL_PAGE)
    result = evaluate_render(_GENERAL_PAGE, resp.status_code, resp.text, ("General Settings",))
    assert result.ok, f"General page render oracle failed: {result.detail}"
    assert _SOFTWARE_TAB_HREF not in resp.text, (
        "the Software tab must be ABSENT on a non-our-build (provenance gate hides it everywhere)"
    )


def test_software_page_renders_when_override_forces_on(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """Forcing the hidden override 'on' renders the Software page POSITIVELY on this sideload deploy.

    Scenario: the Tier-A deploy is a sideload (%R empty) — the page is hidden by default (the
    provenance tests above). Forcing the override 'on' is the ONLY change.
      Given the override sentinel set to 'on',
      When the Software page is GET,
      Then it renders clean (200, no Fatal/Warning/Notice/Uncaught, the 'pfb-software-panel'
           marker present) AND the Software tab now appears on a normal page — proving the gate's
           POSITIVE branch on the same deploy that otherwise hides it (before/after the flip).
      And no new php_error.log line (php_error_log_guard sweeps).
    """
    with software_panel_forced(smoke_vm, "on"):
        resp = webui.get(_SOFTWARE_PAGE)
        result = evaluate_render(_SOFTWARE_PAGE, resp.status_code, resp.text, (_SOFTWARE_PANEL_MARKER,))
        assert result.ok, f"forced-on Software page render failed: {result.detail}"
        # issue #2691: the CA-consent surface (checkbox + section) is retired — signing
        # makes the login.conf CA carry obsolete. A reappearance here is a regression.
        assert "pfb_pkg_ca_consent" not in resp.text, (
            "the retired CA-consent checkbox must not render on the Software page (issue #2691)"
        )
        # The tab is injected everywhere on an enabled build — the positive of the tab-absent test.
        general = webui.get(_GENERAL_PAGE)
        assert _SOFTWARE_TAB_HREF in general.text, "the Software tab must be PRESENT when the gate is forced on"


def test_software_panel_channel_falls_back_to_the_package_name_off_repo(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The rendered channel survives an install whose repo names no channel (issue #2148).

    All four channel catalogues publish the ONE canonical ``pfSense-pkg-pfBlockerNG``, so the
    page derives the channel from the repo the package came from (``pkg query %R`` ->
    ``pfblockerng-<ch>``) and falls back to the package NAME only when that repo names no
    channel. The Tier-A deploy is exactly that case: an offline ``pkg add -f`` sideload leaves
    ``%R`` empty, which is what makes it able to prove the fallback branch at all.

    Scenario:
      Given the sideload deploy, whose installed ``%R`` is NOT one of the channel repos
          (asserted as the before-state — the fallback is only under test while that holds),
      And the hidden override forcing the provenance gate on,
      When the Software page is GET,
      Then the ``pfb-software-panel`` marker renders the channel the BUILT ARTIFACT reports
          (`pkg_identity.branch_channel`, never a hard-coded name — issue #2166), not the
          literal repo string and not the ``unknown`` placeholder.

    Fail-before/pass-after: a repo-only derivation with no name fallback renders ``unknown``
    here, and a derivation that leaked the repo through renders the empty repo string.
    """
    expected_channel = pkg_identity.branch_channel(os.environ.get("SMOKE_PKG"))
    pkgname = pkg_identity.branch_pkg_name(os.environ.get("SMOKE_PKG"))

    repo_probe = smoke_vm.ssh("/usr/local/sbin/pkg", "query", "%R", pkgname)
    assert repo_probe.returncode == 0, (
        f"could not read the installed repo for {pkgname!r} "
        f"(rc={repo_probe.returncode}): {(repo_probe.stderr or repo_probe.stdout).strip()!r}"
    )
    installed_repo = repo_probe.stdout.strip()
    assert not installed_repo.startswith("pfblockerng-"), (
        f"before-state broken: this deploy reports channel repo {installed_repo!r}, so it "
        "exercises the repo branch, not the name fallback this case is written for"
    )

    with software_panel_forced(smoke_vm, "on"):
        resp = webui.get(_SOFTWARE_PAGE)
        result = evaluate_render(_SOFTWARE_PAGE, resp.status_code, resp.text, (_SOFTWARE_PANEL_MARKER,))
        assert result.ok, f"Software page render oracle failed: {result.detail}"
        body = resp.text

    panel = re.search(rf'<span id="{_SOFTWARE_PANEL_MARKER}">([^<]*)</span>', body)
    assert panel is not None, f"the {_SOFTWARE_PANEL_MARKER} span is absent from the Software page body"
    rendered = panel.group(1).strip()
    assert rendered == expected_channel, (
        f"Software panel rendered channel {rendered!r}, expected {expected_channel!r} "
        f"(installed {pkgname!r} from repo {installed_repo!r})"
    )


def test_software_check_checkbox_posts_a_token_the_save_path_accepts(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The "New version check" box must POST a token its own save path accepts (issue #2367).

    pfSense's Form_Checkbox posts ``yes`` unless the page passes a value, and the save path
    filters with PFB_FILTER_ON_OFF, which takes only ``on`` and ``''``. Built without that
    argument the box renders fine and saves to disabled every time, including when ticked,
    with no UI path back — so the rendered VALUE is the thing worth pinning, not the presence
    of the control.

    Scenario:
      Given the override sentinel set to 'on' (so the page renders at all),
      When the Software page is GET,
      Then the pfb_software_check control renders with value="on".
    """
    with software_panel_forced(smoke_vm, "on"):
        resp = webui.get(_SOFTWARE_PAGE)
        result = evaluate_render(_SOFTWARE_PAGE, resp.status_code, resp.text, (_SOFTWARE_PANEL_MARKER,))
        assert result.ok, f"Software page render oracle failed: {result.detail}"
        body = resp.text

    # scrape_form_fields() is the codebase's own attribute parser (quoting variants and
    # all) and it reports a checkbox only when it is CHECKED, which is precisely the state
    # whose posted value decides the save.
    submitted = scrape_form_fields(body)
    assert "pfb_software_check" in submitted, (
        "the Software page must render the pfb_software_check control CHECKED here — the "
        "registry default is enabled, and an unchecked box submits nothing to inspect"
    )
    assert submitted["pfb_software_check"] == "on", (
        f"pfb_software_check posts {submitted['pfb_software_check']!r}; it must post 'on', the "
        "only enabled token PFB_FILTER_ON_OFF accepts (pfSense's Form_Checkbox default 'yes' "
        "is rejected, so a ticked Save would persist disabled)"
    )


def test_software_actions_link_to_package_manager(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """Update/Uninstall reach Package Manager on EVERY origin (issue #2653).

    The deep link carries the package name and ``pkg_mgr_install.php`` acts on that name.
    ``get_pkg_info()``'s ``%R`` filter governs the listing pages, so it decides whether
    Package Manager can show or announce a channel install — not whether these two
    operations work. #2380 read it as the latter and disabled both controls on every
    channel install; #684's shortcuts are restored for all of them.

    Scenario:
      Given the override sentinel set to 'on' (so the provenance gate passes),
      When the Software page is GET,
      Then Update's href is inert ('#') when no update is cached, whatever the origin;
      And Uninstall points at ``pkg_mgr_install.php?mode=delete`` whatever the origin;
      And Update points at ``pkg_mgr_install.php?mode=reinstallpkg`` once an update is
          cached, whatever the origin;
      And the page carries NO in-page pkg machinery — no ``?ajax=tail`` poller, no
          ``pfb_output`` textarea;
      And the clean render oracle (200, no Fatal/Warning/Notice, marker present) holds.
    """
    software_cache = "/var/db/pfblockerng/software_update.json"
    pkgname = pkg_identity.branch_pkg_name(os.environ.get("SMOKE_PKG"))
    repo_probe = smoke_vm.ssh("/usr/local/sbin/pkg", "query", "%R", pkgname)
    # Recorded for failure messages only: the origin no longer changes any expectation
    # here, and asserting the same thing for every origin is the point (issue #2653).
    installed_repo = repo_probe.stdout.strip() if repo_probe.returncode == 0 else ""

    def _update_anchor(body: str) -> str:
        tag = re.search(r'<a\b[^>]*id=["\']pfb_sw_update["\'][^>]*>', body)
        assert tag is not None, f"Update control is not an <a> link in {_SOFTWARE_PAGE} body"
        return tag.group(0)

    def _has_pkgmgr_href(tag: str, mode: str) -> bool:
        # `&` may render HTML-escaped to `&amp;`; the pkg is our pfSense-pkg-pfBlockerNG*.
        pat = rf'href=["\']/pkg_mgr_install\.php\?mode={mode}&(?:amp;)?pkg=pfSense-pkg-pfBlockerNG'
        return bool(re.search(pat, tag))

    with software_panel_forced(smoke_vm, "on"):
        # (A) No cached 'latest' → no update available → the Update href is inert ('#'), NOT an
        #     actionable reinstall link (CodeRabbit #685: the href itself must gate, not just CSS).
        smoke_vm.ssh("/bin/rm", "-f", software_cache)
        resp = webui.get(_SOFTWARE_PAGE)
        result = evaluate_render(_SOFTWARE_PAGE, resp.status_code, resp.text, (_SOFTWARE_PANEL_MARKER,))
        assert result.ok, f"Software page render oracle failed: {result.detail}"
        body = resp.text

        up_tag = _update_anchor(body)
        assert not _has_pkgmgr_href(up_tag, "reinstallpkg"), (
            f"Update must NOT be an actionable reinstall link when no update is available, got: {up_tag!r}"
        )
        assert re.search(r'href=["\']#["\']', up_tag), f"Update href must be inert ('#') when no update: {up_tag!r}"

        un_tag = re.search(r'<a\b[^>]*id=["\']pfb_sw_uninstall["\'][^>]*>', body)
        assert un_tag is not None, f"Uninstall control is not an <a> link in {_SOFTWARE_PAGE} body"
        assert _has_pkgmgr_href(un_tag.group(0), "delete"), (
            f"Uninstall must target pkg_mgr_install.php?mode=delete on any origin (issue #2653), "
            f"%R={installed_repo!r}, got: {un_tag.group(0)!r}"
        )
        assert "cannot see this origin" not in body, (
            "retired #2380 copy: the controls are no longer disabled by origin (issue #2653)"
        )
        # Pinned positively too: an emptied or rewritten help string would otherwise pass
        # on the negative assertion alone. These are the pre-#2380 strings (#684).
        assert "Install the latest version via the pfSense Package Manager" in body, (
            "the Update control must carry its pre-#2380 help text (issue #2653)"
        )
        assert "Remove pfBlockerNG from this firewall via the pfSense Package Manager" in body, (
            "the Uninstall control must carry its pre-#2380 help text (issue #2653)"
        )
        assert "?do=uninstall" not in un_tag.group(0), (
            "Uninstall must NOT route through the removed ?do=uninstall handler (#697)"
        )

        # The in-page pkg machinery is gone entirely. Do NOT assert `/pkg_mgr_installed.php`
        # absent from the body: pfSense's System menu (head.inc) always carries that href for an
        # admin on EVERY page, and no pfBlockerNG GET body ever carried that string — the
        # historical post-uninstall redirects were POST-only machinery (#791).
        assert "?ajax=tail" not in body, "Software page must no longer host the ?ajax=tail poller"
        assert 'name="pfb_output"' not in body, "Software page must no longer render the pfb_output textarea"

        # (B) Seed a newer cached 'latest' → update available. The reinstall deep link is
        #     emitted for every origin (issue #2653).
        try:
            smoke_vm.ssh("/bin/rm", "-f", software_cache)
            seed = json.dumps(
                {
                    "pkgname": pkgname,
                    "latest": "99.0.0",
                    "last_checked": 1,
                }
            )
            _seed_vm_file(smoke_vm, software_cache, seed)
            up_tag2 = _update_anchor(webui.get(_SOFTWARE_PAGE).text)
            assert _has_pkgmgr_href(up_tag2, "reinstallpkg"), (
                f"Update must target pkg_mgr_install.php?mode=reinstallpkg once an update exists, "
                f"on any origin (issue #2653), %R={installed_repo!r}, got: {up_tag2!r}"
            )
        finally:
            smoke_vm.ssh("/bin/rm", "-f", software_cache)


# The two Status-section spans issue #2674 asks the page to keep apart: the last SUCCESSFUL
# catalogue read, and the last attempt that failed. Plus the query token Check now redirects
# with when the refresh it forced did not work, and the message that token renders -- both
# tiers assert the same strings, so the page and the tests cannot drift apart.
_SOFTWARE_CHECKED_MARKER = "pfb-sw-checked"
_SOFTWARE_FAILED_MARKER = "pfb-sw-check-failed"
_SOFTWARE_CHECK_FAILED_QUERY = "?check=failed"
# Must match the Check-now info box ALONE -- the Status row's help text speaks about the same
# failure, so a phrase both carry cannot support the "a plain load stays silent" assertion.
_SOFTWARE_CHECK_FAILED_TEXT = "Check now could not read"


def test_software_page_shows_a_failed_catalogue_check(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """A failed catalogue refresh is visible on the page, and a successful one is not (#2674).

    On a box whose webConfigurator ``pkg`` cannot reach our repository, the page reported a
    version, an "Up to date" verdict and a recent "Last checked" while every check it ran
    failed -- the cron tick kept the cache warm from a context where ``pkg`` works, and a
    failed read left no field on the cache naming the failure. So the state worth rendering
    is the one the cache now records, and this is the tier that proves it REACHES the page.

    Scenario:
      Given the hidden override forcing the provenance gate on,
      And a cache scoped to this install that records a SUCCESSFUL check and no failure
          (the before-state -- the page must stay calm, which is issue #2379's fallback),
      When the Software page is GET,
      Then the failed-attempt marker is ABSENT and the render oracle is clean;
      And when the same cache additionally records a failed attempt,
      Then the failed-attempt row renders its own time, distinct from the last successful
          check's, and the page still renders clean (a state, never a ``pkg`` error dump);
      And Check now's feedback query renders a warning, while a plain GET stays silent.

    Fail-before/pass-after: without the fix the marker is absent in both states, because
    nothing records or renders the failure.
    """
    software_cache = "/var/db/pfblockerng/software_update.json"
    pkgname = pkg_identity.branch_pkg_name(os.environ.get("SMOKE_PKG"))
    repo_probe = smoke_vm.ssh("/usr/local/sbin/pkg", "query", "%R", pkgname)
    installed_repo = repo_probe.stdout.strip() if repo_probe.returncode == 0 else ""

    checked_at = 1735689600  # 2025-01-01 00:00:00 UTC — a fixed, recognisable success time
    failed_at = 1767225600  # 2026-01-01 00:00:00 UTC — strictly later, so ordering is visible

    def _seed(extra: dict[str, object]) -> None:
        smoke_vm.ssh("/bin/rm", "-f", software_cache)
        _seed_vm_file(
            smoke_vm,
            software_cache,
            json.dumps(
                {
                    "pkgname": pkgname,
                    "repo": installed_repo,
                    "latest": "99.0.0",
                    "last_checked": checked_at,
                    **extra,
                }
            ),
        )

    try:
        with software_panel_forced(smoke_vm, "on"):
            # BEFORE: a successful check and nothing else — no failure surface at all.
            _seed({})
            resp = webui.get(_SOFTWARE_PAGE)
            result = evaluate_render(_SOFTWARE_PAGE, resp.status_code, resp.text, (_SOFTWARE_PANEL_MARKER,))
            assert result.ok, f"Software page render oracle failed on the clean cache: {result.detail}"
            assert _SOFTWARE_FAILED_MARKER not in resp.text, (
                "a cache recording only a successful check must render NO failed-attempt row "
                "(issue #2379: a benign stale read is not a scary page)"
            )

            # AFTER: the same cache, now also recording that the last attempt failed.
            _seed({"last_failed": failed_at})
            resp = webui.get(_SOFTWARE_PAGE)
            result = evaluate_render(_SOFTWARE_PAGE, resp.status_code, resp.text, (_SOFTWARE_PANEL_MARKER,))
            assert result.ok, f"Software page render oracle failed on the failed-attempt cache: {result.detail}"
            body = resp.text
            assert _SOFTWARE_FAILED_MARKER in body, (
                f"the Software page must render the {_SOFTWARE_FAILED_MARKER!r} row once the cache "
                "records a failed catalogue read (issue #2674)"
            )
            failure = re.search(rf'id="{_SOFTWARE_FAILED_MARKER}"[^>]*>([^<]*)<', body)
            assert failure is not None, f"the {_SOFTWARE_FAILED_MARKER} span is absent from the body"
            checked = re.search(rf'id="{_SOFTWARE_CHECKED_MARKER}"[^>]*>([^<]*)<', body)
            assert checked is not None, (
                f"the {_SOFTWARE_CHECKED_MARKER!r} span must carry the last SUCCESSFUL check time — "
                "without it the page cannot distinguish the two (issue #2674)"
            )
            # Both are rendered by the guest's own date() with the guest's timezone, so the
            # assertion is that the page names TWO DIFFERENT times, not what either formats to.
            rendered_failure = failure.group(1).strip()
            rendered_checked = checked.group(1).strip()
            assert rendered_failure != "", "the failed-attempt row rendered no time at all"
            assert rendered_checked != "", "the last-checked row rendered no time at all"
            assert rendered_failure != rendered_checked, (
                "the failed attempt and the last successful check must render as DIFFERENT times "
                f"— that distinction is the whole of issue #2674; both read {rendered_failure!r}"
            )
            assert rendered_checked != "never", (
                "before-state broken: the seeded successful-check time did not reach the page, so a "
                "failed attempt could not be told apart from 'never checked' here"
            )

            # Check now's own feedback, on its reachable GET: the query token the page's
            # failure redirect carries renders a warning an admin can actually see.
            #
            # Keyed on the MESSAGE, never on the ``alert-warning`` class: pfBlockerNG's
            # pending-changes banner is also an alert-warning and may be set, so a class-level
            # absence assertion would be about that banner rather than about this feedback.
            resp = webui.get(_SOFTWARE_PAGE + _SOFTWARE_CHECK_FAILED_QUERY)
            result = evaluate_render(
                _SOFTWARE_PAGE + _SOFTWARE_CHECK_FAILED_QUERY,
                resp.status_code,
                resp.text,
                (_SOFTWARE_PANEL_MARKER,),
            )
            assert result.ok, f"Software page render oracle failed on the check-failed query: {result.detail}"
            assert _SOFTWARE_CHECK_FAILED_TEXT in resp.text, (
                "a forced check that failed must say so on the redisplay, not re-serve an "
                f"unchanged page (looked for {_SOFTWARE_CHECK_FAILED_TEXT!r})"
            )
            # And it stays feedback about THIS action: a plain GET is silent.
            assert _SOFTWARE_CHECK_FAILED_TEXT not in webui.get(_SOFTWARE_PAGE).text, (
                "a plain GET must not raise the Check now warning — only the forced check that failed does"
            )
    finally:
        smoke_vm.ssh("/bin/rm", "-f", software_cache)


def _pfb_output_value(body: str) -> str:
    """Return the rendered value (text between the tags) of the ``pfb_output`` textarea."""
    match = re.search(r'<textarea\b[^>]*name="pfb_output"[^>]*>(.*?)</textarea>', body, re.DOTALL)
    assert match is not None, "pfb_output textarea not found in body"
    return match.group(1)


def test_log_output_never_prefilled(smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:
    """The Update page never prefills the output textarea on a GET (#671 — live log AJAX-polled).

    Scenario (no prefill):
      Given the pfBlockerNG log seeded with a unique marker,
      When the Update page is GET -> pfb_output EMPTY.

    The live log is streamed by the client poller (``?ajax=tail``), so the rendered box is always
    empty; the #666 post-upgrade prefill is removed. The seeded marker makes the empty assertion
    meaningful (empty by choice, not an empty log). (The Software page no longer has an output
    textarea at all — its Update/Uninstall now link to pfSense's Package Manager, issue #684.)
    """
    upd_marker = f"pfb-upd-prefill-{uuid.uuid4().hex[:8]}"
    _seed_vm_file(smoke_vm, _PFB_LOG, upd_marker + "\n")

    # Update page → no prefill (clean render, and the seeded log marker must be absent).
    resp = webui.get(_UPDATE_PAGE)
    result = evaluate_render(_UPDATE_PAGE, resp.status_code, resp.text, ("Update Settings", "Schedule"))
    assert result.ok, f"Update page render oracle failed: {result.detail}"
    assert upd_marker not in _pfb_output_value(resp.text), "Update page must not prefill pfb_output"


def test_ajax_tail_endpoint_returns_json(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """The ``?ajax=tail`` poll endpoint returns a well-formed JSON tail payload (#671).

    The live log is served by this endpoint instead of a blocking inline-<script> stream, which
    is why the page now completes loading (foot.inc + nav menu). A GET with no offset must return
    the JSON contract the client poller consumes — parseable JSON (not an HTML page) carrying the
    data/offset/done/source keys — on BOTH pages.

    For the Update source the per-run log is seeded, so the payload tails it: source 'run' with the
    marker present. fail-before: there was no such endpoint, so the request rendered the full HTML
    page and ``json.loads`` would raise. (The Software page no longer has an ``?ajax=tail`` endpoint
    — its Update/Uninstall link to pfSense's Package Manager, issue #684.)
    """
    run_marker = f"pfb-tail-{uuid.uuid4().hex[:8]}"
    _seed_vm_file(smoke_vm, _PFB_RUNLOG, run_marker + "\n")

    resp = webui.get(f"{_UPDATE_PAGE}?ajax=tail")
    assert resp.status_code == 200, f"ajax=tail status {resp.status_code}"
    payload = json.loads(resp.text)  # must parse as JSON, not HTML
    for key in ("data", "offset", "done", "source"):
        assert key in payload, f"update ajax=tail payload missing {key!r}: {payload}"
    assert payload["source"] == "run", f"seeded run log should be tailed (source 'run'): {payload}"
    assert run_marker in payload["data"], f"seeded run-log marker missing from tail data: {payload}"


def test_software_page_hidden_when_override_forces_off(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """Forcing the override 'off' hides the page DETERMINISTICALLY — independent of install %R.

    The 'off' branch must win even on a box that WOULD auto-detect as our-build, so support can
    force the page away. This Tier-A deploy is a SIDELOAD (%R empty), so the provenance gate
    already hides the page by DEFAULT (the tests above) — forcing 'off' alone would be
    indistinguishable from that default no-op. Force 'on' FIRST and assert the page IS visible
    (the sibling positive branch, re-proven here as the before-state), THEN force 'off' on the
    SAME box and assert it becomes hidden again — a real transition proving 'off' is what caused
    the hide, not the deploy's own default state.
    """
    with software_panel_forced(smoke_vm, "on"):
        resp = webui.get(_SOFTWARE_PAGE)
        result = evaluate_render(_SOFTWARE_PAGE, resp.status_code, resp.text, (_SOFTWARE_PANEL_MARKER,))
        assert result.ok, f"forced-on Software page render failed (precondition): {result.detail}"

    with software_panel_forced(smoke_vm, "off"):
        resp = webui.get(_SOFTWARE_PAGE, allow_redirects=False)
        assert resp.status_code in (301, 302, 303, 307, 308), (
            f"forced-off Software page expected a redirect, got HTTP {resp.status_code}"
        )
        assert resp.headers.get("Location", "").endswith("/index.php")
        assert _SOFTWARE_PANEL_MARKER not in resp.text, "forced-off must NOT render the Software panel"


def test_log_settings_section_redesign_render(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """The Log Settings section was regrouped into aligned per-log rows with a single 2-item
    column-help intro and category header rows (issue #489), and the ADR-30 scheduled-reset
    controls (log_rotate_<type>/log_reset_keep_<type>) were replaced by ADR-60's age-based
    log_max_days_<type> field.

    Scenario: Log Settings section redesigned — grouped by category, 2 aligned columns.
      Background: pfBlockerNG deployed; General page renders cleanly.

    Given the General page renders via the clean-render oracle (200, no Fatal/Warning/Notice,
      "General Settings" section marker present),

    When the body is inspected for the grouped-column structure,

    Then the two column-header texts (Max lines / Max days) are present in the body, emitted
      once by the ``.pfb-logcolhdr`` row (PRESENT: option A);
    And the 2-item intro wording markers are present (the column-purpose ``<ul>`` sentences
      written in issue #489's intro ``Form_StaticText``, updated for ADR-60's Max days column);
    And a representative set of ``log_max_days_<type>`` field names spanning the categories the
      retired controls covered (DNS block, General Unified, DNS Reply) are present, plus
      ``log_max_<type>`` — proving no control was dropped by the redesign;
    And the retired ADR-30 ``log_rotate_<type>``/``log_reset_keep_<type>`` field names are
      ABSENT — the scheduled-reset controls were removed (ABSENT: old design, before/after
      evidence);
    And the old repeated per-field help suffix ("</strong> Log", the pattern emitted by
      ``setHelp("Default: <strong>20000<br />{$descr}</strong> Log")`` on every row) is
      ABSENT — the repetition was removed (ABSENT: old design, before/after evidence);
    And the old "Unified Log" label is ABSENT — the trailing " Log" was dropped to "Unified"
      (ABSENT: old design, before/after evidence). ``php_error_log_guard`` enrolls this GET
      in the module-level no-growth sweep.

    Source-inspection proof of fail-before/pass-after (verified against
    ``pfblockerng_general.php`` ~lines 359-418 in this worktree):
    - PRESENT markers ("rolling cap", "trims lines older than", "whichever cap is more
      restrictive") come from the intro ``Form_StaticText`` — one column-purpose ``<ul>``,
      absent from ``origin/devel`` (which instead has the 3-item Schedule/Keep-lines intro).
    - PRESENT markers (the full header-cell markup
      ``form-control-static hidden-xs"><strong>Max lines</strong>`` / Max days) come ONLY
      from the per-category header ``Form_Group`` rows (``Form_StaticText('', '<p
      class="form-control-static hidden-xs"><strong>...</strong></p>')``). A bare
      ``>Max lines<`` substring is NOT sufficient: the intro ``<ul>`` also renders
      ``<li><strong>Max lines</strong> &mdash; ...`` (no ``hidden-xs``, no
      ``form-control-static``), so it satisfies the old bare needle even with every header
      row deleted — the full markup needle only matches the header cell. (The
      ``pfb-loghdr`` class is NOT asserted for the same reason: its name also appears in
      the intro's ``<style>`` block, so it can't prove a header row rendered.)
    - ABSENT markers (``name="log_rotate_..."``/``name="log_reset_keep_..."``) exist ONLY in
      the retired ADR-30 ``Form_Select``/``Form_Input`` calls this phase deletes; they are
      absent from the new code, so the test PASSES after the change and would FAIL if the
      old controls were reinstated (this is the flip of the field-name assertions this same
      test carried through ADR-60 Phase 7, where they were still PRESENT — see git history).
    - ABSENT markers ("</strong> Log", "Unified Log") exist ONLY in the old
      ``setHelp("Default: <strong>20000<br />{$descr}</strong> Log")`` calls and the old
      ``'Unified Log'`` key; they are absent from the new code, so the test PASSES after
      the change and would FAIL if the old code were reinstated.
    """
    resp = webui.get(_GENERAL_PAGE)
    result = evaluate_render(_GENERAL_PAGE, resp.status_code, resp.text, ("General Settings",))
    assert result.ok, f"General page render oracle failed: {result.detail}"
    body = resp.text

    # PRESENT: new 2-item intro wording (emitted by the intro Form_StaticText).
    for needle in (
        "rolling cap",
        "trims lines older than",
        "whichever cap is more restrictive",
    ):
        assert needle in body, f"Log Settings intro wording {needle!r} missing — redesign intro not rendered"

    # PRESENT: the single column-title row. A bare ">Max lines<" substring is ALSO
    # satisfied by the intro <ul> ("<li><strong>Max lines</strong> ...") — dropping the
    # header row entirely would still pass that needle. Assert the full header-cell HTML
    # instead — the intro carries neither "hidden-xs" nor "form-control-static". Count 1
    # pins option A's hoist: the pre-A page emitted this markup three times (once per
    # category).
    for needle in (
        'form-control-static hidden-xs"><strong>Max lines</strong>',
        'form-control-static hidden-xs"><strong>Max days</strong>',
    ):
        assert body.count(needle) == 1, (
            f"Log Settings header cell {needle!r} count={body.count(needle)} — want exactly one (option A)"
        )

    # PRESENT: field names spanning all four categories — no control dropped. The
    # log_max_days_<type> markers cover the same 3 categories the retired
    # log_rotate_<type>/log_reset_keep_<type> markers (below) used to cover.
    for field_name in (
        'name="log_max_log"',  # General: pfBlockerNG
        'name="log_max_days_dnslog"',  # DNS: Block
        'name="log_max_days_unilog"',  # General: Unified
        'name="log_max_ip_blocklog"',  # IP
        'name="log_max_days_dnsreplylog"',  # DNS: Reply
    ):
        assert field_name in body, f"Log Settings field {field_name!r} missing — control dropped by redesign"

    # ABSENT: retired ADR-30 scheduled-reset controls (log_rotate_<type>/
    # log_reset_keep_<type>) — superseded by log_max_days_<type> (ADR-60).
    for field_name in (
        'name="log_rotate_dnslog"',
        'name="log_reset_keep_unilog"',
        'name="log_rotate_dnsreplylog"',
    ):
        assert field_name not in body, (
            f"retired Log Settings field {field_name!r} still present — ADR-30 control not removed"
        )

    # ABSENT: old repeated per-field help suffix (was emitted by every row in the old code).
    assert "</strong> Log" not in body, (
        'old repeated per-field help suffix "</strong> Log" still present — setHelp repetition not removed'
    )

    # ABSENT: old "Unified Log" label (renamed to "Unified" in the redesign).
    assert "Unified Log" not in body, (
        '"Unified Log" label still present — label not updated to "Unified" (issue #489 rename)'
    )


def test_page_table_covers_every_pfblockerng_page() -> None:
    """Guard: the table (plus the recorded exclusions) covers the on-disk page set.

    A new pfBlockerNG .php page added to src/ without a Tier-A entry should fail
    this -- the count is asserted so the sweep can't silently skip a page. 14
    servable main pages: general, ip, dnsbl, feeds, alerts, log, sync,
    safesearch, update, blacklist, category, category_edit, threats, hooks, plus
    the widget. The non-servable pfblockerng.php CLI dispatcher is excluded. The
    9 GeoIP continent/category pages + Reputation
    (all WRITTEN by pfblockerng_geoip.inc via `ugc`) are ALSO covered now that a seeded
    synthetic dataset makes them hermetically renderable -- only the DNSBL-VIP
    sinkhole pages remain a recorded exclusion.
    """
    covered_paths = {p.path.split("?", 1)[0] for p in PAGE_TABLE}
    # 14 distinct main .php files are render-smoked here (pfblockerng.php is never
    # served directly -- it is the CLI dispatcher; pfblockerng_geoip.inc is the template for
    # the GeoIP pages
    # below), plus the widget = 15 distinct paths.
    expected_main = {
        "/pfblockerng/pfblockerng_general.php",
        "/pfblockerng/pfblockerng_ip.php",
        "/pfblockerng/pfblockerng_dnsbl.php",
        "/pfblockerng/pfblockerng_feeds.php",
        "/pfblockerng/pfblockerng_alerts.php",
        "/pfblockerng/pfblockerng_log.php",
        "/pfblockerng/pfblockerng_sync.php",
        "/pfblockerng/pfblockerng_safesearch.php",
        "/pfblockerng/pfblockerng_update.php",
        "/pfblockerng/pfblockerng_blacklist.php",
        "/pfblockerng/pfblockerng_category.php",
        "/pfblockerng/pfblockerng_category_edit.php",
        "/pfblockerng/pfblockerng_threats.php",
        "/pfblockerng/pfblockerng_hooks.php",
        "/widgets/widgets/pfblockerng.widget.php",
    }
    missing = expected_main - covered_paths
    assert not missing, f"Tier-A page table is missing pages: {sorted(missing)}"
    # The 9 GeoIP continent/category pages + Reputation, generated by `ugc`.
    expected_geoip = {
        "/pfblockerng/pfblockerng_Africa.php",
        "/pfblockerng/pfblockerng_Antarctica.php",
        "/pfblockerng/pfblockerng_Asia.php",
        "/pfblockerng/pfblockerng_Europe.php",
        "/pfblockerng/pfblockerng_North_America.php",
        "/pfblockerng/pfblockerng_Oceania.php",
        "/pfblockerng/pfblockerng_South_America.php",
        "/pfblockerng/pfblockerng_Proxy_and_Satellite.php",
        "/pfblockerng/pfblockerng_Top_Spammers.php",
        "/pfblockerng/pfblockerng_reputation.php",
    }
    missing_geoip = expected_geoip - covered_paths
    assert not missing_geoip, f"Tier-A page table is missing GeoIP page(s): {sorted(missing_geoip)}"
    # Only the DNSBL-VIP sinkhole pages remain a recorded (non-hermetic) exclusion.
    excluded_names = {e.name for e in EXCLUDED_FROM_TIER_A}
    assert "geoip_continent_views" not in excluded_names
    assert "dnsbl_vip_sinkhole_pages" in excluded_names


def test_blacklist_download_name_keys_on_provider_id() -> None:
    """Pin the CLI-only provider-naming contract that Tier-A HTTP rendering cannot execute.

    A Blacklist provider's category filenames are derived from its download file name, so
    keying that name on a feed URL literal renames the whole category set the day the URL
    moves. Same reasoning as the sibling pins above: ``pfblockerng.php`` is the CLI
    dispatcher and is never served, so the contract is asserted at the source rather than
    through an HTTP render (issue #2636).
    """
    source_path = helpers.SMOKE_DIR.parent.parent / "src/usr/local/www/pfblockerng/pfblockerng.php"
    source = source_path.read_text(encoding="utf-8")

    assert re.search(r"if\s*\(\s*\$item\['xml'\]\s*==\s*'ut1'\s*\)", source), (
        "the ut1.tar.gz filename patch must key on the provider id"
    )
    assert "ftp://ftp.ut-capitole.fr" not in source, (
        "the filename patch must not key on a feed URL literal -- a URL change would "
        "silently rename every UT1 category file"
    )


def test_pfblockerng_download_extras_uses_typed_download_result() -> None:
    """Pin the CLI-only download contract that Tier-A HTTP rendering cannot execute.

    ``pfblockerng.php`` is never served directly: it is the CLI dispatcher; the
    ``pfblockerng_geoip.inc`` module owns generated GeoIP pages. Keep this source assertion in the
    ``ui_render`` module so the changed PHP call shape still has a front-end
    coverage pairing without pretending an HTTP render reaches this function.
    """
    source_path = helpers.SMOKE_DIR.parent.parent / "src/usr/local/www/pfblockerng/pfblockerng.php"
    source = source_path.read_text(encoding="utf-8")

    declaration = "function pfblockerng_download_extras("
    start = source.index(declaration)
    remainder = source[start + len(declaration) :]
    next_function = re.search(r"^function\s+\w+\s*\(", remainder, flags=re.MULTILINE)
    assert next_function is not None, "pfblockerng_download_extras() must be followed by another function"
    function_source = source[start : start + len(declaration) + next_function.start()]

    assert re.search(r"pfb_download\(\s*new\s+PfbDownloadRequest\(", function_source, flags=re.DOTALL), (
        "pfblockerng_download_extras() must construct PfbDownloadRequest"
    )
    assert re.search(r"\)\s*\)\s*->\s*success\b", function_source, flags=re.DOTALL), (
        "pfblockerng_download_extras() must consume PfbDownloadResult->success"
    )
    assert not re.search(r"pfb_download\(\s*(?!new\s+PfbDownloadRequest\b)", function_source, flags=re.DOTALL), (
        "retired positional pfb_download() call shape must not return"
    )


def test_dnsbl_regex_save_uses_package_python_wrapper() -> None:
    """Pin the POST-only validator path that a Tier-A GET cannot execute.

    PHP may probe ``pfb_python_interpreter()`` for readiness, but the validator
    itself must invoke the package wrapper so interpreter selection stays in one
    implementation.
    """
    source_path = helpers.SMOKE_DIR.parent.parent / "src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php"
    source = source_path.read_text(encoding="utf-8")
    block = extract_between(source, "// A usable validator always runs", "// Validate DNSBL VIP address")

    assert "$pfb_regex_python = pfb_python_interpreter();" in block
    assert re.search(
        r"pfb_dnsbl_regex_validation_errors\(\(string\).*?,\s*PFB_PYTHON_WRAPPER,",
        block,
        flags=re.DOTALL,
    ), "DNSBL regex save validation must execute through PFB_PYTHON_WRAPPER"


def test_pfblockerng_tick_delegates_safesearch_to_due_ledger() -> None:
    """Pin the CLI-only tick dispatch that Tier-A HTTP rendering cannot execute."""
    source_path = helpers.SMOKE_DIR.parent.parent / "src/usr/local/www/pfblockerng/pfblockerng.php"
    source = source_path.read_text(encoding="utf-8")

    tick_branch = extract_between(source, "elseif ($argv[1] == 'tick') {", "elseif ($argv[1] == 'cron-tick') {")
    assert tick_branch.count("pfblockerng_tick();") == 1
    assert "pfblockerng_ss_refresh" not in tick_branch


def test_reputation_page_help_text_names_relocated_matchgen_paths(
    webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:  # noqa: ARG001
    """issue #1250: the Reputation page's ccwhite/ET help text pointed at the machine-generated
    artifacts' OLD matchdir names/location; both moved under matchdir/generated with new names.

    Scenario: Reputation page help text names the relocated matchgen paths.
            Given the Reputation page (written by pfblockerng_geoip.inc via `ugc`)
            renders cleanly
      When  the body is inspected
      Then  it names the NEW matchgendir paths for the ccwhite exempt file and the ET match
            file, and does NOT name either OLD matchdir path (before/after: the old paths were
            the literal help text prior to this change; `matchdedup.txt` was never a real
            filename any writer produced, only `matchdedup_v4.txt` -- so the old help text was
            already unfollowable, not merely stale).
    """
    resp = webui.get("/pfblockerng/pfblockerng_reputation.php")
    result = evaluate_render(
        "/pfblockerng/pfblockerng_reputation.php",
        resp.status_code,
        resp.text,
        ("IPv4 Reputation", "Individual List Reputation"),
    )
    assert result.ok, f"Reputation page render oracle failed: {result.detail}"
    body = resp.text

    for needle in (
        "/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt",
        "/var/db/pfblockerng/match/generated/pfB_Match_ET_v4.txt",
    ):
        assert needle in body, f"relocated matchgen path {needle!r} missing from Reputation help text"

    for needle in (
        "/var/db/pfblockerng/match/matchdedup.txt",
        "/var/db/pfblockerng/match/ETMatch.txt",
    ):
        assert needle not in body, f"stale pre-#1250 matchdir path {needle!r} still present in help text"


# ---------------------------------------------------------------------------
# Tier-B tests — ui_e2e marker; schedule/dispatch-only, NOT PR-blocking.
# These require VM state setup (seeding files or multi-step POST → GET flows).
# ---------------------------------------------------------------------------

_PFB_LOG = "/var/log/pfblockerng/pfblockerng.log"
_PFB_RUNLOG = "/var/log/pfblockerng/pfblockerng_run.log"


def _seed_vm_file(vm: SmokeVM, path: str, content: str, *, timeout: float = 30.0) -> None:
    """Append *content* to *path* on the guest via ``tee -a``.

    Uses ``subprocess.run`` directly so ``input=`` can carry the data (the
    ``SmokeVM.ssh()`` helper captures stdout/stderr only, no stdin pipe).
    The parent directory must already exist (``/var/log/pfblockerng/`` is
    created by pfBlockerNG on install — always present after ``pkg add``).
    """
    result = subprocess.run(
        vm.ssh_argv("tee", "-a", path),
        input=content,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"_seed_vm_file({path!r}) failed: rc={result.returncode} {result.stderr!r}")


_PENDING_MARKER = "/usr/local/etc/pfb_pending_changes"
_PENDING_NEEDLE = "Pending changes will be applied on the next list update"


def test_pending_changes_banner_tracks_the_marker(
    smoke_vm: SmokeVM,
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The "pending changes" banner shows on a settings page iff there are unapplied
    settings changes, and disappears once an Update has applied them.

    A save on a deferred page (DNSBL/IP/Feeds) writes config but only the next Update
    applies it, so the GUI flags the wait with a banner linking to the Update page. The
    flag is the persisted marker file at ``/usr/local/etc/pfb_pending_changes``.

    Scenario:
      Given no marker (no pending changes), the DNSBL page renders WITHOUT the banner;
      When the marker is present (settings changed, no Update run yet),
      Then the DNSBL page renders WITH the banner + its "go to the Update tab" link.
    Driving the marker file directly stands in for the save (which sets it) and the
    Update (which clears it) — a genuine before/after, not a one-sided assertion.
    """
    path = "/pfblockerng/pfblockerng_dnsbl.php"
    try:
        # Given a clean state — banner ABSENT, page still renders cleanly.
        smoke_vm.ssh("rm", "-f", _PENDING_MARKER)
        resp = webui.get(path)
        result = evaluate_render(path, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
        assert result.ok, f"DNSBL render oracle failed (clean state): {result.detail}"
        assert _PENDING_NEEDLE not in resp.text, "pending-changes banner must be ABSENT when there is no marker file"

        # When settings have changed but no Update has run — banner SHOWS, with its link.
        smoke_vm.ssh("touch", _PENDING_MARKER)
        resp2 = webui.get(path)
        result2 = evaluate_render(path, resp2.status_code, resp2.text, ("DNSBL Webserver Configuration",))
        assert result2.ok, f"DNSBL render oracle failed (pending state): {result2.detail}"
        assert _PENDING_NEEDLE in resp2.text, "pending-changes banner must SHOW when the marker file exists"
        assert "To run an update now, go to the" in resp2.text, (
            "pending-changes banner must carry the Update-page call to action"
        )

        # On the Update page itself ($on_update_page=TRUE) the banner SHOWS but drops the
        # redundant self-link — exercising the other branch of pfb_print_pending_changes_box().
        update_path = "/pfblockerng/pfblockerng_update.php"
        resp3 = webui.get(update_path)
        result3 = evaluate_render(update_path, resp3.status_code, resp3.text, ("Update Settings",))
        assert result3.ok, f"Update render oracle failed (pending state): {result3.detail}"
        assert _PENDING_NEEDLE in resp3.text, "banner must SHOW on the Update page too when pending"
        assert "To run an update now, go to the" not in resp3.text, (
            "on the Update page the banner must NOT carry the go-to-Update self-link"
        )
    finally:
        smoke_vm.ssh("rm", "-f", _PENDING_MARKER)
