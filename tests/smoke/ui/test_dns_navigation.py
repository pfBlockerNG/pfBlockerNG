"""Tier-A render proof for the DNS navigation regroup (issue #3593).

Marker ``ui_render``. The old adjacent ``DNSBL`` and ``pfB-DNS`` top-level tabs are one ``DNS`` tab on
``pfblockerng_dns.php``, selected on the DNS family only. The DNS family's second row holds the five DNS
sub-tabs in order, and its breadcrumb's DNS parent links ``pfblockerng_dns.php``.

Every assertion reads the HTML of a real GET. pfSense prints the tab rows as ``<ul class="nav nav-pills">``
(``display_top_tabs``) and the breadcrumb as ``<ol class="breadcrumb">`` (``genhtmltitle``). Both are read into
rows here, so a tab is matched by its own link and label, never by a substring of the body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .test_render_smoke import software_panel_forced
from .webui import scrape_form_fields

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

GENERAL = "/pfblockerng/pfblockerng_general.php"
IP = "/pfblockerng/pfblockerng_ip.php"
DNS = "/pfblockerng/pfblockerng_dns.php"
DNSBL = "/pfblockerng/pfblockerng_dnsbl.php"
UPDATE = "/pfblockerng/pfblockerng_update.php"
HOOKS = "/pfblockerng/pfblockerng_hooks.php"
EDIT_HOOKS = "/pfblockerng/pfblockerng_edit_hooks.php"
FEEDS = "/pfblockerng/pfblockerng_feeds.php"
LOG = "/pfblockerng/pfblockerng_log.php"
SYNC = "/pfblockerng/pfblockerng_sync.php"
SOFTWARE = "/pfblockerng/pfblockerng_software.php"
WIZARD = "/wizard.php?xml=pfblockerng_wizard.xml"
ALERTS = "/pfblockerng/pfblockerng_alerts.php"
CATEGORY = "/pfblockerng/pfblockerng_category.php"
GROUPS = f"{CATEGORY}?type=dnsbl"
CATEGORY_IPV4 = f"{CATEGORY}?type=ipv4"
CATEGORY_IPV6 = f"{CATEGORY}?type=ipv6"
CATEGORY_GEOIP = f"{CATEGORY}?type=geoip"
EDITOR = "/pfblockerng/pfblockerng_category_edit.php"
GROUP_EDITOR = f"{EDITOR}?type=dnsbl"
EDITOR_IPV4 = f"{EDITOR}?type=ipv4"
EDITOR_IPV6 = f"{EDITOR}?type=ipv6"
BLACKLIST = "/pfblockerng/pfblockerng_blacklist.php"
SAFESEARCH = "/pfblockerng/pfblockerng_safesearch.php"
REPUTATION = "/pfblockerng/pfblockerng_reputation.php"

# The Alerts default-page query: none, or one of the views pfb_alerts_default_page() accepts.
_REPORTS_HREF = re.compile(
    r"/pfblockerng/pfblockerng_alerts\.php"
    r"(\?view=(dnsbl_stat|dnsbl_reply_stat|ip_block_stat|ip_permit_stat|ip_match_stat|reply|unified))?"
)
_TAB_ROW_CLASSES = frozenset({"nav-pills", "nav-tabs"})


@dataclass(frozen=True)
class Tab:
    label: str
    href: str
    active: bool


@dataclass(frozen=True)
class Crumb:
    label: str
    href: str | None


@dataclass
class _Item:
    active: bool
    href: str | None = None
    text: list[str] = field(default_factory=list)


class _ChromeParser(HTMLParser):
    """Reads one page's tab rows and breadcrumb out of its HTML.

    A tab row is a ``<ul>`` with pfSense's ``display_top_tabs`` class; its ``<li>`` items are the tabs and
    ``active`` marks the highlighted one. The breadcrumb is the ``<ol class="breadcrumb">``. The main menu is
    ``ul.nav.navbar-nav``, which matches neither class and is never read as a row.
    """

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list[Tab]] = []
        self.crumbs: list[Crumb] = []
        self._in_row = False
        self._in_crumbs = False
        self._item: _Item | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        if tag == "ul" and classes & _TAB_ROW_CLASSES:
            self.rows.append([])
            self._in_row = True
        elif tag == "ol" and "breadcrumb" in classes:
            self._in_crumbs = True
        elif tag == "li" and (self._in_row or self._in_crumbs):
            self._item = _Item(active="active" in classes)
        elif tag == "a" and self._item is not None:
            self._item.href = values.get("href")

    def handle_endtag(self, tag: str) -> None:
        if tag == "ul":
            self._in_row = False
        elif tag == "ol":
            self._in_crumbs = False
        elif tag == "li" and self._item is not None:
            label = " ".join("".join(self._item.text).split())
            if self._in_row:
                self.rows[-1].append(Tab(label, self._item.href or "", self._item.active))
            else:
                self.crumbs.append(Crumb(label, self._item.href))
            self._item = None

    def handle_data(self, data: str) -> None:
        if self._item is not None:
            self._item.text.append(data)


def _chrome(webui: WebUI, path: str) -> _ChromeParser:
    resp = webui.get(path)
    assert resp.status_code == 200, f"{path} answered HTTP {resp.status_code}, not a rendered page"
    parser = _ChromeParser()
    parser.feed(resp.text)
    parser.close()
    return parser


def _top_row(chrome: _ChromeParser, path: str) -> list[Tab]:
    assert chrome.rows, f"{path} renders no tab row"
    return chrome.rows[0]


def _sub_row(chrome: _ChromeParser, path: str) -> list[Tab]:
    assert len(chrome.rows) == 2, (
        f"{path} renders {len(chrome.rows)} tab row(s); expected the top row and one sub-tab row"
    )
    return chrome.rows[1]


def _tab(row: list[Tab], label: str) -> Tab:
    matches = [tab for tab in row if tab.label == label]
    assert len(matches) == 1, f"expected exactly one {label!r} tab, found {len(matches)}"
    return matches[0]


def _top_tabs(reports: str, *, wizard: bool, software: bool = False) -> list[tuple[str, str]]:
    """The top row every pfBlockerNG page prints, in order: DNS sits where DNSBL and pfB-DNS were."""
    tabs = [
        ("General", GENERAL),
        ("IP", IP),
        ("DNS", DNS),
        ("Update", UPDATE),
        ("Reports", reports),
        ("Feeds", FEEDS),
        ("Logs", LOG),
        ("Sync", SYNC),
    ]
    if software:
        tabs.append(("Software", SOFTWARE))
    if wizard:
        tabs.append(("Wizard", WIZARD))
    return tabs


_DNS_FAMILY_ACTIVE = {
    DNS: "pfB-DNS",
    DNSBL: "DNSBL",
    GROUPS: "DNSBL Groups",
    GROUP_EDITOR: "DNSBL Groups",
    BLACKLIST: "DNSBL Category",
    SAFESEARCH: "DNSBL SafeSearch",
}
_CONTINENT_PAGES = (
    "/pfblockerng/pfblockerng_Africa.php",
    "/pfblockerng/pfblockerng_Antarctica.php",
    "/pfblockerng/pfblockerng_Asia.php",
    "/pfblockerng/pfblockerng_Europe.php",
    "/pfblockerng/pfblockerng_North_America.php",
    "/pfblockerng/pfblockerng_Oceania.php",
    "/pfblockerng/pfblockerng_South_America.php",
    "/pfblockerng/pfblockerng_Proxy_and_Satellite.php",
    "/pfblockerng/pfblockerng_Top_Spammers.php",
)
_UNRELATED_PAGES = (
    GENERAL,
    IP,
    CATEGORY_IPV4,
    CATEGORY_IPV6,
    CATEGORY_GEOIP,
    EDITOR_IPV4,
    EDITOR_IPV6,
    f"{FEEDS}?type=ipv4",
    f"{FEEDS}?type=ipv6",
    f"{FEEDS}?type=dnsbl",
    ALERTS,
    f"{ALERTS}?view=ip_block_stat",
    f"{ALERTS}?view=dnsbl_stat",
    LOG,
    SYNC,
    UPDATE,
    HOOKS,
    EDIT_HOOKS,
    REPUTATION,
    *_CONTINENT_PAGES,
)
TOP_ROW_PAGES = (*_DNS_FAMILY_ACTIVE, *_UNRELATED_PAGES)
# The pages that print the Wizard tab: General's (outside its redirect) and the pfB-DNS page's.
_WIZARD_PAGES = frozenset({GENERAL, DNS})

_DNS_SUBTABS = (
    ("pfB-DNS", DNS),
    ("DNSBL", DNSBL),
    ("DNSBL Groups", GROUPS),
    ("DNSBL Category", BLACKLIST),
    ("DNSBL SafeSearch", SAFESEARCH),
)
_UPDATE_SUBTABS = (("Run", UPDATE), ("Hooks", HOOKS), ("Edit Hooks", EDIT_HOOKS))
_IP_SUBTABS = (
    ("IPv4", CATEGORY_IPV4),
    ("IPv6", CATEGORY_IPV6),
    ("GeoIP", CATEGORY_GEOIP),
    ("Reputation", REPUTATION),
)
# (page, its second row, the one tab that row highlights; None when it highlights none)
_SUBTAB_CASES: tuple[tuple[str, tuple[tuple[str, str], ...], str | None], ...] = (
    (DNS, _DNS_SUBTABS, "pfB-DNS"),
    (DNSBL, _DNS_SUBTABS, "DNSBL"),
    (GROUPS, _DNS_SUBTABS, "DNSBL Groups"),
    (GROUP_EDITOR, _DNS_SUBTABS, "DNSBL Groups"),
    (BLACKLIST, _DNS_SUBTABS, "DNSBL Category"),
    (SAFESEARCH, _DNS_SUBTABS, "DNSBL SafeSearch"),
    (UPDATE, _UPDATE_SUBTABS, "Run"),
    (HOOKS, _UPDATE_SUBTABS, "Hooks"),
    (EDIT_HOOKS, _UPDATE_SUBTABS, "Edit Hooks"),
    (IP, _IP_SUBTABS, None),
    (CATEGORY_IPV4, _IP_SUBTABS, "IPv4"),
    (CATEGORY_IPV6, _IP_SUBTABS, "IPv6"),
    (CATEGORY_GEOIP, _IP_SUBTABS, "GeoIP"),
    (EDITOR_IPV4, _IP_SUBTABS, "IPv4"),
    (EDITOR_IPV6, _IP_SUBTABS, "IPv6"),
    (REPUTATION, _IP_SUBTABS, "Reputation"),
)

_DNS_PARENT = Crumb("DNS", DNS)
_IP_PARENT = Crumb("IP", CATEGORY_IPV4)
# (page, its last crumb, the parent crumb it must carry)
_CRUMB_CASES: tuple[tuple[str, str, Crumb], ...] = (
    (DNS, "pfB-DNS", _DNS_PARENT),
    (DNSBL, "DNSBL", _DNS_PARENT),
    (BLACKLIST, "DNSBL Category", _DNS_PARENT),
    (SAFESEARCH, "DNSBL SafeSearch", _DNS_PARENT),
    (GROUPS, "DNSBL Groups", _DNS_PARENT),
    (GROUP_EDITOR, "DNSBL Groups", _DNS_PARENT),
    (CATEGORY_IPV4, "IPv4", _IP_PARENT),
    (CATEGORY_IPV6, "IPv6", _IP_PARENT),
    (CATEGORY_GEOIP, "GeoIP", _IP_PARENT),
    (EDITOR_IPV4, "IPv4", _IP_PARENT),
    (EDITOR_IPV6, "IPv6", _IP_PARENT),
)

_EDITOR_CASES = ((EDITOR_IPV4, "ipv4"), (EDITOR_IPV6, "ipv6"), (GROUP_EDITOR, "dnsbl"))


@pytest.fixture(scope="module")
def reports_href(webui: WebUI) -> str:
    """The Reports tab href the General page prints: the Alerts default query every page must share."""
    href = _tab(_top_row(_chrome(webui, GENERAL), GENERAL), "Reports").href
    assert _REPORTS_HREF.fullmatch(href), f"the Reports tab must link the Alerts page, got {href!r}"
    return href


@pytest.mark.parametrize("path", TOP_ROW_PAGES)
def test_top_row_offers_one_dns_tab_where_dnsbl_and_pfb_dns_were(path: str, webui: WebUI, reports_href: str) -> None:
    """Every page's top row has one DNS tab in the old DNSBL/pfB-DNS slot, and neither old tab.

    DNS is selected on the six DNS-family pages and on no other page. The Reports tab keeps the Alerts query.
    """
    top = _top_row(_chrome(webui, path), path)
    hrefs = [tab.href for tab in top]
    labels = [tab.label for tab in top]
    assert hrefs.count(DNS) == 1, f"{path}: the top row needs exactly one DNS tab (dns.php), got {hrefs.count(DNS)}"
    assert DNSBL not in hrefs, f"{path}: the old top-level DNSBL tab (dnsbl.php) is still in the top row"
    assert "pfB-DNS" not in labels and "DNSBL" not in labels, f"{path}: old top-level tab still present: {labels}"
    shown = [(tab.label, tab.href) for tab in top if tab.label != "Software"]
    assert shown == _top_tabs(reports_href, wizard=path in _WIZARD_PAGES), f"{path}: top row is {shown}"
    active = [tab.label for tab in top if tab.active]
    if path in _DNS_FAMILY_ACTIVE:
        assert active == ["DNS"], f"{path}: the DNS family must select the DNS tab alone, got {active}"
    else:
        assert "DNS" not in active, f"{path}: the DNS tab must not be selected off the DNS family"


@pytest.mark.parametrize(("path", "subtabs", "active"), _SUBTAB_CASES, ids=[case[0] for case in _SUBTAB_CASES])
def test_second_row_lists_the_family_subtabs_with_the_page_active(
    path: str, subtabs: tuple[tuple[str, str], ...], active: str | None, webui: WebUI
) -> None:
    """The second row holds the page's family in order and highlights the page's own sub-tab alone."""
    row = _sub_row(_chrome(webui, path), path)
    pairs = [(tab.label, tab.href) for tab in row]
    assert pairs == list(subtabs), f"{path}: second row is {pairs}"
    assert [tab.label for tab in row if tab.active] == ([active] if active else []), f"{path}: wrong sub-tab active"


@pytest.mark.parametrize(("path", "last", "parent"), _CRUMB_CASES, ids=[case[0] for case in _CRUMB_CASES])
def test_breadcrumb_parent_is_dns_for_the_dns_family_and_ip_for_ip_pages(
    path: str, last: str, parent: Crumb, webui: WebUI
) -> None:
    """The DNS children's parent crumb links dns.php and never dnsbl.php; the IP pages keep their IP parent."""
    crumbs = _chrome(webui, path).crumbs
    assert [crumb.label for crumb in crumbs] == ["Firewall", "pfBlockerNG", parent.label, last], (
        f"{path}: breadcrumb is {crumbs}"
    )
    assert crumbs[2] == parent, f"{path}: parent crumb is {crumbs[2]}, expected {parent}"
    assert DNSBL not in [crumb.href for crumb in crumbs], f"{path}: a crumb still links the old DNSBL page"


@pytest.mark.parametrize(("path", "gtype"), _EDITOR_CASES, ids=[case[0] for case in _EDITOR_CASES])
def test_editor_keeps_its_type_rowid_and_act_hidden_fields(path: str, gtype: str, webui: WebUI) -> None:
    """The editor posts its list type back in a hidden ``type`` field, with ``rowid`` and ``act`` beside it."""
    fields = scrape_form_fields(webui.get(f"{path}&rowid=7&act=add").text)
    expected = {"type": gtype, "rowid": "7", "act": "add"}
    assert {key: fields.get(key) for key in expected} == expected, (
        f"{path}: editor query parameters changed in the form: {fields}"
    )


@pytest.mark.parametrize(
    ("path", "software"),
    [(GENERAL, True), (GENERAL, False), (DNS, True), (DNS, False)],
    ids=["general-software-shown", "general-software-hidden", "dns-software-shown", "dns-software-hidden"],
)
def test_software_tab_sits_between_sync_and_wizard_when_its_gate_is_open(
    path: str, software: bool, webui: WebUI, smoke_vm: SmokeVM, reports_href: str
) -> None:
    """When its provenance gate is open the Software tab follows Sync and precedes Wizard; closed, it is absent.

    The gate is forced both ways through the hidden override sentinel, so both states render on one deploy.
    """
    with software_panel_forced(smoke_vm, "on" if software else "off"):
        top = _top_row(_chrome(webui, path), path)
    pairs = [(tab.label, tab.href) for tab in top]
    expected = _top_tabs(reports_href, wizard=True, software=software)
    assert pairs == expected, f"{path}: top row is {[tab.label for tab in top]}"


def test_software_page_prints_the_same_top_row_with_its_own_tab_active(
    webui: WebUI, smoke_vm: SmokeVM, reports_href: str
) -> None:
    """The Software page prints the shared top row, with its own Software tab the one selected."""
    with software_panel_forced(smoke_vm, "on"):
        top = _top_row(_chrome(webui, SOFTWARE), SOFTWARE)
    assert [(tab.label, tab.href) for tab in top] == _top_tabs(reports_href, wizard=False, software=True)
    assert [tab.label for tab in top if tab.active] == ["Software"]
