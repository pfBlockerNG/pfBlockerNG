"""Tier-B browser test (ADR-16 Phase 5): the Feeds IPv4/IPv6/DNSBL sub-tabs.

The visual replacement for the OLD maintainer manual smoke (ADR-16 §7): instead of
a human eyeballing the split Feeds page, a headless Chromium on the live ADR-04
smoke VM opens ``pfblockerng_feeds.php?type=ipv4|ipv6|dnsbl`` (reusing the Phase-1
authenticated session — the injected ``PHPSESSID`` cookie, no second login) and
asserts, per type:

* the SECOND sub-tab row ``[IPv4 | IPv6 | DNSBL]`` is present (all three sub-tab
  anchors, pointing at ``pfblockerng_feeds.php?type=...``), and
* the requested type's sub-tab is the ACTIVE one (its ``<li>`` carries pfSense's
  ``active`` class — emitted by ``display_top_tabs`` for the highlighted tab), and
* the page lists ONLY that type's feeds — proven by the type-scoped Feed Settings
  alias-name label (``IPv4/IPv6/DNSBL Alias name(s):``), which ``pfblockerng_feeds.php``
  renders for the ACTIVE type only (``pfb_feeds_render_aliasname_inputs($gtype)``,
  Phase 3) — so the other two types' labels are ABSENT from this tab's DOM, and

a per-tab full-page screenshot is written to the ``screenshot_dir`` artifact tree
(the visual record for review — an artifact, not an asserted baseline).

The split is the only ``src/`` change in ADR-16 (Phase 3); this test is the
``ui_browser`` half of its affected-flow coverage (the Tier-A render oracle —
``test_render_smoke.py`` ``feeds_ipv4``/``feeds_ipv6``/``feeds_dnsbl`` — is the
cheap/hermetic half). No ``src/`` change here.

DOM-FRAGILITY NOTE: ``display_top_tabs`` renders pfSense's standard ``nav-pills``
list; the load-bearing, version-tolerant handles are the anchor ``href`` (carries
``?type=``) and the ``active`` class on the highlighted ``<li>`` — NOT a brittle
DOM path. An ``href*="?type="`` match alone is NOT unique, though: by ADR-16 A4 the
main top bar's own "Feeds" tab AND the breadcrumb also carry ``?type=<active>``, so
the active type's query string appears in THREE anchors. The sub-tab row is the only
``<ul class="nav …">`` that contains ALL THREE type anchors at once — so we locate
that row first (``_subtab_nav``) and scope the presence/active assertions to it. The
Feed Settings section is ``COLLAPSIBLE|SEC_CLOSED`` (collapsed on load), so its
alias-name label is in the DOM but not visible — we assert DOM PRESENCE (``count()``),
not visibility, for the per-type label.

NO fixed sleeps: every assertion uses Playwright auto-waiting / ``count()`` after
``networkidle``. Playwright is imported lazily via ``pytest.importorskip`` so
collecting this module without it installed does not hard-error.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The Feeds page, split into ?type sub-tabs (ADR-16 Phase 3). The base path the three
# sub-tab anchors all point at (with a distinct ?type query each).
FEEDS_BASE = "/pfblockerng/pfblockerng_feeds.php"

# The three sub-tab types + the per-type Feed Settings alias-name label that renders
# for the ACTIVE type only (the type-scoped body) -- the "lists only its type" signal.
TYPE_LABELS = {
    "ipv4": "IPv4 Alias name(s):",
    "ipv6": "IPv6 Alias name(s):",
    "dnsbl": "DNSBL Alias name(s):",
}

# A short, explicit timeout (ms): the page renders server-side, so this is a flake
# ceiling for the post-load DOM, not a wait knob.
JS_TIMEOUT_MS = 10_000


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the (cookie-authenticated) page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form -- proving the injected
    session cookie authenticated the browser (no second login). Waits on
    ``networkidle`` so the page is fully rendered before any assertion.
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    # The login form carries #usernamefld; its absence proves we are authed.
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``."""
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _subtab_nav(page: Page) -> Locator:
    """The SECOND ``display_top_tabs`` row -- the ``[IPv4 | IPv6 | DNSBL]`` sub-tab ``<ul>``.

    ``display_top_tabs`` renders every tab row as ``<ul class="nav nav-…">``; the page
    has TWO (the main top bar + this sub-tab row), and -- since ADR-16 A4 -- the main
    bar's own "Feeds" tab AND the breadcrumb also carry ``?type=<active>``. So a bare
    ``href*="?type="`` match is NOT unique (three hits for the active type). The sub-tab
    row is the ONLY nav that contains ALL THREE type anchors at once; filter on that.
    Version-tolerant (works for ``nav-pills`` or ``nav-tabs``, independent of the
    surrounding markup).
    """
    nav = page.locator("ul.nav")
    for t in ("ipv4", "ipv6", "dnsbl"):
        nav = nav.filter(has=page.locator(f'a[href*="{FEEDS_BASE}?type={t}"]'))
    return nav


def _subtab_anchor(nav: Locator, gtype: str) -> Locator:
    """The ``?type=<gtype>`` anchor WITHIN the sub-tab row ``nav`` (scoped, so unique)."""
    return nav.locator(f'a[href*="{FEEDS_BASE}?type={gtype}"]')


@pytest.mark.parametrize("gtype", ["ipv4", "ipv6", "dnsbl"])
def test_feeds_subtab_row_active_and_type_scoped(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
    gtype: str,
) -> None:
    """Each ``?type`` Feeds tab shows the [IPv4|IPv6|DNSBL] row, highlights itself,
    and lists ONLY its own type.

    Scenario (one parametrization per type -- all three sub-tabs are exercised, so
    this is full branch coverage of the ``?type`` switch, not just one tab):

    Given the Feeds page opened at ``?type=<gtype>``,
    Then all THREE sub-tab anchors (``?type=ipv4|ipv6|dnsbl``) are present (the second
      ``[IPv4 | IPv6 | DNSBL]`` row rendered),
    And the requested type's sub-tab is the ACTIVE one (its ``<li>`` carries the
      ``active`` class ``display_top_tabs`` puts on the highlighted tab) while the
      other two are NOT active -- so the highlight tracks ``?type`` (a real branch,
      not an always-active tab),
    And the page's Feed Settings shows the ``<gtype>`` alias-name label and NEITHER of
      the other two types' labels -- proving the body lists only the active type
      (the type-scoped render, ADR-16 Phase 3).
    A per-tab screenshot is written for the visual record (the manual-smoke replacement).
    """
    page = browser_page
    _open(page, webui, f"{FEEDS_BASE}?type={gtype}")

    # The second sub-tab row exists exactly once -- the only nav carrying all three
    # type anchors (A4 makes the top "Feeds" tab + the breadcrumb also carry ?type, so
    # a bare href match is not unique; scope to the sub-tab <ul>).
    nav = _subtab_nav(page)
    expect(nav).to_have_count(1, timeout=JS_TIMEOUT_MS)
    for t in ("ipv4", "ipv6", "dnsbl"):
        expect(_subtab_anchor(nav, t)).to_have_count(1, timeout=JS_TIMEOUT_MS)

    # The requested type's sub-tab is ACTIVE; the other two are not. pfSense's
    # display_top_tabs puts the `active` class on the highlighted tab's <li> (the
    # anchor's parent). Assert via the ancestor <li>'s class -- the version-tolerant
    # handle (the <li> wraps the <a>) -- scoped to the sub-tab row so the A4 self-links
    # in the top bar/breadcrumb don't confuse the match.
    active_li = _subtab_anchor(nav, gtype).locator("xpath=ancestor::li[1]")
    expect(active_li).to_have_class(re.compile(r"\bactive\b"), timeout=JS_TIMEOUT_MS)
    for other in (t for t in ("ipv4", "ipv6", "dnsbl") if t != gtype):
        other_li = _subtab_anchor(nav, other).locator("xpath=ancestor::li[1]")
        expect(other_li).not_to_have_class(re.compile(r"\bactive\b"), timeout=JS_TIMEOUT_MS)

    # The body lists ONLY this type: its Feed Settings alias-name label is in the DOM
    # (the section is COLLAPSIBLE|SEC_CLOSED, so present-but-collapsed -> assert
    # PRESENCE, not visibility), and the other two types' labels are ABSENT.
    own_label = page.get_by_text(TYPE_LABELS[gtype], exact=False)
    assert own_label.count() >= 1, f"{gtype} tab missing its own '{TYPE_LABELS[gtype]}' label (type-scoped body)"
    for other, label in TYPE_LABELS.items():
        if other == gtype:
            continue
        assert page.get_by_text(label, exact=False).count() == 0, (
            f"{gtype} tab wrongly shows the {other} label '{label}' -- the body is not type-scoped"
        )

    _shot(page, screenshot_dir, f"feeds_subtab_{gtype}")
