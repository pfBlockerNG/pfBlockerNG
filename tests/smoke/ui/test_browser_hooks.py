"""Tier-B browser test: the Update sub-tabs (Run | Hooks).

The browser half of the "Update Hooks moved under the Update tab" change: a headless
Chromium on the live ADR-04 smoke VM opens ``pfblockerng_update.php`` and
``pfblockerng_hooks.php`` (reusing the Phase-1 authenticated session — the injected
``PHPSESSID`` cookie, no second login) and asserts, per page:

* the SECOND ``display_top_tabs`` row ``[Run | Hooks]`` is present (both sub-tab
  anchors, pointing at the update and hooks pages), and
* the CURRENT page's sub-tab is the ACTIVE one (its ``<li>`` carries pfSense's
  ``active`` class — emitted by ``display_top_tabs`` for the highlighted tab) while
  the sibling sub-tab is NOT active — so the highlight tracks the page (a real branch,
  not an always-active tab).

A per-page full-page screenshot is written to the ``screenshot_dir`` artifact tree
(the visual record for review — an artifact, not an asserted baseline).

The Tier-A render oracle (``test_render_smoke.test_update_hooks_subtab_relocation``)
is the cheap/hermetic half — it pins the sub-tab anchors' presence and that the old
standalone "Update Hooks" top tab is gone. This file adds the active-state branch the
HTTP-body oracle cannot see. No ``src/`` change here.

DOM-FRAGILITY NOTE: ``display_top_tabs`` renders each tab row as a ``<ul class="nav
…">``; the page has TWO (the main top bar + this sub-tab row). The top bar links the
update page (its "Update" tab) but NOT the hooks page (that tab was removed), so the
sub-tab row is the ONLY ``<ul class="nav …">`` carrying BOTH the update-page anchor
AND the hooks-page anchor — we locate that row first (``_subtab_nav``) and scope the
presence/active assertions to it. The load-bearing, version-tolerant handles are the
anchor ``href`` and the ``active`` class on the highlighted ``<li>`` — not a brittle
DOM path.

NO fixed sleeps: every assertion uses Playwright auto-waiting / ``count()`` after
``networkidle``. Playwright is imported lazily via ``pytest.importorskip`` so
collecting this module without it installed does not hard-error.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The two pages the Update sub-tab row links (each renders the same [Run | Hooks] row).
UPDATE_PAGE = "/pfblockerng/pfblockerng_update.php"
HOOKS_PAGE = "/pfblockerng/pfblockerng_hooks.php"

# A short, explicit timeout (ms): the page renders server-side, so this is a flake
# ceiling for the post-load DOM, not a wait knob.
JS_TIMEOUT_MS = 10_000


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the (cookie-authenticated) page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form -- proving the injected session
    cookie authenticated the browser (no second login). Waits on ``networkidle`` so
    the page is fully rendered before any assertion.
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    # The login form carries #usernamefld; its absence proves we are authed.
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``.

    Value-redacts the Plus VM identity from the DOM first (ADR-24 ``mask_page_identity``);
    a strict no-op on a CE leg (empty redaction set), so CE shots are unchanged.
    """
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _subtab_nav(page: Page) -> Locator:
    """The SECOND ``display_top_tabs`` row -- the ``[Run | Hooks]`` sub-tab ``<ul>``.

    The main top bar carries an "Update" tab linking the update page but has NO hooks
    anchor (that top tab was removed by this change), so the sub-tab row is the only
    ``<ul class="nav …">`` that contains BOTH the update-page anchor and the hooks-page
    anchor -- filter on that. Version-tolerant (independent of nav-pills/nav-tabs).
    """
    nav = page.locator("ul.nav")
    nav = nav.filter(has=page.locator(f'a[href="{UPDATE_PAGE}"]'))
    return nav.filter(has=page.locator(f'a[href="{HOOKS_PAGE}"]'))


def _subtab_anchor(nav: Locator, href: str) -> Locator:
    """The sub-tab anchor for ``href`` WITHIN the sub-tab row ``nav`` (scoped, unique)."""
    return nav.locator(f'a[href="{href}"]')


@pytest.mark.parametrize(
    ("path", "active_href", "other_href", "name"),
    [
        (UPDATE_PAGE, UPDATE_PAGE, HOOKS_PAGE, "run"),
        (HOOKS_PAGE, HOOKS_PAGE, UPDATE_PAGE, "hooks"),
    ],
)
def test_update_subtab_active_tracks_page(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
    path: str,
    active_href: str,
    other_href: str,
    name: str,
) -> None:
    """The [Run | Hooks] sub-tab row renders and highlights the sub-tab of the open page.

    Scenario (one parametrization per page -- BOTH sub-tabs are exercised as the active
    one, so this is full branch coverage of the active-state, not just one side):

    Given the Update Run page (``pfblockerng_update.php``) OR the Hooks page
      (``pfblockerng_hooks.php``) opened,
    Then the second ``[Run | Hooks]`` sub-tab row is present exactly once, carrying both
      the Run (update-page) and Hooks (hooks-page) anchors,
    And the OPEN page's own sub-tab is the ACTIVE one (its ``<li>`` carries the ``active``
      class ``display_top_tabs`` puts on the highlighted tab) while the SIBLING sub-tab is
      NOT active -- so the highlight tracks the page (a real branch: Run is active on the
      update page and inactive on the hooks page, and vice-versa).
    A per-page screenshot is written for the visual record.
    """
    page = browser_page
    _open(page, webui, path)

    # The sub-tab row exists exactly once -- the only nav carrying BOTH anchors.
    nav = _subtab_nav(page)
    expect(nav).to_have_count(1, timeout=JS_TIMEOUT_MS)
    expect(_subtab_anchor(nav, UPDATE_PAGE)).to_have_count(1, timeout=JS_TIMEOUT_MS)
    expect(_subtab_anchor(nav, HOOKS_PAGE)).to_have_count(1, timeout=JS_TIMEOUT_MS)

    # The open page's sub-tab is ACTIVE; the sibling is not. pfSense's display_top_tabs
    # puts the `active` class on the highlighted tab's <li> (the anchor's parent) -- the
    # version-tolerant handle. Scope to the sub-tab row so the top bar's own "Update" tab
    # (also linking the update page) cannot confuse the match.
    active_li = _subtab_anchor(nav, active_href).locator("xpath=ancestor::li[1]")
    expect(active_li).to_have_class(re.compile(r"\bactive\b"), timeout=JS_TIMEOUT_MS)
    other_li = _subtab_anchor(nav, other_href).locator("xpath=ancestor::li[1]")
    expect(other_li).not_to_have_class(re.compile(r"\bactive\b"), timeout=JS_TIMEOUT_MS)

    _shot(page, screenshot_dir, f"update_subtab_{name}")
