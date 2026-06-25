"""Tier-A (ui_render) + Tier-B (ui_browser) tests for the pfBlockerNG title-bar
syslog shortcut icon.

Every pfBlockerNG page sets ``$shortcut_section = 'pfblockerng'`` before including
``head.inc``.  ``head.inc`` reads ``$shortcuts['pfblockerng']['log']`` from
``shortcuts/pkg_pfblockerng.inc`` and renders a log-link anchor whose ``href``
contains ``status_logs_packages.php?pkg=``.  These tests pin that contract.

Tier-A (``ui_render``) -- hermetic HTTP GET only:
  ``test_shortcut_log_link_rendered`` — GET the General page and assert the rendered
  body contains ``status_logs_packages.php?pkg=``.  On pre-change code (no shortcut
  file, no ``$shortcut_section``) that substring is absent, so this is a real
  fail-before / pass-after discriminator.

Tier-B (``ui_browser``) -- Playwright DOM inspection:
  ``test_shortcut_log_anchor_in_dom`` — load the General page in the authenticated
  browser and assert the title-bar log-shortcut anchor is present with an ``href``
  containing ``status_logs_packages.php?pkg=``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from .webui import WebUI

# The General page is the lightest pfBlockerNG page -- always hermetic, no external
# data needed, good witness for the shortcut chrome that appears on every page.
_GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"

# The substring that head.inc renders when $shortcuts['pfblockerng']['log'] is set.
# Present in the href of the log-shortcut anchor ("<a href='...' ...>").
_SHORTCUT_NEEDLE = "status_logs_packages.php?pkg="


# ---------------------------------------------------------------------------
# Tier-A: ui_render
# ---------------------------------------------------------------------------


@pytest.mark.ui_render
def test_shortcut_log_link_rendered(webui: WebUI) -> None:
    """The General page body contains the rendered syslog shortcut link.

    Scenario: pfBlockerNG title-bar shortcut icon links to the package syslog.
      Background: pfBlockerNG deployed; shortcuts/pkg_pfblockerng.inc installed;
        every pfBlockerNG page sets $shortcut_section = 'pfblockerng'.

      Given the authenticated webConfigurator session,

      When GET /pfblockerng/pfblockerng_general.php,

      Then the response body contains the rendered log-shortcut href substring
        ``status_logs_packages.php?pkg=`` — proving head.inc rendered the anchor
        from $shortcuts['pfblockerng']['log'] (absent on pre-change code where
        neither the shortcut file nor $shortcut_section existed).

    Fail-before / pass-after: on origin/devel (before this change) the shortcut
    file does not exist and no page sets $shortcut_section, so the substring is
    absent and this assertion FAILS.  After the change both are present, the
    assertion PASSES.
    """
    resp = webui.get(_GENERAL_PAGE)
    assert resp.status_code == 200, f"GET {_GENERAL_PAGE} -> HTTP {resp.status_code} (expected 200)"
    assert _SHORTCUT_NEEDLE in resp.text, (
        f"Syslog shortcut href {_SHORTCUT_NEEDLE!r} not found in {_GENERAL_PAGE} body "
        f"-- expected head.inc to render the log-shortcut anchor from "
        f"$shortcuts['pfblockerng']['log'] (pkg_pfblockerng.inc + $shortcut_section)"
    )


# ---------------------------------------------------------------------------
# Tier-B: ui_browser
# ---------------------------------------------------------------------------
# NOTE: the playwright import is scoped to the Tier-B test (not module-level) so a
# module-level importorskip does NOT skip the Tier-A ui_render test above, which is
# hermetic HTTP-only and must run in the render tier (no playwright installed there).

if TYPE_CHECKING:
    from playwright.sync_api import Page

# JS-driven DOM settles synchronously; this is a flake ceiling, not a wait knob.
JS_TIMEOUT_MS = 10_000


@pytest.mark.ui_browser
def test_shortcut_log_anchor_in_dom(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """The title-bar log-shortcut anchor is present in the live DOM with the correct href.

    Scenario: pfBlockerNG title-bar shortcut icon links to the package syslog (Tier B).
      Background: pfBlockerNG deployed with the shortcut file + $shortcut_section wired.

      Given the General page is loaded in the authenticated browser,

      When the DOM is inspected for the pfSense shortcuts log-link anchor,

      Then exactly one anchor whose href contains ``status_logs_packages.php?pkg=``
        is attached to the document -- proving the title-bar shortcut icon rendered
        the correct log link.

    Fail-before / pass-after: without $shortcut_section + the shortcut file, head.inc
    emits no such anchor, so the ``count() > 0`` assertion FAILS on pre-change code
    and PASSES after the change.
    """
    # The browser_page fixture already importorskips playwright, so it is present here.
    expect = pytest.importorskip("playwright.sync_api").expect

    page = browser_page
    page.goto(
        webui.url(_GENERAL_PAGE),
        wait_until="domcontentloaded",
        timeout=JS_TIMEOUT_MS * 3,
    )
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, (
        f"GET {_GENERAL_PAGE} showed the login form -- cookie not authenticated"
    )

    # head.inc renders the log-shortcut as an <a href="...status_logs_packages.php?pkg=...">
    # anchor in the title-bar shortcuts area.  Assert it is present in the live DOM.
    log_anchor = page.locator(f'a[href*="{_SHORTCUT_NEEDLE}"]')
    assert log_anchor.count() > 0, (
        f"No anchor with href containing {_SHORTCUT_NEEDLE!r} found in the DOM "
        f"of {_GENERAL_PAGE} -- title-bar syslog shortcut not rendered"
    )
    expect(log_anchor.first).to_be_attached(timeout=JS_TIMEOUT_MS)
