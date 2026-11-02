"""Tier-B browser proof for the #2918 help-text layout: the restructured lists and the threat note.

Tier A (``test_help_reports_hooks.py``) proves the rendered markup. This file proves that, in a real
browser, the definition lists and the threat note are visible and do not push the page wider than
the viewport, at a normal and a narrow width.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

HOOKS_PAGE = "/pfblockerng/pfblockerng_hooks.php"
THREATS_PAGE = "/pfblockerng/pfblockerng_threats.php?host=192.0.2.10"
JS_TIMEOUT_MS = 10_000
WIDTHS = (1280, 390)


def _open(page: Page, webui: WebUI, path: str, width: int) -> None:
    """Size the viewport, load ``path`` with the injected session, and settle the DOM."""
    page.set_viewport_size({"width": width, "height": 844})
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _horizontal_overflow(page: Page) -> int:
    """Pixels the document is wider than its viewport; 0 when nothing spills sideways."""
    return int(
        page.evaluate("() => Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth)")
    )


@pytest.mark.parametrize("width", WIDTHS, ids=["normal", "narrow"])
def test_hooks_environment_lists_show_each_variable_without_overflow(
    browser_page: Page, webui: WebUI, width: int
) -> None:
    """The environment variables are visible as definition terms and the page stays within the viewport.

    Given the Hooks page at a normal or a narrow width,
    When it loads,
    Then the PFB_WHEN term and the PFB_TRIGGER choice list are visible,
    And the document does not scroll sideways.
    """
    _open(browser_page, webui, HOOKS_PAGE, width)

    expect(browser_page.locator("dl dt code", has_text="PFB_WHEN").first).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(browser_page.locator("dl dd ul li code", has_text="force-reload").first).to_be_visible(timeout=JS_TIMEOUT_MS)
    assert _horizontal_overflow(browser_page) == 0, f"Hooks page overflows sideways at {width}px"


@pytest.mark.parametrize("width", WIDTHS, ids=["normal", "narrow"])
def test_threats_note_is_visible_without_overflow(browser_page: Page, webui: WebUI, width: int) -> None:
    """The Note on the threat lookup is visible and the page stays within the viewport.

    Given a threat lookup at a normal or a narrow width,
    When it loads,
    Then the Note label on the threat lookup is visible,
    And the document does not scroll sideways.
    """
    _open(browser_page, webui, THREATS_PAGE, width)

    expect(browser_page.locator("p strong", has_text="Note:").first).to_be_visible(timeout=JS_TIMEOUT_MS)
    assert _horizontal_overflow(browser_page) == 0, f"threat lookup overflows sideways at {width}px"
