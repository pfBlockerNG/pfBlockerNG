"""Tier-B: the Support block reflows from side-by-side to stacked.

The General page replaced a float pair (75%/25%) with Bootstrap
``col-sm-9`` / ``col-sm-3``. That stacking is only observable as rendered
geometry (testing.md principle 4), so it lives here rather than in the
Tier-A string markers.

Issue #2863 gave the setup wizard the same construction; both copies are
exercised here, because the wizard drifted for months while only the General
page was pinned.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page, ViewportSize

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
# The wizard's welcome step is the first <step> in pfblockerng_wizard.xml -> stepid=0.
WIZARD_WELCOME = "/wizard.php?xml=pfblockerng_wizard.xml&stepid=0"

JS_TIMEOUT_MS = 10_000

# Below Bootstrap 3's 768px `sm` breakpoint, col-sm-* become full-width and stack.
PHONE: ViewportSize = {"width": 390, "height": 844}
DESKTOP: ViewportSize = {"width": 1600, "height": 1000}


def _open(page: Page, webui: WebUI, path: str) -> None:
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _support_columns(page: Page, title: str = "Support") -> tuple:
    panel = page.locator("div.panel", has=page.locator(".panel-title", has_text=title))
    expect(panel).to_be_attached(timeout=JS_TIMEOUT_MS)
    row = panel.locator("div.row", has=page.locator("div.col-sm-3"))
    expect(row).to_be_attached(timeout=JS_TIMEOUT_MS)
    text_col = row.locator("div.col-sm-9")
    logo_col = row.locator("div.col-sm-3")
    expect(text_col).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(logo_col).to_be_attached(timeout=JS_TIMEOUT_MS)
    text_col.scroll_into_view_if_needed()
    logo_col.scroll_into_view_if_needed()
    text_box = text_col.bounding_box()
    logo_box = logo_col.bounding_box()
    assert text_box is not None, "Support text column has no bounding box"
    assert logo_box is not None, "Support logo column has no bounding box"
    return text_box, logo_box


def test_support_block_sits_side_by_side_at_desktop(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    page = browser_page
    page.set_viewport_size(DESKTOP)
    _open(page, webui, GENERAL_PAGE)
    text_box, logo_box = _support_columns(page)
    _shot(page, screenshot_dir, "support-desktop")

    assert abs(text_box["y"] - logo_box["y"]) < 40, (
        f"desktop Support columns should share a row; text={text_box!r} logo={logo_box!r}"
    )
    assert logo_box["x"] > text_box["x"] + 50, (
        f"desktop logo column should sit to the right of the text; text={text_box!r} logo={logo_box!r}"
    )


def test_support_block_stacks_at_narrow_viewport(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    page = browser_page
    page.set_viewport_size(PHONE)
    _open(page, webui, GENERAL_PAGE)
    text_box, logo_box = _support_columns(page)
    _shot(page, screenshot_dir, "support-phone")

    assert logo_box["y"] >= text_box["y"] + text_box["height"] - 8, (
        f"phone Support columns should stack (logo below text); text={text_box!r} logo={logo_box!r}"
    )
    assert abs(text_box["x"] - logo_box["x"]) < 40, (
        f"phone Support columns should share a left edge when stacked; text={text_box!r} logo={logo_box!r}"
    )


def test_wizard_support_block_sits_side_by_side_at_desktop(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Issue #2863: the wizard's logo column sits beside the text at desktop width."""
    page = browser_page
    page.set_viewport_size(DESKTOP)
    _open(page, webui, WIZARD_WELCOME)
    text_box, logo_box = _support_columns(page, title="pfBlockerNG Setup")
    _shot(page, screenshot_dir, "wizard-support-desktop")

    assert abs(text_box["y"] - logo_box["y"]) < 40, (
        f"desktop wizard columns should share a row; text={text_box!r} logo={logo_box!r}"
    )
    assert logo_box["x"] > text_box["x"] + 50, (
        f"desktop wizard logo should sit right of the text; text={text_box!r} logo={logo_box!r}"
    )


def test_wizard_support_block_stacks_at_narrow_viewport(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Issue #2863: the wizard logo stacks instead of overflowing a phone viewport.

    This is the defect the issue reported. A fixed 25% float column holding a 180pt
    SVG cannot stack, so it spilled past its column at any narrow width -- observable
    only as geometry, which is why a Tier-A string marker could not have caught it.
    """
    page = browser_page
    page.set_viewport_size(PHONE)
    _open(page, webui, WIZARD_WELCOME)
    text_box, logo_box = _support_columns(page, title="pfBlockerNG Setup")
    _shot(page, screenshot_dir, "wizard-support-phone")

    assert logo_box["y"] >= text_box["y"] + text_box["height"] - 8, (
        f"phone wizard columns should stack (logo below text); text={text_box!r} logo={logo_box!r}"
    )
    assert logo_box["x"] + logo_box["width"] <= PHONE["width"] + 1, (
        f"phone wizard logo must not overflow the viewport; logo={logo_box!r} viewport={PHONE!r}"
    )
