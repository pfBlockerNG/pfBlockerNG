"""Check the catalogue instructions at desktop/mobile widths and the documented log route."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .test_browser_feeds import JS_TIMEOUT_MS, _open, _shot, expect

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser


@pytest.mark.parametrize("gtype", ["ipv4", "ipv6", "dnsbl"])
@pytest.mark.parametrize("width", [1280, 390], ids=["desktop", "mobile"])
def test_catalogue_instructions_remain_visible_and_wrap(
    browser_page: Page, webui: WebUI, screenshot_dir: Path, gtype: str, width: int
) -> None:
    """The import instructions form a visible list that fits its panel at either width."""
    browser_page.set_viewport_size({"width": width, "height": 900})
    _open(browser_page, webui, f"/pfblockerng/pfblockerng_feeds.php?type={gtype}")
    panel = browser_page.locator(".panel-body.bg-info")
    expect(panel).to_have_count(1)
    instructions = panel.locator("ul")
    expect(instructions).to_have_count(1)
    expect(instructions.locator(":scope > li").first).to_be_visible(timeout=JS_TIMEOUT_MS)
    layout = instructions.evaluate(
        "el => ({width: el.clientWidth, content: el.scrollWidth, items: [...el.children].map(child => child.tagName)})"
    )
    assert layout["items"] and set(layout["items"]) == {"LI"}, f"invalid instruction list: {layout}"
    assert layout["content"] <= layout["width"] + 1, f"instructions overflow at {width}px: {layout}"
    _shot(browser_page, screenshot_dir, f"help_catalogue_{gtype}_{width}")


def test_general_documented_package_log_route_is_reachable(browser_page: Page, webui: WebUI) -> None:
    """The core navigation exposes the package log destination named by General help."""
    _open(browser_page, webui, "/pfblockerng/pfblockerng_general.php")
    browser_page.get_by_role("link", name="Status", exact=True).first.click()
    browser_page.get_by_role("link", name="System Logs", exact=True).first.click()
    browser_page.get_by_role("link", name="Packages", exact=True).first.click()
    package_log = browser_page.get_by_role("link", name="pfBlockerNG", exact=True)
    expect(package_log).to_be_visible(timeout=JS_TIMEOUT_MS)
    package_log.click()
    expect(browser_page.locator("#usernamefld")).to_have_count(0)
    expect(browser_page.get_by_role("link", name="pfBlockerNG", exact=True)).to_be_visible()
