"""Threats-page title, breadcrumb, and request-short-circuit coverage."""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .conftest import mask_page_identity
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .webui import LOGIN_MARKERS

if TYPE_CHECKING:
    from collections.abc import Iterator

    from playwright.sync_api import Page

    from ..conftest import SmokeVM
    from .webui import WebUI

THREATS_PAGE = "/pfblockerng/pfblockerng_threats.php"
VALID_LOOKUPS: tuple[tuple[str, str, str], ...] = (
    ("host", f"{THREATS_PAGE}?host=203.0.113.5", "Threat Source IP Lookup"),
    ("domain", f"{THREATS_PAGE}?domain={{domain}}", "Threat Domain Lookup"),
    ("port", f"{THREATS_PAGE}?port=8443", "Threat Port Lookup"),
)
REJECTED_LOOKUPS: tuple[tuple[str, str, str], ...] = (
    ("invalid_host", "host=not-an-ip", "Invalid IP Address, cannot proceed!"),
    ("invalid_domain", "domain=not%20a%20domain", "Invalid Domain name, cannot proceed!"),
    ("invalid_port", "port=99999", "Invalid Port cannot proceed!"),
    ("missing", "", "No Requests found, cannot proceed!"),
)
LOOKUP_TITLES = tuple(row[2] for row in VALID_LOOKUPS)


def _lookup_path(template: str) -> str:
    return template.format(domain=helpers.unique_domain())


def _expected_breadcrumb(path: str, lookup_title: str) -> str:
    return (
        '<ol class="breadcrumb"><li>Firewall</li>'
        '<li><a href="/pfblockerng/pfblockerng_general.php">pfBlockerNG</a></li>'
        '<li><a href="/pfblockerng/pfblockerng_alerts.php">Alerts</a></li>'
        f'<li><a href="{html.escape(path, quote=True)}">{lookup_title}</a></li></ol>'
    )


@pytest.fixture(scope="module")
def threats_php_error_log_guard(smoke_vm: SmokeVM, webui: WebUI) -> Iterator[PhpErrorLogGuard]:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    yield guard
    guard.assert_no_growth()


@pytest.mark.ui_render
@pytest.mark.parametrize(
    ("name", "path_template", "lookup_title"), VALID_LOOKUPS, ids=[row[0] for row in VALID_LOOKUPS]
)
def test_threats_http_title_and_breadcrumb(
    name: str,
    path_template: str,
    lookup_title: str,
    webui: WebUI,
    threats_php_error_log_guard: PhpErrorLogGuard,
) -> None:
    """Each lookup view emits the authenticated document head and exact four-level breadcrumb."""
    path = _lookup_path(path_template)
    response = webui.get(path)
    result = evaluate_render(path, response.status_code, response.text, (lookup_title,))
    assert result.ok, f"{name}: render oracle failed: {result.detail}"
    assert response.text.lstrip().startswith("<!DOCTYPE html>"), f"{name}: output preceded the document header"

    title_match = re.search(r"<title>(.*?)</title>", response.text, re.DOTALL | re.IGNORECASE)
    assert title_match is not None, f"{name}: response has no browser title"
    title = html.unescape(title_match.group(1)).strip()
    expected_page_title = f"Firewall: pfBlockerNG: Alerts: {lookup_title}"
    assert expected_page_title in title, f"{name}: expected {expected_page_title!r} in title, got {title!r}"

    breadcrumb = _expected_breadcrumb(path, lookup_title)
    assert breadcrumb in response.text, f"{name}: expected ordered breadcrumb {breadcrumb!r}"


@pytest.mark.ui_render
@pytest.mark.parametrize(("name", "query", "message"), REJECTED_LOOKUPS, ids=[row[0] for row in REJECTED_LOOKUPS])
def test_threats_http_rejects_before_page_header(
    name: str,
    query: str,
    message: str,
    webui: WebUI,
    threats_php_error_log_guard: PhpErrorLogGuard,
) -> None:
    """Invalid and missing requests keep their message and exit before lookup chrome."""
    path = f"{THREATS_PAGE}?{query}" if query else THREATS_PAGE
    response = webui.get(path)
    result = evaluate_render(path, response.status_code, response.text, (message,))
    assert result.ok, f"{name}: reject render oracle failed: {result.detail}"
    assert not any(marker in response.text for marker in LOGIN_MARKERS), f"{name}: authentication regressed"
    assert "<title>" not in response.text, f"{name}: rejected request unexpectedly included the page head"
    assert '<ol class="breadcrumb">' not in response.text, f"{name}: rejected request rendered a breadcrumb"
    present = [title for title in LOOKUP_TITLES if title in response.text]
    assert not present, f"{name}: rejected request rendered lookup titles {present}"


@pytest.mark.ui_browser
@pytest.mark.parametrize(
    ("name", "path_template", "lookup_title"), VALID_LOOKUPS, ids=[row[0] for row in VALID_LOOKUPS]
)
def test_threats_browser_title_and_breadcrumb(
    name: str,
    path_template: str,
    lookup_title: str,
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Chromium shows the meaningful tab title and linked breadcrumb in DOM order."""
    sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
    path = _lookup_path(path_template)
    page = browser_page
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=30_000)
    page.wait_for_load_state("networkidle", timeout=30_000)
    assert page.locator("#usernamefld").count() == 0, f"{name}: authenticated browser showed the login form"
    sync_api.expect(page).to_have_title(re.compile(re.escape(lookup_title)), timeout=10_000)

    breadcrumb = page.locator("ol.breadcrumb")
    sync_api.expect(breadcrumb).to_have_count(1)
    crumbs = breadcrumb.locator(":scope > li")
    sync_api.expect(crumbs).to_have_count(4)
    assert [text.strip() for text in crumbs.all_inner_texts()] == ["Firewall", "pfBlockerNG", "Alerts", lookup_title]
    assert crumbs.nth(0).locator("a").count() == 0
    assert crumbs.nth(1).locator("a").get_attribute("href") == "/pfblockerng/pfblockerng_general.php"
    assert crumbs.nth(2).locator("a").get_attribute("href") == "/pfblockerng/pfblockerng_alerts.php"
    assert crumbs.nth(3).locator("a").get_attribute("href") == path

    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"threats_header_{name}.png"), full_page=True)
