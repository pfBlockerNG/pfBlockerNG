"""Tier-B browser regression (issue #3517): the pfB-DNS page's accessible names and legible warnings.

Drives a headless Chromium on the live ADR-04 smoke VM against the pfB-DNS page
(``pfblockerng_dns.php``) and measures the live DOM, not the markup:

* the DoH and DoQ interface multi-selects resolve by role ``listbox`` under their visible
  "... Interface(s)" label, and stay operable through that name;
* each "Experimental." disclosure keeps WCAG 2.1 SC 1.4.3 text contrast (4.5:1) against the
  backdrop it paints on.

Scope is the controls and disclosures on this page only: no whole-page axe claim, since the
header breadcrumb and other shared framework markup are outside it. Measured in the box's
current theme (a fresh box is light). The screenshot and the JSON of measured values are
artifacts in ``screenshot_dir``, not asserted baselines.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from .test_browser_feeds import _contrast_ratio, _open, _shot

pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
INTERFACE_LABELS = ("DoH Interface(s)", "DoQ Interface(s)")
# The enable checkbox's, the DoH's and the DoQ's "Experimental." disclosure.
EXPERIMENTAL_DISCLOSURES = 3
WCAG_AA_TEXT_CONTRAST = 4.5

# The painted backdrop: the nearest ancestor with a non-transparent background, else the white canvas.
_BACKDROP_JS = """
(el) => {
  for (let node = el; node; node = node.parentElement) {
    const bg = getComputedStyle(node).backgroundColor;
    if (bg !== 'rgba(0, 0, 0, 0)') return bg;
  }
  return 'rgb(255, 255, 255)';
}
"""

_SELECTED_VALUES_JS = "el => [...el.selectedOptions].map(option => option.value)"


@pytest.mark.parametrize("label", INTERFACE_LABELS, ids=["doh", "doq"])
def test_interface_listbox_resolves_by_its_visible_label(browser_page: Page, webui: WebUI, label: str) -> None:
    """The interface multi-select's accessible name is its visible label."""
    page = browser_page
    _open(page, webui, DNS_PAGE)
    found = page.get_by_role("listbox", name=label, exact=True).count()
    assert found == 1, f"expected exactly one listbox named {label!r} on {DNS_PAGE}, got {found}"


@pytest.mark.parametrize("label", INTERFACE_LABELS, ids=["doh", "doq"])
def test_interface_listbox_selection_works_through_its_name(browser_page: Page, webui: WebUI, label: str) -> None:
    """Selecting an interface through the named listbox selects exactly that interface."""
    page = browser_page
    _open(page, webui, DNS_PAGE)
    listbox = page.get_by_role("listbox", name=label, exact=True)
    found = listbox.count()
    assert found == 1, f"expected exactly one listbox named {label!r} on {DNS_PAGE}, got {found}"
    values = listbox.locator("option").evaluate_all("options => options.map(option => option.value)")
    assert values, f"{label!r} lists no interfaces to select"
    target = values[0]
    before = listbox.evaluate(_SELECTED_VALUES_JS)
    assert target not in before, f"{label!r} already selects {target!r} before the test: {before}"
    listbox.select_option(target)
    after = listbox.evaluate(_SELECTED_VALUES_JS)
    assert after == [target], f"{label!r} selected {after}, expected [{target!r}]"


def test_experimental_disclosures_keep_text_contrast(browser_page: Page, webui: WebUI, screenshot_dir: Path) -> None:
    """Each "Experimental." disclosure meets 4.5:1 against the backdrop it actually paints on."""
    page = browser_page
    _open(page, webui, DNS_PAGE)
    disclosures = page.locator("strong", has_text="Experimental.")
    found = disclosures.count()
    assert found == EXPERIMENTAL_DISCLOSURES, (
        f"expected {EXPERIMENTAL_DISCLOSURES} 'Experimental.' disclosures on {DNS_PAGE}, got {found}"
    )
    measured = []
    for index in range(found):
        node = disclosures.nth(index)
        color = node.evaluate("el => getComputedStyle(el).color")
        backdrop = node.evaluate(_BACKDROP_JS)
        measured.append(
            {"disclosure": index + 1, "color": color, "backdrop": backdrop, "ratio": _contrast_ratio(color, backdrop)}
        )
    (screenshot_dir / "pfb_dns_experimental_contrast.json").write_text(json.dumps(measured, indent=2))
    _shot(page, screenshot_dir, "pfb_dns_experimental")
    for row in measured:
        assert row["ratio"] >= WCAG_AA_TEXT_CONTRAST, (
            f"'Experimental.' disclosure #{row['disclosure']} text {row['color']} on {row['backdrop']} is "
            f"{row['ratio']:.2f}:1, expected at least {WCAG_AA_TEXT_CONTRAST}:1"
        )
