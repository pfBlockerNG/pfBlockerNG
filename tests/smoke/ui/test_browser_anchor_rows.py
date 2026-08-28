"""Tier-B browser tests (issue #1881): page anchors stop rendering empty separator rows.

Three page anchors were each their own empty ``Form_StaticText`` row -- ``#Whitelist``
(DNSBL settings), ``#Suppression`` (IP settings), ``#endofpage`` (Logs). Every
``.form-group`` carries ``border-bottom: 1px solid`` from the pfSense theme, so each drew
a horizontal rule with nothing above it. The issue's original "all three are dead, delete
them" premise was falsified on the issue thread: the dashboard widget links
``#Suppression``/``#Whitelist`` dynamically, and ``#endofpage`` is the Logs page's own
auto-scroll target. The fix relocates instead of deleting: the widget now links the target
sections' own ids, and ``#endofpage`` renders outside the form.

This is rendered-geometry behaviour (testing.md mandate 4): a source pin proves the rows'
markup is gone, but only a browser proves no empty bordered row actually renders and the
relocated scroll target still has a box to scroll to.

Red/green split: the empty-row scans and the endofpage-outside-form/scroll tests are the
red-first proof (red on devel, where the anchor rows still render). The section-id
existence tests are green-by-design -- those ids predate this change; they pin the
contract that the widget's retargeted hrefs (pinned hermetically in
``AnchorRowRelocationWiringTest``) resolve to real elements, so either side regressing
turns one of the two suites red.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .test_browser_custom_list_layout import DESKTOP, JS_TIMEOUT_MS, _open, _shot

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
IP_PAGE = "/pfblockerng/pfblockerng_ip.php"
LOG_PAGE = "/pfblockerng/pfblockerng_log.php"

# The empty-row scan from test_browser_custom_list_layout, widened to the whole page:
# the anchor rows sat at the END of the section PRECEDING the one they named, so a scan
# scoped to the named section would never have seen them.
_EMPTY_ROW_SCAN = """
() => Array.from(document.querySelectorAll('form .form-group'))
  .map((row) => {
    const label = row.querySelector('label.control-label');
    const labelText = (label ? label.textContent : '').trim();
    const control = row.querySelector('textarea, input, select, button, a');
    const bodyText = Array.from(row.children)
      .filter((child) => child !== label)
      .map((child) => (child.textContent || '').trim())
      .join('');
    return { labelText, hasControl: Boolean(control), bodyText, html: row.outerHTML.slice(0, 160) };
  })
  .filter((row) => !row.labelText && !row.hasControl && !row.bodyText)
"""


@pytest.mark.parametrize(
    ("path", "name"),
    [(DNSBL_PAGE, "dnsbl"), (IP_PAGE, "ip"), (LOG_PAGE, "log")],
    ids=["dnsbl", "ip", "log"],
)
def test_page_renders_no_empty_separator_rows(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
    path: str,
    name: str,
) -> None:
    """No ``.form-group`` on the page is empty -- nothing draws a stray separator.

    Whole-page rather than per-section, so the assertion also keeps holding if a future
    anchor row appears anywhere else on these pages.
    """
    page = browser_page
    page.set_viewport_size(DESKTOP)
    _open(page, webui, path)
    _shot(page, screenshot_dir, f"anchor_rows_{name}")

    empty_rows = page.evaluate(_EMPTY_ROW_SCAN)
    assert empty_rows == [], (
        f"{path} renders form rows with no label, no control and no text; each draws the "
        "theme's bottom border as a stray separator:\n" + "\n".join(f"  {row['html']}" for row in empty_rows)
    )


def test_log_status_row_has_visible_initial_content(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The Logs status row has visible content before a file is selected."""
    page = browser_page
    page.set_viewport_size(DESKTOP)
    _open(page, webui, LOG_PAGE)
    _shot(page, screenshot_dir, "anchor_rows_log_initial_status")

    status = page.evaluate(
        """
        () => {
          const el = document.getElementById('fileStatus');
          if (!el) return { exists: false, visible: false, text: '' };
          return {
            exists: true,
            visible: el.getClientRects().length > 0,
            text: (el.textContent || '').trim(),
          };
        }
        """
    )
    assert status["exists"], "the Logs page has no #fileStatus target"
    assert status["visible"] and status["text"], (
        "the initial #fileStatus is hidden or empty, leaving its bordered .form-group "
        f"as a separator-only row: {status!r}"
    )


@pytest.mark.parametrize(
    ("path", "section_id"),
    [(DNSBL_PAGE, "DNSBL_Whitelist_customlist"), (IP_PAGE, "IPv4_Suppression_customlist")],
    ids=["dnsbl-whitelist", "ip-v4suppression"],
)
def test_widget_link_target_section_id_exists(
    browser_page: Page,
    webui: WebUI,
    path: str,
    section_id: str,
) -> None:
    """The section id the dashboard widget now links to resolves to a real element.

    Green-by-design (the ids predate this change) -- this is the browser half of the
    widget-retarget contract; the widget's href side is pinned in
    ``AnchorRowRelocationWiringTest``.
    """
    page = browser_page
    page.set_viewport_size(DESKTOP)
    _open(page, webui, path)

    target = page.locator(f"#{section_id}")
    expect(target).to_be_attached(timeout=JS_TIMEOUT_MS)
    count = target.count()
    assert count == 1, f"{path}: expected exactly one #{section_id} element for the widget link to land on; got {count}"


def test_log_endofpage_target_lives_outside_the_form_and_scrolls(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """``#endofpage`` survives outside any ``.form-group`` and is still scrollable-to.

    Before-state first: the element exists. Then placement (no ``.form-group`` ancestor --
    inside one it IS the stray-separator row), then behaviour: ``scrollIntoView()`` on it
    moves the viewport, proving the relocated div still has a box the page's own
    auto-scroll JS can land on (a removed or display-none target would no-op).
    """
    page = browser_page
    page.set_viewport_size(DESKTOP)
    _open(page, webui, LOG_PAGE)

    in_form_group = page.evaluate(
        """
        () => {
          const el = document.getElementById('endofpage');
          if (!el) return 'MISSING';
          return el.closest('.form-group') !== null;
        }
        """
    )
    assert in_form_group != "MISSING", "the #endofpage scroll target is gone from the Logs page"
    assert in_form_group is False, "#endofpage still renders inside a .form-group -- that row is the stray separator"

    scrolled = page.evaluate(
        """
        () => {
          window.scrollTo(0, 0);
          document.getElementById('endofpage').scrollIntoView();
          return window.scrollY;
        }
        """
    )
    assert scrolled > 0, (
        f"scrollIntoView() on #endofpage left the viewport at scrollY={scrolled} -- "
        "the auto-scroll target has no box to scroll to"
    )
