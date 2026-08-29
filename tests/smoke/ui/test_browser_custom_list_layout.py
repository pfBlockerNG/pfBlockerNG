"""Tier-B browser tests (issues #1872, #1873): the IP group edit Custom List section.

Three defects in one collapsible section on ``pfblockerng_category_edit.php``,
all of them observable only as rendered geometry or rendered text -- which is
why they live in this tier (testing.md mandate 4: visual/structural changes to
a ``www/`` surface).

* **#1872** -- the section heading reads ``IPv4 Custom_List``. ``Custom_List``
  with an underscore is a code-level identifier; every other reference on the
  page, including the section's own help text, says "Custom List".

* **#1873, narrow field** -- the text area does not fill the column it sits
  in. It carries the Bootstrap grid class ``col-sm-12`` but no width of its
  own, so at desktop widths the class's 15px horizontal padding leaves it 30px
  short, and BELOW Bootstrap's ``sm`` breakpoint the class stops applying
  altogether and the control falls back to its default ~20-column width --
  about half the panel on a phone. The DNSBL Regex List field escapes this only
  because it carries an inline ``width: 100%``.

* **#1873, stray separator** -- the ``#Custom`` page anchor is added as its own
  ``Form_StaticText`` row, so it renders as an empty ``.form-group``. Every
  ``.form-group`` carries ``border-bottom: 1px solid`` from the pfSense theme,
  so that empty row draws a horizontal rule with nothing above it.

Both viewports are asserted for the width, because the two failure modes have
different causes and a desktop-only test would miss the one the reporter
actually hit.

NOT in scope, deliberately: below the ``sm`` breakpoint the label column and
the input column stack, so the "Enable Domain/AS" checkbox sits under its
label. That is Bootstrap's ``col-sm-*`` behaviour and it applies to every
field on every pfSense page, not to this section -- measured at 390px, the
label lands at y=2231 and the checkbox at y=2267. Special-casing one checkbox
against the framework's own responsive grid would be a local fix to a global
convention.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Locator, Page, ViewportSize

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

IP_EDITOR = "/pfblockerng/pfblockerng_category_edit.php?type=ipv4"

JS_TIMEOUT_MS = 10_000

# A phone: below Bootstrap's 768px `sm` breakpoint, where col-sm-* stops
# applying and a control with no width of its own collapses to its default size.
PHONE: ViewportSize = {"width": 390, "height": 844}
DESKTOP: ViewportSize = {"width": 1600, "height": 1000}

# The text area is allowed to sit inside its column's padding, but not to give
# up a meaningful share of it. 32px covers the theme's own box spacing on both
# viewports; the observed defect was 30px short on desktop and 186px on phone.
MAX_WIDTH_SHORTFALL_PX = 32


def _open(page: Page, webui: WebUI, path: str) -> None:
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _open_custom_list(page: Page) -> None:
    """Expand the Custom List section (COLLAPSIBLE|SEC_CLOSED) via its toggle anchor."""
    body = page.locator("#IPv4customlist_panel-body")
    expect(body).to_be_attached(timeout=JS_TIMEOUT_MS)
    if "in" not in (body.get_attribute("class") or ""):
        page.locator('a[data-toggle="collapse"][href="#IPv4customlist_panel-body"]').click()
    expect(body).to_be_visible(timeout=JS_TIMEOUT_MS)


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _custom_list_control(page: Page) -> Locator:
    """Return the rendered editor, falling back to the raw textarea."""
    cm_editor = page.locator("#IPv4customlist_panel-body .cm-editor")
    return cm_editor.first if cm_editor.count() else page.locator("#custom")


def test_section_heading_says_custom_list_not_the_internal_identifier(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """The heading reads "IPv4 Custom List" -- no underscore, no code identifier."""
    page = browser_page
    page.set_viewport_size(DESKTOP)
    _open(page, webui, IP_EDITOR)

    # Located via the panel that OWNS the known body id rather than by guessing a
    # heading id: Form/Section.class.php only guarantees the "<id>_panel-body"
    # element, and a heading selector that matches nothing would fail this test for
    # the wrong reason -- looking like the defect while proving nothing about it.
    heading = page.locator("div.panel", has=page.locator("#IPv4customlist_panel-body")).locator(".panel-title")
    expect(heading).to_be_attached(timeout=JS_TIMEOUT_MS)
    text = (heading.text_content() or "").strip()

    assert "Custom_List" not in text, f"the heading still shows the internal identifier: {text!r}"
    assert "Custom List" in text, f"expected the heading to read 'IPv4 Custom List'; got {text!r}"


@pytest.mark.parametrize(("label", "viewport"), [("desktop", DESKTOP), ("phone", PHONE)])
def test_custom_list_textarea_fills_its_column(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
    label: str,
    viewport: ViewportSize,
) -> None:
    """The text area spans its column at both viewports.

    Parametrized rather than duplicated because the two viewports fail for
    different reasons -- padding at desktop, a dropped grid class at phone --
    and fixing only one of them is a partial fix that a single-viewport test
    would sign off on.
    """
    page = browser_page
    page.set_viewport_size(viewport)
    _open(page, webui, IP_EDITOR)
    _open_custom_list(page)

    control = _custom_list_control(page)
    expect(control).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, f"custom_list_width_{label}")

    measured = control.evaluate(
        """
        (control) => {
          const column = control.closest('div[class*="col-sm-"]');
          return {
            control: Math.round(control.getBoundingClientRect().width),
            column: Math.round(column.getBoundingClientRect().width),
          };
        }
        """
    )
    shortfall = measured["column"] - measured["control"]

    assert shortfall <= MAX_WIDTH_SHORTFALL_PX, (
        f"[{label} {viewport['width']}px] the Custom List editing control is {measured['control']}px "
        f"inside a {measured['column']}px column -- {shortfall}px short, over the "
        f"{MAX_WIDTH_SHORTFALL_PX}px allowance"
    )


def test_custom_list_section_has_no_empty_separator_row(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """No ``.form-group`` in the section is empty.

    An empty row is invisible except for the bottom border the theme puts on
    every ``.form-group``, which is what draws the stray rule the report
    describes. Asserted as "no row is empty" rather than "the row count is N",
    so it keeps holding when the section legitimately gains or loses a field.
    """
    page = browser_page
    page.set_viewport_size(DESKTOP)
    _open(page, webui, IP_EDITOR)
    _open_custom_list(page)

    empty_rows = page.evaluate(
        """
        () => {
          const panel = document.querySelector('#IPv4customlist_panel-body');
          return Array.from(panel.querySelectorAll('.form-group'))
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
            .filter((row) => !row.labelText && !row.hasControl && !row.bodyText);
        }
        """
    )

    assert empty_rows == [], (
        "the Custom List section renders form rows with no label, no control and no text; "
        "each draws the theme's bottom border as a stray separator:\n"
        + "\n".join(f"  {row['html']}" for row in empty_rows)
    )
