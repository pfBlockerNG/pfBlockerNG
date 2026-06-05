"""Tier-B browser test (ADR-14) for the ADR-11 General-settings "Aggregated Aliases"
multi-select.

Drives a headless Chromium on the live ADR-04 smoke VM (the ``browser_page``
fixture's cookie-authed context — no second login) to exercise the ``pfb_agg_types``
multi-select that ADR-11 adds to ``pfblockerng_general.php`` (Form_Select 'multiple',
options Deny/Permit/Match/Native). It is a real before->after test AND the source of
the human-review screenshots of the new field (empty default vs a populated selection).

The select + its options are taken from the page's own markup
(``Form_Select('pfb_agg_types', 'Aggregated Aliases', …, $options_pfb_agg_types, TRUE)``,
``$options_pfb_agg_types = ['Deny'=>'Deny','Permit'=>'Permit','Match'=>'Match',
'Native'=>'Native']``) — no ``src/`` change. Selecting options is a pure client-side DOM
change (no Save is clicked), so it never persists.

Screenshots (full page + the field's own form-group) are written to ``screenshot_dir``
for human review (artifacts, not asserted baselines); the assertions are the real gate.
Playwright is imported lazily via ``pytest.importorskip`` so collecting this module
without it installed does not hard-error.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
# The ADR-11 multi-select's four option VALUES (the action-type labels the GUI action
# dropdown / Logs page already use). Order is the canonical type order.
AGG_OPTIONS = ("Deny", "Permit", "Match", "Native")
# Locate the select by its LABEL, not an id: pfSense Form_Select(multiple) renders
# name="pfb_agg_types[]" and the id carries the brackets, so a bare ``#pfb_agg_types``
# CSS id selector does not match. The form-group carrying the "Aggregated Aliases"
# label is unambiguous and id-rendering-agnostic; the <select> within it is the field.
AGG_LABEL = "Aggregated Aliases"

# JS-driven DOM settles synchronously; this is a flake ceiling, not a wait knob.
JS_TIMEOUT_MS = 10_000


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the cookie-authenticated page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form (proves the injected session
    cookie authenticated the browser — no second login).
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``."""
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _shot_field(locator: Locator, screenshot_dir: Path, name: str) -> None:
    """Write a screenshot of just the field's form-group ``<screenshot_dir>/<name>.png``.

    Scrolls the element into view (Playwright auto-scroll) and captures only its box —
    a focused image of the "Aggregated Aliases" row (label + multi-select + help text).
    """
    locator.scroll_into_view_if_needed(timeout=JS_TIMEOUT_MS)
    locator.screenshot(path=str(screenshot_dir / f"{name}.png"))


def _selected_values(select: Locator) -> list[str]:
    """The currently-selected option values of the multi-select, in DOM order."""
    return select.evaluate("el => Array.from(el.selectedOptions).map(o => o.value)")


def test_general_aggregate_types_multiselect(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The ADR-11 "Aggregated Aliases" multi-select renders empty and accepts a selection.

    Before->after (CLAUDE.md): on load the ``pfb_agg_types`` multi-select is a real
    ``<select multiple>`` carrying exactly the four action-type options
    (Deny/Permit/Match/Native) with NONE selected (the opt-in default — no aggregate is
    built). Selecting Deny + Permit makes exactly those two the selected options; the
    before-state (nothing selected) proves the selection CAUSED the change. No Save is
    clicked, so nothing persists — this exercises the rendered control + produces the
    field screenshots (empty vs populated).
    """
    page = browser_page
    _open(page, webui, GENERAL_PAGE)
    # Confirm we are on the real General page, not the first-run wizard (the webui
    # fixture dismisses it; assert it here so a regression points at the wizard, not
    # at the field). The wizard form has no "General Settings" panel title.
    assert "wizard.php" not in page.url, f"landed on the setup wizard, not General settings: {page.url}"

    # The field's enclosing form-group (label + multi-select + help-block) — located by
    # its LABEL, id-rendering-agnostic (see AGG_LABEL). Exactly one such group.
    field = page.locator("div.form-group").filter(has_text=AGG_LABEL)
    expect(field).to_have_count(1, timeout=JS_TIMEOUT_MS)
    select = field.locator("select")
    expect(select).to_be_visible(timeout=JS_TIMEOUT_MS)

    # It is a genuine MULTIPLE select (the opt-in multi-select, not a single dropdown).
    assert select.evaluate("el => el.multiple") is True, "the Aggregated Aliases field is not a multiple-select"
    # Exactly the four action-type options, by value.
    for opt in AGG_OPTIONS:
        expect(select.locator(f"option[value='{opt}']")).to_have_count(1, timeout=JS_TIMEOUT_MS)
    assert select.locator("option").count() == len(AGG_OPTIONS), (
        "unexpected option count on the Aggregated Aliases select"
    )

    # BEFORE: the opt-in default is NONE selected.
    assert _selected_values(select) == [], (
        f"Aggregated Aliases should start with no types selected, got {_selected_values(select)}"
    )
    _shot(page, screenshot_dir, "general_full_aggregate_none")
    _shot_field(field, screenshot_dir, "general_aggregate_types_none")

    # WHEN: select Deny + Permit (a pure client-side DOM change; no Save).
    select.select_option(["Deny", "Permit"])

    # AFTER: exactly Deny + Permit are selected — the selection took.
    assert _selected_values(select) == ["Deny", "Permit"], (
        f"selecting Deny+Permit did not take: selected={_selected_values(select)}"
    )
    _shot(page, screenshot_dir, "general_full_aggregate_selected")
    _shot_field(field, screenshot_dir, "general_aggregate_types_selected")
