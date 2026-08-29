"""Tier-B browser test (ADR-14) for the ADR-11 IP-settings "Aggregated Aliases"
multi-select.

Drives a headless Chromium on the live ADR-04 smoke VM (the ``browser_page``
fixture's cookie-authed context — no second login) to exercise the ``pfb_agg_types``
multi-select that ADR-11 adds to ``pfblockerng_ip.php`` (Form_Select 'multiple';
display labels Alias Deny/Permit/Match/Native, stored values Deny/Permit/Match/Native).
It is a real before->after test AND the source of the human-review screenshots of the
field (empty default vs a populated selection).

The select + its options are read from the page's own rendered markup
(``Form_Select('pfb_agg_types', 'Aggregated Aliases', …, $options_pfb_agg_types, TRUE)``,
``$options_pfb_agg_types = ['Deny'=>'Alias Deny','Permit'=>'Alias Permit',
'Match'=>'Alias Match','Native'=>'Alias Native']``). Selecting options is a pure
client-side DOM change (no Save is clicked), so it never persists.

Screenshots (full page + the field's own form-group) are written to ``screenshot_dir``
for human review (artifacts, not asserted baselines); the assertions are the real gate.
Playwright is imported lazily via ``pytest.importorskip`` so collecting this module
without it installed does not hard-error.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

IP_PAGE = "/pfblockerng/pfblockerng_ip.php"
# The ADR-11 multi-select's four option VALUES (the action-type labels the GUI action
# dropdown / Logs page already use). Order is the canonical type order. Each names the
# destination folder/class an aggregate unions (its Alias variant folds in).
AGG_OPTIONS = ("Deny", "Permit", "Match", "Native")
# Locate the select by its LABEL, not an id: pfSense Form_Select(multiple) renders
# name="pfb_agg_types[]" and the id carries the brackets, so a bare ``#pfb_agg_types``
# CSS id selector does not match. The form-group carrying the "Aggregated Aliases"
# label is unambiguous and id-rendering-agnostic; the <select> within it is the field.
AGG_LABEL = "Aggregated Aliases"

# JS-driven DOM settles synchronously; this is a flake ceiling, not a wait knob.
JS_TIMEOUT_MS = 10_000


def _expand_section(page: Page, section_id: str) -> None:
    """Expand a COLLAPSIBLE|SEC_CLOSED Form_Section so rows inside are observable.

    The body id is ``{id}_panel-body`` (pfSense Section.class.php), not ``#{id}-panel``:
    that selector matches nothing, and a ``count() == 0`` guard turns it into a silent
    success. Assert the body is attached so a wrong selector fails here, loudly.

    Keep this byte-identical to the copy in test_browser_ip.py -- the two drifting apart
    is what left the IP page with the broken selector after the DNSBL page was fixed.
    """
    panel = page.locator(f"#{section_id}")
    expect(panel).to_be_attached(timeout=JS_TIMEOUT_MS)
    body = page.locator(f"#{section_id}_panel-body")
    expect(body).to_be_attached(timeout=JS_TIMEOUT_MS)
    if "in" not in (body.get_attribute("class") or ""):
        page.locator(f'a[data-toggle="collapse"][href="#{section_id}_panel-body"]').click()
    expect(body).to_be_visible(timeout=JS_TIMEOUT_MS)


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the cookie-authenticated page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form (proves the injected session
    cookie authenticated the browser — no second login).
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``.

    Value-redacts the Plus VM identity from the DOM first (ADR-24 ``mask_page_identity``);
    a strict no-op on a CE leg (empty redaction set), so CE shots are unchanged.
    """
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _shot_field(locator: Locator, screenshot_dir: Path, name: str) -> None:
    """Write a screenshot of just the field's form-group ``<screenshot_dir>/<name>.png``.

    Scrolls the element into view (Playwright auto-scroll) and captures only its box —
    a focused image of the "Aggregated Aliases" row (label + multi-select + help text).
    Value-redacts the Plus VM identity from the (whole) DOM first (ADR-24); a strict
    no-op on a CE leg, so the CE shot is unchanged.
    """
    mask_page_identity(locator.page)
    locator.scroll_into_view_if_needed(timeout=JS_TIMEOUT_MS)
    locator.screenshot(path=str(screenshot_dir / f"{name}.png"))


def _selected_values(select: Locator) -> list[str]:
    """The currently-selected option values of the multi-select, in DOM order."""
    return select.evaluate("el => Array.from(el.selectedOptions).map(o => o.value)")


def test_ip_aggregate_types_multiselect(
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
    _open(page, webui, IP_PAGE)
    # Confirm we are on the real IP page, not the first-run wizard (the webui fixture
    # dismisses it; assert it here so a regression points at the wizard, not at the
    # field). The wizard form carries no IP-settings panel.
    assert "wizard.php" not in page.url, f"landed on the setup wizard, not IP settings: {page.url}"

    # Aggregated Aliases now lives in collapsed Advanced Settings; expand so to_be_visible() holds.
    _expand_section(page, "ip_advanced")

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
    _shot(page, screenshot_dir, "ip_full_aggregate_none")
    _shot_field(field, screenshot_dir, "ip_aggregate_types_none")

    # WHEN: select Deny + Permit (a pure client-side DOM change; no Save).
    select.select_option(["Deny", "Permit"])

    # AFTER: exactly Deny + Permit are selected — the selection took.
    assert _selected_values(select) == ["Deny", "Permit"], (
        f"selecting Deny+Permit did not take: selected={_selected_values(select)}"
    )
    _shot(page, screenshot_dir, "ip_full_aggregate_selected")
    _shot_field(field, screenshot_dir, "ip_aggregate_types_selected")


def test_delta_batch_hidden_when_apply_mode_is_replace(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Alias Table Delta Batch Size is hidden when Apply Mode is Replace.

    The batch size only applies on the delta path. Replace mode leaves it
    editable today would be a no-op the user can still change. Both directions,
    before-state asserted. Advanced is expanded first so hideInput is observable.
    """
    page = browser_page
    _open(page, webui, IP_PAGE)
    _expand_section(page, "ip_advanced")

    mode = page.locator("#pfb_alias_delta_mode")
    batch = page.locator("#pfb_alias_delta_batch")
    expect(mode).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(batch).to_be_attached(timeout=JS_TIMEOUT_MS)

    mode.select_option("auto")
    page.evaluate("$('#pfb_alias_delta_mode').trigger('change')")
    expect(batch).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "ip_delta_batch_visible_auto")

    mode.select_option("replace")
    page.evaluate("$('#pfb_alias_delta_mode').trigger('change')")
    expect(batch).to_be_hidden(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "ip_delta_batch_hidden_replace")

    mode.select_option("delta")
    page.evaluate("$('#pfb_alias_delta_mode').trigger('change')")
    expect(batch).to_be_visible(timeout=JS_TIMEOUT_MS)
