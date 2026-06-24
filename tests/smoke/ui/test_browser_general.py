"""Tier-B browser test (ADR-14) for the General-settings ADR-29 gateway round-trip.

Drives a headless Chromium on the live ADR-04 smoke VM (the ``browser_page``
fixture's cookie-authed context — no second login) to exercise the ``pfb_keep``
gateway field on ``pfblockerng_general.php``: a real save→reload→assert round-trip
proving the ADR-29 gateway stores the exact legacy token and the page re-renders the
checkbox state.

Screenshots are written to ``screenshot_dir`` for human review (artifacts, not asserted
baselines); the assertions are the real gate. Playwright is imported lazily via
``pytest.importorskip`` so collecting this module without it installed does not
hard-error.

(The ADR-11 "Aggregated Aliases" multi-select moved to the IP tab — its browser test
lives in ``test_browser_ip.py``.)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"

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
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``.

    Value-redacts the Plus VM identity from the DOM first (ADR-24 ``mask_page_identity``);
    a strict no-op on a CE leg (empty redaction set), so CE shots are unchanged.
    """
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


# --------------------------------------------------------------------------- #
# ADR-29 gateway save→reload→assert round-trip (pfb_keep on General page)
# --------------------------------------------------------------------------- #

# Config path for the pfb_keep field (General section).
_CFG_KEEP = "installedpackages/pfblockerng/config/0/pfb_keep"

# POST timeout for the General page (sync_package_pfblockerng runs after write).
_GENERAL_POST_TIMEOUT = 300.0


def test_gateway_pfb_keep_save_roundtrip(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    screenshot_dir: Path,
) -> None:
    """pfb_keep (PfbToggle gateway field) persists via the General page and reflects in the DOM.

    Proves that the ADR-29 gateway routing on ``pfblockerng_general.php`` stores
    the exact legacy token for ``pfb_keep`` ('on'/''), and that the General page
    re-renders the checkbox in the correct state when the page is reloaded.

    Scenario: ADR-29 gateway save→reload round-trip for pfb_keep on the General page.
      Background: pfBlockerNG deployed; webConfigurator authenticated; wizard dismissed.

    Given the current stored value of pfb_keep (read via config_get oracle) is one
      of the two legal tokens ('on' or ''),

    When the General page is POST-saved with pfb_keep set to the OTHER value,

    Then config.xml holds the new token (write-adapter gate); AND the General page,
      navigated fresh in the browser, renders the pfb_keep checkbox in the state that
      matches the new stored token (DOM-state gate); AND a second POST restores the
      original value with the same two assertions (before-and-after, both directions).
    """
    page = browser_page

    # GIVEN: read the starting value so we know which direction to flip first.
    original = helpers.config_get(smoke_vm, _CFG_KEEP)
    assert original in ("on", ""), f"pfb_keep starting value {original!r} not in expected vocabulary {{'on', ''}}"
    # The two branches: flip to the opposite, then restore.
    flipped = "" if original == "on" else "on"

    try:
        # ---- FLIP: POST pfb_keep to the opposite value ---- #
        # ON sends the checkbox value; OFF omits the field (browser behaviour for
        # unchecked boxes); webui.post() re-GETs for a fresh CSRF token each POST.
        overrides_flip: dict[str, str] = {"pfb_keep": flipped} if flipped == "on" else {"pfb_keep": flipped}
        resp = webui.post(GENERAL_PAGE, overrides_flip, timeout=_GENERAL_POST_TIMEOUT)
        assert "Sign In" not in resp.text, "pfb_keep flip POST lost the session (got login page)"

        # Config oracle: stored token must equal the flipped value.
        stored_flip = helpers.config_get(smoke_vm, _CFG_KEEP)
        assert stored_flip == flipped, (
            f"pfb_keep gateway FAIL after flip: stored {stored_flip!r}, expected {flipped!r} "
            f"(ADR-29 write-adapter must emit the exact legacy token)"
        )
        _shot(page, screenshot_dir, "gateway_general_pfb_keep_before_reload")

        # DOM oracle: reload the General page and assert the checkbox state matches.
        _open(page, webui, GENERAL_PAGE)
        box_flip = page.locator("#pfb_keep")
        expect(box_flip).to_be_attached(timeout=JS_TIMEOUT_MS)
        if flipped == "on":
            expect(box_flip).to_be_checked(timeout=JS_TIMEOUT_MS)
        else:
            expect(box_flip).not_to_be_checked(timeout=JS_TIMEOUT_MS)
        _shot(page, screenshot_dir, "gateway_general_pfb_keep_after_flip")

        # ---- RESTORE: POST pfb_keep back to the original value ---- #
        overrides_restore: dict[str, str] = {"pfb_keep": original} if original == "on" else {"pfb_keep": original}
        resp = webui.post(GENERAL_PAGE, overrides_restore, timeout=_GENERAL_POST_TIMEOUT)
        assert "Sign In" not in resp.text, "pfb_keep restore POST lost the session (got login page)"

        # Config oracle: stored token must equal the original.
        stored_restore = helpers.config_get(smoke_vm, _CFG_KEEP)
        assert stored_restore == original, (
            f"pfb_keep gateway FAIL after restore: stored {stored_restore!r}, expected {original!r}"
        )

        # DOM oracle: reload and assert the checkbox matches the restored value.
        _open(page, webui, GENERAL_PAGE)
        box_restore = page.locator("#pfb_keep")
        expect(box_restore).to_be_attached(timeout=JS_TIMEOUT_MS)
        if original == "on":
            expect(box_restore).to_be_checked(timeout=JS_TIMEOUT_MS)
        else:
            expect(box_restore).not_to_be_checked(timeout=JS_TIMEOUT_MS)
        _shot(page, screenshot_dir, "gateway_general_pfb_keep_after_restore")

    finally:
        # Belt-and-suspenders: ensure box is always left at its original value even
        # if an assertion above aborted mid-flip, so the session VM is left clean.
        if helpers.config_get(smoke_vm, _CFG_KEEP) != original:
            webui.post(
                GENERAL_PAGE,
                {"pfb_keep": original} if original == "on" else {"pfb_keep": original},
                timeout=_GENERAL_POST_TIMEOUT,
            )


# --------------------------------------------------------------------------- #
# issue #489 — Log Settings grouped-column layout (Tier B structural check)
# --------------------------------------------------------------------------- #


def test_log_settings_grouped_layout(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Log Settings section renders with aligned per-category grouped rows in the live DOM.

    Scenario: Log Settings regrouped into aligned per-log rows with category headers (issue #489).
      Background: pfBlockerNG deployed; General page authenticated and settled.

    Given the General page is loaded in the authenticated browser,

    When the DOM is inspected for the new grouped-column structure,

    Then the three column-header texts are visible on the page ("Max lines", "Schedule",
      "Keep lines") — these are NEW elements (the per-category header ``Form_StaticText``
      children); the old layout had no such header row, so this discriminates new from old;
    And the ``log_max_log`` control is present and its enclosing ``.form-group`` left label
      (``col-sm-2.control-label``) shows the log name "pfBlockerNG" — proving per-log rows
      carry the individual log name as the left label, where the OLD layout carried the
      category name "General" on that group, so this too discriminates new from old.

    (Category-name presence is deliberately NOT asserted: "General"/"IP"/"DNSBL" also appear
    as top tabs and the old group labels, so they would pass on the old layout and add no
    signal. The two checks above are the real before/after discriminators.)

    A full-page screenshot is saved as a human-review artifact (not an asserted baseline).
    """
    page = browser_page
    _open(page, webui, GENERAL_PAGE)
    _shot(page, screenshot_dir, "log_settings_grouped_layout")

    # Column header texts visible (emitted by the header Form_Group's StaticText children).
    for col_header in ("Max lines", "Schedule", "Keep lines"):
        expect(page.get_by_text(col_header).first).to_be_visible(timeout=JS_TIMEOUT_MS)

    # The log_max_log control's enclosing form-group carries the per-log label "pfBlockerNG".
    log_max_log = page.locator('select[name="log_max_log"]')
    expect(log_max_log).to_be_attached(timeout=JS_TIMEOUT_MS)
    form_group = log_max_log.locator("xpath=ancestor::div[contains(@class,'form-group')]")
    label = form_group.locator(".control-label")
    expect(label).to_contain_text("pfBlockerNG", timeout=JS_TIMEOUT_MS)
