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
    from playwright.sync_api import Locator, Page

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
    the exact legacy token for ``pfb_keep`` ('on'/'off'), and that the General page
    re-renders the checkbox in the correct state when the page is reloaded.

    NOTE on the off-token (issue #484): the General save persists an EXPLICIT 'off'
    for an unchecked pfb_keep (``(($_POST['pfb_keep'] ?? '') === 'on') ? 'on' : 'off'``),
    not '' -- so a default-on flag can record a deliberate off across a pkg upgrade.
    The two page-reachable tokens are therefore 'on' (checked) and 'off' (unchecked).

    Scenario: ADR-29 gateway save→reload round-trip for pfb_keep on the General page.
      Background: pfBlockerNG deployed; webConfigurator authenticated; wizard dismissed.

    Given the current stored value of pfb_keep (read via config_get oracle) is one
      of the two legal tokens ('on' or 'off'),

    When the General page is POST-saved with pfb_keep set to the OTHER value,

    Then config.xml holds the new token (write-adapter gate); AND the General page,
      navigated fresh in the browser, renders the pfb_keep checkbox in the state that
      matches the new stored token (DOM-state gate); AND a second POST restores the
      original value with the same two assertions (before-and-after, both directions).
    """
    page = browser_page

    # GIVEN: read the starting value so we know which direction to flip first.
    # An absent pfb_keep reads as '' over the raw config path; PfbLenient's canonical off
    # token is 'off' (issue #484), so normalise absent -> 'off' before asserting/flipping.
    original = helpers.config_get(smoke_vm, _CFG_KEEP) or "off"
    assert original in ("on", "off"), f"pfb_keep starting value {original!r} not in expected vocabulary {{'on', 'off'}}"
    # The two branches: flip to the opposite, then restore. The off-token is the explicit
    # 'off' the save emits for an unchecked box (issue #484), not ''.
    flipped = "off" if original == "on" else "on"

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

    Scenario: Log Settings grouped into aligned per-log rows with category headers (issue #489),
      each row exposing the two per-log caps -- Max lines and Max days. (The Max-days column
      replaced the earlier scheduled-reset controls, so the columns are no longer the retired
      "Schedule"/"Keep lines" pair -- ADR-60.)
      Background: pfBlockerNG deployed; General page authenticated and settled.

    Given the General page is loaded in the authenticated browser,

    When the DOM is inspected for the grouped-column structure,

    Then the two column-header texts are visible on the page ("Max lines", "Max days") --
      emitted by the per-category header ``Form_StaticText`` children;
    And the ``log_max_log`` control is present and its enclosing ``.form-group`` left label
      (``col-sm-2.control-label``) shows the log name "pfBlockerNG" -- proving per-log rows
      carry the individual log name as the left label;
    And each category header row is a SHADED divider -- its ``.form-group`` carries the
      ``pfb-loghdr`` class -- and there are EXACTLY three (General / IP / DNS);
    And the IP rows read bare "Block"/"Permit"/"Match": the ``log_max_ip_blocklog`` row's left
      label reads "Block", NOT "IP Block";
    And the DNS-Reply log sits in the merged "DNS" category as the "Reply" row: the
      ``log_max_dnsreplylog`` row's left label reads "Reply", NOT "DNS Reply";
    And every log control carries a per-control ``label.form-label`` (the mobile column label):
      one per Max-lines select and one per Max-days input, so the label count equals the
      control count.

    A full-page screenshot is saved as a human-review artifact (not an asserted baseline).
    """
    page = browser_page
    _open(page, webui, GENERAL_PAGE)
    _shot(page, screenshot_dir, "log_settings_grouped_layout")

    # Column headers must come from the shaded category header rows (.pfb-loghdr), NOT the intro
    # bullets: the intro also wraps "Max lines"/"Max days" in <strong> (exact text nodes) and is
    # emitted before the header rows, so an unscoped exact match resolves to the intro via .first
    # and would pass even if a header StaticText child were missing or renamed. Scope the lookup
    # into the header rows so a broken column header actually fails the test.
    loghdr = page.locator(".pfb-loghdr")
    for col_header in ("Max lines", "Max days"):
        expect(loghdr.get_by_text(col_header, exact=True).first).to_be_visible(timeout=JS_TIMEOUT_MS)

    # The log_max_log control's enclosing form-group carries the per-log label "pfBlockerNG".
    log_max_log = page.locator('select[name="log_max_log"]')
    expect(log_max_log).to_be_attached(timeout=JS_TIMEOUT_MS)
    form_group = log_max_log.locator("xpath=ancestor::div[contains(@class,'form-group')]")
    expect(form_group.locator(".control-label")).to_contain_text("pfBlockerNG", timeout=JS_TIMEOUT_MS)

    # Polish discriminators: shaded category headers, the IP/DNS renames, per-control labels.
    # EXACTLY three shaded category headers (General / IP / DNS) -- assert the count, not just
    # "at least one", so a dropped/extra category divider fails the test.
    expect(page.locator(".form-group.pfb-loghdr")).to_have_count(3, timeout=JS_TIMEOUT_MS)

    def _row_label(field: str) -> Locator:
        ctl = page.locator(f'select[name="{field}"], input[name="{field}"]').first
        return ctl.locator("xpath=ancestor::div[contains(@class,'form-group')]").locator(".control-label")

    expect(_row_label("log_max_ip_blocklog")).to_have_text("Block", timeout=JS_TIMEOUT_MS)
    expect(_row_label("log_max_dnsreplylog")).to_have_text("Reply", timeout=JS_TIMEOUT_MS)

    # EVERY log control carries a per-control mobile label (label-start, class form-label): two
    # per log row -- a Max-lines select and a Max-days input. Count the actual controls on the
    # page (the only label-start sources on the General page) and assert exactly that many
    # form-labels, so the check tracks the real log list and proves every control is labelled,
    # not merely some.
    log_controls = page.locator('select[name^="log_max_"], input[name^="log_max_days_"]').count()
    assert log_controls >= 2, f"expected Log Settings controls (log_max_* select/input), found {log_controls}"
    expect(page.locator("label.form-label")).to_have_count(log_controls, timeout=JS_TIMEOUT_MS)
