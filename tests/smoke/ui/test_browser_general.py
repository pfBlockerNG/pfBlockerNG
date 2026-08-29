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
    the canonical checkbox token for ``pfb_keep`` ('on'/''), and that the General page
    re-renders the checkbox in the correct state when the page is reloaded.

    Unchecked saves persist the empty checkbox token; legacy ``'off'`` remains readable.

    Scenario: ADR-29 gateway save→reload round-trip for pfb_keep on the General page.
      Background: pfBlockerNG deployed; webConfigurator authenticated; wizard dismissed.

    Given the current stored value of pfb_keep (read via config_get oracle) is one
      of the two canonical tokens ('on' or ''),

    When the General page is POST-saved with pfb_keep set to the OTHER value,

    Then config.xml holds the new token (write-adapter gate); AND the General page,
      navigated fresh in the browser, renders the pfb_keep checkbox in the state that
      matches the new stored token (DOM-state gate); AND a second POST restores the
      original value with the same two assertions (before-and-after, both directions).
    """
    page = browser_page

    # GIVEN: capture exact presence/raw state, then resolve the effective state.
    # An absent pfb_keep reads as the registered default 'on'; explicit empty is Off.
    original_state = helpers.config_get_state(smoke_vm, _CFG_KEEP)
    original_raw = original_state[1]
    original = "on" if not original_state[0] or original_raw == "on" else ""
    flipped = "" if original == "on" else "on"

    try:
        # ---- FLIP: POST pfb_keep to the opposite value ---- #
        # ON sends the checkbox value; OFF omits the field (browser behaviour for
        # unchecked boxes); webui.post() re-GETs for a fresh CSRF token each POST.
        overrides_flip: dict[str, str] = {"pfb_keep": flipped} if flipped == "on" else {"pfb_keep": flipped}
        resp = webui.post(GENERAL_PAGE, overrides_flip, timeout=_GENERAL_POST_TIMEOUT)
        assert "Sign In" not in resp.text, "pfb_keep flip POST lost the session (got login page)"

        # Config oracle: stored token must equal the canonical flipped value.
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

        # Config oracle: stored token must equal the canonical original.
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
        helpers.config_restore_state(smoke_vm, _CFG_KEEP, original_state)
        assert helpers.config_get_state(smoke_vm, _CFG_KEEP) == original_state

    finally:
        # Belt-and-suspenders: ensure box is always left at its original value even
        # if an assertion above aborted mid-flip, so the session VM is left clean.
        if helpers.config_get_state(smoke_vm, _CFG_KEEP) != original_state:
            helpers.config_restore_state(smoke_vm, _CFG_KEEP, original_state)


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
      emitted once by the ``.pfb-logcolhdr`` row, not once per category;
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

    # Column headers live on the single .pfb-logcolhdr row, NOT the intro bullets (which also
    # wrap "Max lines"/"Max days" in <strong>) and NOT the category dividers. One cell each.
    colhdr = page.locator(".pfb-logcolhdr")
    expect(colhdr).to_have_count(1, timeout=JS_TIMEOUT_MS)
    for col_header in ("Max lines", "Max days"):
        cells = colhdr.get_by_text(col_header, exact=True)
        expect(cells).to_have_count(1, timeout=JS_TIMEOUT_MS)
        expect(cells.first).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(page.locator(".pfb-loghdr").get_by_text("Max lines", exact=True)).to_have_count(0)

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

    # Each log row carries BOTH a Max-lines select and a Max-days input; each control emits exactly
    # one per-control mobile label (label-start, class form-label -- the only source of
    # label.form-label on this page). Assert the two column families are present and equal-sized,
    # so dropping either whole column fails (counting only their union would miss a symmetric loss),
    # then that every control is labelled (one form-label per control).
    max_lines = page.locator('select[name^="log_max_"]')
    max_days = page.locator('input[name^="log_max_days_"]')
    n_rows = max_lines.count()
    assert n_rows >= 1, f"expected at least one Log Settings row (select[name^=log_max_]), found {n_rows}"
    expect(max_days).to_have_count(n_rows, timeout=JS_TIMEOUT_MS)
    expect(page.locator("label.form-label")).to_have_count(n_rows * 2, timeout=JS_TIMEOUT_MS)
    expect(page.locator(".form-group.pfb-logrow")).to_have_count(n_rows, timeout=JS_TIMEOUT_MS)


def test_quarter_hour_scheduling_controls_and_apply_window(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Scheduling renders in place, persists, validates, and exposes cache warnings."""
    page = browser_page
    _open(page, webui, GENERAL_PAGE)

    expect(page.locator('input[name="pfb_scheduled_feed_updates"]')).to_be_attached(timeout=JS_TIMEOUT_MS)
    weekday = page.locator('select[name="pfb_schedule_weekday"]')
    hour = page.locator('select[name="pfb_schedule_hour"]')
    minute = page.locator('select[name="pfb_schedule_minute"]')
    expect(weekday).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(weekday.locator("option")).to_have_count(7, timeout=JS_TIMEOUT_MS)
    expect(weekday.locator("option").first).to_have_attribute("value", "7", timeout=JS_TIMEOUT_MS)
    expect(hour.locator("option")).to_have_count(24, timeout=JS_TIMEOUT_MS)
    assert minute.locator("option").evaluate_all("options => options.map(option => option.value)") == [
        "0",
        "15",
        "30",
        "45",
    ]

    for retired in ("pfb_interval", "pfb_min", "pfb_hour", "pfb_dailystart"):
        expect(page.locator(f'[name="{retired}"]')).to_have_count(0, timeout=JS_TIMEOUT_MS)

    window_toggle = page.locator('input[name="pfb_quiet_hours_enabled"]')
    start = page.locator('input[name="pfb_quiet_hours_start"]')
    end = page.locator('input[name="pfb_quiet_hours_end"]')
    expect(start).to_have_attribute("type", "time", timeout=JS_TIMEOUT_MS)
    expect(end).to_have_attribute("step", "900", timeout=JS_TIMEOUT_MS)
    sections = page.locator(".panel-title").all_text_contents()
    assert sections.index("General Settings") < sections.index("Scheduling") < sections.index("Log Settings")

    base = "installedpackages/pfblockerng/config/0"
    paths = {
        name: f"{base}/{name}"
        for name in (
            "pfb_scheduled_feed_updates",
            "pfb_schedule_weekday",
            "pfb_schedule_hour",
            "pfb_schedule_minute",
            "pfb_quiet_hours",
        )
    }
    original = {name: helpers.config_get_state(smoke_vm, path) for name, path in paths.items()}
    try:
        helpers.config_set(smoke_vm, paths["pfb_quiet_hours"], "")
        _open(page, webui, GENERAL_PAGE)
        expect(start).to_be_disabled(timeout=JS_TIMEOUT_MS)
        expect(end).to_be_disabled(timeout=JS_TIMEOUT_MS)
        window_toggle.check()
        expect(start).to_be_enabled(timeout=JS_TIMEOUT_MS)
        expect(end).to_be_enabled(timeout=JS_TIMEOUT_MS)

        saved = {
            "pfb_scheduled_feed_updates": "on",
            "pfb_schedule_weekday": "4",
            "pfb_schedule_hour": "6",
            "pfb_schedule_minute": "30",
        }
        response = webui.post(GENERAL_PAGE, saved, timeout=_GENERAL_POST_TIMEOUT)
        assert "Sign In" not in response.text
        for name, value in saved.items():
            assert helpers.config_get(smoke_vm, paths[name]) == value

        _open(page, webui, GENERAL_PAGE)
        expect(page.locator('input[name="pfb_scheduled_feed_updates"]')).to_be_checked(timeout=JS_TIMEOUT_MS)
        expect(page.locator('select[name="pfb_schedule_weekday"]')).to_have_value("4", timeout=JS_TIMEOUT_MS)
        expect(page.locator('select[name="pfb_schedule_hour"]')).to_have_value("6", timeout=JS_TIMEOUT_MS)
        expect(page.locator('select[name="pfb_schedule_minute"]')).to_have_value("30", timeout=JS_TIMEOUT_MS)

        rejected = webui.post(GENERAL_PAGE, {"pfb_schedule_minute": "5"}, timeout=_GENERAL_POST_TIMEOUT)
        assert "Schedule minute is invalid" in rejected.text
        assert helpers.config_get(smoke_vm, paths["pfb_schedule_minute"]) == "30"

        # issue #2855: the warning names the stage that failed, and an unrecognised stage
        # token falls back to the generic label instead of reaching the page.
        _open(page, webui, GENERAL_PAGE + "?schcache=failed&schstage=config")
        expect(
            page.get_by_text(
                "schedule-cache generation failed: the saved schedule configuration was rejected",
                exact=False,
            )
        ).to_be_visible(timeout=JS_TIMEOUT_MS)

        _open(page, webui, GENERAL_PAGE + "?schcache=failed&schstage=not-a-stage")
        # Scoped to THIS message, never to ``.alert-warning`` alone: the pending-changes
        # banner is also an alert-warning and may be set.
        warning = page.locator(".alert-warning:has-text('schedule-cache generation failed')")
        expect(warning).to_contain_text("the failing stage was not recorded", timeout=JS_TIMEOUT_MS)
        # The stage token must not reach the reader. Asserted against the warning's text, not
        # the document: pfSense's Form defaults its action to REQUEST_URI, so the query string
        # is echoed into the form tag and page.content() would match there.
        assert "not-a-stage" not in warning.inner_text()

        # Master Off suppresses scheduled work only; schedule and enabled window remain editable.
        window_toggle.check()
        master = page.locator('input[name="pfb_scheduled_feed_updates"]')
        master.uncheck()
        expect(weekday).to_be_enabled(timeout=JS_TIMEOUT_MS)
        expect(hour).to_be_enabled(timeout=JS_TIMEOUT_MS)
        expect(minute).to_be_enabled(timeout=JS_TIMEOUT_MS)
        expect(start).to_be_enabled(timeout=JS_TIMEOUT_MS)
        expect(end).to_be_enabled(timeout=JS_TIMEOUT_MS)
    finally:
        for name, state in original.items():
            helpers.config_restore_state(smoke_vm, paths[name], state)
