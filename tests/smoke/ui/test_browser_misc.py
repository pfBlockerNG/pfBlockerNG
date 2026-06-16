"""Tier-B browser tests (ADR-14 Phase 4): small, high-confidence JS behaviours.

A companion to ``test_browser.py`` covering the OTHER client-side UX scattered
across the package's settings pages -- the radio-exclusivity / show-hide wiring
and the ``.repeatable`` rowhelper add/delete -- driven by a headless Chromium on
the live ADR-04 smoke VM through the Phase-1 authenticated session (the
``browser_page`` fixture's cookie-authed context, so the browser never logs in a
second time).

The JS under test is READ-ONLY reference (no ``src/`` change); every selector and
handler is taken from the pages' own inline ``events.push`` scripts:

* Update page (``pfblockerng_update.php`` <script> at lines 480-542): the three
  ``Force`` radios ``#pfb_force_update`` (checked by default, php:316),
  ``#pfb_force_cron``, ``#pfb_force_reload`` are mutually exclusive -- each one's
  click handler ``.prop('checked', false)``s the other two (php:500-514). The
  same handlers call ``mode_change()``: ``#pfb_force_reload`` -> ``mode_change('on')``
  -> ``hideCheckbox('pfb_reload_option_all', false)`` SHOWS the ``Select 'Reload'
  option`` group; ``#pfb_force_update``/``#pfb_force_cron`` -> ``mode_change()``
  (no arg) -> ``hideCheckbox(..., true)`` HIDES it (php:490-497, called once on
  load -> the group starts hidden). The three reload radios
  ``#pfb_reload_option_all`` (checked default, php:342), ``#pfb_reload_option_ip``,
  ``#pfb_reload_option_dnsbl`` are likewise mutually exclusive (php:517-528).
* Sync page (``pfblockerng_sync.php``): the ``XMLRPC Replication Targets`` section
  is a pfSense ``.repeatable`` rowhelper (php:236) with an ``#addrow`` Add button
  (php:303) and a per-row ``Delete`` button (php:292-297). Each row carries exactly
  one ``varsyncipaddress-<id>`` input, so the count of those inputs is the row
  count -- Add then Delete is a two-way count transition. (The hooks ``#addrow``
  clone is already covered in ``test_browser.py``; here we exercise the *delete*
  side, on the sync page.)
* Feeds page (``pfblockerng_feeds.php`` <script> at lines 838-849): every
  ``input:radio[name^=alt_]`` (the per-feed Alternate-URL selector) has a click
  handler that ``$('#save').trigger('click')`` -> the form auto-submits. Whether a
  fresh box's pre-defined feed definitions surface any Alternate-URL radios is
  data-dependent, so this is asserted CONDITIONALLY (clean skip when none render),
  and the persisted-config save is DEFERRED -- see the test's docstring/report.

NO fixed sleeps: every assertion uses Playwright auto-waiting
(``expect(...).to_be_*`` / ``to_have_count`` / ``wait_for_*``). Full-page
screenshots of the meaningful states are written to ``screenshot_dir`` for human
review (artifacts, not asserted baselines).

Playwright is imported lazily via ``pytest.importorskip`` so collecting this
module without it installed does not hard-error.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .conftest import mask_page_identity
from .test_render_smoke import software_panel_forced

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from ..conftest import SmokeVM
    from .webui import WebUI

# The provenance-gated Software (version/upgrades) page + its panel marker (ADR-19).
SOFTWARE_PAGE = "/pfblockerng/pfblockerng_software.php"
SOFTWARE_PANEL_MARKER = "pfb-software-panel"

pytestmark = pytest.mark.ui_browser

# The Update page hosts the Force/Reload radio groups + their show/hide wiring.
UPDATE_PAGE = "/pfblockerng/pfblockerng_update.php"
# The Sync page hosts the `.repeatable` XMLRPC Replication Targets rowhelper.
SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"
# The Feeds page hosts the per-feed Alternate-URL radio group (auto-submit wiring).
# Split into ?type sub-tabs (ADR-16 Phase 3); the IPv4 tab carries the bulk of the
# pre-defined feeds (and so any Alternate-URL radios), so the alt-URL flow targets it.
FEEDS_PAGE = "/pfblockerng/pfblockerng_feeds.php?type=ipv4"

# A short, explicit timeout (ms) for the JS-driven DOM transitions: the handlers
# fire synchronously on load/click, so this is a flake ceiling, not a wait knob.
JS_TIMEOUT_MS = 10_000


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the (cookie-authenticated) page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form -- proving the injected
    session cookie authenticated the browser (no second login). Waits on
    ``networkidle`` so the page's ``events`` handlers (which pfSense runs after
    DOMContentLoaded) have executed before any assertion.
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    # The login form carries #usernamefld; its absence proves we are authed.
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``.

    Value-redacts the Plus VM identity from the DOM first (ADR-24 ``mask_page_identity``);
    a strict no-op on a CE leg (empty redaction set), so CE shots are unchanged.
    """
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def test_force_radio_toggles_reload_option_visibility(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Selecting the `Reload` force-radio reveals the `Select 'Reload' option` group.

    Before->after transition with BOTH directions (CLAUDE.md): on load
    ``mode_change()`` ran with no arg so ``hideCheckbox('pfb_reload_option_all',
    true)`` HID the reload-option group (``#pfb_reload_option_all`` not visible),
    and ``#pfb_force_update`` is checked by default. Clicking ``#pfb_force_reload``
    fires ``mode_change('on')`` -> the group becomes VISIBLE. Clicking
    ``#pfb_force_update`` again fires ``mode_change()`` -> the group is HIDDEN once
    more -- proving the show/hide is a real two-way branch, not always-shown.
    """
    page = browser_page
    _open(page, webui, UPDATE_PAGE)

    force_update = page.locator("#pfb_force_update")
    force_reload = page.locator("#pfb_force_reload")
    reload_all = page.locator("#pfb_reload_option_all")

    # These radios live in the non-collapsible Update form section, so they are
    # visible (not the collapsed-panel case test_browser.py handles) -- a real
    # click works and visibility is directly observable.
    expect(force_update).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(force_reload).to_be_visible(timeout=JS_TIMEOUT_MS)

    # BEFORE: default force-radio is Update; the reload-option group is HIDDEN
    # (mode_change() ran on load with no arg -> hideCheckbox(..., true)).
    expect(force_update).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_all).not_to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "update_reload_options_hidden")

    # FLIP to Reload -> mode_change('on') reveals the reload-option group.
    force_reload.click()
    expect(force_reload).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(force_update).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_all).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "update_reload_options_shown")

    # FLIP BACK to Update -> mode_change() hides the group again (two-way branch).
    force_update.click()
    expect(force_update).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_all).not_to_be_visible(timeout=JS_TIMEOUT_MS)


def test_force_radios_are_mutually_exclusive(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The three `Force` radios uncheck each other (php:500-514).

    Before->after (CLAUDE.md): start with ``#pfb_force_update`` checked (default)
    and the other two unchecked; clicking ``#pfb_force_cron`` checks Cron and
    unchecks Update + Reload; clicking ``#pfb_force_reload`` checks Reload and
    unchecks Cron + Update. Each click asserts the prior state first so a green
    proves the click caused the change.
    """
    page = browser_page
    _open(page, webui, UPDATE_PAGE)

    force_update = page.locator("#pfb_force_update")
    force_cron = page.locator("#pfb_force_cron")
    force_reload = page.locator("#pfb_force_reload")
    expect(force_update).to_be_visible(timeout=JS_TIMEOUT_MS)

    # BEFORE: only Update is checked.
    expect(force_update).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(force_cron).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(force_reload).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # Click Cron -> Cron on, the other two off.
    force_cron.click()
    expect(force_cron).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(force_update).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(force_reload).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # Click Reload -> Reload on, the other two off.
    force_reload.click()
    expect(force_reload).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(force_update).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(force_cron).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "update_force_radio_exclusive")


def test_reload_option_radios_are_mutually_exclusive(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The three `Reload` option radios uncheck each other (php:517-528).

    The reload-option group is hidden until a `Force Reload` is selected, so first
    click ``#pfb_force_reload`` to reveal it (proven by the visibility test). Then,
    before->after (CLAUDE.md): ``#pfb_reload_option_all`` is checked by default;
    clicking ``#pfb_reload_option_ip`` checks IP and unchecks All + DNSBL; clicking
    ``#pfb_reload_option_dnsbl`` checks DNSBL and unchecks the other two.
    """
    page = browser_page
    _open(page, webui, UPDATE_PAGE)

    # Reveal the reload-option group (it is hidden on load).
    page.locator("#pfb_force_reload").click()

    reload_all = page.locator("#pfb_reload_option_all")
    reload_ip = page.locator("#pfb_reload_option_ip")
    reload_dnsbl = page.locator("#pfb_reload_option_dnsbl")
    expect(reload_all).to_be_visible(timeout=JS_TIMEOUT_MS)

    # BEFORE: only All is checked.
    expect(reload_all).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_ip).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_dnsbl).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "update_reload_option_all")

    # Click IP -> IP on, the other two off.
    reload_ip.click()
    expect(reload_ip).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_all).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_dnsbl).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # Click DNSBL -> DNSBL on, the other two off.
    reload_dnsbl.click()
    expect(reload_dnsbl).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_all).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(reload_ip).not_to_be_checked(timeout=JS_TIMEOUT_MS)


def test_sync_repeatable_add_then_delete_row(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Sync's `.repeatable` rowhelper adds a Replication Target row, then deletes it.

    Each Target row carries exactly one ``varsyncipaddress-<id>`` input, so the
    count of those inputs is the row count. Two-way count transition (CLAUDE.md):
    assert the starting count, click ``#addrow`` -> count+1 (Add works), then click
    the freshly-added row's ``Delete`` button -> count back to the start (Delete
    works). Deleting the row we just added keeps the page in its original shape and
    never persists (Add/Delete are pure client-side helpers; no Save is clicked).
    """
    page = browser_page
    _open(page, webui, SYNC_PAGE)

    rows = page.locator('input[name^="varsyncipaddress-"]')
    add_btn = page.locator("#addrow")
    expect(rows.first).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(add_btn).to_be_visible(timeout=JS_TIMEOUT_MS)

    # BEFORE: record the starting row count.
    before = rows.count()
    _shot(page, screenshot_dir, "sync_rows_before")

    # ADD -> one more Replication Target row (the rowhelper clones the last row).
    add_btn.click()
    expect(page.locator('input[name^="varsyncipaddress-"]')).to_have_count(before + 1, timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "sync_rows_added")

    # DELETE the last (just-added) row -> back to the starting count. The Delete
    # button lives in the same `.repeatable` group; the last group's button is the
    # one the rowhelper bound to the new row.
    delete_buttons = page.locator(".repeatable button.btn-warning")
    delete_buttons.last.click()
    expect(page.locator('input[name^="varsyncipaddress-"]')).to_have_count(before, timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "sync_rows_deleted")


def test_feeds_alt_radio_submit_wiring(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Feeds' Alternate-URL radios auto-submit the form via `#save` (php:843-845).

    Every ``input:radio[name^=alt_]`` has a click handler that
    ``$('#save').trigger('click')``. Whether the fresh box's pre-defined feed
    definitions surface any Alternate-URL radios is data-dependent, so this is
    asserted CONDITIONALLY: if none render, the test skips cleanly (no false pass).
    When present, we prove the wiring WITHOUT actually navigating/persisting --
    intercept ``HTMLFormElement.submit`` and the ``#save`` button's click, then
    click an alt radio and assert our interceptor fired (the handler reached
    ``#save``). The persisted-config save (selecting an *alternate* value and
    asserting ``feed_alt_<header>`` in config.xml) is DEFERRED -- it depends on a
    feed that exposes an alternate URL being present on the box, and on knowing the
    base-vs-alternate values to assert a real transition (see report).
    """
    page = browser_page
    _open(page, webui, FEEDS_PAGE)

    alt_radios = page.locator("input[type=radio][name^=alt_]")
    if alt_radios.count() == 0:
        pytest.skip("no Alternate-URL feed radios on this box -- pre-defined feeds expose none")

    # Confirm the always-rendered scaffolding the handler submits through exists.
    expect(page.locator("#save")).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(page.locator("#alt_selected")).to_be_attached(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "feeds_alt_radios")

    # Neutralise the actual navigation so asserting the wiring does not persist or
    # leave the page: flag a global when the bound handler reaches #save's click,
    # and stop the form from really submitting.
    page.evaluate(
        "(function(){var $=window.jQuery;window.__pfb_alt_submitted=false;"
        "$('#save').on('click', function(e){window.__pfb_alt_submitted=true;e.preventDefault();});"
        "$('form#iform').on('submit', function(e){e.preventDefault();});})()"
    )

    # BEFORE: the interceptor has not fired.
    assert page.evaluate("window.__pfb_alt_submitted") is False, "submit flag set before any radio click"

    # Click the first alt radio -> its handler triggers #save -> our flag flips.
    alt_radios.first.click()
    expect(page.locator("#save")).to_be_attached(timeout=JS_TIMEOUT_MS)
    assert page.evaluate("window.__pfb_alt_submitted") is True, (
        "clicking an Alternate-URL radio did not trigger the #save submit handler"
    )


def test_software_panel_screenshot_when_enabled(
    smoke_vm: SmokeVM,
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Capture the Software (version/upgrades) panel in its ENABLED state.

    The default Tier-A/B sideload deploy hides the page (provenance gate, %R empty), so it never
    appears in a normal browser run. Forcing the hidden override 'on' (software_panel_forced)
    renders the panel deterministically; assert its marker is in the DOM and write a full-page
    screenshot artifact for human review. Captures the state the always-on tiers otherwise can't.
    """
    with software_panel_forced(smoke_vm, "on"):
        _open(browser_page, webui, SOFTWARE_PAGE)
        assert SOFTWARE_PANEL_MARKER in browser_page.content(), "Software panel marker absent when forced on"
        _shot(browser_page, screenshot_dir, "software_panel_enabled")
