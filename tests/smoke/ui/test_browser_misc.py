"""Tier-B browser tests (ADR-14 Phase 4): small, high-confidence JS behaviours.

A companion to ``test_browser.py`` covering the OTHER client-side UX scattered
across the package's settings pages -- the radio-exclusivity and auto-submit wiring
and the ``.repeatable`` rowhelper add/delete -- driven by a headless Chromium on
the live ADR-04 smoke VM through the Phase-1 authenticated session (the
``browser_page`` fixture's cookie-authed context, so the browser never logs in a
second time).

The JS under test is READ-ONLY reference (no ``src/`` change); every selector and
handler is taken from the pages' own inline ``events.push`` scripts:

* Update page (``pfblockerng_update.php``, ADR-43 revamp): two ``displayAsRadio``
  groups -- ``Run Scope`` (``#pfb_scope_both``/``#pfb_scope_ip``/``#pfb_scope_dnsbl``,
  php:286-308) and ``Force`` mode (``#pfb_force_none``/``#pfb_force_parse``/
  ``#pfb_force_download``/``#pfb_force_both``, php:316-323). Each group is a native
  radio set (shared ``name``), so selecting one unchecks its siblings -- there is no
  custom show/hide JS in this revamp (the page's only script is layout/scroll).
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
from .test_render_smoke import _seed_vm_file, software_panel_forced

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

# The Update page hosts the Run-Scope + Force-mode radio groups (ADR-43 revamp).
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


def test_force_radios_are_mutually_exclusive(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The four `Force` mode radios (None/Parse/Download/Both) uncheck each other.

    The Update page (ADR-43 revamp) renders ``pfb_force_mode`` as four
    mutually-exclusive radios via ``displayAsRadio``: ``#pfb_force_none``,
    ``#pfb_force_parse``, ``#pfb_force_download``, ``#pfb_force_both``. To stay
    order-independent on the shared session VM (a sibling test may have persisted a
    force_mode), the test establishes its own baseline by clicking None first, then
    drives transitions: before->after (CLAUDE.md) each click asserts the clicked
    radio becomes checked and every sibling becomes unchecked -- proving the click
    caused the exclusivity.
    """
    page = browser_page
    _open(page, webui, UPDATE_PAGE)

    none = page.locator("#pfb_force_none")
    parse = page.locator("#pfb_force_parse")
    download = page.locator("#pfb_force_download")
    both = page.locator("#pfb_force_both")
    expect(none).to_be_visible(timeout=JS_TIMEOUT_MS)

    # Baseline: None checked, the rest off (independent of any persisted force_mode).
    none.click()
    expect(none).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(parse).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(download).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(both).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # Click Download -> Download on, the other three off.
    download.click()
    expect(download).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(none).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(parse).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(both).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # Click Both -> Both on, the other three off.
    both.click()
    expect(both).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(none).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(parse).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(download).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "update_force_mode_exclusive")


def test_scope_radios_are_mutually_exclusive(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The three `Run Scope` radios (Both/IP/DNSBL) uncheck each other.

    The Update page (ADR-43 revamp) renders ``pfb_scope`` as three
    mutually-exclusive radios via ``displayAsRadio``: ``#pfb_scope_both``,
    ``#pfb_scope_ip``, ``#pfb_scope_dnsbl``. The test establishes its own baseline
    by clicking Both first (order-independent on the shared VM), then drives
    transitions: before->after (CLAUDE.md) each click asserts the clicked radio
    becomes checked and every sibling becomes unchecked.
    """
    page = browser_page
    _open(page, webui, UPDATE_PAGE)

    both = page.locator("#pfb_scope_both")
    ip = page.locator("#pfb_scope_ip")
    dnsbl = page.locator("#pfb_scope_dnsbl")
    expect(both).to_be_visible(timeout=JS_TIMEOUT_MS)

    # Baseline: Both checked, the rest off.
    both.click()
    expect(both).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(ip).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(dnsbl).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # Click IP -> IP on, the other two off.
    ip.click()
    expect(ip).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(both).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(dnsbl).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # Click DNSBL -> DNSBL on, the other two off.
    dnsbl.click()
    expect(dnsbl).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(both).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(ip).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "update_scope_exclusive")


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


@pytest.mark.ui_browser
def test_update_page_completes_while_tailing(
    smoke_vm: SmokeVM,
    browser_page: Page,
    webui: WebUI,
) -> None:
    """The page finishes loading while the live log tails — the nav menu is no longer dead (#671).

    The old blocking stream parked the request inside pfb_livetail(), so foot.inc never ran and the
    navigation JS never initialized during a run/view: tapping the menu did nothing until the run
    ended. The log is now AJAX-polled, so the document reaches readyState 'complete' with the poller
    active and the page is fully interactive.

    Scenario:
      Given the Update page,
      When the View button is clicked (which wires the live-log poller),
      Then the document reaches readyState 'complete' (it parked mid-stream before #671) and the
           output textarea the poller targets is present.
    """
    page = browser_page
    _open(page, webui, UPDATE_PAGE)
    page.locator('button[name="log_view"], #log_view').first.click()
    page.wait_for_load_state("load")
    assert page.evaluate("document.readyState") == "complete", (
        "the page must finish loading while the live-log poller runs (it parked mid-stream before #671)"
    )
    assert page.locator('textarea[name="pfb_output"]').count() == 1, "poller target textarea must be present"


def test_update_output_is_not_prefilled(
    smoke_vm: SmokeVM,
    browser_page: Page,
    webui: WebUI,
) -> None:
    """The Update page no longer prefills the output textarea on a plain GET (#666).

      Given the pfBlockerNG log seeded with content,
      When the Update page is opened on a plain GET (no run / view / in-progress update),
      Then pfb_output is EMPTY — the last log tail is no longer prefilled.

    Fail-before / pass-after: the old code prefilled pfb_output with the log tail on a plain
    GET; now it starts empty (use the View button to inspect the log). The seeded marker proves
    the textarea is empty by choice, not because the log is empty.
    """
    page = browser_page
    seed = "".join(f"pfb-update-noprefill-{i:03d}\n" for i in range(1, 41))
    _seed_vm_file(smoke_vm, "/var/log/pfblockerng/pfblockerng.log", seed)

    _open(page, webui, UPDATE_PAGE)
    val = page.locator('textarea[name="pfb_output"]').input_value()
    assert val == "", f"the Update page must not prefill pfb_output on a plain GET, got {val!r}"


@pytest.mark.ui_browser
def test_update_runnow_does_not_scroll_the_page(
    smoke_vm: SmokeVM,
    browser_page: Page,
    webui: WebUI,
) -> None:
    """Clicking Run Now must not auto-scroll the whole page to the bottom (matches View).

    Run Now reloads into the AJAX poll tail, which sticky-follows the live log WITHIN the
    output box. A leftover jQuery handler additionally animated the ENTIRE page to the
    document bottom on '#run' click (View had no such handler), yanking the page down and
    leaving the reloaded page scrolled off the top. This pins that the page stays put.

    Fail-before / pass-after: with the old '#run' bottom-animate handler present the window
    scrolls down after the click; with it removed the offset stays at the top.

    Scenario:
      Given the Update page loaded at the top and tall enough to scroll,
      When Run Now is clicked (its form submit suppressed so the on-click page animation is
           observed in isolation — no real update run is dispatched on the VM),
      Then the window scroll offset stays at the top (no whole-page auto-scroll).
    """
    page = browser_page
    _open(page, webui, UPDATE_PAGE)

    # Precondition: the page must actually be scrollable, else a no-scroll assertion is vacuous.
    scrollable = page.evaluate("document.documentElement.scrollHeight > window.innerHeight + 50")
    assert scrollable, "Update page is not tall enough to scroll — cannot assert no auto-scroll"

    # Suppress the POST navigation so the (old) on-click animation is observed alone and no
    # real run is dispatched; the click handler under test still fires either way.
    page.evaluate("document.forms[0].addEventListener('submit', e => e.preventDefault(), true)")
    assert page.evaluate("window.pageYOffset") == 0, "the page should start at the top"

    page.locator('button[name="run"], #run').first.click()
    # Bounded wait to prove ABSENCE of the scroll: outlast the old 2000ms animate window so a
    # regression would have moved the page by the time we read the offset.
    page.wait_for_timeout(2500)

    offset = page.evaluate("window.pageYOffset")
    assert offset == 0, f"Run Now must not auto-scroll the page; expected top (0), got pageYOffset={offset}"
