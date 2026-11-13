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
  custom show/hide JS in this revamp (the page's other scripts are layout/scroll and
  the live-log poller, covered below).
* Update page live-log poller (``pfblockerng_update.php``, issues #678, #3941): the poller of
  ``?ajax=update`` -- the sticky auto-follow (measure before append, re-pin only when already at the
  bottom), Core's cursor handed back unchanged, the stop once the Update is done and the log drained, a
  new Update (its ``startedAt``) starting a clean log, and a Core error stopping the poll. Core's answers
  are controlled at the network edge (``_FakeCore``), so each stream is deterministic.
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

import json
import re
import uuid
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest

from .conftest import mask_page_identity, wait_for_document_ready
from .test_render_smoke import (
    _SOFTWARE_CHECK_FAILED_QUERY,
    _SOFTWARE_CHECKED_MARKER,
    _seed_vm_file,
    software_panel_forced,
)

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page, Route

    from ..conftest import SmokeVM
    from .webui import WebUI

# The provenance-gated Software (version/upgrades) page + its panel marker (ADR-19). The
# failed-check markers/query are imported from Tier A so both tiers assert the same strings.
SOFTWARE_PAGE = "/pfblockerng/pfblockerng_software.php"
SOFTWARE_PANEL_MARKER = "pfb-software-panel"
SOFTWARE_CHECKED_MARKER = _SOFTWARE_CHECKED_MARKER
SOFTWARE_CHECK_FAILED_QUERY = _SOFTWARE_CHECK_FAILED_QUERY

pytestmark = pytest.mark.ui_browser

# The Update page hosts the Run-Scope + Force-mode radio groups (ADR-43 revamp).
UPDATE_PAGE = "/pfblockerng/pfblockerng_update.php"
# The Sync page hosts the `.repeatable` XMLRPC Replication Targets rowhelper.
SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"
# The Feeds page hosts the per-feed Alternate-URL radio group (auto-submit wiring).
# Split into ?type sub-tabs (ADR-16 Phase 3); the IPv4 tab carries the bulk of the
# pre-defined feeds (and so any Alternate-URL radios), so the alt-URL flow targets it.
FEEDS_PAGE = "/pfblockerng/pfblockerng_feeds.php?type=ipv4"
# The IP page includes pfBlockerNG.js, whose window.onload runs the
# location.hash scroll-to-anchor + CustomList panel toggle (issue #714).
IP_PAGE = "/pfblockerng/pfblockerng_ip.php"

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
    wait_for_document_ready(page)


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


def test_software_failed_check_feedback_is_visible(
    smoke_vm: SmokeVM,
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """A forced check that failed says so in the browser, and a plain load does not (#2674).

    Check now POSTs, runs the check and redirects, so before #2674 an admin who explicitly
    asked for a fresh answer was silently re-served the old one. The handler now redirects
    carrying ``?check=failed`` when the refresh it forced did not work, which is the state
    this tier renders. Driving the query directly keeps the case deterministic: clicking the
    button on a live guest runs a real ``pkg update`` whose outcome is not ours to fix.

    Scenario:
      Given the hidden override forcing the provenance gate on,
      When the Software page is opened plainly,
      Then this feedback's warning box is absent (a benign load stays calm — issue #2379);
      And when it is opened with the feedback query Check now redirects with,
      Then the warning box IS visible, names the catalogue read that failed, and sits beside
          the last-successful-check row rather than replacing it.

    The locator is scoped to this message, never to ``.alert-warning`` alone: pfBlockerNG's
    pending-changes banner is also an alert-warning and may be set, so a bare class assertion
    would be about that banner instead of this feedback.
    """
    failed_box = ".alert-warning:has(strong:text-is('Check now'))"
    with software_panel_forced(smoke_vm, "on"):
        _open(browser_page, webui, SOFTWARE_PAGE)
        assert SOFTWARE_PANEL_MARKER in browser_page.content(), "Software panel marker absent when forced on"
        expect(browser_page.locator(failed_box)).to_have_count(0, timeout=JS_TIMEOUT_MS)

        _open(browser_page, webui, SOFTWARE_PAGE + SOFTWARE_CHECK_FAILED_QUERY)
        expect(browser_page.locator(failed_box)).to_be_visible(timeout=JS_TIMEOUT_MS)
        expect(browser_page.locator(f"#{SOFTWARE_CHECKED_MARKER}")).to_be_visible(timeout=JS_TIMEOUT_MS)
        _shot(browser_page, screenshot_dir, "software_check_failed_feedback")


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
    page.wait_for_function(
        "() => window.jQuery && window.jQuery(':animated').length === 0",
        timeout=JS_TIMEOUT_MS,
    )

    offset = page.evaluate("window.pageYOffset")
    assert offset == 0, f"Run Now must not auto-scroll the page; expected top (0), got pageYOffset={offset}"


def test_onload_survives_hash_with_no_matching_element(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """A URL hash naming no element must not crash pfBlockerNG.js's window.onload (#714).

    ``window.onload`` (pfBlockerNG.js:24-33) is wired to scroll to, and expand the
    CustomList panel for, a bookmarked ``location.hash`` anchor (used by the widget's
    Suppression/Whitelist links). It called ``document.getElementById(elId)
    .scrollIntoView(true)`` unconditionally -- a hash the page does not recognise (a
    stale bookmark, a typo, user-supplied) makes ``getElementById`` return ``null``,
    so ``null.scrollIntoView()`` threw and aborted onload before the CustomList panel
    toggle ran.

    Scenario:
      Given the IP page (which includes pfBlockerNG.js),
      When it is loaded with a hash that names no element on the page,
      Then onload completes without an uncaught page error, and the page still
           renders (the login form is absent, proving a real authenticated render,
           not a blank/errored page).
    """
    page = browser_page
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))

    _open(page, webui, f"{IP_PAGE}#pfb_nonexistent_anchor_714")

    assert errors == [], f"window.onload threw on an unmatched hash: {errors!r}"
    # Same marker Tier A (test_render_smoke.py PAGE_TABLE) asserts for this page --
    # proves a real authenticated render, not a blank/errored page.
    assert "IP Configuration" in page.content(), "IP page did not render its 'IP Configuration' section after onload"


def _scroll_metrics(page: Page) -> dict[str, float]:
    """Read scrollTop/scrollHeight/clientHeight off the ``pfb_output`` textarea."""
    return page.eval_on_selector(
        'textarea[name="pfb_output"]',
        "el => ({scrollTop: el.scrollTop, scrollHeight: el.scrollHeight, clientHeight: el.clientHeight})",
    )


def _is_pinned(metrics: dict[str, float]) -> bool:
    """Mirror the poller's own bottom test (pfblockerng_update.php:590): within 16px of bottom."""
    return (metrics["scrollHeight"] - metrics["scrollTop"] - metrics["clientHeight"]) <= 16


def _wait_for_marker(page: Page, marker: str) -> None:
    """Block until *marker* has arrived in the ``pfb_output`` textarea value.

    Bounded ``wait_for_function`` (raises loudly on timeout) -- never a fixed sleep (#456). The
    poller's cadence is 1s, so 15s comfortably outlasts a few ticks without masking a real hang.
    On timeout, re-raises with the expected marker next to the textarea's actual tail (CLAUDE.md
    "print expected vs actual") -- distinguishing "seed never landed" from "poller never appended".
    """
    try:
        page.wait_for_function(
            "needle => document.forms[0].pfb_output.value.includes(needle)",
            arg=marker,
            timeout=15_000,
        )
    except sync_api.TimeoutError as exc:
        actual = page.eval_on_selector('textarea[name="pfb_output"]', "el => el.value.slice(-600)")
        raise AssertionError(
            f"marker never arrived in pfb_output within 15s\n"
            f"  expected to contain: {marker!r}\n"
            f"  actual (last 600 chars): {actual!r}"
        ) from exc


class _FakeCore:
    """Core's GetUpdate as the Update page's poll endpoint relays it, under the test's control (issue #3941).

    The page's poller is the code under test, so the server side is replaced at the network edge: every
    ``?ajax=update`` is answered from this object, with Core's cursor semantics -- ``next`` is an opaque string, an
    ``after`` that is not the one this Update handed out reads from the start. ``requests`` records the ``after``
    of each poll (None: none sent), which is how the cursor round trip is asserted.
    """

    def __init__(self) -> None:
        self.log = ""
        self.running = True
        self.started_at = 1_700_000_000
        self.error: str | None = None
        self.requests: list[str | None] = []

    def append(self, text: str) -> None:
        self.log += text

    def new_update(self, log: str) -> None:
        """A new Update (or a restarted Core): another startedAt and a log that starts again."""
        self.started_at += 1
        self.log = log
        self.running = True

    def handle(self, route: Route) -> None:
        after = parse_qs(urlsplit(route.request.url).query).get("after", [None])[0]
        self.requests.append(after)
        if self.error is not None:
            body: dict[str, object] = {
                "error": self.error,
                "running": False,
                "done": True,
                "log": "",
                "next": "0",
                "update": None,
            }
        else:
            start = int(after) if after is not None and after.isdigit() and int(after) <= len(self.log) else 0
            body = {
                "running": self.running,
                "done": not self.running,
                "log": self.log[start:],
                "next": str(len(self.log)),
                "update": {"trigger": "manual", "scope": "dnsbl", "force": "none", "startedAt": self.started_at},
            }
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))


def _follow_with(page: Page, webui: WebUI, core: _FakeCore) -> None:
    """Open the Update page, answer its poll from ``core`` and click View, which wires the poller."""
    _open(page, webui, UPDATE_PAGE)
    page.route(re.compile(r"pfblockerng_update\.php\?ajax=update"), core.handle)
    page.locator('button[name="log_view"], #log_view').first.click()
    page.wait_for_load_state("load")  # View submits/reloads the page with the poller wired


def _status(page: Page) -> str:
    return page.locator('textarea[name="pfb_status"]').input_value()


def _wait_for_status(page: Page, text: str) -> None:
    """Block until the status box says ``text``; on timeout, expected next to the actual status."""
    try:
        page.wait_for_function("t => document.forms[0].pfb_status.value.includes(t)", arg=text, timeout=15_000)
    except sync_api.TimeoutError as exc:
        raise AssertionError(f"status never said {text!r} within 15s; it says {_status(page)!r}") from exc


@pytest.mark.ui_browser
def test_update_livelog_sticky_follow_scroll(browser_page: Page, webui: WebUI) -> None:
    """The live-log viewer sticky-follows the tail, but only while parked at the bottom (#678).

    The auto-follow logic lives in the inline poller JS (pfblockerng_update.php). This pins it end-to-end against
    the real poll loop, with Core's answers controlled (``_FakeCore``), so the stream is deterministic.

    Scenario:
      Given Core's Update is running and its log is past the textarea's capacity,
      When the Update page's View button wires the live-log poller and the seed arrives,
      Then the view starts pinned at the bottom (overflow precondition asserted first, else the
           scroll assertions below would be vacuous);

      When further lines arrive while still pinned at the bottom (batch A),
      Then it stays pinned -- sticky auto-follow;

      When the user scrolls up to read (to the top) and more lines arrive (batch B),
      Then the view does NOT get yanked back down -- follow is paused while reading;

      When the user scrolls back down to the bottom and more lines arrive (batch C),
      Then auto-follow resumes -- scrolling to the bottom re-arms the sticky behaviour.
    """
    page = browser_page
    run_id = uuid.uuid4().hex[:8]
    marker_a = f"pfb-678-{run_id}-a"
    marker_b = f"pfb-678-{run_id}-b"
    marker_c = f"pfb-678-{run_id}-c"
    seed_last = f"pfb-678-{run_id}-seed-0150"
    core = _FakeCore()
    core.append("".join(f"pfb-678-{run_id}-seed-{i:04d} {'x' * 80}\n" for i in range(1, 151)))

    _follow_with(page, webui, core)
    _wait_for_marker(page, seed_last)

    # Given: the seed overflows the box AND starts pinned at the bottom. Overflow must exceed
    # the poller's 16px at-bottom slack, else scrollTop=0 would still read as "at bottom" and
    # phase 2 could fail against a correct poller.
    metrics = _scroll_metrics(page)
    assert metrics["scrollHeight"] - metrics["clientHeight"] > 16, (
        f"seed must overflow the textarea past the 16px pin slack, got {metrics}"
    )
    assert _is_pinned(metrics), f"expected pinned at the bottom right after the seed loaded, got {metrics}"

    # Phase 1 -- pinned follow: new lines arrive while at the bottom -> stays pinned.
    core.append(f"{marker_a}\n")
    _wait_for_marker(page, marker_a)
    metrics = _scroll_metrics(page)
    assert _is_pinned(metrics), f"expected still pinned at the bottom after batch A, got {metrics}"

    # Phase 2 -- follow paused when scrolled up: new lines must NOT yank the view down.
    page.eval_on_selector('textarea[name="pfb_output"]', "el => { el.scrollTop = 0; }")
    metrics = _scroll_metrics(page)
    assert metrics["scrollTop"] == 0, f"expected scrollTop 0 right after scrolling to the top, got {metrics}"

    core.append(f"{marker_b}\n")
    _wait_for_marker(page, marker_b)
    metrics = _scroll_metrics(page)
    assert metrics["scrollTop"] == 0, (
        f"batch B must NOT yank the scrolled-up-to-read view back to the bottom, got {metrics}"
    )

    # Phase 3 -- follow resumes at the bottom: scrolling back down re-arms auto-follow.
    page.eval_on_selector('textarea[name="pfb_output"]', "el => { el.scrollTop = el.scrollHeight; }")
    metrics = _scroll_metrics(page)
    assert _is_pinned(metrics), f"expected pinned immediately after scrolling back to the bottom, got {metrics}"

    core.append(f"{marker_c}\n")
    _wait_for_marker(page, marker_c)
    metrics = _scroll_metrics(page)
    assert _is_pinned(metrics), f"expected still pinned at the bottom after batch C, got {metrics}"


@pytest.mark.ui_browser
def test_update_poller_hands_the_cursor_back_and_stops_once_the_log_is_drained(
    browser_page: Page, webui: WebUI
) -> None:
    """The poller sends Core's ``next`` back as ``after`` unchanged, and stops when Update is done and the log drained.

    Scenario:
      Given Core's last Update has ended and left a four-byte log,
      When the View button wires the poller,
      Then the first poll carries no cursor, the log appears, and the next poll carries exactly the ``next`` the
           first reply gave (a string, not re-derived by the page);
      And once that poll finds nothing more the status says the viewer is idle, and no further poll is made.
    """
    page = browser_page
    core = _FakeCore()
    core.running = False
    core.append("a\nb\n")

    _follow_with(page, webui, core)
    _wait_for_status(page, "Log viewer idle.")

    assert page.locator('textarea[name="pfb_output"]').input_value() == "a\nb\n"
    assert core.requests == [None, "4"], (
        f"expected a first poll without a cursor then the cursor 'next' gave, got {core.requests!r}"
    )
    with pytest.raises(sync_api.TimeoutError):  # absence, asserted only after the drain barrier above
        page.wait_for_request(lambda r: "ajax=update" in r.url, timeout=2_500)


@pytest.mark.ui_browser
def test_update_poller_clears_the_log_when_a_new_update_starts(browser_page: Page, webui: WebUI) -> None:
    """A new Update (its ``startedAt`` changes) starts a clean log and is read from its start.

    Scenario:
      Given the viewer follows a running Update whose log shows,
      When Core starts a new Update (another startedAt, a log that starts again),
      Then the old Update's lines are gone, the new Update's log shows from its first line, and the poll that
           follows carries no cursor (the page dropped the one it held: it may belong to a restarted Core).
    """
    page = browser_page
    core = _FakeCore()
    core.append("old-update-line-1\nold-update-line-2\n")

    _follow_with(page, webui, core)
    _wait_for_marker(page, "old-update-line-2")
    polls_before = len(core.requests)

    core.new_update("new-update-line-1\n")
    _wait_for_marker(page, "new-update-line-1")

    out = page.locator('textarea[name="pfb_output"]').input_value()
    assert out == "new-update-line-1\n", f"the new Update's log must replace the old one, the box holds {out!r}"
    assert None in core.requests[polls_before:], (
        f"the page must re-read the new Update from its start: {core.requests!r}"
    )


@pytest.mark.ui_browser
def test_update_poller_reports_a_core_error_and_stops(browser_page: Page, webui: WebUI) -> None:
    """An error from the poll endpoint is shown in the status box and ends the polling.

    Scenario:
      Given Core does not answer the page's GetUpdate (the endpoint's {error, done:true}),
      When the View button wires the poller,
      Then the status box carries the error text, and no further poll is made.
    """
    page = browser_page
    core = _FakeCore()
    core.error = "the Core API did not answer: Failed to connect"

    _follow_with(page, webui, core)
    _wait_for_status(page, core.error)

    with pytest.raises(sync_api.TimeoutError):  # absence, asserted only after the status barrier above
        page.wait_for_request(lambda r: "ajax=update" in r.url, timeout=2_500)
