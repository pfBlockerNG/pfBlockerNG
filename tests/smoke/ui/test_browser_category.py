"""Tier-B browser tests (ADR-14 Phase 4): the Category Summary page's inline JS.

These drive the client-side behaviours of ``pfblockerng_category.php?type=ipv4``
(the IPv4 "Summary" list page) that an HTTP POST cannot reach -- the
``confirm()``-gated save flow and the ``confirm()``-gated row-delete -- against
the LIVE webConfigurator on the ADR-04 smoke VM, reusing the Phase-1
authenticated session (the ``PHPSESSID`` cookie injected into the browser
context by the ``browser_context`` fixture, so the browser never logs in twice).

The JS under test is READ-ONLY reference (no ``src/`` change); the exact
ids/handlers/messages are taken from the page's inline ``<script>``
(``src/usr/local/www/pfblockerng/pfblockerng_category.php``):

* ``events.push(function(){...})`` (category.php:633-700) runs after
  DOMContentLoaded and (a) hides the result banner -- ``$('#savemsg_json').hide()``
  (category.php:695) -- and (b) binds the Save control --
  ``$('#btnsave').click(function(){ save_new_changes(); $('#savemsg_json').hide(); })``
  (category.php:696-699). So on load ``#savemsg_json`` (the ``<div id="savemsg_json">``
  at category.php:368) is present-but-hidden and ``#btnsave`` (the ``<button
  id="btnsave">`` at category.php:588) is wired. ``#btnsave`` lives in the
  always-rendered ``<nav class="action-buttons">`` (outside the per-row loop), so
  it exists even on a fresh box with no categories.
* ``save_new_changes()`` (category.php:635-679) opens a ``confirm()`` with the
  message ``"Save settings and/or page 'Order' changes?"`` (category.php:644)
  BEFORE issuing its ``$.ajax`` POST. Cancelling the confirm short-circuits the
  whole branch -- no AJAX, no ``$('form').submit()`` -- so the click's confirm()
  gate is observable with ZERO box side-effects (we never accept it here).
* ``pfb_rownamedelete()`` (category.php:627-631) is a GLOBAL function (defined
  unconditionally, outside ``events.push``) that opens a ``confirm('Delete
  selected entry?')`` (category.php:628) and only on accept does
  ``$('form').submit()``. The per-row trash icon's ``onclick``
  (category.php:536-539) sets ``#rowid``/``#act`` and calls it; a fresh box has
  NO category rows (the "No Alias/Groups are defined." placeholder renders
  instead, category.php:567-575), so no trash icon exists to click. We assert the
  function is wired and its confirm() gate fires (cancelling it), and DEFER the
  end-to-end row removal (needs an injected category row) -- see the module
  report.

For a ``confirm()`` dialog Playwright would otherwise auto-dismiss, the handler
(``page.on("dialog", ...)``) is registered BEFORE the click and records the
dialog so the test can assert it fired AND its message; we ``dismiss()`` every
dialog so no save/delete ever lands (the page stays a no-op).

NO fixed sleeps: every assertion uses Playwright's auto-waiting
(``expect(...).to_be_visible()`` / ``to_be_hidden()`` / ``wait_for_function``).
Per-page full-page screenshots are written to the ``screenshot_dir`` artifact
tree for human review.

Playwright is imported lazily via ``pytest.importorskip`` so importing/collecting
this module does not hard-error when Playwright is absent.

This file does NOT duplicate ``test_browser.py`` (which covers the
``pfblockerng_category_edit.php`` toggles/autocomplete/state-greying, the
dashboard widget, the DNSBL auto-VIP checkbox, and the hooks Add-row clone).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# Tier-B dep: guard the import so collecting this module without Playwright
# installed (this dev venv, or any host that skips the browser tier) does not
# hard-error. Everything below references `expect` from the imported module.
from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The IPv4 Category "Summary" page. ?type=ipv4 -> the IP list view; its inline
# <script> hosts the Save (confirm->AJAX) flow + the global pfb_rownamedelete().
# A fresh box serves it (the page renders with the "No Alias/Groups" placeholder
# when no categories are saved -- the JS wiring is unconditional regardless).
CATEGORY_IPV4 = "/pfblockerng/pfblockerng_category.php?type=ipv4"

# The exact confirm() messages from the inline JS -- asserting the message proves
# the SPECIFIC handler ran, not merely "some dialog appeared".
SAVE_CONFIRM_MSG = "Save settings and/or page 'Order' changes?"
DELETE_CONFIRM_MSG = "Delete selected entry?"

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


def test_savemsg_banner_hidden_and_save_button_wired_on_load(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """On load the result banner is hidden and the Save control is present.

    Proves the inline ``events.push`` block (category.php:633-700) ran: the
    ``#savemsg_json`` banner -- present in the DOM (category.php:368) -- is
    HIDDEN by the on-load ``$('#savemsg_json').hide()`` (category.php:695), and
    the ``#btnsave`` control (category.php:588, in the always-rendered
    action-buttons nav) is attached and visible (ready to receive the click
    binding at category.php:696). This is the deterministic before-state the
    save-confirm test builds on -- no rows or saved config needed.
    """
    page = browser_page
    _open(page, webui, CATEGORY_IPV4)

    banner = page.locator("#savemsg_json")
    save_btn = page.locator("#btnsave")

    # The banner div is rendered unconditionally; the on-load hide() must have run.
    expect(banner).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(banner).to_be_hidden(timeout=JS_TIMEOUT_MS)

    # The Save control lives in <nav class="action-buttons"> -- always rendered
    # (outside the per-row loop), visible (not in a collapsed panel).
    expect(save_btn).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "category_ipv4_summary")


def test_save_button_click_opens_confirm_and_cancel_is_a_noop(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Clicking ``#btnsave`` fires the save ``confirm()``; cancelling lands nothing.

    ``#btnsave``'s bound handler calls ``save_new_changes()`` (category.php:696),
    which opens ``confirm("Save settings and/or page 'Order' changes?")``
    (category.php:644) BEFORE its AJAX POST. Register the dialog handler BEFORE
    the click, capture the message, and DISMISS (cancel) -- so the ``$.ajax`` /
    ``$('form').submit()`` branch never runs and the box stays untouched.

    Before-state (CLAUDE.md): no dialog has been seen and the result banner is
    hidden. After the click: exactly the save confirm fired (asserted by its
    message), and -- because we cancelled -- we are STILL on the Category page
    (no navigation) with the banner still hidden. This proves the click->confirm
    wiring with zero side-effects; the accept path (AJAX/save/navigation) is
    DEFERRED (it persists/navigates) -- see the module report.
    """
    page = browser_page
    _open(page, webui, CATEGORY_IPV4)

    seen: list[str] = []

    def _on_dialog(dialog: object) -> None:
        # Record the message, then cancel so the gated AJAX/submit never runs.
        seen.append(dialog.message)  # type: ignore[attr-defined]
        dialog.dismiss()  # type: ignore[attr-defined]

    page.on("dialog", _on_dialog)

    save_btn = page.locator("#btnsave")
    banner = page.locator("#savemsg_json")

    # BEFORE: no dialog seen, banner hidden, and we are on the Category page.
    assert seen == [], "a dialog fired before the Save click"
    expect(banner).to_be_hidden(timeout=JS_TIMEOUT_MS)
    assert "pfblockerng_category.php" in page.url

    # CLICK -> the bound handler runs save_new_changes() -> confirm() fires
    # synchronously; the dialog handler records it and cancels before click()
    # returns (Playwright blocks the page on the dialog), so no sleep is needed.
    save_btn.click()
    expect(banner).to_be_hidden(timeout=JS_TIMEOUT_MS)

    # AFTER: exactly the save confirm fired, and cancelling kept us on the page
    # (no AJAX-success $('form').submit() navigation).
    assert SAVE_CONFIRM_MSG in seen, f"save confirm() did not fire; dialogs seen: {seen!r}"
    assert "pfblockerng_category.php" in page.url, f"cancel still navigated away (url={page.url!r})"
    _shot(page, screenshot_dir, "category_save_confirm_cancelled")


def test_row_delete_helper_is_wired_and_confirm_gates_it(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """``pfb_rownamedelete()`` is a global fn whose ``confirm()`` gates the submit.

    The per-row trash icon's ``onclick`` (category.php:536-539) calls the global
    ``pfb_rownamedelete()`` (category.php:627-631), which opens
    ``confirm('Delete selected entry?')`` and only on ACCEPT submits the form. A
    fresh box has NO category rows (the "No Alias/Groups are defined." placeholder
    renders instead, category.php:567-575), so there is no trash icon to click --
    we therefore drive the global function directly to exercise its confirm()
    gate, and DEFER the end-to-end row removal (needs an injected row).

    Before-state (CLAUDE.md): the function exists, no trash icons render (fresh
    box), and no dialog has fired. After invoking it: the delete confirm fired
    (asserted by its message) and -- because we cancel -- we are STILL on the
    Category page (the ``$('form').submit()`` was gated away). Zero side-effects.
    """
    page = browser_page
    _open(page, webui, CATEGORY_IPV4)

    # BEFORE: the global delete helper is defined (wiring present)...
    is_fn = page.evaluate("() => typeof window.pfb_rownamedelete === 'function'")
    assert is_fn is True, "pfb_rownamedelete is not a global function -- the inline JS did not define it"

    # ...and a fresh box renders no trash icons (no category rows to delete).
    trash = page.locator("i.fa-trash-can")
    assert trash.count() == 0, f"expected no delete icons on a fresh box, found {trash.count()}"
    _shot(page, screenshot_dir, "category_no_rows")

    seen: list[str] = []

    def _on_dialog(dialog: object) -> None:
        # Cancel: the accept branch ($('form').submit()) must NOT run.
        seen.append(dialog.message)  # type: ignore[attr-defined]
        dialog.dismiss()  # type: ignore[attr-defined]

    page.on("dialog", _on_dialog)

    assert seen == [], "a dialog fired before invoking pfb_rownamedelete()"
    assert "pfblockerng_category.php" in page.url

    # Invoke the real global handler -> its confirm() fires synchronously; the
    # dialog handler records it and cancels before evaluate() returns.
    page.evaluate("() => window.pfb_rownamedelete()")

    # AFTER: the delete confirm fired and the cancel kept us on the page (no
    # form submit -> no navigation, no delete).
    assert DELETE_CONFIRM_MSG in seen, f"delete confirm() did not fire; dialogs seen: {seen!r}"
    assert "pfblockerng_category.php" in page.url, f"cancel still navigated away (url={page.url!r})"
