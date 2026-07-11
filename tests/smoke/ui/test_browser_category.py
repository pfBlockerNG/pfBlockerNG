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

from .. import helpers

# Tier-B dep: guard the import so collecting this module without Playwright
# installed (this dev venv, or any host that skips the browser tier) does not
# hard-error. Everything below references `expect` from the imported module.
from .conftest import mask_page_identity
from .test_category import (
    CONF_NODE_BY_GTYPE,
    _page_url,
    _restore_node,
    _seed_three_rows,
    _snapshot_node,
)

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

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


# --------------------------------------------------------------------------- #
# ADR-63 Phase 3 (issue #1147): anchor-click reorder wired onto the LIVE
# category.php page (drag preserved). Unlike test_reorder_component.py (the
# standalone component contract against static fixtures), these drive the
# real page's AJAX Save -> config.xml persistence, seeding/restoring rows the
# same way test_category.py's ids[] oracles do.
# --------------------------------------------------------------------------- #


def _names(gtype: str) -> list[str]:
    """Three short (< 20 char), word-only aliasnames -- render unabridged."""
    return [f"pfbr{gtype}a", f"pfbr{gtype}b", f"pfbr{gtype}c"]


def _rows(page: Page) -> Locator:
    return page.locator("tr.sortable")


def _row_names(page: Page) -> list[str]:
    """Rendered Name-column text for every row, in current DOM order."""
    return [t.strip() for t in page.locator("tr.sortable td:first-child").all_text_contents()]


def _check_row(page: Page, i: int) -> None:
    _rows(page).nth(i).locator(".pfb-reorder-chk").check()


def _click_anchor(page: Page, i: int, *, shift: bool = False) -> None:
    _rows(page).nth(i).locator(".pfb-reorder-anchor").click(modifiers=["Shift"] if shift else None)


def _drag_row(page: Page, src: int, dst: int) -> None:
    """Drag row ``src`` to below row ``dst`` via real mouse events (distance:10 threshold).

    Grabs the first (Name) ``<td>`` -- plain text, not a form control -- since
    jQuery UI sortable's default ``cancel`` selector excludes
    input/textarea/button/select/option from starting a drag.
    """
    handle = _rows(page).nth(src).locator("td").first
    target = _rows(page).nth(dst)
    hb = handle.bounding_box()
    tb = target.bounding_box()
    assert hb is not None and tb is not None, "could not compute bounding boxes for drag handle/target"
    start_x, start_y = hb["x"] + hb["width"] / 2, hb["y"] + hb["height"] / 2
    page.mouse.move(start_x, start_y)
    page.mouse.down()
    page.mouse.move(start_x, start_y + 20, steps=5)
    page.mouse.move(tb["x"] + tb["width"] / 2, tb["y"] + tb["height"] + 5, steps=10)
    page.mouse.up()


def _save_via_ui(page: Page) -> None:
    """Click #btnsave, ACCEPT the save confirm(), wait for the resulting reload.

    Unlike the cancel-only tests above, this drives the real AJAX POST ->
    ``$('form').submit()`` -> full-page reload path (save_new_changes(),
    category.php:646-671), so the persisted config can be verified over SSH.
    """
    seen: list[str] = []

    def _on_dialog(dialog: object) -> None:
        seen.append(dialog.message)  # type: ignore[attr-defined]
        dialog.accept()  # type: ignore[attr-defined]

    page.on("dialog", _on_dialog)
    with page.expect_navigation(wait_until="networkidle", timeout=JS_TIMEOUT_MS * 3):
        page.locator("#btnsave").click()
    page.remove_listener("dialog", _on_dialog)
    assert SAVE_CONFIRM_MSG in seen, f"save confirm() did not fire; dialogs seen: {seen!r}"


def _persisted_names(vm: helpers.SmokeVM, node: str) -> list[str]:
    """The three seeded rows' aliasname, read from config.xml over SSH, in index order."""
    return [helpers.config_get(vm, f"{node}/{i}/aliasname") for i in range(3)]


_ROWORDER_PATH = "system/webgui/roworderdragging"


def _roworderdragging_enabled(vm: helpers.SmokeVM) -> bool:
    """Whether system/webgui/roworderdragging is present (pfSense checkbox: presence = ON)."""
    result = helpers.php_eval(vm, "echo config_path_enabled('system/webgui', 'roworderdragging') ? '1' : '0';")
    return result.stdout.strip().endswith("1")


def _set_roworderdragging(vm: helpers.SmokeVM, enabled: bool) -> None:
    """Set/clear the checkbox node -- presence = ON, matches config_path_enabled semantics."""
    if enabled:
        snippet = (
            f"config_set_path({helpers._php_str(_ROWORDER_PATH)}, '');\n"
            "write_config('pfBlockerNG smoke: set roworderdragging');\n"
            "echo 'OK';"
        )
    else:
        snippet = (
            f"config_del_path({helpers._php_str(_ROWORDER_PATH)});\n"
            "write_config('pfBlockerNG smoke: clear roworderdragging');\n"
            "echo 'OK';"
        )
    result = helpers.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_roworderdragging({enabled}) failed: rc={result.returncode} {result.stderr!r}")


@pytest.mark.parametrize("gtype", sorted(CONF_NODE_BY_GTYPE))
def test_reorder_drag_only_then_save_persists_dom_order(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """Drag-only reorder (no anchor-click), then Save: persisted order == DOM order.

    Behaviour-preserving regression: drag continues to reorder exactly as
    before this wiring landed -- only the client-side order-READ swapped from
    ``sortable('serialize')`` to ``pfb_reorder_read_order()``; the drag
    mechanics themselves (jQuery UI sortable options) are unchanged.
    """
    vm = smoke_vm
    node = CONF_NODE_BY_GTYPE[gtype]
    names = _names(gtype)
    snap = _snapshot_node(vm, node)
    try:
        _seed_three_rows(vm, node, gtype, names)
        page = browser_page
        _open(page, webui, _page_url(gtype))

        before = _row_names(page)
        assert before == names, f"seeded rows did not render in order {names}, got {before!r}"

        # Drag row 0 (a) below row 2 (c) -> DOM order becomes [b, c, a].
        _drag_row(page, 0, 2)
        after_drag = _row_names(page)
        expected = [names[1], names[2], names[0]]
        assert after_drag == expected, f"drag did not relocate row 0: got {after_drag!r}, expected {expected!r}"

        _save_via_ui(page)

        persisted = _persisted_names(vm, node)
        assert persisted == expected, (
            f"drag-only Save did not persist the DOM order for gtype={gtype!r}: "
            f"expected {expected!r}, got {persisted!r}"
        )
    finally:
        _restore_node(vm, node, snap)


@pytest.mark.parametrize("gtype", sorted(CONF_NODE_BY_GTYPE))
def test_reorder_anchor_click_single_row_then_save_persists_dom_order(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """Anchor-click (single checked row, no drag) reorder, then Save: persisted == DOM order.

    This is the red->green delta (issue #1147): before this phase's wiring the
    page offered NO anchor-click control -- a touch/mobile user had no way to
    reorder rows at all.
    """
    vm = smoke_vm
    node = CONF_NODE_BY_GTYPE[gtype]
    names = _names(gtype)
    snap = _snapshot_node(vm, node)
    try:
        _seed_three_rows(vm, node, gtype, names)
        page = browser_page
        _open(page, webui, _page_url(gtype))

        before = _row_names(page)
        assert before == names, f"seeded rows did not render in order {names}, got {before!r}"

        # On a <tr> page the injected control must be a real <td> (valid table
        # markup, aligns under the Reorder <th>), and the checkbox/anchor must
        # carry an accessible name -- not the bare arrow glyph (PR #1205 review).
        assert page.locator("tr.sortable td.pfb-reorder-ctl").count() == len(names), (
            f"reorder control must be a <td> per row on {gtype}: "
            f"found {page.locator('tr.sortable td.pfb-reorder-ctl').count()}, expected {len(names)}"
        )
        assert page.locator("tr.sortable td.pfb-reorder-ctl .pfb-reorder-chk[aria-label]").count() == len(names), (
            "each injected reorder checkbox must carry an aria-label"
        )
        assert page.locator("tr.sortable td.pfb-reorder-ctl .pfb-reorder-anchor[aria-label]").count() == len(names), (
            "each injected reorder anchor must carry an aria-label"
        )

        # Check row 2 (c), plain-anchor-click row 0 (a) -> c moves before a: [c, a, b].
        _check_row(page, 2)
        _click_anchor(page, 0, shift=False)
        after_click = _row_names(page)
        expected = [names[2], names[0], names[1]]
        assert after_click == expected, (
            f"anchor-click did not relocate row 2: got {after_click!r}, expected {expected!r}"
        )

        _save_via_ui(page)

        persisted = _persisted_names(vm, node)
        assert persisted == expected, (
            f"anchor-click-only Save did not persist the DOM order for gtype={gtype!r}: "
            f"expected {expected!r}, got {persisted!r}"
        )
    finally:
        _restore_node(vm, node, snap)


@pytest.mark.parametrize("gtype", sorted(CONF_NODE_BY_GTYPE))
def test_reorder_anchor_click_straddle_then_save_persists_dom_order(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """Checked rows straddling the anchor on both sides, then Save: persisted == DOM order.

    Given [a, b, c] (indices 0,1,2). Check a (0) and c (2); plain-anchor-click
    b (1): both relocate immediately before b, preserving their relative
    order (a before c) -- final order [a, c, b].
    """
    vm = smoke_vm
    node = CONF_NODE_BY_GTYPE[gtype]
    names = _names(gtype)
    snap = _snapshot_node(vm, node)
    try:
        _seed_three_rows(vm, node, gtype, names)
        page = browser_page
        _open(page, webui, _page_url(gtype))

        before = _row_names(page)
        assert before == names, f"seeded rows did not render in order {names}, got {before!r}"

        _check_row(page, 0)
        _check_row(page, 2)
        _click_anchor(page, 1, shift=False)
        after_click = _row_names(page)
        expected = [names[0], names[2], names[1]]
        assert after_click == expected, f"straddle anchor-click produced {after_click!r}, expected {expected!r}"

        _save_via_ui(page)

        persisted = _persisted_names(vm, node)
        assert persisted == expected, (
            f"straddle anchor-click Save did not persist the DOM order for gtype={gtype!r}: "
            f"expected {expected!r}, got {persisted!r}"
        )
    finally:
        _restore_node(vm, node, snap)


@pytest.mark.parametrize("gtype", sorted(CONF_NODE_BY_GTYPE))
def test_reorder_mixed_drag_then_anchor_click_then_save_persists_dom_order(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """One drag move, then one anchor-click move, in the SAME session, then Save.

    Given [a, b, c]. Drag a (0) below b (1) -> [b, a, c]. Then check a (now
    index 1), shift-anchor-click c (now index 2, after) -> a relocates after
    c -> [b, c, a].
    """
    vm = smoke_vm
    node = CONF_NODE_BY_GTYPE[gtype]
    names = _names(gtype)
    snap = _snapshot_node(vm, node)
    try:
        _seed_three_rows(vm, node, gtype, names)
        page = browser_page
        _open(page, webui, _page_url(gtype))

        before = _row_names(page)
        assert before == names, f"seeded rows did not render in order {names}, got {before!r}"

        # Drag: a (0) below b (1) -> [b, a, c]
        _drag_row(page, 0, 1)
        after_drag = _row_names(page)
        expected_after_drag = [names[1], names[0], names[2]]
        assert after_drag == expected_after_drag, f"drag step produced {after_drag!r}, expected {expected_after_drag!r}"

        # Anchor-click: check a (now index 1), shift-click c (now index 2) -> after c: [b, c, a]
        _check_row(page, 1)
        _click_anchor(page, 2, shift=True)
        after_click = _row_names(page)
        expected_final = [names[1], names[2], names[0]]
        assert after_click == expected_final, f"mixed drag+anchor produced {after_click!r}, expected {expected_final!r}"

        _save_via_ui(page)

        persisted = _persisted_names(vm, node)
        assert persisted == expected_final, (
            f"mixed drag+anchor Save did not persist the DOM order for gtype={gtype!r}: "
            f"expected {expected_final!r}, got {persisted!r}"
        )
    finally:
        _restore_node(vm, node, snap)


def test_reorder_roworderdragging_set_disables_drag_anchor_click_still_persists(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """system/webgui/roworderdragging SET: no drag handles render; anchor-click still persists.

    Decision 2 (ADR-63): dragEnabled = !roworderdragging. When the admin has
    globally disabled row-drag, the Category page must still offer the
    anchor-click reorder as a full-fidelity fallback -- proving both the
    render gate (no .sortable() instance) and the FULL reorder+Save+reload
    round trip (a render check alone would miss a serialize-time regression).
    """
    vm = smoke_vm
    node = CONF_NODE_BY_GTYPE["ipv4"]
    names = _names("ipv4")
    was_enabled = _roworderdragging_enabled(vm)
    snap = _snapshot_node(vm, node)
    try:
        _set_roworderdragging(vm, True)
        _seed_three_rows(vm, node, "ipv4", names)
        page = browser_page
        _open(page, webui, _page_url("ipv4"))

        has_instance = page.evaluate("() => $('#pfb_table table tbody').sortable('instance') !== undefined")
        assert has_instance is False, "roworderdragging SET must never initialise .sortable()"

        before = _row_names(page)
        assert before == names, f"seeded rows did not render in order {names}, got {before!r}"

        _check_row(page, 2)
        _click_anchor(page, 0, shift=False)
        after_click = _row_names(page)
        expected = [names[2], names[0], names[1]]
        assert after_click == expected, f"anchor-click (drag disabled) produced {after_click!r}, expected {expected!r}"

        _save_via_ui(page)

        persisted = _persisted_names(vm, node)
        assert persisted == expected, (
            f"anchor-click Save under roworderdragging=SET did not persist: expected {expected!r}, got {persisted!r}"
        )
    finally:
        _restore_node(vm, node, snap)
        _set_roworderdragging(vm, was_enabled)


def test_reorder_save_with_field_edit_only_and_zero_reorder_still_persists_field(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A Save with a per-row field edit and NO drag/anchor-click still lands the edit.

    Proves #btnsave is never gated by a staged reorder (Constraints: onAfterMove
    is passed as null, so a staged or zero-checked anchor-click can never touch
    Save-button/dirty state).
    """
    vm = smoke_vm
    node = CONF_NODE_BY_GTYPE["ipv4"]
    names = _names("ipv4")
    snap = _snapshot_node(vm, node)
    try:
        _seed_three_rows(vm, node, "ipv4", names)
        page = browser_page
        _open(page, webui, _page_url("ipv4"))

        before = _row_names(page)
        assert before == names, f"seeded rows did not render in order {names}, got {before!r}"
        before_action = helpers.config_get(vm, f"{node}/0/action")
        assert before_action == "Deny_Inbound", f"seed action must start Deny_Inbound, got {before_action!r}"

        # Field edit only -- no checkbox, no anchor-click, no drag.
        page.locator("select[id='action-0']").select_option("Permit_Both")

        _save_via_ui(page)

        persisted_order = _persisted_names(vm, node)
        assert persisted_order == names, (
            f"a field-edit-only Save (zero reorder staged) must leave row order unchanged: "
            f"expected {names!r}, got {persisted_order!r}"
        )
        persisted_action = helpers.config_get(vm, f"{node}/0/action")
        assert persisted_action == "Permit_Both", (
            f"field-edit-only Save did not persist the action edit, got {persisted_action!r}"
        )
    finally:
        _restore_node(vm, node, snap)


def test_reorder_geoip_page_injects_no_anchor_ui(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """GeoIP renders NO reorder anchor/checkbox controls (container '#pfb_table' resolves empty).

    issue #1201: GeoIP has no ids[] persist sink; pfb_reorder_init('#pfb_table
    ...') on the GeoIP page (whose table id is 'pfb_table_geoip') matches zero
    elements, so it injects nothing -- proven directly against the rendered DOM.
    """
    page = browser_page
    _open(page, webui, _page_url("geoip"))

    anchors = page.locator(".pfb-reorder-anchor")
    assert anchors.count() == 0, f"GeoIP page must inject NO reorder anchors, found {anchors.count()}"
    checks = page.locator(".pfb-reorder-chk")
    assert checks.count() == 0, f"GeoIP page must inject NO reorder checkboxes, found {checks.count()}"
