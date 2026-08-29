"""Tier-B browser tests (issue #1875 step 3): the CM6 plain-list editor shell actually
MOUNTS on the 9 fields the #1875 rollout wired ("pfblockerng: mount the shared list
editor on every plaintext list field"), and follows the textarea's
disabled state. This is client-side-only progressive enhancement (``pfbCM.mountLists``
replacing a ``Form_Textarea`` with a CodeMirror 6 view) -- a source-level grep can pin the
``mountLists([...])`` call sites, but only a real browser proves the JS actually ran: the
element exists, replaced the right textarea, and the hidden mirror stays in sync. No other
tier observes this (testing.md mandate 4).

Reuses helpers rather than re-deriving the panel-expansion dance: ``_open``/``_shot``/
``JS_TIMEOUT_MS``/``_clear_and_type`` come from ``test_browser_lint.py``, ``_line_numbers``
from ``test_browser_line_numbers.py``, and ``ADVANCED_IP_EDITOR`` (the no-rowid, new-group
category_edit URL) from ``test_browser.py``.

Mount contract pinned here (``tools/webassets/cm-shell.js``'s ``mountTextarea``):
the CM6 view is inserted ``beforebegin`` the textarea (so ``.cm-editor`` is the textarea's
immediately-PRECEDING sibling) and the textarea itself is set ``display: none`` -- both
asserted per field, never one alone (a half-mounted editor sitting next to a still-visible
textarea is exactly the kind of defect a source-only pin would miss).

Three of the fields are gated behind a checkbox that ``.hide()``/``.show()``s their whole
section (``pfb_gp`` / ``pfb_noaaaa`` / ``tld_wildcard`` -- all default OFF on a fresh box), on
top of the ``COLLAPSIBLE|SEC_CLOSED`` panel-body collapse every field's section also
carries; ``_gate`` and ``_expand`` drive those two independent layers.

The category_edit "custom" field row deliberately uses ``ADVANCED_IP_EDITOR`` (no
``rowid`` -- a brand-new, unsaved group): this is also the live proof for the #1875
sort-mode-placement fix (the mount init used to sit inside the ADR-63 no-sort
conditional, so a new group with no rows rendered no editor at all). A separate test
reopening the identical URL to reassert the identical DOM would add nothing, so that one
parametrized row IS the "new-group" coverage row the brief calls out -- no duplicate test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .test_browser import ADVANCED_IP_EDITOR
from .test_browser_line_numbers import _line_numbers
from .test_browser_lint import DNSBL_PAGE, JS_TIMEOUT_MS, _clear_and_type, _open, _shot

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from playwright.sync_api import Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

IP_PAGE = "/pfblockerng/pfblockerng_ip.php"
GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"

# RFC 5737 TEST-NET-1 -- inert, never routed; plain "one per line" content, no regex/lint
# concerns (these are the plain-list mode, not the DNSBL regex editor).
THREE_IPS = "192.0.2.1\n192.0.2.2\n192.0.2.3"


def _gate(page: Page, checkbox_id: str) -> None:
    """Check a section-gating checkbox (default OFF) so its ``.hide()``d section shows."""
    box = page.locator(f"#{checkbox_id}")
    expect(box).to_be_attached(timeout=JS_TIMEOUT_MS)
    if not box.is_checked():
        box.evaluate("el => el.click()")
    expect(box).to_be_checked(timeout=JS_TIMEOUT_MS)


def _expand(page: Page, section_id: str) -> None:
    """Expand a ``COLLAPSIBLE|SEC_CLOSED`` panel-body (same dance as ``_regex_editor``)."""
    body = page.locator(f"#{section_id}_panel-body")
    expect(body).to_be_attached(timeout=JS_TIMEOUT_MS)
    if "in" not in (body.get_attribute("class") or ""):
        page.locator(f'a[data-toggle="collapse"][href="#{section_id}_panel-body"]').click()
    expect(body).to_be_visible(timeout=JS_TIMEOUT_MS)


_CM_EDITOR_XPATH = "xpath=preceding-sibling::*[1][contains(concat(' ', normalize-space(@class), ' '), ' cm-editor ')]"


def _editor_for(page: Page, field_id: str) -> Locator:
    """The ``.cm-editor`` mounted ``beforebegin`` textarea ``#<field_id>`` (mountTextarea contract)."""
    return page.locator(f"#{field_id}").locator(_CM_EDITOR_XPATH)


def _assert_mounted(page: Page, page_label: str, field_id: str) -> None:
    """A field is "mounted" iff its textarea is hidden AND exactly one ``.cm-editor``
    sits immediately before it in the DOM -- a field whose mount never ran leaves the
    textarea visible with no such sibling.
    """
    textarea = page.locator(f"#{field_id}")
    editor = _editor_for(page, field_id)
    try:
        expect(textarea).to_be_attached(timeout=JS_TIMEOUT_MS)
        expect(editor).to_be_attached(timeout=JS_TIMEOUT_MS)
        expect(textarea).to_be_hidden(timeout=JS_TIMEOUT_MS)
    except AssertionError as exc:
        raise AssertionError(
            f"{page_label} field {field_id!r}: editor did not mount -- expected the "
            f"textarea hidden with one .cm-editor immediately preceding it; "
            f"textarea_visible={textarea.is_visible()!r} cm_editor_count={editor.count()}\n{exc}"
        ) from exc


def _prep_noop(_page: Page) -> None:
    """No gating -- the field's section is always rendered and expanded (general allowlist)."""


def _prep_gp(page: Page) -> None:
    _gate(page, "pfb_gp")
    _expand(page, "Python_Group_Policy")


def _prep_noaaaa(page: Page) -> None:
    _gate(page, "pfb_noaaaa")
    _expand(page, "Python_noaaaa_list")


def _prep_whitelist(page: Page) -> None:
    _expand(page, "DNSBL_Whitelist_customlist")


def _prep_tld_exclusion(page: Page) -> None:
    _gate(page, "tld_wildcard")
    _expand(page, "TLD_Exclusion")


def _prep_tld_blacklist(page: Page) -> None:
    _gate(page, "tld_wildcard")
    _expand(page, "TLD_BW_list")


def _prep_v4_suppression(page: Page) -> None:
    _expand(page, "IPv4_Suppression_customlist")


def _prep_v6_suppression(page: Page) -> None:
    _expand(page, "IPv6_Suppression_customlist")


def _prep_category_custom(page: Page) -> None:
    _expand(page, "IPv4customlist")


# (page label, path, field id, prep callback) -- the 9 fields wired by #1875 step 2b.
FIELDS: list[tuple[str, str, str, "Callable[[Page], None]"]] = [
    ("dnsbl", DNSBL_PAGE, "pfb_gp_bypass_list", _prep_gp),
    ("dnsbl", DNSBL_PAGE, "pfb_noaaaa_list", _prep_noaaaa),
    ("dnsbl", DNSBL_PAGE, "whitelist", _prep_whitelist),
    ("dnsbl", DNSBL_PAGE, "tld_wildcard_exclusion", _prep_tld_exclusion),
    ("dnsbl", DNSBL_PAGE, "tld_wildcard_blacklist", _prep_tld_blacklist),
    ("ip", IP_PAGE, "v4suppression", _prep_v4_suppression),
    ("ip", IP_PAGE, "v6suppression", _prep_v6_suppression),
    ("general", GENERAL_PAGE, "pfb_feed_internal_allowlist", _prep_noop),
    # No rowid -- new group; also the sort-mode-placement-fix proof (see module docstring).
    ("category_edit(new-group)", ADVANCED_IP_EDITOR, "custom", _prep_category_custom),
]


@pytest.mark.parametrize(("page_label", "path", "field_id", "prep"), FIELDS, ids=[f"{f[0]}:{f[2]}" for f in FIELDS])
def test_editor_mounts_on_every_wired_field(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
    page_label: str,
    path: str,
    field_id: str,
    prep: Callable[[Page], None],
) -> None:
    """Every one of the 9 #1875 fields mounts a CM6 editor: textarea hidden + `.cm-editor` adjacent."""
    page = browser_page
    _open(page, webui, path)
    prep(page)
    _assert_mounted(page, f"{page_label} ({path})", field_id)
    if field_id in ("whitelist", "custom"):
        _shot(page, screenshot_dir, f"list_editor_mount_{page_label.split('(')[0]}_{field_id}")


def test_whitelist_editor_types_and_syncs_hidden_textarea(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Interactive spot-check on one representative plain-list field (DNSBL whitelist):
    typing 3 lines numbers the gutter 1-3 AND syncs the hidden textarea's value -- the
    data-loss contract a plain-list mount must honour (a mount that replaced the textarea
    but never wired ``updateListener`` would pass the mount-presence test above and still
    silently drop every edit on save).
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _expand(page, "DNSBL_Whitelist_customlist")

    textarea = page.locator("#whitelist")
    content = _editor_for(page, "whitelist").locator(".cm-content")
    expect(content).to_be_visible(timeout=JS_TIMEOUT_MS)

    _clear_and_type(content, THREE_IPS)

    numbers = _line_numbers(content)
    assert numbers == ["1", "2", "3"], f"whitelist editor gutter: expected ['1', '2', '3'], got {numbers!r}"

    synced = textarea.input_value()
    assert synced == THREE_IPS, (
        f"whitelist editor: hidden textarea did not sync typed content -- expected {THREE_IPS!r}, got {synced!r}"
    )
    _shot(page, screenshot_dir, "whitelist_editor_typed_and_synced")


def test_general_allowlist_editor_follows_disabled_state(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The internal-feed allowlist editor mirrors ``#pfb_feed_internal_filter``: OFF ->
    ``.cm-content`` non-editable and typing is a no-op; ON -> editable and typing works.
    Both directions, before-state asserted first (transition-test rule) -- proves
    ``cm-shell.js``'s mount-time editable facet AND its live ``MutationObserver`` follow
    ``disableInput()``'s runtime attribute flip, not just the initial page-load state.
    """
    page = browser_page
    _open(page, webui, GENERAL_PAGE)

    checkbox = page.locator("#pfb_feed_internal_filter")
    textarea = page.locator("#pfb_feed_internal_allowlist")
    content = _editor_for(page, "pfb_feed_internal_allowlist").locator(".cm-content")
    expect(checkbox).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(content).to_be_attached(timeout=JS_TIMEOUT_MS)

    # Drive to OFF first regardless of the box's current default (view-state only, no Save).
    if checkbox.is_checked():
        checkbox.evaluate("el => el.click()")
    expect(checkbox).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # BEFORE: filter off -> non-editable, greyed (cm-shell.js's contenteditable=false rule).
    expect(content).to_have_attribute("contenteditable", "false", timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "general_allowlist_disabled_before")

    before_doc = textarea.input_value()
    _clear_and_type(content, "should-not-appear")
    after_attempt_doc = textarea.input_value()
    assert after_attempt_doc == before_doc, (
        f"general allowlist: typing into a DISABLED editor changed the doc -- "
        f"expected unchanged {before_doc!r}, got {after_attempt_doc!r}"
    )

    # AFTER: check the filter on -> editable, typing works and syncs.
    checkbox.evaluate("el => el.click()")
    expect(checkbox).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(content).to_have_attribute("contenteditable", "true", timeout=JS_TIMEOUT_MS)

    _clear_and_type(content, "192.0.2.10")
    synced = textarea.input_value()
    assert synced == "192.0.2.10", (
        f"general allowlist: editor stayed non-functional after enabling the filter -- "
        f"expected synced textarea '192.0.2.10', got {synced!r}"
    )
    _shot(page, screenshot_dir, "general_allowlist_disabled_after_enabled")
