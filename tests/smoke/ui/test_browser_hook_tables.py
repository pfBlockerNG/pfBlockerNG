"""Tier-B browser tests (issue #1871): the Edit Hooks picker is a table with actions.

The page listed existing hook scripts as a run of inline links -- one ``Pre``
row and one ``Post`` row of names separated by spaces, the name itself being
the link that loads the script. Two consequences:

* **There was no way to delete a hook script from the Web UI at all.** Once
  created, a hook could only be neutered by emptying its contents; removing the
  file needed shell access, so a typo in the Name field at creation time was
  unrecoverable from the GUI.
* The list did not follow the row-with-actions pattern used elsewhere in the
  package (the IP/DNSBL group lists render each entry as a table row with
  pencil and trash-can icons).

These are structural/visual facts about rendered markup plus a multi-step flow
(create -> delete -> confirm it is gone), so they are observable only in this
tier -- testing.md mandate 4 names both cases explicitly.

The delete test is self-cleaning: it creates its own hook script through the
page's own create flow and then deletes it, so the box's hook directory ends
the test exactly as it started. It never touches a script it did not create.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

from .test_browser_lint import HOOKS_PAGE, JS_TIMEOUT_MS, _open

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Dialog, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# A name this suite owns outright, so nothing here can collide with an operator's
# real hook or with another test's fixture.
PROBE_CORE = "pfb_uitest_hook"
PROBE_SCRIPT = f"hook_post_{PROBE_CORE}.sh"


def _create_probe_hook(page: Page, webui: WebUI) -> None:
    """Create ``hook_post_pfb_uitest_hook.sh`` through the page's own create flow."""
    _open(page, webui, HOOKS_PAGE)
    page.select_option("#pfb_eh_new_when", "post")
    page.fill("#pfb_eh_new_core", PROBE_CORE)
    page.select_option("#pfb_eh_new_lang", "sh")
    page.click("[name='pfb_eh_create']")
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)


def _delete_probe_hook_if_present(page: Page, webui: WebUI) -> None:
    """Best-effort cleanup so a failed assertion cannot leave the box dirty."""
    _open(page, webui, HOOKS_PAGE)
    row = page.locator(f"tr[data-pfb-hook='{PROBE_SCRIPT}']")
    if row.count():
        page.once("dialog", lambda dialog: dialog.accept())
        row.locator(".fa-trash-can").click()
        page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)


@pytest.fixture
def probe_hook(browser_page: Page, webui: WebUI) -> Iterator[str]:
    """Create the probe hook for a test, and make sure it is gone afterwards."""
    _create_probe_hook(browser_page, webui)
    try:
        yield PROBE_SCRIPT
    finally:
        _delete_probe_hook_if_present(browser_page, webui)


def test_hook_scripts_are_listed_in_pre_and_post_tables(
    browser_page: Page,
    webui: WebUI,
    probe_hook: str,
) -> None:
    """One table per Pre/Post group, one row per script, the name a plain cell.

    Before this change the names were bare ``<a>`` links with no table and no
    per-row actions, so both halves of the assertion failed.
    """
    page = browser_page
    _open(page, webui, HOOKS_PAGE)

    for when in ("pre", "post"):
        table = page.locator(f"table[data-pfb-hook-table='{when}']")
        expect(table).to_be_attached(timeout=JS_TIMEOUT_MS)

    row = page.locator(f"tr[data-pfb-hook='{probe_hook}']")
    expect(row).to_be_visible(timeout=JS_TIMEOUT_MS)

    name_cell = row.locator("td").first
    assert (name_cell.text_content() or "").strip() == probe_hook, (
        "the script name must be a plain table cell, not the click target"
    )
    assert name_cell.locator("a").count() == 0, "the name cell must not be a link -- the pencil action loads the script"


def test_each_row_has_a_pencil_action_that_loads_the_script(
    browser_page: Page,
    webui: WebUI,
    probe_hook: str,
) -> None:
    """The pencil loads the script into the editor -- replacing the name-as-link."""
    page = browser_page
    _open(page, webui, HOOKS_PAGE)

    row = page.locator(f"tr[data-pfb-hook='{probe_hook}']")
    expect(row).to_be_visible(timeout=JS_TIMEOUT_MS)
    pencil = row.locator("a .fa-pencil")
    expect(pencil).to_be_visible(timeout=JS_TIMEOUT_MS)

    pencil.click()
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)

    # The "Now editing" line names the loaded script once the pencil has done its job.
    expect(page.locator("form")).to_contain_text(probe_hook, timeout=JS_TIMEOUT_MS)
    assert page.locator("#pfb_eh_cur_script").input_value() == probe_hook, (
        "the pencil must load the row's script into the editor"
    )


def test_a_hook_script_can_be_deleted_from_the_web_ui(
    browser_page: Page,
    webui: WebUI,
    probe_hook: str,
) -> None:
    """Create -> delete -> gone. The capability the page never had.

    Asserts the before-state (the row IS listed) first, so green proves the
    delete caused the disappearance rather than the row never existing.
    """
    page = browser_page
    _open(page, webui, HOOKS_PAGE)

    row = page.locator(f"tr[data-pfb-hook='{probe_hook}']")
    # Before-state: the freshly created hook IS listed, so green proves the delete
    # caused the row to disappear rather than it never having been there.
    expect(row).to_be_visible(timeout=JS_TIMEOUT_MS)

    page.once("dialog", lambda dialog: dialog.accept())
    row.locator(".fa-trash-can").click()
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)

    expect(page.locator(f"tr[data-pfb-hook='{probe_hook}']")).to_have_count(0, timeout=JS_TIMEOUT_MS)


def test_saving_a_script_still_works_alongside_the_delete_field(
    browser_page: Page,
    webui: WebUI,
    probe_hook: str,
) -> None:
    """Save still saves once the delete flow's hidden fields exist on the form.

    The delete action posts through hidden inputs on the page's single form, and
    a browser submits hidden inputs on EVERY submit -- including a Save. A
    delete branch guarded on presence alone therefore swallows Save, fails, and
    discards whatever the admin had typed. This pins the dispatch: Save reaches
    the save handler, the content is written, and it survives a reload.
    """
    page = browser_page
    _open(page, webui, HOOKS_PAGE)

    row = page.locator(f"tr[data-pfb-hook='{probe_hook}']")
    expect(row).to_be_visible(timeout=JS_TIMEOUT_MS)
    row.locator("a .fa-pencil").click()
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#pfb_eh_cur_script").input_value() == probe_hook, "precondition: the script is loaded"

    marker = "# pfb-uitest-save-marker"
    content = page.locator(".cm-content")
    expect(content).to_be_visible(timeout=JS_TIMEOUT_MS)
    content.click()
    page.keyboard.press("ControlOrMeta+a")
    page.keyboard.press("Delete")
    content.press_sequentially(f"#!/bin/sh\n{marker}\nexit 0", delay=20)

    page.click("[name='pfb_eh_save']")
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)

    # The save handler's own PRG lands on ?saved=1; the delete branch would
    # instead have produced an input-error box and an emptied editor.
    expect(page.locator(".alert-success")).to_contain_text("saved", timeout=JS_TIMEOUT_MS)
    expect(page.locator(".input-errors")).to_have_count(0)

    # The content itself round-tripped. The field's id is pfb_hook_editor_content
    # ('pfb_eh_content' is its NAME, the POST key); it is the hidden mirror textarea
    # behind the CodeMirror view, so its VALUE is what the page re-rendered from
    # disk -- proving the bytes reached the file rather than only that the page
    # reported success.
    expect(page.locator("#pfb_hook_editor_content")).to_have_value(re.compile(re.escape(marker)), timeout=JS_TIMEOUT_MS)


def test_dismissing_the_delete_confirmation_keeps_the_script(
    browser_page: Page,
    webui: WebUI,
    probe_hook: str,
) -> None:
    """Deleting a hook is irreversible from the UI, so the confirmation must hold.

    The other branch of the confirm dialog: dismissing it leaves the script in
    place. Without this, a confirmation that was wired but always proceeded
    would pass every other test here.
    """
    page = browser_page
    _open(page, webui, HOOKS_PAGE)

    row = page.locator(f"tr[data-pfb-hook='{probe_hook}']")
    expect(row).to_be_visible(timeout=JS_TIMEOUT_MS)

    dialogs: list[str] = []

    def dismiss_dialog(dialog: Dialog) -> None:
        dialogs.append(dialog.type)
        dialog.dismiss()

    page.once("dialog", dismiss_dialog)
    row.locator(".fa-trash-can").click()
    assert dialogs == ["confirm"], "the delete action must show one confirmation dialog"
    expect(row).to_be_visible(timeout=JS_TIMEOUT_MS)

    _open(page, webui, HOOKS_PAGE)
    expect(page.locator(f"tr[data-pfb-hook='{probe_hook}']")).to_have_count(1, timeout=JS_TIMEOUT_MS)


def test_enter_in_name_field_never_discards_unsaved_editor_content(
    browser_page: Page,
    webui: WebUI,
    probe_hook: str,
) -> None:
    """A stray Enter in the Name field must not cost unsaved editor work (#1884).

    ``#pfb_eh_new_core`` is the form's only text input and Create is its first
    submit button, so the browser treats Enter there as a Create click. When
    that create fails validation, the page must come back with the loaded
    script still loaded and the unsaved buffer intact -- not the empty
    "Load an existing script above" state.
    """
    page = browser_page
    _open(page, webui, HOOKS_PAGE)

    row = page.locator(f"tr[data-pfb-hook='{probe_hook}']")
    expect(row).to_be_visible(timeout=JS_TIMEOUT_MS)
    row.locator("a .fa-pencil").click()
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#pfb_eh_cur_script").input_value() == probe_hook, "precondition: the script is loaded"

    marker = "# pfb-uitest-enter-keeps-buffer"
    content = page.locator(".cm-content")
    expect(content).to_be_visible(timeout=JS_TIMEOUT_MS)
    content.click()
    page.keyboard.press("ControlOrMeta+a")
    page.keyboard.press("Delete")
    content.press_sequentially(f"#!/bin/sh\n{marker}\nexit 0", delay=20)

    # The probe hook is a POST hook -- pick the OPPOSITE create-When so the echo
    # assertion below cannot be satisfied by the restored loaded-script when.
    page.select_option("#pfb_eh_new_when", "pre")

    # A hyphen fails the compose validation (letters/digits/underscores only),
    # and Enter submits the form as Create.
    name = page.locator("#pfb_eh_new_core")
    name.click()
    name.fill("bad-name")
    name.press("Enter")
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)

    # Before-state of the defect: the create DID run and DID fail validation --
    # so green proves the restore, not that the submit never happened.
    expect(page.locator(".input-errors")).to_contain_text("Invalid new-hook fields", timeout=JS_TIMEOUT_MS)

    # The data-loss pin: the loaded script and the unsaved buffer both survive.
    assert page.locator("#pfb_eh_cur_script").input_value() == probe_hook, (
        "a failed create must keep the loaded script loaded"
    )
    expect(page.locator("#pfb_hook_editor_content")).to_have_value(re.compile(re.escape(marker)), timeout=JS_TIMEOUT_MS)

    # The typed create-When echo also survives the error -- distinct from the
    # loaded script's own when (set to the opposite above).
    assert page.locator("#pfb_eh_new_when").input_value() == "pre", (
        "the typed create-When choice must still be selected after a validation error"
    )
