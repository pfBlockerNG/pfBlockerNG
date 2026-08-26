"""Tier-B browser tests (issue #1870): the syntax editors' view follows the CARET.

Both editors deliberately do NOT soft-wrap, so a line wider than the field is read
by scrolling horizontally -- which makes the view's horizontal position part of the
feature, not a cosmetic detail. Two reported failures, both asserted here:

1. Pressing Enter at the end of a long line leaves the view scrolled right, so the
   caret (correctly placed at the start of the new line) is off-screen to the left.
2. From a hand-scrolled position, typing snaps the view all the way right again on
   every keystroke, hiding the text as it is typed.

Only this tier can see it: the failure is the ``.cm-scroller``'s ``scrollLeft`` after
a real key event settles, which needs a real browser laying out real text in the real
page (the pfSense theme's CSS, the panel geometry and the shipped bundle together) --
a source-level pin cannot observe a scroll offset.

Both editors are driven because they are separate bundles built from separate entry
points (``cm-regex.js`` / ``cm-hooks.js``) over one shared shell (``cm-shell.js``):
a scroll fix wired into one shell but shadowed by one bundle's own extensions would
pass a single-editor test.

Reuses ``test_browser_lint.py``'s editor helpers (the DNSBL regex section is
COLLAPSIBLE|SEC_CLOSED and its CM instance only becomes usable after the panel
expands) rather than re-deriving the panel-expansion dance.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

import pytest

from .test_browser_lint import (
    DNSBL_PAGE,
    HOOKS_PAGE,
    JS_TIMEOUT_MS,
    _clear_and_type,
    _hook_editor,
    _open,
    _regex_editor,
    _shot,
)
from .webui import SESSION_COOKIE

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from playwright.sync_api import BrowserContext, Locator, Page

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The reported scenario is a phone: a narrow field, so nearly every line overflows, and
# a touch/mobile Chrome whose input path (composition, focus scrolling) differs from the
# desktop one. Emulation cannot reproduce the on-screen keyboard, but it does give the
# narrow viewport, the mobile UA string, touch events and the device pixel ratio.
PHONE_WIDTH = 412
PHONE_HEIGHT = 915
PHONE_SCALE = 2.625
PHONE_UA = (
    "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36"
)


# Viewport height once the on-screen keyboard is up. Android Chrome shrinks the layout
# viewport when the keyboard opens, which re-lays out the page under a focused editable
# -- the one step of the reported scenario that no device descriptor reproduces.
PHONE_HEIGHT_KEYBOARD_OPEN = 420

# A page-scale factor shrinks the VISUAL viewport while the layout viewport keeps its
# size -- the same relationship an on-screen keyboard creates, and the one CodeMirror
# tests for (`window.innerHeight - window.visualViewport.height > 1`) before it reaches
# for the caret-rescue path this file pins. A device descriptor alone never gets there,
# which is why the steady-state assertions above all pass on a defect that is real on a
# phone. 4x puts the visual viewport comfortably above the editor.
KEYBOARD_PAGE_SCALE = 4


@contextlib.contextmanager
def _phone_page(
    browser_context: BrowserContext,
    webui: WebUI,
    smoke_vm: SmokeVM,
) -> Iterator[Page]:
    """An authenticated page on a second, phone-emulating context of the same browser.

    Re-uses the session cookie rather than logging in again (a second login is a second
    flake source). Torn down with the test that asked for it.
    """
    browser = browser_context.browser
    assert browser is not None, "browser_context must come from a live browser"
    cookie = webui.session_cookie()
    if cookie is None:
        pytest.skip("no PHPSESSID on the webui session -- cannot authenticate the phone context")
    context = browser.new_context(
        ignore_https_errors=webui.base_url.startswith("https://"),
        viewport={"width": PHONE_WIDTH, "height": PHONE_HEIGHT},
        device_scale_factor=PHONE_SCALE,
        is_mobile=True,
        has_touch=True,
        user_agent=PHONE_UA,
    )
    context.add_cookies([{"name": SESSION_COOKIE, "value": cookie, "domain": smoke_vm.host, "path": "/"}])
    page = context.new_page()
    try:
        yield page
    finally:
        context.close()


@pytest.fixture(params=["desktop", "phone"])
def editor_page(
    request: pytest.FixtureRequest,
    browser_page: Page,
    browser_context: BrowserContext,
    webui: WebUI,
    smoke_vm: SmokeVM,
) -> Iterator[tuple[Page, str]]:
    """The authenticated page under test, once per form factor.

    ``desktop`` is the session-scoped context every other browser test uses; ``phone``
    emulates the device the failure was reported on.
    """
    if request.param == "desktop":
        yield browser_page, request.param
        return
    with _phone_page(browser_context, webui, smoke_vm) as page:
        yield page, request.param


@pytest.fixture
def phone_page(browser_context: BrowserContext, webui: WebUI, smoke_vm: SmokeVM) -> Iterator[Page]:
    """A phone-emulating authenticated page, for the mobile-only steps."""
    with _phone_page(browser_context, webui, smoke_vm) as page:
        yield page


# Long enough that the line cannot fit any plausible field width, so the editor is
# genuinely scrolled right before the action under test. Regex-list syntax on one
# side, shell on the other -- each editor gets a doc its own grammar accepts, so a
# lint/parse error can never be what moves the view.
LONG_REGEX_LINE = "^" + ("a" * 300) + "\\.example\\.com$"
LONG_SHELL_LINE = "echo " + ("a" * 300)

# The caret sits one character in from the left edge after a newline, so CM6 leaves a
# pixel or two of margin rather than a hard 0. Anything in this band is "scrolled back
# to the beginning"; the failure mode is a scrollLeft in the thousands.
AT_LEFT_PX = 8

# Frames the scroll position must hold still for before it is read. CM6 scrolls in its
# measure phase (one rAF after the key event), so the value immediately after a
# keystroke is the PREVIOUS position -- reading it without settling would fail even a
# correct editor. Capped so a permanently-oscillating view still returns a value to
# assert on instead of hanging.
_SETTLE_JS = """
el => new Promise((resolve) => {
  const scroller = el.closest('.cm-scroller');
  let last = -1, stable = 0, frames = 0;
  const tick = () => {
    const now = Math.round(scroller.scrollLeft);
    if (now === last) { stable += 1; } else { stable = 0; last = now; }
    frames += 1;
    if (stable >= 4 || frames >= 90) { resolve(now); return; }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
})
"""


def _settled_scroll_left(content: Locator) -> int:
    """The editor's horizontal scroll offset, once it has stopped moving."""
    return int(content.evaluate(_SETTLE_JS))


def _max_scroll_left(content: Locator) -> int:
    """The furthest right the editor CAN be scrolled -- the failure's landing spot."""
    return int(
        content.evaluate(
            "el => { const s = el.closest('.cm-scroller'); return Math.round(s.scrollWidth - s.clientWidth); }"
        )
    )


def _assert_scrolled_right(content: Locator, where: str) -> int:
    """Precondition: the long line really did push the view off to the right."""
    offset = _settled_scroll_left(content)
    assert offset > AT_LEFT_PX, (
        f"precondition failed at {where}: the editor is at scrollLeft={offset}, so the "
        "long line never scrolled the view right and the test below proves nothing"
    )
    return offset


# Caret a dozen characters into a line well down the document. Set through the DOM
# selection rather than a click: under a page-scale factor, input coordinates no longer
# map to the layout box a click target is computed from, and a click that misses leaves
# the caret at the end of the inserted text -- genuinely off screen, where CodeMirror
# scrolling to it is CORRECT and the tests below would fail on a healthy editor.
_PLACE_CARET_JS = """
el => { const lines = el.querySelectorAll('.cm-line');
 const line = lines[Math.min(lines.length - 1, 20)];
 const walk = document.createTreeWalker(line, NodeFilter.SHOW_TEXT);
 let node, seen = 0, target = null, off = 0;
 while ((node = walk.nextNode())) {
   if (seen + node.length >= 12) { target = node; off = 12 - seen; break; }
   seen += node.length; }
 if (!target) return false;
 const r = document.createRange(); r.setStart(target, off); r.collapse(true);
 const sel = document.getSelection(); sel.removeAllRanges(); sel.addRange(r);
 return true; }
"""

# Where the caret sits relative to both viewports, and how much room there is to slide
# sideways -- the conditions that decide whether the caret-rescue path is reached at all.
_REACH_JS = """
el => { const vv = window.visualViewport, sel = document.getSelection();
 const r = sel && sel.rangeCount ? sel.getRangeAt(0).getBoundingClientRect() : null;
 const s = el.closest('.cm-scroller');
 return {shrunk: vv ? window.innerHeight - vv.height : 0,
         belowBy: r && vv ? Math.round(r.top - (window.pageYOffset + vv.offsetTop + vv.height)) : null,
         belowLayoutBy: r ? Math.round(r.top - window.innerHeight) : null,
         scrollable: Math.round(s.scrollWidth - s.clientWidth)}; }
"""


def _seed_overflowing_document(page: Page, content: Locator) -> None:
    """Thirty overflowing lines: every line has somewhere to slide, and the caret can
    sit far enough down the document to be out of the shrunken viewport's reach.

    Inserted in one shot -- typing this many characters key-by-key would dominate the
    runtime and prove nothing extra.
    """
    page.keyboard.insert_text("\n".join(f"echo {i:02d} " + "a" * 200 for i in range(30)))
    expect(content).to_contain_text("echo 29", timeout=JS_TIMEOUT_MS)


def _place_caret_inside_a_line(content: Locator) -> None:
    assert content.evaluate(_PLACE_CARET_JS), "precondition: could not place the caret inside a line"


def _caret_offset_x(content: Locator) -> int | None:
    """The caret's distance from the scroller's left edge, or ``None`` with no selection."""
    return content.evaluate(
        "el => { const s = el.closest('.cm-scroller'); const sel = document.getSelection();"
        " if (!sel || !sel.rangeCount) return null;"
        " return Math.round(sel.getRangeAt(0).getBoundingClientRect().left - s.getBoundingClientRect().left); }"
    )


def _assert_the_keyboard_is_up(content: Locator) -> dict[str, float | None]:
    """Preconditions every keyboard-open test shares, and returns the reading.

    A page-scale factor that silently failed to apply, or a document with nothing to
    scroll sideways, makes these tests pass on broken code without exercising anything.
    """
    reach = content.evaluate(_REACH_JS)
    assert reach["shrunk"] > 1, f"precondition: the visual viewport must shrink; got {reach!r}"
    assert reach["scrollable"] > 0, f"precondition: the document must be horizontally scrollable; got {reach!r}"
    return reach


def _assert_the_rescue_path_is_reachable(content: Locator) -> None:
    """Additionally: the caret is far enough down that CodeMirror's rescue really runs.

    Only for the tests that need the rescue itself -- a caret CodeMirror has already
    scrolled into view (pressing End, say) legitimately fails these.

    ``belowLayoutBy`` is the subtle one. CodeMirror gates the rescue on the VISUAL
    viewport, but Chromium pans the visual viewport to the caret by itself whenever the
    caret is still within the LAYOUT viewport -- so with the editor high enough on the
    page every other precondition holds, the rescue never runs, and the defective bundle
    passes. Requiring the caret below ``innerHeight`` too pins the band where the browser
    cannot rescue it first; if a future page layout lifts the editor out of that band,
    the test fails loudly here instead of quietly measuring nothing.
    """
    reach = _assert_the_keyboard_is_up(content)
    assert reach["belowBy"] is not None and reach["belowBy"] > 0, (
        f"precondition: the caret must sit below the visual viewport; got {reach!r}"
    )
    assert reach["belowLayoutBy"] is not None and reach["belowLayoutBy"] > 0, (
        f"precondition: the caret must sit below the LAYOUT viewport too, or Chromium "
        f"pans it into view before CodeMirror's rescue can run; got {reach!r}"
    )


def _newline_returns_to_left(page: Page, content: Locator, long_line: str, screenshot_dir: Path, name: str) -> None:
    """Type ``long_line``, press Enter, and require the view back at the left edge."""
    _clear_and_type(content, long_line)
    _assert_scrolled_right(content, "end of the long line")

    page.keyboard.press("Enter")
    offset = _settled_scroll_left(content)
    _shot(page, screenshot_dir, name)

    assert offset <= AT_LEFT_PX, (
        f"after Enter the view stayed at scrollLeft={offset} (max {_max_scroll_left(content)}); "
        "the caret is at the start of the new line, so the view must follow it back to the left edge"
    )


def _typing_at_left_keeps_view_at_left(page: Page, content: Locator, long_line: str, typed: str) -> None:
    """With a long line above, typing on a short line must not snap the view right."""
    _clear_and_type(content, long_line)
    _assert_scrolled_right(content, "end of the long line")

    page.keyboard.press("Enter")
    assert _settled_scroll_left(content) <= AT_LEFT_PX, "precondition: Enter returns the view to the left edge"

    for char in typed:
        content.press_sequentially(char, delay=20)
        offset = _settled_scroll_left(content)
        assert offset <= AT_LEFT_PX, (
            f"typing {char!r} on a short line snapped the view to scrollLeft={offset} "
            f"(max {_max_scroll_left(content)}); the text being typed is off-screen"
        )


def test_regex_editor_newline_scrolls_back_to_the_left(
    editor_page: tuple[Page, str],
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """DNSBL regex list: Enter at the end of a long line brings the view back left."""
    page, form_factor = editor_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)
    _newline_returns_to_left(
        page, content, LONG_REGEX_LINE, screenshot_dir, f"regex_editor_newline_scroll_{form_factor}"
    )


def test_regex_editor_typing_on_a_short_line_stays_visible(
    editor_page: tuple[Page, str],
    webui: WebUI,
) -> None:
    """DNSBL regex list: each keystroke on a short line keeps the caret on screen."""
    page, _ = editor_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)
    _typing_at_left_keeps_view_at_left(page, content, LONG_REGEX_LINE, "^ok")


def test_hook_editor_newline_scrolls_back_to_the_left(
    editor_page: tuple[Page, str],
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Edit Hooks: separate bundle, same caret-tracking requirement."""
    page, form_factor = editor_page
    _open(page, webui, HOOKS_PAGE)
    content = _hook_editor(page)
    _newline_returns_to_left(
        page, content, LONG_SHELL_LINE, screenshot_dir, f"hook_editor_newline_scroll_{form_factor}"
    )


def test_hook_editor_typing_on_a_short_line_stays_visible(
    editor_page: tuple[Page, str],
    webui: WebUI,
) -> None:
    """Edit Hooks: each keystroke on a short line keeps the caret on screen."""
    page, _ = editor_page
    _open(page, webui, HOOKS_PAGE)
    content = _hook_editor(page)
    _typing_at_left_keeps_view_at_left(page, content, LONG_SHELL_LINE, "echo")


def _gutter_width(content: Locator) -> int:
    """Width of the editor's gutter column (line numbers + lint marker)."""
    return int(
        content.evaluate(
            "el => { const g = el.closest('.cm-editor').querySelector('.cm-gutters');"
            " return g ? Math.round(g.getBoundingClientRect().width) : 0; }"
        )
    )


def test_hook_editor_does_not_shift_by_the_gutter_width_under_a_shrunken_viewport(
    phone_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Typing must not shift the view right by the gutter's width (issue #1870).

    With the on-screen keyboard up, CodeMirror rescues a caret that the keyboard has
    covered by calling ``scrollIntoView({block: "nearest"})`` on the caret's LINE
    element. That element is a full-width block, so the browser also acts on the inline
    axis: it aligns the line's start edge to the scrollport's start, and because the
    content sits one gutter-width inside the scrollport, the view slides right by exactly
    that width -- hiding the beginning of the line the admin is typing on. Line numbers
    made the gutter wide enough for it to be unmissable.

    The keyboard is emulated with a page-scale factor: it shrinks the visual viewport
    while the layout viewport keeps its size, which is the condition CodeMirror gates
    that rescue on. The preconditions below are asserted rather than assumed, because
    every one of them silently un-reaches the defect -- a viewport that never shrank, a
    caret that is not below it, or a document with nothing to scroll horizontally all
    make this pass on broken code.
    """
    page = phone_page
    _open(page, webui, HOOKS_PAGE)
    content = _hook_editor(page)

    _seed_overflowing_document(page, content)

    cdp = page.context.new_cdp_session(page)
    cdp.send("Emulation.setPageScaleFactor", {"pageScaleFactor": KEYBOARD_PAGE_SCALE})

    _place_caret_inside_a_line(content)

    # CodeMirror compares the caret's CLIENT rect against a PAGE coordinate
    # (``pageYOffset + visualViewport.offsetTop + height``), so a window scrolled down
    # never satisfies its guard however far under the keyboard the caret really is.
    # A phone with the keyboard up sits at the top of a short page, which is what this
    # restores -- and what the reporter's device was doing.
    page.evaluate("() => window.scrollTo(0, 0)")

    _assert_the_rescue_path_is_reachable(content)

    content.evaluate("el => { el.closest('.cm-scroller').scrollLeft = 0; }")
    assert _settled_scroll_left(content) == 0, "precondition: the view starts at the left edge"

    # With the view at the left edge the caret must already be visible, or scrolling to
    # it is the editor doing its job rather than the defect under test.
    caret_x = _caret_offset_x(content)
    width = int(content.evaluate("el => Math.round(el.closest('.cm-scroller').clientWidth)"))
    assert caret_x is not None and _gutter_width(content) < caret_x < width, (
        f"precondition: the caret must be on screen before typing; caret_x={caret_x}, width={width}"
    )

    page.keyboard.insert_text("X")
    offset = _settled_scroll_left(content)
    _shot(page, screenshot_dir, "hook_editor_gutter_shift")

    assert offset == 0, (
        f"typing shifted the view right by {offset}px with the caret already on screen "
        f"(gutter is {_gutter_width(content)}px wide); the start of the edited line is now hidden"
    )


def test_hook_editor_still_follows_the_caret_off_the_right_edge(
    phone_page: Page,
    webui: WebUI,
) -> None:
    """Typing PAST the right edge must still scroll the view after the caret (#1870).

    The sibling test above requires the view to hold still when the caret is already on
    screen. The obvious way to satisfy that -- pinning the horizontal position while the
    keyboard is up -- would break the case that matters more: a caret typed off the right
    edge has to be followed, or the admin types blind. Same shrunken viewport, caret at
    the END of a long line instead of the middle.
    """
    page = phone_page
    _open(page, webui, HOOKS_PAGE)
    content = _hook_editor(page)

    _seed_overflowing_document(page, content)

    cdp = page.context.new_cdp_session(page)
    cdp.send("Emulation.setPageScaleFactor", {"pageScaleFactor": KEYBOARD_PAGE_SCALE})

    # Caret at the end of a long line: the view is scrolled right to reach it, which is
    # the state the previous test never visits. Seed the caret inside the line the same
    # way as the sibling test, then let CodeMirror itself move it to the line end -- a
    # DOM range collapsed past the line's contents is not necessarily adopted into
    # CodeMirror's own selection, and its scrolling would then target a stale position.
    _place_caret_inside_a_line(content)
    page.evaluate("() => window.scrollTo(0, 0)")
    page.keyboard.press("End")

    # The keyboard state has to be genuinely reached, or the fix this guards against --
    # pinning the horizontal position while the keyboard is up -- would sail through. Not
    # the sibling's caret-below-the-viewport preconditions though: End makes CodeMirror
    # scroll to the caret, bringing it back into view vertically, so requiring it below
    # the viewport here can never hold.
    _assert_the_keyboard_is_up(content)

    before = _settled_scroll_left(content)
    assert before > 0, f"precondition: reaching a long line's end must scroll the view right; got {before}"

    page.keyboard.insert_text("Z")
    after = _settled_scroll_left(content)

    caret_x = _caret_offset_x(content)
    width = int(content.evaluate("el => Math.round(el.closest('.cm-scroller').clientWidth)"))
    assert after >= before, f"the view stopped following the caret rightwards: {before} -> {after}"
    assert caret_x is not None and _gutter_width(content) <= caret_x <= width, (
        f"the caret typed off the right edge is no longer visible; caret_x={caret_x}, width={width}"
    )


def test_hook_editor_keeps_the_caret_visible_once_the_keyboard_opens(
    phone_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Phone only: the view stays with the caret across the keyboard opening.

    The reported sequence happens with the on-screen keyboard already up, which on
    Android shrinks the layout viewport under a focused editable and forces a re-layout
    (and, in Chrome, a scroll-the-focused-editable-into-view pass) that the steady-state
    emulation above never triggers. Shrinking the viewport mid-edit is the closest a
    headless browser gets to it.
    """
    page = phone_page
    _open(page, webui, HOOKS_PAGE)
    content = _hook_editor(page)

    _clear_and_type(content, LONG_SHELL_LINE)
    _assert_scrolled_right(content, "end of the long line")
    page.keyboard.press("Enter")
    assert _settled_scroll_left(content) <= AT_LEFT_PX, "precondition: Enter returns the view to the left edge"

    page.set_viewport_size({"width": PHONE_WIDTH, "height": PHONE_HEIGHT_KEYBOARD_OPEN})
    offset = _settled_scroll_left(content)
    _shot(page, screenshot_dir, "hook_editor_keyboard_open")
    assert offset <= AT_LEFT_PX, (
        f"the keyboard opening moved the view to scrollLeft={offset} (max {_max_scroll_left(content)}) "
        "while the caret sat at the start of an empty line"
    )

    for char in "echo":
        content.press_sequentially(char, delay=20)
        offset = _settled_scroll_left(content)
        assert offset <= AT_LEFT_PX, (
            f"with the keyboard up, typing {char!r} snapped the view to scrollLeft={offset} "
            f"(max {_max_scroll_left(content)}); the text being typed is off-screen"
        )
