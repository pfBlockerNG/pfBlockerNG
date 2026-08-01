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

from typing import TYPE_CHECKING

import pytest

from .test_browser_lint import (
    DNSBL_PAGE,
    HOOKS_PAGE,
    _clear_and_type,
    _hook_editor,
    _open,
    _regex_editor,
    _shot,
)

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from playwright.sync_api import BrowserContext, Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The reported scenario is a phone: a narrow field, so nearly every line overflows, and
# a touch/mobile Chrome whose input path (composition, focus scrolling) differs from the
# desktop one. Emulation cannot reproduce the on-screen keyboard, but it does give the
# narrow viewport, the mobile UA string, touch events and the device pixel ratio.
PHONE_CONTEXT = {
    "viewport": {"width": 412, "height": 915},
    "device_scale_factor": 2.625,
    "is_mobile": True,
    "has_touch": True,
    "user_agent": (
        "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36"
    ),
}


@pytest.fixture(params=["desktop", "phone"])
def editor_page(
    request: pytest.FixtureRequest,
    browser_page: Page,
    browser_context: BrowserContext,
    webui: WebUI,
) -> Iterator[tuple[Page, str]]:
    """The authenticated page under test, once per form factor.

    ``desktop`` is the session-scoped context every other browser test uses. ``phone``
    is a second context on the SAME browser, emulating the device the failure was
    reported on; it re-uses the desktop context's cookies rather than logging in again
    (a second login is a second flake source), and is torn down with the test.
    """
    if request.param == "desktop":
        yield browser_page, request.param
        return

    browser = browser_context.browser
    assert browser is not None, "browser_context must come from a live browser"
    context = browser.new_context(ignore_https_errors=webui.base_url.startswith("https://"), **PHONE_CONTEXT)
    context.add_cookies(browser_context.cookies())
    page = context.new_page()
    try:
        yield page, request.param
    finally:
        context.close()


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
