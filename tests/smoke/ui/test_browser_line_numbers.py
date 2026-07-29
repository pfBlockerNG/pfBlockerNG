"""Tier-B browser tests (issue #1869): the syntax editors show LINE NUMBERS.

Both CM6 editors already render a gutter -- ``@codemirror/lint``'s
``lintGutter()`` puts one there so a diagnostic has somewhere to hang its
marker. Nothing ever filled it, so the admin saw a narrow empty strip down the
left edge of every line and had to count rows by hand to find the line a
diagnostic named. The save-time regex validator reports "line N: ...", the
shell/python lint reports by line, and the gutter marker sits on the line --
all three are useless as navigation aids without the number beside them.

This is a VISUAL/STRUCTURAL change to a ``www/`` surface, so it is observable
only in this tier (testing.md mandate 4): a source-level pin can prove the
extension is wired, but only a real browser proves numbers actually render in
the gutter, in order, next to the right lines.

Both editors are asserted because the two bundles are built from separate
entry points (``cm-regex.js`` and ``cm-hooks.js``) -- wiring one and not the
other is exactly the kind of half-fix that a single-editor test would pass.
The lint gutter is asserted to survive alongside the numbers, because these
two gutters share one editor and displacing the lint marker would trade one
defect for another.

Reuses ``test_browser_lint.py``'s editor helpers rather than re-deriving the
panel-expansion dance: the DNSBL regex section is COLLAPSIBLE|SEC_CLOSED and
its CM instance only becomes usable after the panel expands.
"""

from __future__ import annotations

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

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# Three short lines: enough to prove the numbers COUNT rather than just appear,
# and short enough that no horizontal scrolling is involved.
THREE_LINES = "^one\\.example\\.com$\n^two\\.example\\.com$\n^three\\.example\\.com$"


def _editor_root(content: Locator) -> Locator:
    """The ``.cm-editor`` ancestor of a ``.cm-content`` node."""
    return content.locator("xpath=ancestor::div[contains(concat(' ', @class, ' '), ' cm-editor ')][1]")


def _line_numbers(content: Locator) -> list[str]:
    """The VISIBLE line-number gutter texts, in DOM order.

    CM6's gutter carries a sizing spacer as its first ``.cm-gutterElement``: it
    holds the widest number the gutter must fit (``9`` for a short document) and
    is hidden with an inline ``visibility: hidden`` rather than removed from the
    DOM (``@codemirror/view``'s ``GutterView`` constructor). Filtering on
    ``:visible`` drops it for the reason the admin never sees it, whereas
    filtering on "looks like a number" would keep it -- the spacer's text is a
    digit too.
    """
    gutter = _editor_root(content).locator(".cm-lineNumbers")
    expect(gutter).to_be_attached(timeout=JS_TIMEOUT_MS)
    texts = gutter.locator(".cm-gutterElement:visible").all_text_contents()
    return [text.strip() for text in texts if text.strip()]


def test_regex_editor_gutter_numbers_every_line(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The DNSBL regex-list editor numbers its lines 1, 2, 3 -- in that order."""
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)

    _clear_and_type(content, THREE_LINES)
    numbers = _line_numbers(content)
    _shot(page, screenshot_dir, "regex_editor_line_numbers")

    assert numbers == ["1", "2", "3"], (
        f"expected the gutter to number all three lines; got {numbers!r} -- "
        "an empty list means the gutter renders with no numbers in it at all"
    )


def test_regex_editor_line_numbers_track_added_lines(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """Adding a fourth line adds a fourth number -- the gutter is live, not static.

    Before/after on the same editor: three lines number 1-3, and typing one
    more takes it to 1-4. A gutter that rendered a fixed set once would pass the
    first assertion and fail this one.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)

    _clear_and_type(content, THREE_LINES)
    assert _line_numbers(content) == ["1", "2", "3"], "precondition: three lines number 1-3"

    content.press_sequentially("\n^four\\.example\\.com$", delay=20)
    assert _line_numbers(content) == ["1", "2", "3", "4"], "a fourth line must gain a fourth gutter number"


def test_hook_editor_gutter_numbers_every_line(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The Edit Hooks script editor numbers its lines too.

    Separate bundle, separate entry point -- wiring the regex editor alone
    would leave this one blank.
    """
    page = browser_page
    _open(page, webui, HOOKS_PAGE)
    content = _hook_editor(page)

    _clear_and_type(content, "echo one\necho two\necho three")
    numbers = _line_numbers(content)
    _shot(page, screenshot_dir, "hook_editor_line_numbers")

    assert numbers == ["1", "2", "3"], f"expected the hook editor's gutter to number all three lines; got {numbers!r}"


def test_line_numbers_do_not_displace_the_lint_gutter(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """Both gutters coexist, with the numbers LEFT of the lint markers.

    The lint gutter is the one that was already there; adding a second gutter
    to the same editor must not cost the diagnostic its home (issue #1732's
    marker path). The lint gutter's own marker behaviour stays pinned by
    ``test_browser_lint.py``.

    The left-right order is asserted on rendered geometry rather than left to
    the extension-order argument in the source comments: "numbers sit leftmost"
    is a claim about what the admin sees, and CodeMirror decides gutter order
    from facet precedence, which a future extension could reorder without
    touching either bundle entry point.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)
    _clear_and_type(content, THREE_LINES)

    editor = _editor_root(content)
    numbers_gutter = editor.locator(".cm-lineNumbers")
    lint_gutter = editor.locator(".cm-gutter-lint")
    expect(numbers_gutter).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(lint_gutter).to_be_attached(timeout=JS_TIMEOUT_MS)

    numbers_box = numbers_gutter.bounding_box()
    lint_box = lint_gutter.bounding_box()
    assert numbers_box is not None and lint_box is not None, (
        f"both gutters must have a rendered box; got numbers={numbers_box!r} lint={lint_box!r}"
    )
    assert numbers_box["x"] < lint_box["x"], (
        f"the line-number gutter must render LEFT of the lint gutter; "
        f"numbers at x={numbers_box['x']}, lint at x={lint_box['x']}"
    )
