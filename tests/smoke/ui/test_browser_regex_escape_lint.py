"""Tier-B browser tests (issues #1866, #1867, #1868): the regex editor's own view of them.

The escape rule and the description-length rule are proven hermetically at the
layers that implement them (``tests/test_issue1867_regex_hash_escape.py`` on the
resolver's load path, ``DnsblRegexHashEscapeTest`` /
``DnsblRegexDescriptionLintTest`` on the validator and the lint endpoint). What
those cannot show is that the admin actually SEES the result: the lint endpoint
is reached over a real POST from a real editor, and its diagnostics land in the
gutter of the page being edited.

Three things are asserted here, each end-to-end through the live webConfigurator:

* **#1867** -- a pattern whose only hash is escaped no longer draws an error
  marker. Before the fix the validator saw ``^ads\\`` and reported "bad escape
  (end of pattern)", so a correctly written pattern was flagged in the gutter.
* **#1868** -- a description longer than 15 characters now draws a marker, on
  the line that carries it. Nothing appeared before.
* **#1866** -- the rendered help text states the real split rule and documents
  the escape, and no longer claims a space is required before the ``#``.

Never saves: typing into a CM editor only updates its own in-memory doc and the
hidden mirror textarea, and no Save is clicked -- same no-POST discipline as
``test_browser_lint.py``, whose editor and marker helpers this file reuses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .test_browser_lint import (
    DNSBL_PAGE,
    LINT_TIMEOUT_MS,
    _clear_and_type,
    _lint_markers,
    _open,
    _regex_editor,
)

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# Only hash in the pattern is escaped, so the whole line is the pattern and it
# compiles. Pre-fix this was split at the hash into "^ads\" -- a bad escape.
ESCAPED_HASH_PATTERN = "^ads\\#tag\\.example\\.com$"

# Balanced, compilable, and syntactically fine -- the ONLY thing wrong with it is
# that the description runs past the documented 15-character limit.
LONG_DESCRIPTION_LINE = "^ads\\.example\\.com$ # this description is far too long"


def test_an_escaped_hash_pattern_draws_no_lint_marker(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """#1867 end-to-end: the escaped-hash pattern is accepted by the live lint.

    Asserts a CONTRAST rather than a bare absence: a genuinely broken pattern is
    typed first and its marker observed, so the empty result for the escaped
    pattern cannot be an editor that simply stopped linting.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)

    # Vacuity guard: the lint IS live in this editor right now.
    _clear_and_type(content, "^ads\\")
    expect(_lint_markers(content).first).to_be_visible(timeout=LINT_TIMEOUT_MS)

    _clear_and_type(content, ESCAPED_HASH_PATTERN)
    expect(_lint_markers(content)).to_have_count(0, timeout=LINT_TIMEOUT_MS)


def test_an_over_long_description_draws_a_lint_marker(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """#1868 end-to-end: the advisory description-length note reaches the gutter."""
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)

    # Before: the same pattern with a SHORT description is unmarked, so the marker
    # below is caused by the description length and nothing else on the line.
    _clear_and_type(content, "^ads\\.example\\.com$ # short")
    expect(_lint_markers(content)).to_have_count(0, timeout=LINT_TIMEOUT_MS)

    _clear_and_type(content, LONG_DESCRIPTION_LINE)
    expect(_lint_markers(content).first).to_be_visible(timeout=LINT_TIMEOUT_MS)


def test_the_help_text_documents_the_escape_and_drops_the_space_claim(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """#1866 as rendered: what the admin actually reads under the field."""
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _regex_editor(page)

    help_text = " ".join((page.locator("#Python_regex_list_panel-body .help-block").first.text_content() or "").split())

    assert "space is entered before" not in help_text, (
        f"the help text still claims a space is required before '#': {help_text!r}"
    )
    assert "unescaped" in help_text, f"the help text must state the first UNESCAPED '#' splits the line: {help_text!r}"
    assert "\\#" in help_text, f"the help text must show the \\# escape: {help_text!r}"
