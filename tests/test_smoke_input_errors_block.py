"""Hermetic cover for the smoke suite's ``$input_errors`` extractor (issue #2954).

``tests/smoke/ui/render_oracle`` holds the page-diagnostic readers the UI tiers
share. They are pure string functions, so they are pinned here rather than only
on a live VM -- the same arrangement ``tests/test_bench_pfctl_parse.py`` uses for
``tests.smoke.test_bench_pfctl``.

What is pinned is the thing a failure message depends on: when a category-edit
save is REJECTED, the page renders the reason and the helper has to hand it back.
Before this, ``_post_form()`` discarded it and the failure surfaced at whatever
the caller asserted next -- naming the config path instead of the rejection.
"""

from __future__ import annotations

from tests.smoke.ui.render_oracle import input_errors_block

# pfSense's print_input_errors() (guiconfig.inc) renders one non-nested
# <div class="alert alert-danger input-errors"> per response.
_REJECTED = (
    "<html><body><div class='pane'>x</div>"
    '<div class="alert alert-danger input-errors">'
    "<p>The following input errors were detected:</p>"
    "<ul><li>Header/Label field is a reserved name.</li></ul>"
    "</div><form>...</form>"
    # A closing </div> AFTER the alert, or the greedy/non-greedy distinction the
    # extractor depends on is untestable: with nothing following, both match the
    # same span and a greedy pattern passes.
    '<div class="footer">y</div></body></html>'
)
_ACCEPTED = "<html><body><div class='pane'>saved</div><form>...</form></body></html>"


def test_rejected_save_yields_the_rendered_reason() -> None:
    """The block is returned whole, so the reason reaches the failure message."""
    block = input_errors_block(_REJECTED)
    assert "reserved name" in block, f"the rejection reason was dropped: {block!r}"
    assert block.startswith('<div class="alert alert-danger input-errors">'), block


def test_accepted_save_says_so_rather_than_returning_empty() -> None:
    """No block must read as an explicit marker, never as an empty response.

    An empty string here would render in a failure message as though the page came
    back blank, which points at the wrong layer -- the defect this helper exists to
    stop.
    """
    assert input_errors_block(_ACCEPTED) == "<no input-errors block in response>"


def test_extraction_stops_at_the_first_closing_div() -> None:
    """Only the alert is taken, not the rest of the page after it.

    The pattern is non-greedy for this reason: pfSense renders the block
    non-nested, so a greedy match would swallow the whole document and bury the
    reason it was called to surface.
    """
    block = input_errors_block(_REJECTED)
    assert "<form>" not in block, f"extraction ran past the alert: {block!r}"
    assert "footer" not in block, f"extraction ran to a later </div>: {block!r}"
    assert block.endswith("</div>"), block
