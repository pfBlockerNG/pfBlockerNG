"""The Stats "Time range" pane is made of pfSense form rows (#3773 follow-up, owner request 2026-11-09).

Every other pfBlockerNG field ("Update Settings" -> Run Scope, "IP Configuration" -> Links) is a pfSense
``.form-group``: label in the left ``col-sm-2``, control in the columns to its right. The Stats pane must
line up with them, so it is asserted by DOM classes and rendered geometry -- the Run Scope / Links rows on
the Update page are the measured reference. Logs and settings are seeded and restored; nothing is stubbed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from .conftest import mask_page_identity
from .test_dns_stats_review import _stats_log
from .test_stats_time_range import VIEWS, _open, _pick, _row, _saved_default, _settle, _vm_stamps

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Expect, Locator, Page, ViewportSize

    from .webui import WebUI

UPDATE = "/pfblockerng/pfblockerng_update.php"
DESKTOP: ViewportSize = {"width": 1440, "height": 1000}
SAME_LINE_PX = 6  # label vs control vertical centers
SAME_COLUMN_PX = 1  # the two Stats rows share the value column
REFERENCE_PX = 2  # Stats row offsets vs the Update page rows, each relative to its own .panel-body
REFERENCE_ROWS = ("Run Scope", "Links")
PANES = tuple(view[:3] for view in VIEWS)  # view, log, hidden-stat preference

# Geometry of one pfSense ``.form-group``: its label, the column after the label, and (optionally) the control
# ``id`` inside that column. Offsets are relative to the row's own ``.panel-body`` left edge.
ROW_JS = """
(row, id) => {
  const label = row.firstElementChild;
  const column = label.nextElementSibling;
  const control = id ? document.getElementById(id) : null;
  const body = row.closest('.panel-body').getBoundingClientRect();
  const l = label.getBoundingClientRect();
  const c = column.getBoundingClientRect();
  const k = control ? control.getBoundingClientRect() : null;
  return {
    labelTag: label.tagName.toLowerCase(),
    labelClasses: Array.from(label.classList),
    labelText: label.textContent.trim(),
    labelAlign: getComputedStyle(label).textAlign,
    labelRight: l.right - body.left,
    labelMiddle: (l.top + l.bottom) / 2,
    columnClasses: Array.from(column.classList),
    columnLeft: c.left - body.left,
    bodyWidth: body.width,
    controlInColumn: control ? column.contains(control) : null,
    controlClasses: control ? Array.from(control.classList) : null,
    controlLeft: k ? k.left - body.left : null,
    controlMiddle: k ? (k.top + k.bottom) / 2 : null,
  };
}
"""


def _expect() -> Expect:
    return pytest.importorskip("playwright.sync_api").expect


def _shot(page: Page, target: Locator, screenshot_dir: Path, name: str) -> None:
    """Pane screenshot artifact ``<screenshot_dir>/<name>.png`` (Plus identity masked first, ADR-24)."""
    mask_page_identity(page)
    target.screenshot(path=str(screenshot_dir / f"{name}.png"))


def _metrics(row: Locator, control_id: str | None = None) -> dict[str, Any]:
    _expect()(row).to_have_count(1)
    return row.evaluate(ROW_JS, control_id)  # type: ignore[no-any-return]


def _stats_pane(page: Page) -> tuple[Locator, Locator, Locator]:
    """The top Statistics panel, its Time range row and its Showing row."""
    top = page.locator("#iform_stats > .panel:has(#Alert_Stats_Total)").first
    body = top.locator(".panel-body")
    return (
        top,
        body.locator(".form-group:has(#Alert_Stats_Range)"),
        body.locator(".form-group:has(#Alert_Stats_Window)"),
    )


def _reference_rows(page: Page, webui: WebUI, screenshot_dir: Path) -> dict[str, dict[str, Any]]:
    """Run Scope and Links on the Update page, the rows the owner points at."""
    page.goto(webui.url(UPDATE), wait_until="domcontentloaded", timeout=90_000)
    assert page.locator("#usernamefld").count() == 0
    rows = {
        title: page.locator(".panel-body .form-group").filter(has=page.get_by_text(title, exact=True))
        for title in REFERENCE_ROWS
    }
    _expect()(rows["Run Scope"]).to_be_visible()
    _shot(page, page.locator(".panel", has=rows["Run Scope"]).first, screenshot_dir, "stats_range_pane_reference")
    return {title: _metrics(row) for title, row in rows.items()}


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference"), PANES)
def test_stats_range_pane_uses_pfsense_form_rows(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    screenshot_dir: Path,
    view: str,
    log: str,
    preference: str,
) -> None:
    page = browser_page
    expect = _expect()
    page.set_viewport_size(DESKTOP)
    recent_stamp, _older = _vm_stamps(smoke_vm)
    contents = _row(view, recent_stamp, helpers.unique_domain("rangepane"))

    with _stats_log(smoke_vm, log, preference, contents), _saved_default(smoke_vm, "24"):
        _open(page, webui, view)
        top, range_row, window_row = _stats_pane(page)
        _shot(page, top, screenshot_dir, f"stats_range_pane_{view}")

        # "Time range": a pfSense row -- label in col-sm-2, the select in a col-sm-4 column, like the
        # Alert Settings chart-range select.
        rng = _metrics(range_row, "Alert_Stats_Range")
        assert rng["labelTag"] == "label", rng
        assert {"col-sm-2", "control-label"} <= set(rng["labelClasses"]), rng["labelClasses"]
        assert rng["labelText"] == "Time range"
        # pfSense omits <label for> unless the left-column-hyperlink user setting is on: the name must not depend on it.
        _expect()(page.locator("#Alert_Stats_Range")).to_have_attribute("aria-label", "Time range")
        assert rng["controlInColumn"], "the select is not in the column that follows the label"
        assert "col-sm-4" in rng["columnClasses"], rng["columnClasses"]
        assert "form-control" in rng["controlClasses"], rng["controlClasses"]

        # Label and select share one line; the label sits left of the select, text right-aligned.
        assert rng["labelAlign"] == "right", rng["labelAlign"]
        assert rng["labelRight"] <= rng["controlLeft"], (rng["labelRight"], rng["controlLeft"])
        assert abs(rng["labelMiddle"] - rng["controlMiddle"]) <= SAME_LINE_PX, (
            rng["labelMiddle"],
            rng["controlMiddle"],
        )

        expect(range_row.locator(".help-block")).to_be_visible()
        assert range_row.locator(".help-block").inner_text().strip()

        # "Showing": the second row, same columns, holds the window.
        win = _metrics(window_row, "Alert_Stats_Window")
        assert win["labelTag"] == "label", win
        assert {"col-sm-2", "control-label"} <= set(win["labelClasses"]), win["labelClasses"]
        assert win["labelText"] == "Showing"
        assert win["controlInColumn"], "#Alert_Stats_Window is not in the Showing row's value column"
        assert abs(win["columnLeft"] - rng["columnLeft"]) <= SAME_COLUMN_PX, (win["columnLeft"], rng["columnLeft"])
        assert "Showing" not in window_row.locator("#Alert_Stats_Window").inner_text(), "the label already says it"

        # Owner's acceptance: the same offsets as the Update page's rows, each from its own .panel-body.
        # The picker still navigates from the pfSense select.
        query = _pick(page, value="48")
        assert query["range"] == ["48"]
        assert query["view"] == [view]
        _settle(page, view)
        expect(page.locator("#Alert_Stats_Range")).to_have_value("48")

        for title, ref in _reference_rows(page, webui, screenshot_dir).items():
            for row_name, row in (("Time range", rng), ("Showing", win)):
                for edge in ("labelRight", "columnLeft"):
                    assert abs(row[edge] - ref[edge]) <= REFERENCE_PX, (
                        f"{row_name} {edge}={row[edge]:.1f}px (panel {row['bodyWidth']:.0f}px) vs "
                        f"{title} {ref[edge]:.1f}px (panel {ref['bodyWidth']:.0f}px)"
                    )
