"""Stats pies and tables fit their content, with per-pie zoom (#3796), on real appliance data.

Each test seeds a small log stamped with the appliance clock (logs and settings are backed up and restored; nothing is
stubbed) and reads rendered geometry only: bounding boxes, scroll extents and computed overflow at four viewports.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from .test_dns_stats_review import _stats_log
from .test_stats_time_range import _expect, _open, _reveal, _vm_stamps

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

CAP = 390  # a Stats column's configured height: a maximum, never a fixed height
RATIO = 390 / 560  # a pie box's height over its width
TOLERANCE = 2  # px
ZOOM_FACTOR = 2  # the zoomed svg's area over the inline pie's
SIZES = ((1440, 900), (1024, 768), (768, 1024), (375, 812))  # viewport width, height
VIEWS = (
    # view, log, hidden-stat preference, three-row table panel, long table panel
    ("dnsbl_reply_stat", "dns_reply.log", "pfbdnsblreplystat", "replytype", "replydomain"),
    ("ip_block_stat", "ip_block.log", "pfbblockstat", "ipprotocol", "ipfeed"),
)
KINDS = {"dnsbl_reply_stat": ("resolver", "cache", "local"), "ip_block_stat": ("TCP", "UDP", "ICMP")}
ZOOM = re.compile(r"^Zoom")

GEOMETRY = """(stat) => {
    const box = (e) => {
        const b = e.getBoundingClientRect();
        return {left: b.left, right: b.right, top: b.top, bottom: b.bottom, width: b.width, height: b.height};
    };
    const scroll = (e) => Object.assign({
        overflowY: getComputedStyle(e).overflowY, scrollHeight: e.scrollHeight, clientHeight: e.clientHeight,
        scrollWidth: e.scrollWidth, clientWidth: e.clientWidth}, box(e));
    const pieBox = document.getElementById('pieChart_' + stat);
    const pieColumn = pieBox.closest('.pfb-stats-col');
    const tableColumn = pieColumn.parentElement.querySelector('.pfb-stats-col');
    const table = tableColumn.querySelector('table');
    const svg = pieBox.querySelector('svg');
    return {
        tableColumn: scroll(tableColumn),
        content: table.getBoundingClientRect().bottom + parseFloat(getComputedStyle(table).marginBottom)
            - tableColumn.getBoundingClientRect().top,
        pieColumn: scroll(pieColumn),
        pieBox: box(pieBox),
        svg: svg && box(svg),
    };
}"""

# The inline pies as the zoom must leave them: sizes and labels, never positions (the page scrolls under a dialog).
PIES = """(stats) => stats.map((stat) => {
    const box = document.getElementById('pieChart_' + stat);
    const svgs = box.querySelectorAll('svg');
    const size = (e) => { const b = e.getBoundingClientRect(); return [Math.round(b.width), Math.round(b.height)]; };
    return {svgs: svgs.length, box: size(box), svg: size(svgs[0]),
        texts: Array.from(svgs[0].querySelectorAll('text')).map((e) => e.textContent).sort()};
})"""
# The pies on the page that have an svg but no tooltips yet: d3pie adds them on a timer tick after the svg.
UNDRAWN = """() => Array.from(document.querySelectorAll('[id^="pieChart_"] > svg'))
    .filter((svg) => !svg.querySelector('g[class$="_tooltips"]')).map((svg) => svg.parentElement.id)"""


def _seed(view: str, stamp: str) -> str:
    """24 events: three Top Reply Type / Top Protocol values and one distinct Top Reply Domain / Top Feed value each."""
    lines = []
    for index in range(24):
        kind = KINDS[view][index % 3]
        token = helpers.unique_domain(f"pie{index}")
        if view == "dnsbl_reply_stat":
            lines.append(f"DNS-reply,{stamp},{kind},A,A,300,{token},192.0.2.1,192.0.2.53,US\n")
        else:
            lines.append(
                f"{stamp},100,em0,WAN,block,4,6,{kind},192.0.2.1,198.51.100.1,54321,80,in,US,pfB_Range_v4,"
                f"192.0.2.1,{token},Unknown,Unknown,64500,asn.range.com,Range ASN,+\n"
            )
    return "".join(lines)


def _show_pie(page: Page, stat: str) -> None:
    """Expand the panel (DNS panels are fetched and mounted as they scroll into view) and wait for its pie."""
    _reveal(page, stat)
    expect = _expect()
    expect(page.locator(f"#Alert_Stats_{stat}_panel-body")).not_to_have_class(re.compile("collapsing"))
    expect(page.locator(f"#pieChart_{stat} svg")).to_have_count(1, timeout=30_000)


def _pies_drawn(page: Page) -> None:
    """Wait until every pie on the page has its tooltips, so a snapshot of them holds no pie still drawing."""
    try:
        page.wait_for_function(f"() => ({UNDRAWN})().length === 0", timeout=30_000)
    except pytest.importorskip("playwright.sync_api").TimeoutError:
        pytest.fail(f"these pies never got their tooltips: {page.evaluate(UNDRAWN)}")


def _geometry(page: Page, stat: str) -> dict[str, Any]:
    geometry: dict[str, Any] = page.evaluate(GEOMETRY, stat)
    return geometry


def _unclipped(column: dict[str, Any]) -> bool:
    """No scrollable overflow in either direction (1 px: layout rounding)."""
    return column["scrollHeight"] <= column["clientHeight"] + 1 and column["scrollWidth"] <= column["clientWidth"] + 1


def _inside(inner: dict[str, Any], outer: dict[str, Any], slack: float = 1) -> bool:
    return (
        inner["left"] >= outer["left"] - slack
        and inner["right"] <= outer["right"] + slack
        and inner["top"] >= outer["top"] - slack
        and inner["bottom"] <= outer["bottom"] + slack
    )


def _fit_problems(where: str, geometry: dict[str, Any], *, short: bool) -> list[str]:
    """What is wrong with one panel's table column and pie column; ``short`` is the three-row table."""
    problems: list[str] = []
    table, content = geometry["tableColumn"], geometry["content"]
    column, pie, svg = geometry["pieColumn"], geometry["pieBox"], geometry["svg"]

    if short:
        if table["height"] > content + TOLERANCE:
            problems.append(f"{where}: table column is {table['height']:.0f}px for {content:.0f}px of content")
        if not _unclipped(table) or table["overflowY"] == "scroll":
            problems.append(f"{where}: table that fits still scrolls or draws a scroll track: {table}")
    else:
        assert content > CAP, f"{where}: the seeded table is only {content:.0f}px, not past the {CAP}px cap"
        if abs(table["height"] - CAP) > TOLERANCE:
            problems.append(f"{where}: long table column is {table['height']:.0f}px, not the {CAP}px cap")
        if table["scrollHeight"] <= table["clientHeight"] or table["overflowY"] not in ("auto", "scroll"):
            problems.append(f"{where}: long table does not scroll past the cap: {table}")

    if not _unclipped(column) or column["overflowY"] == "scroll":
        problems.append(f"{where}: pie column scrolls or draws a scroll track: {column}")
    if svg is None or not _inside(svg, pie):
        problems.append(f"{where}: pie svg {svg} is not inside its box {pie}")
    expected = min(pie["width"] * RATIO, CAP)
    if abs(pie["height"] - expected) > TOLERANCE:
        problems.append(
            f"{where}: pie box is {pie['height']:.1f}px tall, expected {expected:.1f}px (width {pie['width']:.1f})"
        )
    if abs((pie["left"] - column["left"]) - (column["right"] - pie["right"])) > TOLERANCE:
        problems.append(
            f"{where}: pie box {pie['left']:.0f}-{pie['right']:.0f} is off-center in "
            f"{column['left']:.0f}-{column['right']:.0f}"
        )
    if column["height"] > pie["height"] + TOLERANCE:
        problems.append(
            f"{where}: pie column is {column['height']:.0f}px around a {pie['height']:.0f}px pie: empty band"
        )
    return problems


def _print_problems(page: Page, view: str, short: str, long: str) -> list[str]:
    """Print keeps whole tables above whole pies, with no zoom button."""
    problems: list[str] = []
    buttons: list[Any] = []
    for stat in (short, long):  # found on screen: the role query skips what print hides
        found = page.locator(f"#Alert_Stats_{stat}_panel-body").get_by_role("button", name=ZOOM)
        if found.count() == 1:
            buttons.append(found.element_handle())
        else:
            problems.append(f"{view} {stat}: {found.count()} zoom buttons, expected 1")
    page.emulate_media(media="print")
    try:
        if any(button.is_visible() for button in buttons):
            problems.append(f"{view}: a zoom button is visible in print")
        for stat in (short, long):
            geometry = _geometry(page, stat)
            table, column, pie, svg = (geometry[k] for k in ("tableColumn", "pieColumn", "pieBox", "svg"))
            where = f"{view} {stat} in print"
            if not _unclipped(table) or table["overflowY"] != "visible":
                problems.append(f"{where}: table column clips or scrolls: {table}")
            if not _unclipped(column) or column["overflowY"] != "visible":
                problems.append(f"{where}: pie column clips or scrolls: {column}")
            if svg is None or not _inside(svg, pie) or not _inside(pie, column):
                problems.append(f"{where}: pie {svg} leaves its box {pie} or column {column}")
            if table["bottom"] > column["top"] + 1:
                problems.append(
                    f"{where}: table ends at {table['bottom']:.0f}px, over the pie at {column['top']:.0f}px"
                )
    finally:
        page.emulate_media(media="screen")
    return problems


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "short", "long"), VIEWS)
def test_stats_pies_and_tables_fit_their_content(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    view: str,
    log: str,
    preference: str,
    short: str,
    long: str,
) -> None:
    page = browser_page
    stamp, _ = _vm_stamps(smoke_vm)
    problems: list[str] = []
    with _stats_log(smoke_vm, log, preference, _seed(view, stamp)):
        for width, height in SIZES:
            page.set_viewport_size({"width": width, "height": height})
            _open(page, webui, view, "&range=max")  # the seeds are stamped inside every window; max is the widest
            for stat in (short, long):
                _show_pie(page, stat)
            _expect()(page.locator(f"#Alert_Stats_{short} tbody tr")).to_have_count(3)
            for stat in (short, long):
                problems += _fit_problems(f"{view} {stat} @{width}", _geometry(page, stat), short=stat == short)
            if width == SIZES[0][0]:
                problems += _print_problems(page, view, short, long)
    assert not problems, "\n".join(problems)


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "short", "long"), VIEWS)
def test_stats_pie_zoom_opens_one_dialog_and_returns_focus(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    view: str,
    log: str,
    preference: str,
    short: str,
    long: str,
) -> None:
    page = browser_page
    expect = _expect()
    stamp, _ = _vm_stamps(smoke_vm)
    stats = (short, long)
    with _stats_log(smoke_vm, log, preference, _seed(view, stamp)):
        for width, height in SIZES:
            page.set_viewport_size({"width": width, "height": height})
            _open(page, webui, view, "&range=max")
            for stat in stats:
                _show_pie(page, stat)
            _pies_drawn(page)
            before = page.evaluate(PIES, list(stats))
            assert [pie["svgs"] for pie in before] == [1, 1]
            inline_area = before[0]["svg"][0] * before[0]["svg"][1]

            # One zoom button per pie, found by its accessible name, reached and pressed with the keyboard only.
            button = page.locator(f"#Alert_Stats_{short}_panel-body").get_by_role("button", name=ZOOM)
            expect(button).to_have_count(1)
            expect(page.locator(f"#Alert_Stats_{long}_panel-body").get_by_role("button", name=ZOOM)).to_have_count(1)
            for how in ("Escape", "the close button", "a click outside"):
                where = f"{view} @{width}, closed with {how}"
                button.focus()
                page.keyboard.press("Enter")
                dialog = page.locator(".modal.in")
                expect(dialog).to_have_count(1)
                expect(dialog).to_have_attribute("role", "dialog")
                zoomed = dialog.locator("svg")
                expect(zoomed).to_have_count(1, timeout=30_000)  # only this pie, drawn once the dialog has opened
                expect(zoomed).to_be_visible()
                rect = zoomed.bounding_box()
                assert rect is not None
                assert rect["width"] * rect["height"] >= ZOOM_FACTOR * inline_area, (
                    f"{where}: zoomed svg {rect['width']:.0f}x{rect['height']:.0f} is under {ZOOM_FACTOR}x the "
                    f"inline pie's {inline_area}px²"
                )
                _pies_drawn(page)  # the zoomed pie, too, draws its labels on a tick after its svg
                assert sorted(zoomed.locator("text").all_text_contents()) == before[0]["texts"], f"{where}: other data"

                if how == "Escape":
                    page.keyboard.press("Escape")
                elif how == "the close button":
                    dialog.get_by_role("button", name=re.compile("close", re.IGNORECASE)).click()
                else:
                    page.mouse.click(2, 2)  # the dimmed page around the dialog
                expect(dialog).to_have_count(0)
                expect(page.locator(".modal-backdrop")).to_have_count(0)
                expect(button).to_be_focused()
                assert page.evaluate(PIES, list(stats)) == before, f"{where}: the inline pies changed"
