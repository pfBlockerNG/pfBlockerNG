"""Stats pies and their zoom dialog keep working in every state the page can be in (#3796 review).

Same setup as ``test_stats_pie_fit``: a small log stamped with the appliance clock, read through rendered geometry and
the accessibility tree only. Empty panels, collapse/expand, the pie the dialog actually draws, a double activation, the
dialog's name, the page's auto-refresh and what the dialog leaves behind.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from .test_dns_stats_review import _stats_log
from .test_stats_pie_fit import SIZES, VIEWS, ZOOM, _pies_drawn, _seed, _show_pie
from .test_stats_time_range import _expect, _open, _reveal, _vm_stamps
from .test_stats_time_range_refresh import _auto_refresh_on

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

    from .webui import WebUI

EMPTY = {"dnsbl_reply_stat": "replytld3", "ip_block_stat": "ipsrcport"}  # a pie panel the seed leaves without data
NEXT = {"dnsbl_reply_stat": "replysrcip", "ip_block_stat": "ipdstport"}  # the panel drawn right below it
DRAWN_FACTOR = {1440: 2.0, 1024: 2.0, 768: 1.5, 375: 1.5}  # zoomed pie's drawn area over the inline pie's, by width
REFRESH = 3  # s: the page's refresh meta is re-armed to this, so a refresh that is not paused shows within the test
REFRESH_WAIT = 4_500  # ms: longer than REFRESH
META = "meta#AlertRefresh"
ACTIVE_META = f'{META}[http-equiv="refresh"]'

# The empty panel's pie box, and how far its body scrolls (a Stats panel body clips its overflow: overflow-x: auto).
HOLDER = """(stat) => {
    const body = document.getElementById('Alert_Stats_' + stat + '_panel-body');
    return {
        height: document.getElementById('pieChart_' + stat).getBoundingClientRect().height,
        scrolls: body.scrollHeight - body.clientHeight,
    };
}"""

# What answers a click on the panel below: every element under a 5x5 grid of its visible part that is not inside it.
INTERCEPTED = """(stat) => {
    const panel = document.getElementById('Alert_Stats_' + stat);
    panel.scrollIntoView({block: 'start'});
    window.scrollBy(0, -120);  // clear the appliance's fixed navbar
    const box = panel.getBoundingClientRect();
    const top = Math.max(box.top, 0) + 4, bottom = Math.min(box.bottom, window.innerHeight) - 4;
    const stolen = [];
    for (let i = 0; i < 5; i++) {
        for (let j = 0; j < 5; j++) {
            const x = box.left + box.width * (i + 0.5) / 5, y = top + (bottom - top) * (j + 0.5) / 5;
            const hit = document.elementFromPoint(x, y);
            if (!hit || !panel.contains(hit)) { stolen.push(hit ? hit.tagName + '#' + hit.id : 'nothing'); }
        }
    }
    return stolen;
}"""

# The segments' bounding box, and the main label's font size as drawn (user units times the viewBox scale).
DRAWN = """(scope) => {
    const svg = document.querySelector(scope + ' svg');
    const pie = svg && svg.querySelector('g[class$="_pieChart"]');
    const label = svg && svg.querySelector('text[id*="_segmentMainLabel"]');
    if (!pie || !label) { return null; }
    const box = pie.getBoundingClientRect();
    return {area: box.width * box.height, label: parseFloat(getComputedStyle(label).fontSize) * label.getScreenCTM().a};
}"""

# Everything the zoom dialog creates outside its own markup.
ZOOM_NODES = """() => Array.from(document.querySelectorAll('[id$="_zoom"], [id*="tooltip" i]')).map((e) => e.id)"""

ARM = """(seconds) => {
    const old = document.getElementById('AlertRefresh');
    if (old) { old.remove(); }
    const meta = document.createElement('meta');
    meta.id = 'AlertRefresh';
    meta.httpEquiv = 'refresh';
    meta.content = seconds + ';url=' + location.href;
    document.body.appendChild(meta);
    window.pfbAlive = true;  // gone if the page reloads
}"""
DISARM = "() => { document.getElementById('AlertRefresh')?.remove(); window.pfbAlive = true; }"


def _drawn(page: Page, scope: str) -> dict[str, float]:
    """The pie's drawn size once d3pie's load animation has stopped changing it."""
    previous: dict[str, float] | None = None
    for _ in range(40):
        current: dict[str, float] | None = page.evaluate(DRAWN, scope)
        if current is not None and previous is not None and abs(current["area"] - previous["area"]) < 1:
            return current
        previous = current
        page.wait_for_timeout(150)
    pytest.fail(f"{scope}: the pie never stopped changing, last {previous}")


def _zoom_button(page: Page, stat: str) -> Locator:
    button = page.locator(f"#Alert_Stats_{stat}_panel-body").get_by_role("button", name=ZOOM)
    _expect()(button).to_have_count(1)
    return button


def _press_zoom(page: Page, button: Locator) -> Locator:
    """Activate the zoom button from the keyboard; the dialog, once it is shown and its pie is drawn."""
    button.focus()
    page.keyboard.press("Enter")
    dialog = page.locator(".modal.in")
    _expect()(dialog).to_have_count(1)
    _expect()(dialog.locator("svg")).to_have_count(1, timeout=30_000)
    return dialog


def _close(page: Page, dialog: Locator) -> None:
    page.keyboard.press("Escape")
    _expect()(dialog).to_have_count(0)
    _expect()(page.locator(".modal-backdrop")).to_have_count(0)


def _alive(page: Page) -> bool:
    """True while the page has not reloaded since ``ARM`` or ``DISARM`` (a reload loses the flag and the context)."""
    try:
        return bool(page.evaluate("window.pfbAlive === true"))
    except Exception:  # a reload in flight destroys the context
        return False


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "short", "long"), VIEWS)
def test_stats_empty_pie_panel_takes_no_space_and_blocks_no_clicks(
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
    empty, below = EMPTY[view], NEXT[view]
    stamp, _ = _vm_stamps(smoke_vm)
    problems: list[str] = []
    with _stats_log(smoke_vm, log, preference, _seed(view, stamp)):
        for width, height in SIZES:
            page.set_viewport_size({"width": width, "height": height})
            _open(page, webui, view, "&range=max")
            for stat in (empty, below):
                _reveal(page, stat)
                _expect()(page.locator(f"#Alert_Stats_{stat} tbody")).to_be_attached()
            assert page.locator(f"#Alert_Stats_{empty} tbody tr").count() == 0, f"{view}: the seed fills {empty}"
            assert page.locator(f"#pieChart_{empty} svg").count() == 0, f"{view} @{width}: {empty} draws a pie"
            holder = page.evaluate(HOLDER, empty)
            if holder["height"] != 0:
                problems.append(f"{view} @{width}: the empty {empty} pie box is {holder['height']:.0f}px tall, not 0")
            if holder["scrolls"] > 1:
                problems.append(f"{view} @{width}: the empty {empty} panel scrolls by {holder['scrolls']}px")
            stolen = page.evaluate(INTERCEPTED, below)
            if stolen:
                problems.append(f"{view} @{width}: clicks on {below} reach {sorted(set(stolen))}")
    assert not problems, "\n".join(problems)


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "short", "long"), VIEWS)
def test_stats_pie_zoom_button_survives_collapse_and_expand(
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
    with _stats_log(smoke_vm, log, preference, _seed(view, stamp)):
        page.set_viewport_size({"width": SIZES[0][0], "height": SIZES[0][1]})
        _open(page, webui, view, "&range=max")
        for stat in (short, long):
            _show_pie(page, stat)
        for stat in (short, long):
            body = page.locator(f"#Alert_Stats_{stat}_panel-body")
            toggle = page.locator(f"#Alert_Stats_A_{stat}")
            toggle.click()
            expect(body).not_to_be_visible()
            toggle.click()
            expect(body).to_be_visible()
            expect(body).not_to_have_class(re.compile("collapsing"))
            expect(page.locator(f"#pieChart_{stat} svg")).to_have_count(1)
            expect(page.locator(f"#pieChart_{stat}").get_by_role("button", name=ZOOM)).to_have_count(1)
            dialog = _press_zoom(page, _zoom_button(page, stat))  # and it still opens the dialog
            _close(page, dialog)


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "short", "long"), VIEWS)
def test_stats_pie_zoom_draws_the_pie_larger_with_readable_labels(
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
            _open(page, webui, view, "&range=max")
            _show_pie(page, short)
            inline = _drawn(page, f"#pieChart_{short}")
            dialog = _press_zoom(page, _zoom_button(page, short))
            zoomed = _drawn(page, ".modal.in")
            _close(page, dialog)
            where = f"{view} @{width}"
            factor = zoomed["area"] / inline["area"]
            if factor < DRAWN_FACTOR[width]:
                problems.append(
                    f"{where}: zoomed pie is {factor:.2f}x the inline pie's area, under {DRAWN_FACTOR[width]}x"
                )
            if zoomed["label"] < inline["label"] - 0.1:  # 0.1 px: the same size, laid out at a different scale
                problems.append(f"{where}: zoomed labels are {zoomed['label']:.1f}px, under {inline['label']:.1f}px")
    assert not problems, "\n".join(problems)


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "short", "long"), VIEWS)
def test_stats_pie_zoom_opens_once_is_named_and_leaves_nothing_behind(
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
        page.set_viewport_size({"width": SIZES[0][0], "height": SIZES[0][1]})
        _open(page, webui, view, "&range=max")
        _show_pie(page, short)
        button = _zoom_button(page, short)
        name = button.get_attribute("aria-label")
        assert name, "the zoom button has no accessible name"
        _pies_drawn(page)
        before: list[str] = page.evaluate(ZOOM_NODES)

        button.focus()
        page.keyboard.press("Enter")
        page.keyboard.press("Enter")  # a held key, or a second press while the dialog fades in
        page.locator(".modal.in").first.wait_for()
        _expect()(page.locator(".modal.in svg").first).to_be_visible(timeout=30_000)
        counts = {
            "dialogs": page.locator(".modal").count(),
            "backdrops": page.locator(".modal-backdrop").count(),
            "pies": page.locator(".modal svg").count(),
            "dialogs named like the button": page.get_by_role("dialog", name=name, exact=True).count(),
        }
        problems += [f"{view}: {count} {what}, not 1" for what, count in counts.items() if count != 1]
        assert not problems, "\n".join(problems)

        _close(page, page.locator(".modal"))
        after: list[str] = page.evaluate(ZOOM_NODES)
        assert after == before, f"{view}: the dialog left {sorted(set(after) - set(before))} behind"


def _refresh_running(page: Page, view: str, short: str) -> list[str]:
    """An open dialog holds the refresh off, and closing it hands the refresh back."""
    page.evaluate(ARM, REFRESH)
    dialog = _press_zoom(page, _zoom_button(page, short))
    problems = (
        [f"{view}: the refresh meta is still in the page under the open dialog"] if page.locator(META).count() else []
    )
    page.wait_for_timeout(REFRESH_WAIT)
    if not _alive(page):
        return [*problems, f"{view}: the page refreshed under the open dialog"]
    _close(page, dialog)
    if page.locator(ACTIVE_META).count() != 1:
        problems.append(f"{view}: closing the dialog did not hand the refresh back")
    return problems


def _refresh_paused(page: Page, view: str, short: str) -> list[str]:
    """A refresh the user paused stays paused after the dialog, and Resume still restarts it."""
    page.evaluate(ARM, REFRESH)
    page.locator("[id=PauseRefresh]").first.click()
    assert page.locator(ACTIVE_META).count() == 0, f"{view}: Pause left the refresh running"
    _close(page, _press_zoom(page, _zoom_button(page, short)))
    page.wait_for_timeout(REFRESH_WAIT)
    if not _alive(page):
        return [f"{view}: closing the dialog resumed a paused refresh"]
    problems = [f"{view}: closing the dialog restarted a paused refresh"] if page.locator(ACTIVE_META).count() else []
    page.locator("[id=PauseRefresh]").first.click()
    if page.locator(ACTIVE_META).count() != 1:
        problems.append(f"{view}: Resume no longer restarts the refresh after the dialog")
    return problems


def _refresh_absent(page: Page, view: str, short: str) -> list[str]:
    """Without a refresh on the page the dialog has nothing to hold and conjures none."""
    page.evaluate(DISARM)
    _close(page, _press_zoom(page, _zoom_button(page, short)))
    return [f"{view}: closing the dialog put a refresh meta in the page"] if page.locator(META).count() else []


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "short", "long"), VIEWS)
def test_stats_pie_zoom_pauses_auto_refresh_while_open(
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
    errors: list[Any] = []
    page.on("pageerror", lambda error: errors.append(error))
    problems: list[str] = []
    with _auto_refresh_on(smoke_vm), _stats_log(smoke_vm, log, preference, _seed(view, stamp)):
        page.set_viewport_size({"width": SIZES[0][0], "height": SIZES[0][1]})
        for scenario in (_refresh_running, _refresh_paused, _refresh_absent):
            _open(page, webui, view, "&range=max")
            _show_pie(page, short)
            problems += scenario(page, view, short)
    problems += [f"{view}: page error {error}" for error in errors if "stats.js" in (error.stack or "")]
    assert not problems, "\n".join(problems)
