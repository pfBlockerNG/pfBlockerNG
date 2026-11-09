"""Tier-B: timeline labels fit without discarding event bars (issue #3754)."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_alerts_render_verify import _backup_seeded_files, _restore_seeded_files
from .test_browser_stats import _open, _shot
from .test_stats_progressive import _vm_hours

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# Measured screen-space boxes, not chart options: restoring all ordinal ticks
# after an NVD3 redraw must fail this same assertion.
GEOMETRY = """() => {
    const visible = selector => [...document.querySelectorAll(selector)].filter(e => {
        const s = getComputedStyle(e), b = e.getBoundingClientRect();
        return s.visibility !== 'hidden' && +s.opacity > 0.5 && b.width && b.height;
    });
    const box = e => { const b = e.getBoundingClientRect();
        return {text:e.textContent, x:b.x, right:b.right, y:b.y, bottom:b.bottom}; };
    const labels = visible('#chart .nv-x .tick text').map(box).sort((a,b) => a.x-b.x);
    const title = visible('#chart .nv-x .nv-axislabel').map(box);
    const overlaps = [];
    for (let i=1; i<labels.length; i++) {
        if (labels[i].x < labels[i-1].right - 0.5) overlaps.push([labels[i-1],labels[i]]);
    }
    for (const label of labels) for (const t of title) {
        if (label.x < t.right && label.right > t.x && label.y < t.bottom && label.bottom > t.y)
            overlaps.push([label,t]);
    }
    return {labels, title, overlaps,
        y:visible('#chart .nv-y .tick text').length,
        bars:[...document.querySelectorAll('#chart .nv-bar')].filter(e => e.__data__.ecount > 0).length};
}"""


def assert_timeline_geometry(page: Page, expected_bars: int) -> None:
    """Read only after the actual NVD3 transitions have drained."""
    if not expected_bars and not page.locator("#chart").count():
        return
    page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
    page.wait_for_function(
        """() => !nv.render.active && ![...document.querySelectorAll('#chart svg *')]
            .some(e => e.__transition__) && (document.querySelector('#chart .nv-bar') ||
            document.querySelector('#chart .nv-noData'))"""
    )
    geometry = page.evaluate(GEOMETRY)
    assert geometry["bars"] == expected_bars, geometry
    assert not geometry["overlaps"], geometry
    if expected_bars:
        assert geometry["labels"] and geometry["title"] and geometry["y"], geometry


def _put(vm: helpers.SmokeVM, path: str, content: str) -> None:
    result = subprocess.run(
        vm.ssh_argv("tee", path), input=content, text=True, capture_output=True, timeout=30, check=False
    )
    assert result.returncode == 0, f"write {path}: {result.stderr}"


def _rows(view: str, stamps: list[str]) -> str:
    rows = []
    for stamp in stamps:
        if view == "dnsbl_stat":
            rows.append(f"DNSBL-python,{stamp},timeline.com,192.0.2.1,Python,DNSBL,Timeline,Match,Timeline,+,A\n")
        elif view == "dnsbl_reply_stat":
            rows.append(f"DNS-reply,{stamp},cache,A,A,300,timeline.com,192.0.2.1,203.0.113.1,US,Unknown\n")
        else:
            rows.append(
                f"{stamp},100,em0,WAN,block,4,6,TCP,192.0.2.1,203.0.113.1,1234,80,in,US,pfB_Timeline_v4,192.0.2.1,Timeline,Unknown,Unknown,Unknown,+\n"
            )
    return "".join(rows)


def _show_timeline(page: Page, view: str) -> None:
    kind = {"dnsbl_stat": "dnsblchart", "dnsbl_reply_stat": "replychart"}.get(view, "ipchart")
    page.locator(f"#Alert_Stats_{kind}").scroll_into_view_if_needed()
    pytest.importorskip("playwright.sync_api").expect(page.locator("#chart")).to_be_attached()


def _pick_range(page: Page, view: str, hours: int) -> None:
    """Choose the shared Time range: the page reloads with it, and the timeline is redrawn for that window."""
    expect = pytest.importorskip("playwright.sync_api").expect
    with page.expect_navigation(wait_until="domcontentloaded"):
        page.locator("#Alert_Stats_Range").select_option(str(hours))
    page.wait_for_load_state("networkidle")
    expect(page.locator("#Alert_Stats_Range")).to_have_value(str(hours))
    _show_timeline(page, view)


@pytest.mark.parametrize(
    "view,log,selection",
    [
        ("dnsbl_reply_stat", "dns_reply.log", "pfbdnsblreplystat"),
        ("dnsbl_stat", "dnsbl.log", "pfbdnsblstat"),
        ("ip_block_stat", "ip_block.log", "pfbblockstat"),
    ],
)
def test_timeline_labels_fit_on_range_redraw_and_resize(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    screenshot_dir: Path,
    view: str,
    log: str,
    selection: str,
) -> None:
    """Every shared timeline keeps full tooltip dates and all nonzero bars."""
    vm, page = smoke_vm, browser_page
    path = f"/var/log/pfblockerng/{log}"
    backups = _backup_seeded_files(vm, (path,))
    prefix = "installedpackages/pfblockerngglobal"
    keys = {f"{prefix}/{selection}": "", f"{prefix}/pfbchartcnt": "8064"}
    priors = {key: helpers.config_get_state(vm, key) for key in keys}
    try:
        for key, value in keys.items():
            helpers.config_set(vm, key, value)
        stamps = _vm_hours(vm, 8064)
        _put(vm, path, _rows(view, stamps))
        page.set_viewport_size({"width": 1440, "height": 1000})
        _open(page, webui, f"/pfblockerng/pfblockerng_alerts.php?view={view}")
        _show_timeline(page, view)
        for count in (24, 168, 8064):
            _pick_range(page, view, count)
            for width in (1440, 320, 768, 1024, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert_timeline_geometry(page, count)
            _shot(page, screenshot_dir, f"timeline-{view}-{count}")
        bar = page.locator("#chart .nv-bar").last
        bar.hover(force=True)
        tooltip = page.locator(".nvtooltip").last
        expect = pytest.importorskip("playwright.sync_api").expect
        expect(tooltip).to_be_visible()
        expected_date = f"{stamps[-1][:10]} ({stamps[-1][11:13]})"
        assert expected_date in tooltip.inner_text(), tooltip.inner_text()
        for count in (1, 0):
            _put(vm, path, _rows(view, _vm_hours(vm, count)))
            _open(page, webui, f"/pfblockerng/pfblockerng_alerts.php?view={view}")
            _show_timeline(page, view)
            assert_timeline_geometry(page, count)
    finally:
        for key, prior in priors.items():
            helpers.config_restore_state(vm, key, prior)
        errors = _restore_seeded_files(vm, backups)
        assert not errors, errors
