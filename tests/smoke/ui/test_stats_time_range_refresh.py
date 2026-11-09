"""#3773: the 60 s auto-refresh keeps the chosen Stats range, and a malformed ``range`` falls back without an error.

HTTP only. The refresh ``<meta>`` is emitted only for a Host header the package accepts, so each page is requested with
the default Host first and then with the appliance's own hostname; the test fails (never skips) if neither shows it.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_stats_time_range import ALERTS, _saved_default

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

ALERT_REFRESH = "installedpackages/pfblockerngglobal/alertrefresh"
VIEWS = ("dnsbl_stat", "dnsbl_reply_stat", "ip_block_stat", "ip_permit_stat", "ip_match_stat")
META = re.compile(r'<meta id="AlertRefresh" http-equiv="refresh" content="60;url=([^"]+)"')
PICKER = re.compile(r'<select id="Alert_Stats_Range".*?</select>', re.DOTALL)
SELECTED = re.compile(r'<option value="([^"]*)" selected')


@contextmanager
def _auto_refresh_on(vm: helpers.SmokeVM) -> Iterator[None]:
    prior = helpers.config_get_state(vm, ALERT_REFRESH)
    try:
        helpers.config_set(vm, ALERT_REFRESH, "on")
        yield
    finally:
        helpers.config_restore_state(vm, ALERT_REFRESH, prior)


def _hosts(vm: helpers.SmokeVM) -> list[str | None]:
    name = f"{helpers.config_get(vm, 'system/hostname')}.{helpers.config_get(vm, 'system/domain')}"
    return [None, f"{name}:{vm.web_port}"]


def _refresh_query(webui: WebUI, vm: helpers.SmokeVM, path: str) -> dict[str, list[str]]:
    """Query of the auto-refresh URL of ``path``; the page is fetched with every Host the package may accept."""
    tried = []
    for host in _hosts(vm):
        response = webui.get(path, headers={"Host": host} if host else {})
        assert response.status_code == 200, f"{path} via Host {host!r}: HTTP {response.status_code}"
        match = META.search(response.text)
        if match:
            return parse_qs(urlsplit(html.unescape(match.group(1))).query)
        tried.append(host)
    pytest.fail(f"{path}: no AlertRefresh meta for Host {tried!r} -- auto-refresh is on, so the page lost it")


def _selected_range(page_html: str) -> str:
    picker = PICKER.search(page_html)
    assert picker, "no Time range picker"
    selected = SELECTED.findall(picker.group(0))
    assert len(selected) == 1, f"expected exactly one selected range, got {selected}"
    return selected[0]


@pytest.mark.parametrize("view", VIEWS)
def test_auto_refresh_keeps_the_chosen_range(webui: WebUI, smoke_vm: helpers.SmokeVM, view: str) -> None:
    with _auto_refresh_on(smoke_vm), _saved_default(smoke_vm, "24"):
        for chosen in ("48", "max"):
            query = _refresh_query(webui, smoke_vm, f"{ALERTS}?view={view}&range={chosen}")
            assert query == {"view": [view], "range": [chosen]}, f"{chosen}: {query}"
        # No range in the URL: the refresh must keep the saved default, not drop to nothing or to a stale pick.
        assert _refresh_query(webui, smoke_vm, f"{ALERTS}?view={view}") == {"view": [view], "range": ["24"]}


@pytest.mark.parametrize("view", VIEWS)
def test_array_valued_range_falls_back_to_the_saved_default_without_error(
    webui: WebUI, smoke_vm: helpers.SmokeVM, view: str
) -> None:
    guard = PhpErrorLogGuard(smoke_vm)
    with _saved_default(smoke_vm, "24"):
        guard.snapshot()
        for query in ("range[]=x", "range[a]=48&range[b]=max", "range[]=24&range[]=max"):
            response = webui.get(f"{ALERTS}?view={view}&{query}")
            result = evaluate_render(f"{ALERTS}?view={view}", response.status_code, response.text, ("Time range",))
            assert result.ok, f"{query}: {result.detail}"
            assert _selected_range(response.text) == "24", query
        if view in ("dnsbl_stat", "dnsbl_reply_stat"):
            data = webui.get(f"{ALERTS}?view={view}&stats_data=1&range[]=x")
            assert data.status_code == 200, f"stats data with range[]=x: HTTP {data.status_code}"
            assert "application/json" in data.headers.get("content-type", "")
            assert "panels" in data.json()
        guard.assert_no_growth()
