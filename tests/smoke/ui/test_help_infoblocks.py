"""Rendered setting associations and expandable help for issue #3701.

Pin the useful list structure and setting names, not the surrounding prose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .render_oracle import evaluate_render
from .test_render_smoke import php_error_log_guard  # noqa: F401 - shared log guard fixture

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from .webui import WebUI

GENERAL = "/pfblockerng/pfblockerng_dns_general.php"
IP = "/pfblockerng/pfblockerng_ip.php"
SYNC = "/pfblockerng/pfblockerng_sync.php"
PAGE_MARKERS = {
    GENERAL: ("DNS Reply Logging", "pfB-DNS Settings"),
    IP: ("IP Configuration",),
    SYNC: ("XMLRPC Sync Settings",),
}

pytestmark = pytest.mark.usefixtures("php_error_log_guard")

# These are UI setting names and intentional list groupings, not sentence contracts.
LIST_HELP = (
    (GENERAL, "pfb_dns_listen_vip", (("DNS Resolver",), ("DHCPv4",), ("DHCPv6",), ("Router Advertisements",))),
    (GENERAL, "pfb_dns_listen_vip_only", (("pfB-DNS", "Resolver addresses"), ("DNS Name",))),
    (GENERAL, "pfb_dns_dot", (("pfB-DNS",), ("DNS Name", "SSL/TLS Certificate"), ("DNSBL",))),
    (
        GENERAL,
        "pfb_dns_doh",
        (("pfB-DNS",), ("DNS Name", "SSL/TLS Certificate"), ("DNSBL",), ("DoH Trusted Front Ends",)),
    ),
    (GENERAL, "pfb_dns_doq", (("pfB-DNS",), ("DNS Name", "SSL/TLS Certificate"), ("DNSBL",))),
    (GENERAL, "pfb_dns_ddr", (("pfB-DNS", "DNS Name"), ("DoT", "DoH", "DoQ"), ("DDR",))),
    (
        GENERAL,
        "pfb_dns_ddr_doh_443_interfaces",
        (("DDR", "DoH"), ("IPv4 DoH Port", "IPv6 DoH Port"), ("Resolver VIPs",)),
    ),
    (GENERAL, "pfb_dns", (("Resolver addresses", "VIP-only mode", "Sync Scope"), ("DNS Name", "SSL/TLS Certificate"))),
    (IP, "pfb_agg_types", (("List Action",), ("Deny Inbound", "Deny Outbound", "Deny Both", "Alias Deny"))),
    (IP, "pfb_alias_delta_mode", (("Auto (recommended)", "5%"), ("Always incremental",), ("Always full replace",))),
    (SYNC, "syncscope", (("VIP-only mode",), ("DNS Name", "SSL/TLS Certificate"), ("Automatic VIP interface",))),
)
EXPANDABLE_HELP = tuple(row for row in LIST_HELP if row[1] not in {"pfb_alias_delta_mode", "syncscope"})


@dataclass
class _Group:
    names: set[str] = field(default_factory=set)
    items: list[list[str]] = field(default_factory=list)
    warnings: int = 0


class _HelpGroups(HTMLParser):
    """Read the real form row containing each control, including nested infoblocks."""

    def __init__(self) -> None:
        super().__init__()
        self.groups: dict[str, _Group] = {}
        self._group: _Group | None = None
        self._depth = 0
        self._item: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = (values.get("class") or "").split()
        if tag == "div":
            if self._group is None and "form-group" in classes:
                self._group = _Group()
            if self._group is not None:
                self._depth += 1
        if self._group is None:
            return
        if tag in {"input", "select"} and values.get("name"):
            self._group.names.add((values["name"] or "").removesuffix("[]"))
        if "text-danger" in classes:
            self._group.warnings += 1
        if tag == "li":
            self._item = []
            self._group.items.append(self._item)

    def handle_endtag(self, tag: str) -> None:
        if self._group is None:
            return
        if tag == "li":
            self._item = None
        if tag == "div":
            self._depth -= 1
            if self._depth == 0:
                for name in self._group.names:
                    self.groups[name] = self._group
                self._group = None

    def handle_data(self, data: str) -> None:
        if self._item is not None:
            self._item.append(data)


def _rendered_groups(webui: WebUI, path: str) -> dict[str, _Group]:
    response = webui.get(path)
    result = evaluate_render(path, response.status_code, response.text, PAGE_MARKERS[path])
    assert result.ok, f"{path}: {result.detail}"
    parser = _HelpGroups()
    parser.feed(response.text)
    parser.close()
    return parser.groups


@pytest.mark.ui_render
@pytest.mark.parametrize(("path", "name", "associations"), LIST_HELP, ids=[row[1] for row in LIST_HELP])
def test_help_lists_belong_to_their_settings(
    webui: WebUI, path: str, name: str, associations: tuple[tuple[str, ...], ...]
) -> None:
    """A setting's prerequisites and related settings are readable as list items in its own row."""
    groups = _rendered_groups(webui, path)
    assert name in groups, f"{path} has no form row for {name}; rendered rows: {sorted(groups)}"
    items = [" ".join("".join(item).split()) for item in groups[name].items]
    for labels in associations:
        assert any(all(label in item for label in labels) for item in items), (
            f"{name}: expected one help-list item associating {labels!r}; got {items!r}"
        )
    if name == "pfb_dns_listen_vip_only":
        assert groups[name].warnings, f"{name}: client migration warning lost its warning emphasis"


@pytest.mark.ui_browser
@pytest.mark.parametrize(("path", "name", "associations"), EXPANDABLE_HELP, ids=[row[1] for row in EXPANDABLE_HELP])
def test_help_toggle_reveals_readable_setting_lists(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
    path: str,
    name: str,
    associations: tuple[tuple[str, ...], ...],
) -> None:
    """Named controls keep help collapsed until requested, then expose semantic, visible list items."""
    from .test_browser_feeds import JS_TIMEOUT_MS, _open, _shot
    from .test_browser_ip import _expand_section

    page = browser_page
    _open(page, webui, path)
    if name == "pfb_agg_types":
        _expand_section(page, "ip_advanced")
    control = page.locator(f'[name="{name}"], [name="{name}[]"]')
    assert control.count() == 1, f"{name}: expected one associated control, got {control.count()}"
    row = page.locator(".form-group").filter(has=control)
    block = row.locator('[class^="infoblock"]')
    assert block.count() == 1, f"{name}: expected one expandable help block, got {block.count()}"
    assert not block.is_visible(), f"{name}: help must be collapsed before requesting more information"
    toggle = row.get_by_title("More information", exact=True)
    assert toggle.count() == 1, f"{name}: no uniquely named More information control"
    toggle.click()
    block.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    items = block.locator("ul > li")
    texts = items.all_text_contents()
    assert texts, f"{name}: expanded help contains no semantic list items"
    for labels in associations:
        matches = [index for index, text in enumerate(texts) if all(label in text for label in labels)]
        assert matches, f"{name}: visible help lacks setting association {labels!r}; got {texts!r}"
        assert items.nth(matches[0]).is_visible(), f"{name}: associated list item {labels!r} is hidden"
    _shot(page, screenshot_dir, f"help_{name}_expanded")
    toggle.click()
    block.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
