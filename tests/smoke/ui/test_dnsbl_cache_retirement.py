"""The obsolete Resolver cache control is retired; Clear Resolver Cache still works."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
SECTION = "installedpackages/pfblockerngdnsblsettings/config/0"


class _Checkboxes(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.names: set[str] = set()
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        fields = dict(attrs)
        if tag == "input" and fields.get("type") == "checkbox":
            name = fields.get("name")
            if name:
                self.names.add(name)


@pytest.mark.ui_render
def test_dnsbl_renders_only_the_supported_resolver_cache_control(webui: WebUI) -> None:
    response = webui.get(PAGE)
    assert response.status_code == 200, f"DNSBL GET returned {response.status_code}"
    assert not looks_like_login_page(response.text), "DNSBL GET returned the login page"
    controls = _Checkboxes(response.text).names
    assert "pfb_cache_flush" in controls, f"Clear Resolver Cache checkbox missing: {sorted(controls)}"
    assert "pfb_cache" not in controls, "obsolete Resolver cache checkbox is still offered"


@pytest.mark.ui_e2e
def test_dnsbl_save_ignores_retired_cache_and_preserves_clear_cache_toggle(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    cache = f"{SECTION}/pfb_cache"
    flush = f"{SECTION}/pfb_cache_flush"
    original_cache = helpers.config_get_state(smoke_vm, cache)
    original_flush = helpers.config_get_state(smoke_vm, flush)
    try:
        helpers.config_restore_state(smoke_vm, cache, (True, "on"))
        assert helpers.config_get_state(smoke_vm, cache) == (True, "on")
        helpers.config_restore_state(smoke_vm, flush, (True, ""))
        assert helpers.config_get_state(smoke_vm, flush) == (True, ""), "could not seed Clear Resolver Cache Off"
        for token in ("on", ""):
            response = webui.post(PAGE, {"pfb_cache": "on", "pfb_cache_flush": token}, timeout=300.0)
            assert not looks_like_login_page(response.text), "DNSBL POST returned the login page"
            assert helpers.config_get_state(smoke_vm, flush) == (True, token), (
                f"Clear Resolver Cache POST {token!r} did not persist"
            )
            assert helpers.config_get_state(smoke_vm, cache)[0] is False, "normal save recreated obsolete pfb_cache"
            controls = _Checkboxes(webui.get(PAGE).text).names
            assert "pfb_cache_flush" in controls, "Clear Resolver Cache disappeared after save"
            assert "pfb_cache" not in controls, "obsolete Resolver cache returned after save"
    finally:
        helpers.config_restore_state(smoke_vm, cache, original_cache)
        helpers.config_restore_state(smoke_vm, flush, original_flush)
