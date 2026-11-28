"""The Resolver cache controls are retired: the obsolete cache (#3701) and Clear Resolver Cache (#3977)."""

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
RETIRED = ("pfb_cache", "pfb_cache_flush")


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
def test_dnsbl_renders_no_resolver_cache_control(webui: WebUI) -> None:
    response = webui.get(PAGE)
    assert response.status_code == 200, f"DNSBL GET returned {response.status_code}"
    assert not looks_like_login_page(response.text), "DNSBL GET returned the login page"
    controls = _Checkboxes(response.text).names
    assert "pfb_py_cache_max" in response.text, "the DNS Caching section lost its decision cache setting"
    for name in RETIRED:
        assert name not in controls, f"retired Resolver cache checkbox {name} is still offered"


@pytest.mark.ui_e2e
def test_dnsbl_save_drops_the_retired_resolver_cache_settings(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    paths = {name: f"{SECTION}/{name}" for name in RETIRED}
    originals = {name: helpers.config_get_state(smoke_vm, path) for name, path in paths.items()}
    try:
        for path in paths.values():
            helpers.config_restore_state(smoke_vm, path, (True, "on"))
            assert helpers.config_get_state(smoke_vm, path) == (True, "on"), f"could not seed {path}"
        response = webui.post(PAGE, {"pfb_cache": "on", "pfb_cache_flush": "on"}, timeout=300.0)
        assert not looks_like_login_page(response.text), "DNSBL POST returned the login page"
        for name, path in paths.items():
            assert helpers.config_get_state(smoke_vm, path)[0] is False, f"a DNSBL save kept retired {name}"
        controls = _Checkboxes(webui.get(PAGE).text).names
        for name in RETIRED:
            assert name not in controls, f"retired {name} returned after save"
    finally:
        for name, path in paths.items():
            helpers.config_restore_state(smoke_vm, path, originals[name])
