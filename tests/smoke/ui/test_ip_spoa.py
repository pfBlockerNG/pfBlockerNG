"""Tier-A (ui_render) and Tier-B (ui_e2e) UI coverage for pfb-core HAProxy SPOA controls on pfblockerng_ip.php (#4309).

* Tier-A asserts the rendered SPOA checkbox, listen address input, aliases input, and generated HAProxy SPOE snippet.
* Tier-B drives the real webConfigurator form (CSRF round trip) on the smoke VM to verify enabling, changing,
  disabling, and rejecting invalid SPOA settings, plus regenerating /usr/local/etc/rc.d/pfb_core.sh.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from .webui import WebUI

PAGE = "/pfblockerng/pfblockerng_ip.php"
IP_SECTION = "installedpackages/pfblockerngipsettings/config/0"
CORE_RC = "/usr/local/etc/rc.d/pfb_core.sh"


@pytest.fixture
def ip_spoa_state(smoke_vm: helpers.SmokeVM) -> Iterator[helpers.SmokeVM]:
    """Snapshot and restore the three ip/spoa_* config keys and regenerate pfb_core.sh on teardown."""
    vm = smoke_vm
    keys = ("spoa_enable", "spoa_listen", "spoa_aliases")
    saved = {k: helpers.config_get_state(vm, f"{IP_SECTION}/{k}") for k in keys}
    try:
        yield vm
    finally:
        for k, state in saved.items():
            helpers.config_restore_state(vm, f"{IP_SECTION}/{k}", state)
        helpers.php_eval(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            "pfb_global();\n"
            "pfb_core_service();\n"
            "if (function_exists('restart_service')) { restart_service('pfb_core'); }\n",
        )


def _save_ip(webui: WebUI, overrides: dict[str, str | list[str]]) -> str:
    response = webui.post(PAGE, overrides, timeout=120.0)  # type: ignore[arg-type]
    assert response.status_code == 200, f"save answered HTTP {response.status_code}"
    assert not looks_like_login_page(response.text), "the save returned the login form"
    return response.text


@pytest.mark.ui_render
def test_ip_spoa_controls_and_snippet_render(webui: WebUI) -> None:
    html = webui.get(PAGE).text
    assert not looks_like_login_page(html), "GET pfblockerng_ip.php returned login page"
    fields = scrape_form_fields(html)
    for name in ("spoa_listen", "spoa_aliases"):
        assert name in fields, f"missing {name!r} field in {sorted(fields)}"
    assert re.search(
        r'<input[^>]*name="spoa_enable"[^>]*type="checkbox"|type="checkbox"[^>]*name="spoa_enable"',
        html,
    ), "missing spoa_enable checkbox"
    assert "spoe-agent pfb-core-agent" in html, "missing pfb-core SPOE snippet"
    assert "send-spoe-group pfb-core" in html, "missing ordered HAProxy frontend snippet"


@pytest.mark.ui_e2e
def test_ip_spoa_save_updates_config_and_rc_script(webui: WebUI, ip_spoa_state: helpers.SmokeVM) -> None:
    vm = ip_spoa_state
    # 1. Enable SPOA with a custom loopback port and alias filter.
    html = _save_ip(
        webui,
        {
            "spoa_enable": "on",
            "spoa_listen": "127.0.0.1:10095",
            "spoa_aliases": "pfB_Test_v4",
        },
    )
    assert "input-errors" not in html, "valid SPOA save returned input errors"
    rc_on = vm.ssh("/bin/cat", CORE_RC)
    assert rc_on.returncode == 0, rc_on.stderr
    assert "--spoa-listen '127.0.0.1:10095'" in rc_on.stdout, rc_on.stdout
    assert "--spoa-aliases 'pfB_Test_v4'" in rc_on.stdout, rc_on.stdout

    # 2. Re-render confirms persisted values and updated HAProxy snippet.
    reloaded = webui.get(PAGE).text
    assert "server pfb-core 127.0.0.1:10095 check" in reloaded, "snippet did not reflect updated spoa_listen"

    # 3. Disable SPOA and verify --spoa-listen is removed from pfb_core.sh.
    html_off = _save_ip(
        webui,
        {
            "spoa_enable": "",
            "spoa_listen": "127.0.0.1:10090",
            "spoa_aliases": "",
        },
    )
    assert "input-errors" not in html_off, "disabling SPOA returned input errors"
    rc_off = vm.ssh("/bin/cat", CORE_RC)
    assert rc_off.returncode == 0, rc_off.stderr
    assert "--spoa-listen" not in rc_off.stdout, rc_off.stdout


@pytest.mark.ui_e2e
def test_ip_spoa_invalid_listen_and_aliases_refused(webui: WebUI, ip_spoa_state: helpers.SmokeVM) -> None:
    html = _save_ip(
        webui,
        {
            "spoa_enable": "on",
            "spoa_listen": "0.0.0.0:10090",
            "spoa_aliases": "bad;alias",
        },
    )
    assert "HAProxy SPOA Listen Address" in html, "non-loopback spoa_listen was not rejected"
    assert "HAProxy SPOA Aliases" in html, "invalid spoa_aliases was not rejected"
