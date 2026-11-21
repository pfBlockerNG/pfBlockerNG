"""Tier-B proof of the CrowdSec tab's Settings subtab (issue #4071; docs/specs/crowdsec-integration.md, D2-D4).

Marker ``ui_e2e``: a new page, driven through the real webConfigurator form (CSRF round trip) on the smoke VM.

* The form offers every D2 field; the stored bouncer key is never rendered back, not even masked.
* Each D2 validation rule answers with its own message, and a refused save stores nothing.
* The save applies the "should run" decision at once: with pfBlockerNG on, the CrowdSec enable on and a key, the
  config file exists (mode 0600, the D3 values) and the bouncer runs; turning it off stops it and removes the file,
  and an empty key field keeps the stored key. pfBlockerNG's master enable off keeps it off.
* Issue #4139: the save marks no pending changes (it syncs at once, as the General save does), and the General save of
  pfBlockerNG's master enable stops the bouncer at once, without an Update.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

PAGE = "/pfblockerng/pfblockerng_crowdsec.php"
SECTION = "installedpackages/pfblockerngcrowdsec/config/0"
MASTER = f"{helpers.CFG_GLOBAL}/enable_cb"
CONFIG_FILE = "/usr/local/etc/pfb_crowdsec.json"
PIDFILE = "/var/run/pfb_crowdsec.pid"
GENERAL = "/pfblockerng/pfblockerng_general.php"
PENDING = "/usr/local/etc/pfb_pending_changes"
# An address nothing answers on (RFC 5737): the bouncer runs and retries its first pull, which is all this test needs.
LAPI = "http://192.0.2.10:8080"


def _apply_php() -> str:
    return "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\npfb_global();\npfb_crowdsec_apply();\n"


@pytest.fixture
def crowdsec(smoke_vm: helpers.SmokeVM) -> Iterator[helpers.SmokeVM]:
    """The CrowdSec section starts absent and is removed again; the bouncer is stopped, the master enable restored."""
    vm = smoke_vm
    master = helpers.config_get_state(vm, MASTER)
    remove = (
        f"config_del_path({helpers._php_str(SECTION)});\n"
        "write_config('pfBlockerNG smoke: remove the CrowdSec settings');\n" + _apply_php() + "echo 'OK';"
    )
    result = helpers.php_eval(vm, remove)
    assert result.returncode == 0 and "OK" in result.stdout, result.stderr
    try:
        yield vm
    finally:
        helpers.php_eval(vm, remove)
        helpers.config_restore_state(vm, MASTER, master)


def _running(vm: helpers.SmokeVM) -> bool:
    snippet = "echo isvalidpid('/var/run/pfb_crowdsec.pid') ? '<<RUN>>' : '<<STOP>>';"
    out = helpers.php_eval(vm, snippet).stdout
    assert "<<RUN>>" in out or "<<STOP>>" in out, out
    return "<<RUN>>" in out


def _file(vm: helpers.SmokeVM) -> tuple[str, dict[str, str]] | None:
    """(mode, decoded content) of the config file, or None when it does not exist."""
    probe = vm.ssh("/bin/sh", "-c", f"test -f {CONFIG_FILE} && stat -f %Lp {CONFIG_FILE} && cat {CONFIG_FILE}")
    if probe.returncode != 0:
        return None
    mode, _, body = probe.stdout.partition("\n")
    return mode.strip(), json.loads(body)


def _save(webui: WebUI, overrides: dict[str, str | list[str]]) -> str:
    response = webui.post(PAGE, overrides, timeout=120.0)  # type: ignore[arg-type]
    assert response.status_code == 200, f"save answered HTTP {response.status_code}"
    assert not looks_like_login_page(response.text), "the save returned the login form"
    return response.text


def test_the_form_offers_every_setting_and_never_renders_the_stored_key(
    webui: WebUI, crowdsec: helpers.SmokeVM
) -> None:
    key = f"smoke4071-{uuid.uuid4().hex}"
    helpers.config_set(crowdsec, f"{SECTION}/api_key", key)

    html = webui.get(PAGE).text

    fields = scrape_form_fields(html)
    for name in ("lapi_url", "api_key", "log_level", "rules_tag"):
        assert name in fields, f"the form has no {name!r} field: {sorted(fields)}"
    for name in ("enable", "rules_all_interfaces", "rules_log", "rule_v4", "rule_v6"):
        assert re.search(rf'<input[^>]*name="{name}"[^>]*type="checkbox"|type="checkbox"[^>]*name="{name}"', html), (
            f"no {name!r} checkbox"
        )
    assert re.search(r'<select[^>]*name="rules_interfaces\[\]"[^>]*multiple', html), "no interface multi-select"
    assert fields["log_level"] == "info", f"the log level defaults to info, got {fields['log_level']!r}"
    # A browser submits a checkbox only when it is checked: the D2 defaults
    checked = {name for name in ("enable", "rules_all_interfaces", "rules_log", "rule_v4", "rule_v6") if name in fields}
    assert checked == {"rules_all_interfaces", "rule_v4", "rule_v6"}, f"checked by default: {sorted(checked)}"
    assert re.search(r'<input[^>]*name="api_key"[^>]*type="password"|type="password"[^>]*name="api_key"', html)
    assert fields["api_key"] == "", f"the key field must be empty, got {fields['api_key']!r}"
    assert key not in html, "the stored bouncer key was rendered into the page"
    assert "cscli bouncers add" in html, "the page tells the operator how to get a key"
    assert "Remote Logging" in html, "the page says where pfSense's own logs go"
    # #4158: each line at its level's severity, and pfSense keeps only what its own System Logs level lets through
    assert "its own syslog severity" in html, "the log level help says each line has its level's severity"
    assert "System Logs &gt; Settings</strong>' log level" in html, "the log level help points at pfSense's level"
    assert "A key is stored" in html, "the page says that a key is stored, without showing it"


def test_each_rule_answers_with_its_message_and_a_refused_save_stores_nothing(
    webui: WebUI, crowdsec: helpers.SmokeVM
) -> None:
    key = f"smoke4071-{uuid.uuid4().hex}"
    helpers.config_set(crowdsec, f"{SECTION}/api_key", key)

    html = _save(
        webui,
        {
            "enable": "on",
            "lapi_url": "ftp://lapi.example/",
            "api_key": "has a space",
            "rules_tag": "bad tag",
            "rules_all_interfaces": "",
            "rules_interfaces[]": [],
        },
    )

    # Only the error alert's own text: the form below it names every field too
    alert = re.search(r'<div[^>]*class="[^"]*alert-danger[^"]*"[^>]*>(.*?)</div>', html, re.S)
    assert alert, "the refused save shows no input-error alert"
    errors = [re.sub(r"<[^>]+>", "", item).strip() for item in re.findall(r"<li>(.*?)</li>", alert.group(1), re.S)]
    expected = {
        "LAPI URL": "The Remote LAPI URL must be",
        "API key": "The Bouncer API key must be",
        "Tag": "The Tag must be",
        "interface": "Select at least one interface",
    }
    for field, start in expected.items():
        assert any(error.startswith(start) for error in errors), f"no input error about {field!r}: {errors}"
    assert len(errors) == len(expected), f"exactly one error per refused field, got {errors}"
    assert helpers.config_get(crowdsec, f"{SECTION}/enable") == "", "a refused save stores nothing"
    assert helpers.config_get(crowdsec, f"{SECTION}/api_key") == key, "the stored key is untouched"
    assert key not in html and "has a space" not in html, "no key is echoed, stored or refused"
    assert 'value="ftp://lapi.example/"' in html, "the refused URL is shown again for correction"


def test_the_save_starts_and_stops_the_bouncer_and_an_empty_key_field_keeps_the_key(
    webui: WebUI, crowdsec: helpers.SmokeVM
) -> None:
    vm = crowdsec
    key = f"smoke4071-{uuid.uuid4().hex}"
    helpers.set_package_enabled(vm, True)
    assert _file(vm) is None and not _running(vm), "before-state: never configured, not running"

    _save(webui, {"enable": "on", "lapi_url": LAPI, "api_key": key, "log_level": "debug"})

    stored = _file(vm)
    assert stored is not None, "the save wrote the config file"
    mode, content = stored
    assert mode == "600", f"the config file must be mode 0600, is {mode}"
    assert content == {
        "api_url": LAPI,
        "api_key": key,
        "update_frequency": "10s",
        "table_v4": "crowdsec_v4",
        "table_v6": "crowdsec_v6",
        "log_level": "debug",
        "status_file": "/var/run/pfb_crowdsec.json",
        "decisions_dir": "/var/run/pfb_crowdsec",
    }
    helpers.wait_until(lambda: _running(vm), timeout=30.0, what="the bouncer runs after the save")

    html = _save(webui, {"enable": "", "api_key": ""})

    assert key not in html
    assert _file(vm) is None, "off removes the config file"
    assert not _running(vm), "off stops the bouncer"
    assert helpers.config_get(vm, f"{SECTION}/api_key") == key, "an empty key field keeps the stored key"


def test_with_pfblockerng_off_the_save_stores_the_settings_but_starts_nothing(
    webui: WebUI, crowdsec: helpers.SmokeVM
) -> None:
    vm = crowdsec
    helpers.set_package_enabled(vm, False)

    _save(webui, {"enable": "on", "lapi_url": LAPI, "api_key": f"smoke4071-{uuid.uuid4().hex}"})

    assert helpers.config_get(vm, f"{SECTION}/enable") == "on", "vacuity guard: the settings were stored"
    assert _file(vm) is None, "pfBlockerNG off: no config file"
    assert not _running(vm), "pfBlockerNG off: no bouncer"


def test_a_policy_save_leaves_nothing_pending(webui: WebUI, crowdsec: helpers.SmokeVM) -> None:
    vm = crowdsec
    helpers.set_package_enabled(vm, True)
    vm.ssh("/bin/rm", "-f", PENDING)
    assert vm.ssh("/bin/sh", "-c", f"test -e {PENDING}").returncode != 0, "before-state: nothing is pending"

    _save(webui, {"enable": "on", "lapi_url": LAPI, "api_key": f"smoke4139-{uuid.uuid4().hex}"})

    assert helpers.config_get(vm, f"{SECTION}/enable") == "on", "vacuity guard: a policy setting changed"
    pending = vm.ssh("/bin/sh", "-c", f"test -e {PENDING}").returncode == 0
    assert not pending, "the save syncs at once: nothing waits for an Update"


def test_turning_pfblockerng_off_on_the_general_page_stops_the_bouncer_at_once(
    webui: WebUI, crowdsec: helpers.SmokeVM
) -> None:
    vm = crowdsec
    helpers.set_package_enabled(vm, True)
    _save(webui, {"enable": "on", "lapi_url": LAPI, "api_key": f"smoke4139-{uuid.uuid4().hex}"})
    helpers.wait_until(lambda: _running(vm), timeout=30.0, what="before-state: the bouncer runs")

    response = webui.post(GENERAL, {"enable_cb": ""}, timeout=300.0)  # type: ignore[arg-type]

    assert response.status_code == 200, f"the General save answered HTTP {response.status_code}"
    assert helpers.config_get(vm, MASTER) == "", "vacuity guard: pfBlockerNG is off"
    assert _file(vm) is None, "the General save removed the config file"
    assert not _running(vm), "the General save stopped the bouncer"
