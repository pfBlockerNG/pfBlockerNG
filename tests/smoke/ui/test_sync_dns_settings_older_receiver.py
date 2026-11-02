"""Core's whole-section receive stores the new section without replacing an older node's state.

This invariant is expected to pass before and after #3649. Run it against both the
older receiver and the candidate; unlike the sender regressions, it needs no new API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_sync_dns_settings_receive import LOCAL_ROOT, SHARED, SHARED_ROOT, _php_value
from .test_sync_policy_receive import _emit, _guest_json, _redact

if TYPE_CHECKING:
    from ..conftest import SmokeVM

pytestmark = pytest.mark.ui_e2e


@pytest.mark.parametrize("toggle", ["", "on"], ids=["disabled", "enabled"])
def test_real_core_keeps_older_package_activation_and_snapshot_while_storing_unknown_section(
    deployed_vm: SmokeVM,
    admin_credentials: tuple[str, str],
    webgui_protocol: str,
    request: pytest.FixtureRequest,
    toggle: str,
) -> None:
    vm = deployed_vm
    assert vm.ssh("/bin/test", "-f", helpers.PFB_CRON_DISABLE_PATH).returncode == 0, "cron must be inhibited"
    assert helpers.config_get(vm, "hasync/synchronizetoip") != "127.0.0.1", "core would swallow a sync loop"
    paths = [LOCAL_ROOT, SHARED_ROOT]
    expression = "array(" + ",".join(f"config_get_path('{p}', NULL)" for p in paths) + ")"
    original = _guest_json(vm, _emit(expression))

    def restore() -> None:
        php = f"$saved = {_php_value(original)};\n"
        for index, path in enumerate(paths):
            php += (
                f"if ($saved[{index}] === NULL) {{ PfbConfig::deleteSection('{path}'); }}\n"
                f"elseif (is_array($saved[{index}])) {{ "
                f"PfbConfig::writeSectionRawSystem('{path}', $saved[{index}]); }}\n"
                f"else {{ config_set_path('{path}', $saved[{index}]); }}\n"
            )
        php += "write_config('pfBlockerNG smoke: restore older receiver fixture');\n" + _emit("TRUE")
        assert _guest_json(vm, php) is True, "could not restore older receiver fixture"
        assert _guest_json(vm, _emit(expression)) == original, "older receiver fixture restoration changed stored state"

    request.addfinalizer(restore)
    helpers.config_set(vm, f"{LOCAL_ROOT}/config/0/pfb_dns", toggle)
    state_expression = (
        f"array('local' => config_get_path('{LOCAL_ROOT}'), 'unbound' => config_get_path('unbound'), "
        "'old_doh_port' => isset(pfb_cfg_registry()['dns/pfb_dns_doh_port']) "
        "? PfbConfig::read('dns/pfb_dns_doh_port') : NULL)"
    )
    before = _guest_json(vm, _emit(state_expression))
    port_text = helpers.config_get(vm, "system/webgui/port")
    port = int(port_text) if port_text else (443 if webgui_protocol == "https" else 80)
    user, password = admin_credentials
    payload = {"pfblockerngdnssettings": {"config": [SHARED]}}
    result = _guest_json(
        vm,
        "require_once('xmlrpc_client.inc');\n$c = new pfsense_xmlrpc_client();\n"
        f"$c->setConnectionData('127.0.0.1', {port}, {helpers._php_str(user)}, "
        f"{helpers._php_str(password)}, {helpers._php_str(webgui_protocol)});\n"
        f"$ok = $c->xmlrpc_method('merge_installedpackages_section', {_php_value(payload)}, 60);\n" + _emit("$ok"),
        secret=password,
        timeout=180,
    )
    assert result is True, _redact(f"real core XMLRPC receive failed: {result!r}", password)
    after = _guest_json(vm, _emit(state_expression))
    assert after == before, "core receive changed older package local/Resolver state or its effective DoH port"
    stored = _guest_json(vm, _emit(f"PfbConfig::readSection('{SHARED_ROOT}/config/0')"))
    assert stored == SHARED, f"unknown shared section was not stored: expected {SHARED!r}, got {stored!r}"
