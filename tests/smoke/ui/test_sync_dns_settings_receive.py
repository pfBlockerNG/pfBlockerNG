"""Real XMLRPC legacy-all receive keeps pfB-DNS activation/recovery per node (#3649).

The real manual sender calls the disposable VM's own XMLRPC endpoint. The automatic
case builds its payload from the real send hook and calls core's restore endpoint,
which invokes the real receive hook. No receiver merge is copied or mocked.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_sync_policy_receive import _emit, _guest_json, _redact

if TYPE_CHECKING:
    from ..conftest import SmokeVM

pytestmark = pytest.mark.ui_e2e

LOCAL_ROOT = "installedpackages/pfblockerngdns"
SHARED_ROOT = "installedpackages/pfblockerngdnssettings"
SHARED = {
    "pfb_dns_dot": "",
    "pfb_dns_doh": "on",
    "pfb_dns_doq": "off",
    "pfb_dns_dot_port": "8853",
    "pfb_dns_doh_port": "4444",
    "pfb_dns_doq_port": "8854",
    "pfb_dns_doh_trusted": "192.0.2.20/32",
    "pfb_dns_ddr": "on",
}
SAVED_SNAPSHOT = base64.b64encode(
    json.dumps(
        {
            "active_interface": {"present": True, "value": "lan"},
            "enablessl": {"present": True, "value": ""},
            "custom_options": {
                "present": True,
                "value": base64.b64encode(b"server:\n# receiver snapshot sentinel\nhide-identity: yes").decode(),
            },
        }
    ).encode()
).decode()


def _php_value(value: object) -> str:
    return f"json_decode({helpers._php_str(json.dumps(value))}, TRUE)"


@pytest.mark.parametrize("transport", ["manual", "auto"])
@pytest.mark.parametrize("toggle", ["", "on"], ids=["disabled", "enabled"])
def test_real_legacy_receive_transfers_eight_shared_fields_and_keeps_seven_local_fields(
    deployed_vm: SmokeVM,
    admin_credentials: tuple[str, str],
    webgui_protocol: str,
    request: pytest.FixtureRequest,
    transport: str,
    toggle: str,
) -> None:
    vm = deployed_vm
    assert vm.ssh("/bin/test", "-f", helpers.PFB_CRON_DISABLE_PATH).returncode == 0, (
        "scheduled ticks must be inhibited before changing stored pfB-DNS choices"
    )
    assert helpers.config_get(vm, "hasync/synchronizetoip") != "127.0.0.1", (
        "core's loop guard would swallow the self-XMLRPC call"
    )
    paths = [LOCAL_ROOT, SHARED_ROOT]
    original = _guest_json(vm, _emit("array(" + ",".join(f"config_get_path('{p}', NULL)" for p in paths) + ")"))

    def restore() -> None:
        php = f"$saved = {_php_value(original)};\n"
        for index, path in enumerate(paths):
            php += (
                f"if ($saved[{index}] === NULL) {{ PfbConfig::deleteSection('{path}'); }}\n"
                f"elseif (is_array($saved[{index}])) {{ "
                f"PfbConfig::writeSectionRawSystem('{path}', $saved[{index}]); }}\n"
                f"else {{ config_set_path('{path}', $saved[{index}]); }}\n"
            )
        php += "write_config('pfBlockerNG smoke: restore pfB-DNS receive fixture');\n" + _emit("TRUE")
        assert _guest_json(vm, php) is True, "could not restore pfB-DNS fixture"
        restored = _guest_json(vm, _emit("array(" + ",".join(f"config_get_path('{p}', NULL)" for p in paths) + ")"))
        assert restored == original, "pfB-DNS receive fixture restoration changed original values"

    request.addfinalizer(restore)  # Registered before the first mutation, including failed setup.
    local = {
        "pfb_dns": toggle,
        "pfb_dns_saved": SAVED_SNAPSHOT,
        "pfb_dns_interface": "lan",
        "pfb_dns_dot_interface": "lo0",
        "pfb_dns_doh_interface": "192.0.2.2",
        "pfb_dns_doq_interface": "192.0.2.3",
        "pfb_dns_sslcertref": "receiver-local-certificate",
    }
    before = _guest_json(
        vm,
        f"PfbConfig::writeSectionRawSystem('{LOCAL_ROOT}/config/0', {_php_value(local)});\n"
        f"PfbConfig::writeSectionRawSystem('{SHARED_ROOT}/config/0', array('pfb_dns_doh_port' => '4443'));\n"
        "write_config('pfBlockerNG smoke: prepare real legacy receive');\n"
        + _emit(
            f"array('local' => PfbConfig::readSection('{LOCAL_ROOT}/config/0'), "
            "'snapshot_valid' => pfb_dns_proxy_saved() !== NULL, 'unbound' => config_get_path('unbound'))"
        ),
    )
    assert before["local"] == local, "receiver's seven local before-values were not stored as arranged"
    assert before["snapshot_valid"] is True and before["local"]["pfb_dns_saved"], (
        "receiver must start with a nonempty snapshot accepted by the production validator"
    )
    port_text = helpers.config_get(vm, "system/webgui/port")
    port = int(port_text) if port_text else (443 if webgui_protocol == "https" else 80)
    user, password = admin_credentials
    # These are sender-process-only changes. The real endpoint reads the receiver's disk copy.
    php = (
        f"PfbConfig::writeSectionRawSystem('{SHARED_ROOT}/config/0', {_php_value(SHARED)});\n"
        f"PfbConfig::writeSectionRawSystem('{LOCAL_ROOT}/config/0', array('pfb_dns' => '"
        + ("" if toggle else "on")
        + "', 'pfb_dns_saved' => 'sender-only-snapshot'));\n"
        "PfbConfig::writeSectionRawSystem(PFB_SECTIONS['sync'], "
        f"array('syncscope' => 'all', 'varsynconchanges' => '{transport}'));\n"
    )
    connection = (
        f"$c->setConnectionData('127.0.0.1', {port}, {helpers._php_str(user)}, "
        f"{helpers._php_str(password)}, {helpers._php_str(webgui_protocol)});\n"
    )
    if transport == "manual":
        php += (
            "$error = NULL;\n"
            f"$ok = pfblockerng_do_xmlrpc_sync('127.0.0.1', {port}, {helpers._php_str(webgui_protocol)}, "
            f"{helpers._php_str(user)}, {helpers._php_str(password)}, 60, $error);\n"
        )
    else:
        php += (
            "$payload = array();\n"
            "foreach (pfblockerng_plugin_xmlrpc_send() as $p) {\n"
            "    array_set_path($payload, $p, array_get_path($GLOBALS['config'], $p, array()));\n"
            "}\n"
            "require_once('xmlrpc_client.inc');\n$c = new pfsense_xmlrpc_client();\n"
            + connection
            + "$ok = $c->xmlrpc_method('restore_config_section', $payload, 60);\n"
        )
    result = _guest_json(vm, php + _emit("$ok"), secret=password, timeout=180)
    assert result is True, _redact(f"real {transport} XMLRPC receive failed: {result!r}", password)
    after = _guest_json(
        vm,
        _emit(
            f"array('local' => PfbConfig::readSection('{LOCAL_ROOT}/config/0'), "
            f"'shared' => PfbConfig::readSection('{SHARED_ROOT}/config/0'), 'unbound' => config_get_path('unbound'))"
        ),
    )
    assert after["shared"] == SHARED, f"real {transport} receive: expected {SHARED!r}, got {after['shared']!r}"
    assert after["local"] == before["local"], f"real {transport} receive changed node-local activation/recovery fields"
    assert after["unbound"] == before["unbound"], f"real {transport} receive changed the receiver's Resolver"
