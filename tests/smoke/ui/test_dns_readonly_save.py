"""Tier B: real pfSense read-only users cannot save DNS General, its pfB-DNS settings, DNSBL or a DNSBL group.

Reuse the scoped-operator account lifecycle: real auth.inc password/OS provisioning,
real CSRF login, and user-config-readonly enforced by config.lib.inc::write_config().
"""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render, input_errors_block
from .test_category_edit import CFG_DNSBL, _del_rowid, _dnsbl_payload, _free_rowid, _post_form
from .test_general_scoped_operator import _create_scoped_user, _delete_scoped_user
from .test_sanitize_persist import _dnsbl_folder
from .webui import WebUI, looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from ..conftest import SmokeVM

pytestmark = pytest.mark.ui_e2e

_REPLY = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply"
_CACHE = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_cache_max"


def _write_state(vm: SmokeVM) -> dict[str, str | None]:
    """Disk config and pending/apply marker bytes: no save may change any of them."""
    result = helpers.php_eval(
        vm,
        "$state = ['config' => hash_file('sha256', '/conf/config.xml')];\n"
        "foreach (['/usr/local/etc/pfb_pending_changes', '/usr/local/etc/pfb_pending_changes.applied'] as $path) {\n"
        "    $state[$path] = is_file($path) ? base64_encode(file_get_contents($path)) : NULL;\n"
        "}\n"
        "echo 'PFB_READONLY_STATE:' . json_encode($state);",
    )
    for line in result.stdout.splitlines():
        if line.startswith("PFB_READONLY_STATE:"):
            return json.loads(line.split(":", 1)[1])
    raise AssertionError(f"state probe did not finish: {result.stdout!r} {result.stderr!r}")


def _grant_readonly(vm: SmokeVM, username: str) -> None:
    """Give the scoped operator ``user-config-readonly``: pfSense's write_config() then refuses every save it makes."""
    result = helpers.php_eval(
        vm,
        "require_once('auth.inc');\n"
        "$found = FALSE;\n"
        "foreach (config_get_path('system/user', []) as $i => $user) {\n"
        f"    if ($user['name'] === {helpers._php_str(username)}) {{\n"
        "        $user['priv'][] = 'user-config-readonly';\n"
        "        config_set_path('system/user/' . $i, $user);\n"
        "        local_user_set($user);\n"
        "        $found = TRUE;\n"
        "        break;\n"
        "    }\n"
        "}\n"
        "if (!$found) { throw new RuntimeException('read-only user not found'); }\n"
        "write_config('pfBlockerNG smoke: read-only DNS operator');\n"
        "echo 'PFB_READONLY_USER:OK';",
    )
    assert "PFB_READONLY_USER:OK" in result.stdout, f"read-only privilege setup failed: {result.stdout!r}"


def _operator_ui(deployed_vm: SmokeVM, webgui_protocol: str, username: str, password: str) -> WebUI:
    """The operator's own logged-in webConfigurator session."""
    scoped = WebUI(
        host=deployed_vm.host,
        port=deployed_vm.web_port,
        username=username,
        password=password,
        scheme=webgui_protocol,
        verify=webgui_protocol != "https",
    )
    scoped.login()
    return scoped


def test_readonly_dns_forms_refuse_save_and_redisplay_submitted_values(
    smoke_vm: SmokeVM, deployed_vm: SmokeVM, webgui_protocol: str, webui: WebUI
) -> None:
    """All POSTs reach write_config's refusal, retain submitted fields, and change no disk/marker bytes."""
    vm = smoke_vm
    username = f"pfbro{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    seeded = {
        _REPLY: "on",
        _CACHE: "10000",
        **{
            "installedpackages/pfblockerng/config/0/" + key: value
            for key, value in {
                "pfb_dns_listen_vip": "",
                "pfb_dns_listen_vip_only": "",
                "pfb_dns_listen_vip4": "",
                "pfb_dns_listen_vip6": "",
                "pfb_dns_listen_interface": "lo0",
            }.items()
        },
        **{
            helpers.dns_config_path(key): value
            for key, value in {
                "pfb_dns": "on",
                "pfb_dns_name": "",
                "pfb_dns_dot": "",
                "pfb_dns_doh": "",
                "pfb_dns_doq": "",
                "pfb_dns_ddr": "",
                "pfb_dns_sslcertref": "",
                "pfb_dns_doh_trusted": "",
                "pfb_dns_ddr_doh_443_interfaces": "",
                "pfb_dns_interface": "lo0",
                "pfb_dns_dot_interface": "lo0",
                "pfb_dns_doh_interface": "lo0",
                "pfb_dns_doq_interface": "lo0",
                "pfb_dns_dot_port": "853",
                "pfb_dns_doh_port": "443",
                "pfb_dns_doq_port": "853",
                "pfb_dns_dot_port6": "",
                "pfb_dns_doh_port6": "",
                "pfb_dns_doq_port6": "",
            }.items()
        },
    }
    originals = {path: helpers.config_get_state(vm, path) for path in seeded}
    original_nextuid = helpers.config_get(vm, "system/nextuid")
    created = False
    try:
        _create_scoped_user(vm, username, password)
        created = True
        _grant_readonly(vm, username)
        for path, value in seeded.items():
            helpers.config_set(vm, path, value)
        assert {path: helpers.config_get(vm, path) for path in seeded} == seeded, (
            "read-only fixture must start with valid DNS General and transport siblings"
        )
        scoped = _operator_ui(deployed_vm, webgui_protocol, username, password)
        guard = PhpErrorLogGuard(vm)
        guard.snapshot()
        general = "/pfblockerng/pfblockerng_dns_general.php"
        for page, markers, field, original, submitted, submit in (
            (general, ("DNS Reply Logging",), "pfb_py_reply", "on", "", ("save", "save")),
            (general, ("pfB-DNS Settings",), "pfb_dns", "on", "", ("save", "save")),
            (
                "/pfblockerng/pfblockerng_dnsbl.php",
                ("DNSBL Webserver Configuration",),
                "pfb_py_cache_max",
                "10000",
                "777",
                ("save", "save"),
            ),
        ):
            where = f"{page} [{field}]"
            before_page = scoped.get(page)
            rendered = evaluate_render(page, before_page.status_code, before_page.text, markers)
            assert rendered.ok, f"read-only GET {where}: {rendered.detail}"
            assert scrape_form_fields(before_page.text).get(field, "") == original, (
                f"before {where}: {field} must render stored {original!r}"
            )
            before = _write_state(vm)
            response = scoped.post(page, {field: submitted}, submit=submit, allow_redirects=False, timeout=300.0)
            assert response.status_code == 200, (
                f"{where} refused POST must render, not redirect: {response.status_code}"
            )
            assert not looks_like_login_page(response.text), f"{where}: operator session lost"
            errors = input_errors_block(response.text)
            assert errors and "the configuration could not be written" in errors, (
                f"{where}: POST must reach the real write_config refusal, not an unrelated validation error: "
                f"{response.text[-8000:]}"
            )
            assert scrape_form_fields(response.text).get(field, "") == submitted, (
                f"{where}: form must re-display submitted {field}={submitted!r}, not stored {original!r}"
            )
            assert _write_state(vm) == before, f"{where}: refused save changed config.xml or a pending/apply marker"
        guard.assert_no_growth()
    finally:
        for path, state in originals.items():
            helpers.config_restore_state(vm, path, state)
        if created:
            _delete_scoped_user(vm, username, original_nextuid)


def test_readonly_group_save_of_a_custom_list_requests_no_rebuild(
    smoke_vm: SmokeVM, deployed_vm: SmokeVM, webgui_protocol: str, webui: WebUI
) -> None:
    """Issue #3999: the custom list's rebuild marker follows a written save only.

    Given: a stored DNSBL group with no custom list, and an operator whose saves pfSense's write_config() refuses
    When:  the operator saves the group with a custom list, then an administrator saves the same
    Then:  the refused save leaves no rebuild marker and stores nothing; the written save stores the list and leaves it
    """
    vm = smoke_vm
    username = f"pfbro{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    name = f"ro{uuid.uuid4().hex[:8]}"
    marker = f"{_dnsbl_folder(vm)}/{name}_custom.update"
    rowid = _free_rowid(vm, CFG_DNSBL)
    original_nextuid = helpers.config_get(vm, "system/nextuid")
    created = False
    try:
        _post_form(webui, _dnsbl_payload(rowid, name))
        assert helpers.config_get(vm, f"{CFG_DNSBL}/{rowid}/aliasname") == name, "before-state: the group is stored"
        assert not helpers.hook_marker_exists(vm, marker), "before-state: no rebuild is requested"
        _create_scoped_user(vm, username, password)
        created = True
        _grant_readonly(vm, username)
        scoped = _operator_ui(deployed_vm, webgui_protocol, username, password)

        _post_form(
            scoped,
            _dnsbl_payload(rowid, name, custom="example.com"),
            expect_rejection="the configuration could not be written",
        )
        assert helpers.config_get(vm, f"{CFG_DNSBL}/{rowid}/custom") == "", "the refused save stores no custom list"
        assert not helpers.hook_marker_exists(vm, marker), "a custom list that was never stored must not be rebuilt"

        _post_form(webui, _dnsbl_payload(rowid, name, custom="example.com"))
        assert helpers.config_get(vm, f"{CFG_DNSBL}/{rowid}/custom") != "", "the administrator's save stores the list"
        assert helpers.hook_marker_exists(vm, marker), "and requests its rebuild"
    finally:
        vm.ssh("/bin/rm", "-f", marker)
        _del_rowid(vm, CFG_DNSBL, rowid)
        if created:
            _delete_scoped_user(vm, username, original_nextuid)
