"""Tier B: real pfSense read-only users cannot save either DNS settings page.

Reuse the scoped-operator account lifecycle: real auth.inc password/OS provisioning,
real CSRF login, and user-config-readonly enforced by config.lib.inc::write_config().
"""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_general_scoped_operator import _create_scoped_user, _delete_scoped_user
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


def test_readonly_dns_forms_refuse_save_and_redisplay_submitted_values(
    smoke_vm: SmokeVM, deployed_vm: SmokeVM, webgui_protocol: str, webui: WebUI
) -> None:
    """Both POSTs reach write_config's refusal, retain the submitted fields, and change no disk/marker bytes."""
    vm = smoke_vm
    username = f"pfbro{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    original_reply = helpers.config_get_state(vm, _REPLY)
    original_cache = helpers.config_get_state(vm, _CACHE)
    original_nextuid = helpers.config_get(vm, "system/nextuid")
    created = False
    try:
        _create_scoped_user(vm, username, password)
        created = True
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
        helpers.config_set(vm, _REPLY, "on")
        helpers.config_set(vm, _CACHE, "10000")
        scoped = WebUI(
            host=deployed_vm.host,
            port=deployed_vm.web_port,
            username=username,
            password=password,
            scheme=webgui_protocol,
            verify=webgui_protocol != "https",
        )
        scoped.login()
        guard = PhpErrorLogGuard(vm)
        guard.snapshot()
        for page, markers, field, original, submitted in (
            ("/pfblockerng/pfblockerng_dns.php", ("pfB-DNS Settings",), "pfb_py_reply", "on", ""),
            (
                "/pfblockerng/pfblockerng_dnsbl.php",
                ("DNSBL Webserver Configuration",),
                "pfb_py_cache_max",
                "10000",
                "777",
            ),
        ):
            before_page = scoped.get(page)
            rendered = evaluate_render(page, before_page.status_code, before_page.text, markers)
            assert rendered.ok, f"read-only GET {page}: {rendered.detail}"
            assert scrape_form_fields(before_page.text).get(field, "") == original, (
                f"before {page}: {field} must render stored {original!r}"
            )
            before = _write_state(vm)
            response = scoped.post(page, {field: submitted}, allow_redirects=False, timeout=300.0)
            assert response.status_code == 200, f"{page} refused POST must render, not redirect: {response.status_code}"
            assert not looks_like_login_page(response.text), f"{page}: operator session lost"
            assert "the configuration could not be written" in response.text, (
                f"{page}: POST must reach the real write_config refusal, not an unrelated validation error: "
                f"{response.text[-8000:]}"
            )
            assert scrape_form_fields(response.text).get(field, "") == submitted, (
                f"{page}: form must re-display submitted {field}={submitted!r}, not stored {original!r}"
            )
            assert _write_state(vm) == before, f"{page}: refused save changed config.xml or a pending/apply marker"
        guard.assert_no_growth()
    finally:
        helpers.config_restore_state(vm, _REPLY, original_reply)
        helpers.config_restore_state(vm, _CACHE, original_cache)
        if created:
            _delete_scoped_user(vm, username, original_nextuid)
