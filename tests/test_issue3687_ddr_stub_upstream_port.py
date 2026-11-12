"""The guest's Unbound forwarder must use the runner stub's actual port (#3687)."""

from __future__ import annotations

import base64
import json
import subprocess
from types import SimpleNamespace
from typing import Any, cast

import pytest

from tests.smoke import helpers as h
from tests.smoke.conftest import GUEST_TO_HOST_ALIAS, STUB_DNS_A

EPHEMERAL_PORT = 41249


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Execute the actual guest PHP against isolated config and service boundaries."""
    states: list[dict[str, Any]] = []

    def php_eval(_vm: object, snippet: str, **_kw: object) -> SimpleNamespace:
        prelude = """
$config = ['system' => ['dnsallowoverride' => 'on', 'dnsserver' => ['192.0.2.1']],
           'unbound' => ['dnssec' => 'on', 'custom_options' => 'stale']];
$writes = 0; $reloads = 0;
function config_get_path($key, $default) { global $config; return $config[$key] ?? $default; }
function config_set_path($key, $value) { global $config; $config[$key] = $value; }
function write_config($message) { global $writes; $writes++; }
function services_unbound_configure() { global $reloads; $reloads++; }
ob_start();
"""
        epilogue = "ob_end_clean(); echo json_encode(['config'=>$config,'writes'=>$writes,'reloads'=>$reloads]);"
        result = subprocess.run(["php", "-r", prelude + snippet + epilogue], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        states.append(json.loads(result.stdout))
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    monkeypatch.setattr(h, "_remember_dns_baseline", lambda *_a, **_kw: None)
    monkeypatch.setattr(h, "php_eval", php_eval)
    monkeypatch.setattr(h, "wait_unbound_ready", lambda *_a, **_kw: None)
    monkeypatch.setattr(h, "dns_probe", lambda *_a, **_kw: h.DnsAnswer(rcode="NOERROR", records=[STUB_DNS_A]))
    return states


@pytest.mark.parametrize("port", [EPHEMERAL_PORT, 53, None], ids=["ephemeral", "system-dns-port", "unrecorded-port"])
def test_upstream_configuration_reaches_the_stub_and_preserves_forwarding(
    configured: list[dict[str, Any]], port: int | None
) -> None:
    h.use_system_dns_upstream(cast(h.SmokeVM, SimpleNamespace(upstream_dns_port=port)))
    [state] = configured
    system = state["config"]["system"]
    unbound = state["config"]["unbound"]
    assert system["dnsserver"] == [GUEST_TO_HOST_ALIAS]
    assert "dnsallowoverride" not in system
    assert unbound["forwarding"] == ""
    assert "dnssec" not in unbound
    assert (state["writes"], state["reloads"]) == (1, 1)
    if port == EPHEMERAL_PORT:
        zone = base64.b64decode(unbound["custom_options"], validate=True).decode()
        assert zone == f'forward-zone:\n    name: "."\n    forward-addr: {GUEST_TO_HOST_ALIAS}@{port}\n'
    else:
        assert "custom_options" not in unbound
