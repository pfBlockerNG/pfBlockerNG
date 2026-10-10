"""Tier-A ``ui_render`` coverage for issue #3450: the IP and DNSBL settings pages read
their registered scalars through ``PfbConfig::read`` and render exactly what the node
stores, or the registry default when it is absent.

#3450 registered twenty IP/DNSBL scalars and moved the pages' reads
(``pfblockerng_ip.php``, ``pfblockerng_dnsbl.php``) off ``$pfb['iconfig'|'dconfig'][...] ?: '<literal>'``
and onto the gateway. The observable consequence is the rendered form, so these tests
assert it against the real pages over the authenticated webConfigurator session:

* a stored non-default value renders as the selected option / input value (a reverted
  read, a swapped in/out read or a hard-coded literal fails);
* an absent key renders the default declared in ``pfb_cfg_registry()`` -- read from the
  guest, not restated here (a wrong registered default fails);
* the write-only MaxMind key and ASN token never reach the page body.

What it cannot prove: the save handlers' persistence (a POST round trip per key).

Self-encapsulated: ``seed`` records each node's raw prior state (including genuine
absence) in one guest round trip and restores it exactly, asserting the restore took.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_toggle_registry_default_render import _input_value, _render, _select_selected_values

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

IP_CFG = "installedpackages/pfblockerngipsettings/config/0"
DNSBL_CFG = "installedpackages/pfblockerngdnsblsettings/config/0"
GATEWAY_GROUPS = ("PFB3450_GW_IN", "PFB3450_GW_OUT")

# alias -> (page, a marker the page always renders, config node, {field: (widget, stored non-default value)}).
# widget: "text" (<input value>) or "select" (the selected <option> set; a multi-select for the interfaces).
# Stored values are the opposite of the registry default so a crossed or reverted read cannot pass:
# deny actions are swapped, and the in/out pairs differ.
PAGES: dict[str, tuple[str, str, str, dict[str, tuple[str, str]]]] = {
    "ip": (
        "/pfblockerng/pfblockerng_ip.php",
        "pfBlockerNG",
        IP_CFG,
        {
            "ip_placeholder": ("text", "127.9.9.9"),
            "maxmind_locale": ("select", "fr"),
            "maxmind_account": ("text", "pfb3450acct"),
            "asn_reporting": ("select", "24hour"),
            "inbound_interface": ("select", "<first-if>"),
            "inbound_deny_action": ("select", "reject"),
            "outbound_interface": ("select", "<last-if>"),
            "outbound_deny_action": ("select", "block"),
            "pass_order": ("select", "order_3"),
            "autorule_suffix": ("select", "ar"),
        },
    ),
    "dnsbl": (
        "/pfblockerng/pfblockerng_dnsbl.php",
        "DNSBL Webserver Configuration",
        DNSBL_CFG,
        {
            "aliasaddr_in": ("text", "pfb3450_addr_in"),
            "aliasaddr_out": ("text", "pfb3450_addr_out"),
            "aliasports_in": ("text", "pfb3450_ports_in"),
            "aliasports_out": ("text", "pfb3450_ports_out"),
            "autoproto_in": ("select", "udp"),
            "autoproto_out": ("select", "tcp"),
            "agateway_in": ("select", GATEWAY_GROUPS[0]),
            "agateway_out": ("select", GATEWAY_GROUPS[1]),
        },
    ),
}

_STATE_OPEN, _STATE_CLOSE = "<<<STATE>>>", "<<<STATEEND>>>"


def _read_states(vm: SmokeVM, paths: list[str]) -> dict[str, str | None]:
    """Raw state of each config node in one round trip: the scalar, or None when genuinely absent."""
    quoted = ", ".join(helpers._php_str(p) for p in paths)
    result = helpers.php_eval(
        vm,
        f"$o = array(); foreach (array({quoted}) as $p) {{ $v = config_get_path($p, NULL); "
        f"$o[$p] = $v === NULL ? NULL : (string) $v; }}\n"
        f"echo '{_STATE_OPEN}' . json_encode($o) . '{_STATE_CLOSE}';\n",
    )
    out = result.stdout
    start, end = out.find(_STATE_OPEN), out.find(_STATE_CLOSE)
    assert result.returncode == 0 and start != -1 and end != -1, (
        f"failed to read config state: rc={result.returncode} stdout={out!r} stderr={result.stderr!r}"
    )
    states: dict[str, str | None] = json.loads(out[start + len(_STATE_OPEN) : end])
    return states


def _write_states(vm: SmokeVM, values: dict[str, str | None]) -> None:
    """Set (str) or delete (None) every node in one write_config."""
    php = "".join(
        f"config_del_path({helpers._php_str(p)});\n"
        if v is None
        else f"config_set_path({helpers._php_str(p)}, {helpers._php_str(v)});\n"
        for p, v in values.items()
    )
    result = helpers.php_eval(vm, php + "write_config('pfBlockerNG smoke #3450: seed');\necho 'SEED-OK';\n")
    assert result.returncode == 0 and "SEED-OK" in result.stdout, (
        f"failed to write config: stdout={result.stdout!r} stderr={result.stderr!r}"
    )


@pytest.fixture
def seed(smoke_vm: SmokeVM) -> Iterator[Callable[[dict[str, str | None]], None]]:
    """Seed (or delete) config nodes for one test, then restore their exact prior state."""
    saved: dict[str, str | None] = {}

    def apply(values: dict[str, str | None]) -> None:
        saved.update(_read_states(smoke_vm, [p for p in values if p not in saved]))
        _write_states(smoke_vm, values)

    yield apply

    if saved:
        _write_states(smoke_vm, saved)
        restored = _read_states(smoke_vm, list(saved))
        assert restored == saved, f"restore did not take -- seeded state leaked: expected {saved!r}, found {restored!r}"


@pytest.fixture
def gateway_groups(smoke_vm: SmokeVM) -> Iterator[None]:
    """Add two gateway groups so the DNSBL gateway selects have non-default options; remove them after."""
    names = ", ".join(helpers._php_str(n) for n in GATEWAY_GROUPS)
    add = (
        "$g = config_get_path('gateways/gateway_group', array());\n"
        f"foreach (array({names}) as $n) {{ $g[] = array('name' => $n, 'item' => array('WAN_DHCP|1'), "
        "'trigger' => 'down', 'descr' => ''); }\n"
        "config_set_path('gateways/gateway_group', $g);\n"
        "write_config('pfBlockerNG smoke #3450: add gateway groups');\necho 'GW-OK';\n"
    )
    remove = (
        "$g = array(); foreach (config_get_path('gateways/gateway_group', array()) as $i) {\n"
        "  if (strpos($i['name'] ?? '', 'PFB3450_GW_') !== 0) { $g[] = $i; } }\n"
        "if ($g) { config_set_path('gateways/gateway_group', $g); }\n"
        "else { config_del_path('gateways/gateway_group'); }\n"
        "write_config('pfBlockerNG smoke #3450: remove gateway groups');\necho 'GW-OK';\n"
    )
    result = helpers.php_eval(smoke_vm, add)
    assert result.returncode == 0 and "GW-OK" in result.stdout, f"add gateway groups failed: {result.stdout!r}"

    yield

    result = helpers.php_eval(smoke_vm, remove)
    assert result.returncode == 0 and "GW-OK" in result.stdout, f"remove gateway groups failed: {result.stdout!r}"


def _registry_defaults(vm: SmokeVM, alias: str, fields: list[str]) -> dict[str, str]:
    """The defaults pfb_cfg_registry() declares, read from the guest (never restated in the test)."""
    quoted = ", ".join(helpers._php_str(f"{alias}/{f}") for f in fields)
    result = helpers.php_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
        f"$r = pfb_cfg_registry(); $o = array();\n"
        f"foreach (array({quoted}) as $k) {{ $o[substr($k, strpos($k, '/') + 1)] = $r[$k]['default']; }}\n"
        f"echo '{_STATE_OPEN}' . json_encode($o) . '{_STATE_CLOSE}';\n",
    )
    out = result.stdout
    start, end = out.find(_STATE_OPEN), out.find(_STATE_CLOSE)
    assert result.returncode == 0 and start != -1 and end != -1, (
        f"failed to read registry defaults: rc={result.returncode} stdout={out!r} stderr={result.stderr!r}"
    )
    defaults: dict[str, str] = json.loads(out[start + len(_STATE_OPEN) : end])
    assert set(defaults) == set(fields), f"registry is missing fields: {set(fields) - set(defaults)}"
    return defaults


def _select_options(html: str, name: str) -> list[str]:
    """Option values of the named ``<select>`` (single or ``name[]`` multi-select), in page order."""
    match = re.search(rf'<select[^>]*\bname="{re.escape(name)}(?:\[\])?"[^>]*>(.*?)</select>', html, re.DOTALL)
    assert match is not None, f'select name="{name}" not found in the rendered page'
    return re.findall(r'<option[^>]*\bvalue="([^"]*)"', match.group(1))


def _assert_renders(html: str, fields: dict[str, tuple[str, str]], expected: dict[str, str], why: str) -> None:
    for name, (widget, _stored) in fields.items():
        if widget == "text":
            assert _input_value(html, name) == expected[name], f"{why}: {name} input must render {expected[name]!r}"
        else:
            # An empty registry default has no matching option, so nothing is selected.
            want = {expected[name]} if expected[name] else set()
            got = _select_selected_values(html, name)
            assert got == want, f"{why}: {name} must select {sorted(want)!r}, selected {sorted(got)!r}"


@pytest.mark.ui_e2e
@pytest.mark.parametrize("alias", sorted(PAGES))
def test_stored_non_default_values_render_selected(
    smoke_vm: SmokeVM,
    webui: WebUI,
    seed: Callable[[dict[str, str | None]], None],
    gateway_groups: None,
    alias: str,
) -> None:
    """Scenario: every registered scalar stored with a non-default value.

    Given the node stores a non-default value for each field the page reads through the gateway.
    When the page renders.
    Then each input carries that value and each select has exactly that option selected --
      a reverted read (renders the default), a hard-coded literal or an in/out swap fails.
    """
    page, marker, cfg, fields = PAGES[alias]
    html = _render(smoke_vm, webui, page, marker)
    interfaces = _select_options(html, "inbound_interface") if alias == "ip" else []
    stored = {
        name: {"<first-if>": interfaces[0:1], "<last-if>": interfaces[-1:]}.get(value, [value])[0]
        for name, (_widget, value) in fields.items()
    }
    seed({f"{cfg}/{name}": value for name, value in stored.items()})

    html = _render(smoke_vm, webui, page, marker)

    _assert_renders(html, fields, stored, "stored")


@pytest.mark.ui_e2e
@pytest.mark.parametrize("alias", sorted(PAGES))
def test_absent_values_render_the_registry_defaults(
    smoke_vm: SmokeVM, webui: WebUI, seed: Callable[[dict[str, str | None]], None], alias: str
) -> None:
    """Scenario: none of the registered scalars exist in config.xml.

    Given every field is absent from the node.
    When the page renders.
    Then each shows the default ``pfb_cfg_registry()`` declares (read from the guest): the registry,
      not the page, owns the default, so a wrong registered default (e.g. 'any' for autoproto,
      which would change the generated rule protocol) fails here.
    """
    page, marker, cfg, fields = PAGES[alias]
    defaults = _registry_defaults(smoke_vm, alias, list(fields))
    seed({f"{cfg}/{name}": None for name in fields})

    html = _render(smoke_vm, webui, page, marker)

    _assert_renders(html, fields, defaults, "absent")


@pytest.mark.ui_e2e
def test_ip_page_never_renders_stored_maxmind_key_or_asn_token(
    smoke_vm: SmokeVM, webui: WebUI, seed: Callable[[dict[str, str | None]], None]
) -> None:
    """Scenario: the write-only credentials are stored.

    Given a MaxMind key and an ASN token are stored (and a MaxMind account, as the control).
    When the IP page renders.
    Then the account renders (the seed took effect) but neither secret appears anywhere in the body
      nor in its input -- registering the keys must not make the form repopulate them (#924, #2922).
    """
    page, marker, cfg, _ = PAGES["ip"]
    key, token = "PFB3450-SENTINEL-MAXMIND-KEY", "PFB3450-SENTINEL-ASN-TOKEN"
    seed(
        {
            f"{cfg}/maxmind_key": key,
            f"{cfg}/asn_token": token,
            f"{cfg}/maxmind_account": "pfb3450acct",
        }
    )

    html = _render(smoke_vm, webui, page, marker)

    assert _input_value(html, "maxmind_account") == "pfb3450acct", "control: the stored account must render"
    assert key not in html, "the stored MaxMind key leaked into the rendered page"
    assert token not in html, "the stored ASN token leaked into the rendered page"
    assert _input_value(html, "maxmind_key") == "", "maxmind_key input must render empty"
    assert _input_value(html, "asn_token") == "", "asn_token input must render empty"
