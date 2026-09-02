"""Tier-A ``ui_render`` coverage for issue #2123: the registry, not the page, decides
what a toggle checkbox renders as when its key is absent from ``config.xml``.

#2123 deleted seventeen page-level default declarations and replaced them with
``PfbConfig::read('<alias>/<key>')``. The observable consequence is the rendered
``checked`` state of a checkbox on a configuration that has never stored the key, so
that is what these tests assert, against the real pages over the authenticated
webConfigurator session.

Two directions matter, and they are opposites:

* the sixteen off-by-default keys (here: the IP page's ``enable_dup`` and the Sync
  page's ``syncinterfaces``) must render UNCHECKED when absent;
* ``alertrefresh`` must render CHECKED when absent — its page-level default was ``on``
  (``pfblockerng_alerts.php:41``'s ``isset(...) ? ... : 'on'``), and a registered
  default of ``''`` would silently switch the Alerts page's auto-refresh off for every
  install that never touched the checkbox. The stored-``''`` half is asserted too: an
  operator who unchecked the box must keep it unchecked, which is the inversion
  issue #2120 ruled on.

What this proves: the registered default, the gateway read, and the render agree on the
real surface, for both an absent key and a stored empty token.
What it cannot prove: the SAVE handler's persistence. ``pfblockerng_ip.php`` and the
sibling settings pages run their save inside a top-level handler that PHPUnit cannot
execute at all (issue #2525: ``require_once('guiconfig.inc')`` exits 255), and asserting
persistence here would need a POST round trip per key; the save side is covered by the
existing Tier-A/Tier-B page flows and by ``CfgToggleRegistryPageParityTest``'s
read-parity matrix in the PHP suite.

Self-encapsulated: each fixture records the node's prior raw state (including genuine
absence) and restores it exactly, asserting the restore took.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

IP_PAGE = "/pfblockerng/pfblockerng_ip.php"
ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"

CFG_ENABLE_DUP = "installedpackages/pfblockerngipsettings/config/0/enable_dup"
CFG_ALERTREFRESH = "installedpackages/pfblockerngglobal/alertrefresh"
CFG_SYNCINTERFACES = "installedpackages/pfblockerngsync/config/0/syncinterfaces"


def _checkbox_is_checked(html: str, name: str) -> bool:
    """True iff the named checkbox renders with the ``checked`` boolean attribute."""
    match = re.search(rf'<input[^>]*\bname="{re.escape(name)}"[^>]*>', html)
    assert match is not None, (
        f'checkbox input name="{name}" not found in the rendered page -- fixture or '
        "page structure broken, not a #2123 signal"
    )
    tag = match.group(0)
    return re.search(r'\bchecked\b(?!\s*=\s*"?[^">]*")', tag) is not None or 'checked="checked"' in tag


def _input_value(html: str, name: str) -> str:
    """The ``value`` attribute of the named ``<input>``, or '' if omitted."""
    match = re.search(rf'<input[^>]*\bname="{re.escape(name)}"[^>]*>', html)
    assert match is not None, f'input name="{name}" not found in the rendered page'
    val = re.search(r'\bvalue="([^"]*)"', match.group(0))
    return val.group(1) if val else ""


def _select_selected(html: str, name: str) -> str:
    """The selected option value of the named ``<select>``."""
    match = re.search(
        rf'<select[^>]*\bname="{re.escape(name)}"[^>]*>(.*?)</select>',
        html,
        re.DOTALL,
    )
    assert match is not None, f'select name="{name}" not found in the rendered page'
    selected = re.search(r'<option[^>]*\bselected\b[^>]*\bvalue="([^"]*)"', match.group(1))
    if selected is None:
        selected = re.search(r'<option[^>]*\bvalue="([^"]*)"[^>]*\bselected\b', match.group(1))
    assert selected is not None, f'select name="{name}" has no selected option'
    return selected.group(1)


def _node_state(vm: SmokeVM, path: str) -> str:
    """Serialise the node's raw state so an ABSENT key is restored as absent."""
    result = helpers.php_eval(
        vm,
        f"$v = config_get_path('{path}');\necho $v === NULL ? 'ABSENT' : 'VALUE:' . $v;\n",
    )
    assert result.returncode == 0, f"failed to read {path}: {result.stderr!r}"
    return result.stdout.strip().splitlines()[-1]


def _restore_node(vm: SmokeVM, path: str, state: str) -> None:
    if state == "ABSENT":
        php = f"config_del_path('{path}');\n"
    else:
        php = f"config_set_path('{path}', '{state[len('VALUE:') :]}');\n"
    result = helpers.php_eval(vm, php + "write_config('pfBlockerNG smoke #2123: restore');\necho 'RESTORE-OK';\n")
    assert result.returncode == 0 and "RESTORE-OK" in result.stdout, (
        f"failed to restore {path}: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert _node_state(vm, path) == state, f"{path} restore did not take -- the seeded state leaked to sibling tests"


@pytest.fixture
def node_state(smoke_vm: SmokeVM) -> Iterator[Callable[[str, str | None], None]]:
    """Set (or delete) a config node for the duration of one test, then restore it."""
    vm = smoke_vm
    saved: dict[str, str] = {}

    def apply(path: str, value: str | None) -> None:
        if path not in saved:
            saved[path] = _node_state(vm, path)
        php = f"config_del_path('{path}');\n" if value is None else f"config_set_path('{path}', '{value}');\n"
        result = helpers.php_eval(vm, php + "write_config('pfBlockerNG smoke #2123: seed');\necho 'SEED-OK';\n")
        assert result.returncode == 0 and "SEED-OK" in result.stdout, (
            f"failed to seed {path}: stdout={result.stdout!r} stderr={result.stderr!r}"
        )

    yield apply

    for path, state in saved.items():
        _restore_node(vm, path, state)


def _render(smoke_vm: SmokeVM, webui: WebUI, path: str, marker: str) -> str:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, (marker,))
    assert result.ok, f"Tier-A render oracle failed for {path}: {result.detail}"
    guard.assert_no_growth()
    return resp.text


def test_absent_ip_toggle_renders_unchecked_from_the_registered_default(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """Scenario: the IP page's De-Duplication checkbox with no stored key.

    Given ``enable_dup`` is absent from config.xml.
    When the IP page renders.
    Then the checkbox is unchecked — the registry's '' default, which is what
      ``pfblockerng_ip.php``'s deleted ``?: ''`` produced. A registered default of
      'on' would silently enable de-duplication on every untouched install.
    """
    # BEFORE: prove the enabled state renders checked, so the unchecked assertion
    # below cannot pass just because the page never renders a checked box.
    node_state(CFG_ENABLE_DUP, "on")
    html = _render(smoke_vm, webui, IP_PAGE, "pfBlockerNG")
    assert _checkbox_is_checked(html, "enable_dup"), "before: a stored 'on' enable_dup must render checked"

    node_state(CFG_ENABLE_DUP, None)
    html = _render(smoke_vm, webui, IP_PAGE, "pfBlockerNG")
    assert not _checkbox_is_checked(html, "enable_dup"), (
        "an absent enable_dup must render UNCHECKED -- the registered '' default "
        "must reproduce the page default #2123 deleted"
    )


def test_absent_alertrefresh_renders_checked_and_a_stored_uncheck_stays_off(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """Scenario: the Alerts page's Auto-Refresh checkbox, the default-ON survivor.

    Given ``alertrefresh`` is absent from config.xml.
    When the Alerts page renders.
    Then the checkbox is CHECKED — the registry now carries the 'on' default that
      ``pfblockerng_alerts.php:41``'s ``isset()`` fallback used to declare.
    And given the operator unchecked it (PFB_FILTER_ON_OFF stored ''),
    Then it renders UNCHECKED — a present empty token is a decision, not the
      default (issue #2120).
    """
    node_state(CFG_ALERTREFRESH, None)
    html = _render(smoke_vm, webui, ALERTS_PAGE, "Alert Settings")
    assert _checkbox_is_checked(html, "alertrefresh"), (
        "an absent alertrefresh must render CHECKED -- the registered 'on' default "
        "carries the ON default deleted from pfblockerng_alerts.php:41; rendering it "
        "unchecked is the user-visible inversion #2123 had to avoid"
    )

    node_state(CFG_ALERTREFRESH, "")
    html = _render(smoke_vm, webui, ALERTS_PAGE, "Alert Settings")
    assert not _checkbox_is_checked(html, "alertrefresh"), (
        "a stored '' alertrefresh must render UNCHECKED -- an operator's uncheck is not the registered default"
    )


def test_absent_syncinterfaces_renders_unchecked_from_the_registered_default(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """Scenario: the Sync page's settings-sync opt-out checkbox.

    Given ``syncinterfaces`` is absent from config.xml.
    When the Sync page renders.
    Then the checkbox is unchecked, so General/IP/DNSBL settings keep syncing —
      the behaviour ``pfblockerng_sync.php:35``'s deleted ``?: ''`` produced.
    """
    node_state(CFG_SYNCINTERFACES, "on")
    html = _render(smoke_vm, webui, SYNC_PAGE, "XMLRPC Sync Settings")
    assert _checkbox_is_checked(html, "syncinterfaces"), "before: a stored 'on' syncinterfaces must render checked"

    node_state(CFG_SYNCINTERFACES, None)
    html = _render(smoke_vm, webui, SYNC_PAGE, "XMLRPC Sync Settings")
    assert not _checkbox_is_checked(html, "syncinterfaces"), (
        "an absent syncinterfaces must render UNCHECKED -- the registered '' default "
        "must reproduce the page default #2123 deleted"
    )


# ---------------------------------------------------------------------------
# issue #2812: the seven residue toggles whose page-level default the registry
# now owns exclusively (the sites #2123's regrowth gate exempted). The sweep is
# behaviour-equivalent by design -- every toggle-contract state renders exactly
# as before -- so these tests pin the end-state observable on the real pages: a
# stored 'on' renders CHECKED (control), and an absent key renders UNCHECKED
# (registry defaults: '' for five, legacy-'off' for lenient), plus the lenient
# key's two Off spellings ('' and legacy 'off') both rendering UNCHECKED.
# Every case mutates config.xml, so each rides the isolation net (dual-marked
# ui_e2e per conftest's _ui_pfb_isolation marker discipline).

_DNSBL_SETTINGS_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
_GENERAL_SETTINGS_PAGE = "/pfblockerng/pfblockerng_general.php"

_SWEPT_DNSBL_TOGGLES = {
    "pfb_dnsbl": "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl",
    "pfb_dnsvip_auto": "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto",
    "pfb_dnsbl_nonat": "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_nonat",
    "pfb_idn_escalate_suspicious": "installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_escalate_suspicious",
    "pfb_regex_cap": "installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex_cap",
    "pfb_dnsbl_lenient": "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient",
}
CFG_ENABLE_CB = "installedpackages/pfblockerng/config/0/enable_cb"


@pytest.mark.ui_e2e
@pytest.mark.parametrize("name", sorted(_SWEPT_DNSBL_TOGGLES))
def test_swept_dnsbl_toggle_renders_on_when_stored_and_off_when_absent(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None], name: str
) -> None:
    """issue #2812: each swept DNSBL toggle's checked state comes from the registry.

    Given the key stored as 'on', the checkbox renders CHECKED -- the control that
    the page can render this box checked at all. Given the key absent, it renders
    UNCHECKED: the registered '' (or, for the lenient key, legacy-'off') default
    that replaced the page literal #2812 deleted.
    """
    path = _SWEPT_DNSBL_TOGGLES[name]
    node_state(path, "on")
    html = _render(smoke_vm, webui, _DNSBL_SETTINGS_PAGE, "DNSBL Webserver Configuration")
    assert _checkbox_is_checked(html, name), f"control: a stored 'on' {name} must render checked"

    node_state(path, None)
    html = _render(smoke_vm, webui, _DNSBL_SETTINGS_PAGE, "DNSBL Webserver Configuration")
    assert not _checkbox_is_checked(html, name), (
        f"an absent {name} must render UNCHECKED -- the registered default "
        "must reproduce the page default #2812 deleted"
    )


@pytest.mark.ui_e2e
def test_swept_pfb_dnsbl_lenient_off_spellings_render_unchecked(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """issue #2812: the lenient key's registry default is legacy 'off' where the old
    page literal was '' -- under the #2120 toggle contract both spell Off, so both
    stored spellings render UNCHECKED (the equivalence the sweep relied on)."""
    for stored in ("off", ""):
        node_state(_SWEPT_DNSBL_TOGGLES["pfb_dnsbl_lenient"], stored)
        html = _render(smoke_vm, webui, _DNSBL_SETTINGS_PAGE, "DNSBL Webserver Configuration")
        assert not _checkbox_is_checked(html, "pfb_dnsbl_lenient"), (
            f"a stored {stored!r} pfb_dnsbl_lenient must render UNCHECKED -- both Off "
            "spellings agree under the #2120 toggle contract"
        )


@pytest.mark.ui_e2e
def test_swept_general_enable_cb_renders_on_when_stored_and_off_when_absent(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """issue #2812: the General page's master-enable checkbox with no stored key
    renders UNCHECKED (registered '' default); a stored 'on' renders CHECKED."""
    node_state(CFG_ENABLE_CB, "on")
    html = _render(smoke_vm, webui, _GENERAL_SETTINGS_PAGE, "General Settings")
    assert _checkbox_is_checked(html, "enable_cb"), "control: a stored 'on' enable_cb must render checked"

    node_state(CFG_ENABLE_CB, None)
    html = _render(smoke_vm, webui, _GENERAL_SETTINGS_PAGE, "General Settings")
    assert not _checkbox_is_checked(html, "enable_cb"), (
        "an absent enable_cb must render UNCHECKED -- the registered '' default "
        "must reproduce the page default #2812 deleted"
    )


# ---------------------------------------------------------------------------
# issue #2994: registered plain-scalar absent-key render. The six divergences
# were aligned so an absent key still renders the operator-visible value the
# page used to declare itself. Dual-marked ui_e2e: each case mutates config.xml.
# ---------------------------------------------------------------------------

_CFG_DNSBL = "installedpackages/pfblockerngdnsblsettings/config/0"


@pytest.mark.ui_e2e
def test_absent_dnsbl_ports_render_the_page_defaults(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """issue #2994: absent pfb_dnsport/ssl still render 8081/8443 from the registry."""
    node_state(f"{_CFG_DNSBL}/pfb_dnsport", None)
    node_state(f"{_CFG_DNSBL}/pfb_dnsport_ssl", None)
    html = _render(smoke_vm, webui, _DNSBL_SETTINGS_PAGE, "DNSBL")
    assert _input_value(html, "pfb_dnsport") == "8081"
    assert _input_value(html, "pfb_dnsport_ssl") == "8443"


@pytest.mark.ui_e2e
def test_absent_aliaslog_renders_enabled(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """issue #2994: absent aliaslog still selects Enable (the page/help default)."""
    node_state(f"{_CFG_DNSBL}/aliaslog", None)
    html = _render(smoke_vm, webui, _DNSBL_SETTINGS_PAGE, "DNSBL")
    assert _select_selected(html, "aliaslog") == "enabled"


@pytest.mark.ui_e2e
def test_absent_dnsbl_rule_renders_unchecked(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """issue #2994: absent pfb_dnsbl_rule stays Off under the registry Disabled token."""
    node_state(f"{_CFG_DNSBL}/pfb_dnsbl_rule", None)
    html = _render(smoke_vm, webui, _DNSBL_SETTINGS_PAGE, "DNSBL")
    assert not _checkbox_is_checked(html, "pfb_dnsbl_rule")


@pytest.mark.ui_e2e
def test_absent_dnsbl_vips_render_the_none_sentinel(
    smoke_vm: SmokeVM, webui: WebUI, node_state: Callable[[str, str | None], None]
) -> None:
    """issue #2994: absent pfb_dnsvip4/6 still select the widget none sentinel."""
    node_state(f"{_CFG_DNSBL}/pfb_dnsvip4", None)
    node_state(f"{_CFG_DNSBL}/pfb_dnsvip6", None)
    html = _render(smoke_vm, webui, _DNSBL_SETTINGS_PAGE, "DNSBL")
    assert _select_selected(html, "pfb_dnsvip4") == "none"
    assert _select_selected(html, "pfb_dnsvip6") == "none"
