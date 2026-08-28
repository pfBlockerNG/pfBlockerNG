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
