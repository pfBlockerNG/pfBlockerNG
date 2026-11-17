"""Tier-A ``ui_render`` coverage for issue #4031: a Hooks, SafeSearch or IP save reaches Core at once.

Core reads the hook rows, the DNSBL build policy and the IP policy through its settings adapter (`hooks`,
`policy/dnsbl`, `policy/ip`); each page tells Core once its write succeeded. With Core serving, a save leaves Core at
the revision config.xml projects, and the adapter's read holds what the page saved. The oracle is Core's own answer
and config.xml read back over SSH, never the HTTP body.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from ..test_smoke_core_api import await_core_up, config_revision, core_dns, php_json, tell_core
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_dns_general_core_push import _core_in_step
from .test_hooks import HOOKS_PAGE, SCRIPT_PRE, _install_test_scripts

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

SAFESEARCH_PAGE = "/pfblockerng/pfblockerng_safesearch.php"
IP_PAGE = "/pfblockerng/pfblockerng_ip.php"
SAFESEARCH_YOUTUBE = "installedpackages/pfblockerngsafesearch/safesearch_youtube"
IP_AGGREGATE = "installedpackages/pfblockerngipsettings/config/0/enable_agg"


@pytest.fixture
def core_serving(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Core answers (the webui fixture has the package deployed, and its install starts the service)."""
    await_core_up(smoke_vm)


def _core_revision(vm: SmokeVM) -> int:
    """The revision Core holds."""
    held = core_dns(vm)
    assert held is not None, "Core did not answer"
    return held[0]


def _save(vm: SmokeVM, webui: WebUI, page: str, overrides: dict[str, str], marker: str) -> None:
    """Save ``page`` with ``overrides`` and hold its next render to the Tier-A oracle."""
    guard = PhpErrorLogGuard(vm)
    guard.snapshot()
    webui.post(page, overrides, timeout=120.0)
    response = webui.get(page)
    rendered = evaluate_render(page, response.status_code, response.text, (marker,))
    assert rendered.ok, f"{page} GET after the save: {rendered.detail}"
    guard.assert_no_growth()


def test_a_hooks_save_with_core_serving_leaves_core_at_the_revision_config_xml_projects(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """Core holds the saved hook row: it is at config.xml's revision, which the save moved.

    Given: Core serving at config.xml's revision, and no hook row
    When:  the Hooks page saves one enabled ``pre`` row
    Then:  the adapter's read lists the row, and Core is at config.xml's new revision
    """
    vm = smoke_vm
    helpers.clear_update_hooks(vm)
    _install_test_scripts(vm)
    with _core_in_step(vm):
        try:
            tell_core(vm)
            before = config_revision(vm)
            assert _core_revision(vm) == before, "before-state: Core must be at config.xml's revision"
            assert php_json(vm, "pfb_core_settings()['hooks']['rows']") == [], "before-state: no hook row projects"

            _save(
                vm,
                webui,
                HOOKS_PAGE,
                {"hook_script-0": SCRIPT_PRE, "hook_when-0": "pre", "hook_timeout-0": "45", "hook_enabled-0": "on"},
                "Hooks",
            )

            rows = php_json(vm, "pfb_core_settings()['hooks']['rows']")
            expected = [
                {"id": "0", "when": "pre", "script": SCRIPT_PRE, "description": "", "timeout": 45, "enabled": True}
            ]
            assert rows == expected, f"the adapter's read must list the saved row: {rows}"
            after = config_revision(vm)
            assert after != before, "the save moved the revision"
            assert _core_revision(vm) == after, "Core must have read the saved row: it is at config.xml's revision"
        finally:
            helpers.clear_update_hooks(vm)


def test_a_safesearch_save_with_core_serving_leaves_core_at_the_revision_config_xml_projects(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """Core reads a SafeSearch save at once, not at the next tick.

    Given: Core serving at config.xml's revision
    When:  the SafeSearch page saves another YouTube restriction
    Then:  config.xml and the adapter's read hold it, and Core is at config.xml's new revision
    """
    vm = smoke_vm
    was = helpers.config_get(vm, SAFESEARCH_YOUTUBE)
    wanted = "Moderate" if was == "Strict" else "Strict"
    with _core_in_step(vm):
        try:
            tell_core(vm)
            before = config_revision(vm)
            assert _core_revision(vm) == before, "before-state: Core must be at config.xml's revision"

            _save(vm, webui, SAFESEARCH_PAGE, {"safesearch_youtube": wanted}, "SafeSearch")

            assert helpers.config_get(vm, SAFESEARCH_YOUTUBE) == wanted, "the save must be written"
            projected = php_json(vm, "pfb_core_settings()['policy/dnsbl']['safeSearchYoutube']")
            assert projected == wanted, f"the adapter's read must hold the saved restriction: {projected}"
            after = config_revision(vm)
            assert after != before, "the save moved the revision"
            assert _core_revision(vm) == after, "Core must have read the save: it is at config.xml's revision"
        finally:
            _save(vm, webui, SAFESEARCH_PAGE, {"safesearch_youtube": was or "Disable"}, "SafeSearch")


def test_an_ip_save_with_core_serving_leaves_core_at_the_revision_config_xml_projects(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """Core reads an IP page save at once: its Update reads the aggregation switch as ``policy/ip``.

    Given: Core serving at config.xml's revision
    When:  the IP page saves the CIDR aggregation switch flipped
    Then:  the adapter's read holds the new switch, and Core is at config.xml's new revision
    """
    vm = smoke_vm
    was = helpers.config_get(vm, IP_AGGREGATE) == "on"
    with _core_in_step(vm):
        try:
            tell_core(vm)
            before = config_revision(vm)
            assert _core_revision(vm) == before, "before-state: Core must be at config.xml's revision"
            assert php_json(vm, "pfb_core_settings()['policy/ip']['aggregate']") is was, (
                "before-state: the switch as stored"
            )

            _save(vm, webui, IP_PAGE, {"enable_agg": "" if was else "on"}, "IP")

            projected = php_json(vm, "pfb_core_settings()['policy/ip']['aggregate']")
            assert projected is (not was), f"the adapter's read must hold the flipped switch: {projected}"
            after = config_revision(vm)
            assert after != before, "the save moved the revision"
            assert _core_revision(vm) == after, "Core must have read the save: it is at config.xml's revision"
        finally:
            _save(vm, webui, IP_PAGE, {"enable_agg": "on" if was else ""}, "IP")
