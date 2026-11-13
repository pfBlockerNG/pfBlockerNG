"""Tier-A ``ui_render`` coverage for issue #3937: a group save or delete reaches Core, or says it did not.

Core reads the IP and DNSBL groups through its settings adapter; the Groups editor and the group list tell Core once
their write succeeded. With Core serving, a Groups editor save leaves Core at the revision config.xml projects, holding
the saved group in the adapter's read. With Core stopped, a group list delete is written anyway and DNS General shows
that Core has not read the settings yet; a started Core reads them, and the next tick clears the notice. The oracle is
Core's own answer and config.xml read back over SSH, never the HTTP body.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from ..test_smoke_core_api import CORE_RC, await_core_up, config_revision, core_dns, php_json, run_tick, tell_core
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_category import CATEGORY_PAGE, IPV4_LISTS, _ajax_post, _restore_lists, _seed_single_ipv4_row, _snapshot_lists
from .test_category_edit import CFG_DNSBL, _del_rowid, _dnsbl_payload, _free_rowid, _post_form
from .test_dns_general_core_push import NOTICE, _core_in_step
from .test_dns_general_foreign_list_warning import _render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render


@pytest.fixture
def core_serving(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Core answers (the webui fixture has the package deployed, and its install starts the service)."""
    await_core_up(smoke_vm)


@contextmanager
def _tier_a(vm: SmokeVM, webui: WebUI, gtype: str, markers: tuple[str, ...]) -> Iterator[None]:
    """Tier-A oracle around a Groups page request: the list page renders its markers; php_error.log does not grow."""
    guard = PhpErrorLogGuard(vm)
    guard.snapshot()
    yield
    response = webui.get(CATEGORY_PAGE, params={"type": gtype})
    rendered = evaluate_render(f"{CATEGORY_PAGE}?type={gtype}", response.status_code, response.text, markers)
    assert rendered.ok, f"Groups page GET: {rendered.detail}"
    guard.assert_no_growth()


def _core_revision(vm: SmokeVM) -> int:
    """The revision Core holds."""
    held = core_dns(vm)
    assert held is not None, "Core did not answer"
    return held[0]


def test_a_group_save_with_core_serving_leaves_core_at_the_revision_config_xml_projects(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """Core holds the saved group: it is at config.xml's revision, which the save moved.

    Given: Core serving at config.xml's revision, and a free DNSBL group slot
    When:  the Groups editor saves a new group with one feed
    Then:  the adapter's read holds the group, and Core is at config.xml's new revision
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    alias = f"CoreFeed{rowid}"
    with _core_in_step(vm):
        try:
            tell_core(vm)
            before = config_revision(vm)
            assert _core_revision(vm) == before, "before-state: Core must be at config.xml's revision"

            with _tier_a(vm, webui, "dnsbl", ("Summary", "DNSBL", alias)):
                _post_form(
                    webui,
                    _dnsbl_payload(rowid, alias, **{"header-0": "CoreFeed", "url-0": "https://example.com/hosts"}),
                )

            groups = php_json(vm, "pfb_core_settings()['feeds/dnsbl']['groups']")
            assert alias in [group["name"] for group in groups], f"the adapter's read must hold the group: {groups}"
            after = config_revision(vm)
            assert after != before, "the save moved the revision"
            assert _core_revision(vm) == after, "Core must have read the saved group: it is at config.xml's revision"
        finally:
            _del_rowid(vm, CFG_DNSBL, rowid)


def test_a_group_delete_with_core_stopped_is_written_and_says_core_does_not_have_it_yet(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """A stopped Core never blocks the delete; DNS General says so until Core has read config.xml.

    Given: an IPv4 group in config.xml and in Core, then Core stopped
    When:  the group list deletes it
    Then:  config.xml no longer holds it and DNS General shows the notice; a started Core reads it, a tick clears it
    """
    vm = smoke_vm
    alias = "pfbcorefeed"
    snap = _snapshot_lists(vm)
    with _core_in_step(vm):
        try:
            _seed_single_ipv4_row(vm, alias, "Deny_Both")
            tell_core(vm)
            stop = vm.ssh(f"{CORE_RC} stop", timeout=60)
            assert stop.returncode == 0, f"{CORE_RC} stop failed: {stop.stdout}{stop.stderr}"
            assert core_dns(vm) is None, "before-state: Core must be unreachable"
            name = f"{IPV4_LISTS}/0/aliasname"
            assert helpers.config_get(vm, name) == alias, "before-state: the group is in config.xml"
            assert NOTICE not in _render(vm, webui), "before-state: no notice before the delete"

            with _tier_a(vm, webui, "ipv4", ("Summary", "pfBlockerNG")):
                _ajax_post(webui, {"act": "del", "type": "ipv4", "rowid": "0"})

            assert helpers.config_get(vm, name) == "", "the delete must be written while Core is down"
            assert NOTICE in _render(vm, webui), "DNS General must say that Core does not have the saved settings"

            start = vm.ssh(f"{CORE_RC} start", timeout=60)
            assert start.returncode == 0, f"{CORE_RC} start failed: {start.stdout}{start.stderr}"
            await_core_up(vm)
            assert _core_revision(vm) == config_revision(vm), "a started Core reads config.xml as the delete left it"
            run_tick(vm)
            assert NOTICE not in _render(vm, webui), "Core holds the settings: the notice must be gone"
        finally:
            _restore_lists(vm, snap)
