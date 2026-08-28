"""issue #1076 -- a crafted ``alt_selected`` token must not become a config key.

The Feeds save handler exploded ``alt_selected`` and used each raw token as
part of a ``config_set_path()`` KEY
(``installedpackages/pfblockerngglobal/feed_alt_{$value}``); only the alt_
VALUE was filtered, so a token like ``a/b`` spliced a path separator into the
config tree and wrote an unintended nested node. Tokens are now vetted
through ``PFB_FILTER_WORD`` before any key use (off-appliance red/green
pinned by ``tests/php/FeedsAltSelectedKeyTest.php``; this exercises the same
save end-to-end through the real page).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_feeds import FEEDS_PAGE_IPV4, _config_del
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

# Tier B: a mutating POST flow whose failure artifact (a spliced config.xml
# node) is observable only on-box. Tier A render coverage of this page already
# exists (test_render_smoke.py / test_feeds.py).
pytestmark = pytest.mark.ui_e2e


def test_path_bearing_alt_selected_token_writes_no_config_node(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Scenario: a save POST carrying ``alt_selected=a/b`` with a clean value.

    Given the Feeds IPv4 tab and a POST whose ``alt_selected`` token carries a
      path separator while its matching ``alt_a/b`` value is filter-clean (so
      only the KEY vetting can stop the write),

    When the save is POSTed through the real CSRF form,

    Then config.xml gains NO node under ``pfblockerngglobal`` for the token --
      neither the spliced nested ``feed_alt_a`` parent nor a literal child
      (oracle: config.xml over SSH, never the HTTP body).
    """
    vm = smoke_vm
    # A test-unique token so the spliced parent cannot collide with anything a
    # sibling flow (or an earlier run on the shared VM) left in config.xml.
    token = "iss1076crafted/b"
    spliced_parent = "installedpackages/pfblockerngglobal/feed_alt_iss1076crafted"

    # Clean baseline: drop any node a pre-guard build may have left behind.
    _config_del(vm, spliced_parent)
    try:
        assert helpers.config_get(vm, spliced_parent) == "", f"{spliced_parent} not empty before the POST"

        resp = webui.post(
            FEEDS_PAGE_IPV4,
            {"alt_selected": token, f"alt_{token}": "EvilWord"},
            timeout=120.0,
        )
        assert not looks_like_login_page(resp.text), "Feeds alt_selected POST returned the login form"

        assert helpers.config_get(vm, spliced_parent) == "", (
            f"a path-bearing alt_selected token must not splice {spliced_parent} into config.xml"
        )
        assert helpers.config_get(vm, f"{spliced_parent}/b") == "", (
            f"no nested child may appear under {spliced_parent} either"
        )
    finally:
        # Sweep whatever this run may have written on the shared VM.
        _config_del(vm, spliced_parent)
