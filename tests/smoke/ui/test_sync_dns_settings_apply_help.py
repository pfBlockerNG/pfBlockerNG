"""Tier-A operator guidance for stored-only legacy pfB-DNS receives (#3649)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .test_sync_dnsblip_warning import SYNC_PAGE, _render

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render


def test_sync_help_names_the_receivers_update_action_and_absent_field_semantics(
    smoke_vm: SmokeVM, webui: WebUI
) -> None:
    html = _render(smoke_vm, webui, SYNC_PAGE, "XMLRPC Sync Settings")
    for phrase in (
        "Received pfB-DNS settings are stored only",
        "without a changes-pending marker",
        "receiving node",
        "<strong>Run Now</strong>",
        "<strong>Update</strong>",
        "absent DoT fields clear the receiver's stored choices",
    ):
        assert phrase in html, f"expected receiver apply guidance {phrase!r} in rendered Sync help"
