"""Tier-B proof that TOP1M auth changes retain active data."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_dnsbl_top1m_retention import (
    ACTIVE_TOP1M_FILES,
    DNSBL_PAGE,
    TOP1M_BASE,
    TOP1M_FILES,
    TOP1M_PROVIDER_CFG,
    _restore_guest_files,
    _snapshot_guest_files,
    _write_guest_file,
)
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

TOP1M_TOKEN_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/top1m_token"


def test_dnsbl_top1m_token_save_retains_active_files_and_invalidates_baseline(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Replacing Cloudflare auth keeps active bytes and drops stale detector state."""
    vm = smoke_vm
    original = _snapshot_guest_files(vm)
    old_token = "issue1542OldTokenA"
    new_token = "issue1542NewTokenB"

    try:
        response = webui.post(
            DNSBL_PAGE,
            {"top1m_source": "cloudflare", "top1m_token": old_token},
            timeout=300.0,
        )
        assert not looks_like_login_page(response.text), "TOP1M auth setup POST returned the login form"
        assert helpers.config_get(vm, TOP1M_PROVIDER_CFG) == "cloudflare"
        assert helpers.config_get(vm, TOP1M_TOKEN_CFG) == old_token

        seeded = {
            f"{helpers.PFB_DBDIR}/top-1m.csv": "1,active.example\n",
            f"{helpers.PFB_DBDIR}/pfbalexawhitelist.txt": "active.example\n",
            f"{TOP1M_BASE}.orig": "1,active.example\n",
            f"{TOP1M_BASE}.xxhash128": "0123456789abcdef0123456789abcdef\n",
            f"{TOP1M_BASE}.md5": "fedcba9876543210fedcba9876543210\n",
            f"{TOP1M_BASE}.source": '{"provider":"cloudflare"}\n',
            f"{TOP1M_BASE}.orig.etag": '"top1m-cloudflare"\n',
            f"{TOP1M_BASE}.orig.lastmod": "1700000000\n",
        }
        for path, content in seeded.items():
            _write_guest_file(vm, path, content)

        response = webui.post(DNSBL_PAGE, {"top1m_token": new_token}, timeout=300.0)
        assert not looks_like_login_page(response.text), "TOP1M auth-change POST returned the login form"
        assert helpers.config_get(vm, TOP1M_TOKEN_CFG) == new_token
        assert new_token not in response.text, "TOP1M token was echoed into the rendered page"

        for path in ACTIVE_TOP1M_FILES:
            assert helpers.read_log_file(vm, path) == seeded[path], (
                f"TOP1M bytes changed after auth save at {path}; active data must remain until replacement"
            )
        for path in TOP1M_FILES[2:]:
            assert vm.ssh("test", "-e", path).returncode != 0, (
                f"TOP1M detector sidecar {path} survived auth identity change"
            )
    finally:
        _restore_guest_files(vm, original)
