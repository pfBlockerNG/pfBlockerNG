"""Tier-B proof that a TOP1M provider save keeps the active source files."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
TOP1M_PROVIDER_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/top1m_source"
TOP1M_BASE = f"{helpers.PFB_DBDIR}/top-1m.csv.zip"
TOP1M_FILES = (
    f"{helpers.PFB_DBDIR}/top-1m.csv",
    f"{helpers.PFB_DBDIR}/pfbalexawhitelist.txt",
    f"{TOP1M_BASE}.orig",
    f"{TOP1M_BASE}.xxhash128",
    f"{TOP1M_BASE}.md5",
    f"{TOP1M_BASE}.source",
    f"{TOP1M_BASE}.orig.etag",
    f"{TOP1M_BASE}.orig.lastmod",
)
ACTIVE_TOP1M_FILES = TOP1M_FILES[:2]


def _write_guest_file(vm: helpers.SmokeVM, path: str, content: str) -> None:
    helpers.write_local_feed(vm, path.removeprefix(f"{helpers.PFB_DBDIR}/"), content)


def _snapshot_guest_files(vm: helpers.SmokeVM) -> dict[str, str | None]:
    snapshot: dict[str, str | None] = {}
    for path in TOP1M_FILES:
        exists = vm.ssh("test", "-f", path).returncode == 0
        snapshot[path] = helpers.read_log_file(vm, path) if exists else None
    return snapshot


def _restore_guest_files(vm: helpers.SmokeVM, snapshot: dict[str, str | None]) -> None:
    for path, content in snapshot.items():
        vm.ssh("rm", "-f", path)
        if content is not None:
            _write_guest_file(vm, path, content)


def test_dnsbl_top1m_provider_save_retains_active_files_and_invalidates_baseline(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Changing Tranco to Cisco keeps the active TOP1M bytes until replacement."""
    vm = smoke_vm
    original = _snapshot_guest_files(vm)
    if helpers.config_get(vm, TOP1M_PROVIDER_CFG) != "tranco":
        response = webui.post(DNSBL_PAGE, {"top1m_source": "tranco"}, timeout=300.0)
        assert not looks_like_login_page(response.text), "TOP1M provider reset POST returned the login form"
    assert helpers.config_get(vm, TOP1M_PROVIDER_CFG) == "tranco", (
        "TOP1M provider must start at Tranco so the POST proves a provider transition"
    )

    seeded = {
        f"{helpers.PFB_DBDIR}/top-1m.csv": "1,active.example\n",
        f"{helpers.PFB_DBDIR}/pfbalexawhitelist.txt": "active.example\n",
        f"{TOP1M_BASE}.orig": "1,active.example\n",
        f"{TOP1M_BASE}.xxhash128": "0123456789abcdef0123456789abcdef\n",
        f"{TOP1M_BASE}.md5": "fedcba9876543210fedcba9876543210\n",
        f"{TOP1M_BASE}.source": '{"provider":"tranco"}\n',
        f"{TOP1M_BASE}.orig.etag": '"top1m-tranco"\n',
        f"{TOP1M_BASE}.orig.lastmod": "1700000000\n",
    }

    try:
        for path, content in seeded.items():
            _write_guest_file(vm, path, content)
        for path, content in seeded.items():
            assert helpers.read_log_file(vm, path) == content, f"failed to seed exact bytes at {path}"

        # WebUI.post re-scrapes and submits the complete current form; only the
        # provider changes, with no token-authenticated fields involved.
        response = webui.post(DNSBL_PAGE, {"top1m_source": "cisco"}, timeout=300.0)
        assert not looks_like_login_page(response.text), "DNSBL provider POST returned the login form"
        assert helpers.config_get(vm, TOP1M_PROVIDER_CFG) == "cisco", "TOP1M provider was not persisted"

        for path in ACTIVE_TOP1M_FILES:
            content = seeded[path]
            assert helpers.read_log_file(vm, path) == content, (
                f"TOP1M bytes changed after provider save at {path}; active data must remain until replacement"
            )
        for path in TOP1M_FILES[2:]:
            assert vm.ssh("test", "-e", path).returncode != 0, (
                f"TOP1M detector sidecar {path} survived provider identity change"
            )
    finally:
        _restore_guest_files(vm, original)
