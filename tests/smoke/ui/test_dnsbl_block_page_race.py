"""Tier-A ``ui_render`` coverage for issue #3998: a DNS > DNSBL save serves the block page config.xml names.

The page loads config.xml when the request starts and reads it again under the ``pfb_dns_config`` lock before it
writes. Whether the served block page (``dnsbl_active.php``) must be replaced is decided against that fresh read: a
save that posts the stored page unchanged still serves it when another save chose and served another page while this
request waited for the lock. The oracle is the box, read back over SSH: the stored choice and the served page's digest.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import NO_INPUT_ERRORS
from .test_dns_general_forms import SAVE_TIMEOUT
from .test_dnsbl_core_refusal import ACTIVE, BLOCK_PAGE_CFG, DNSBL_PAGE, OTHER_PAGE, WWW, _digest, _other_block_page
from .test_dnsbl_follows_pfb_dns import _errors_text

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

LOCK_FILE = "/tmp/pfb_dns_config.lock"
DEFAULT_PAGE = "dnsbl_default.php"


def _save_waits_for_the_lock(vm: SmokeVM) -> bool:
    """True once a webConfigurator process has the config lock's file open: the save waits in try_lock."""
    return "php-fpm" in vm.ssh(f"fstat {LOCK_FILE}").stdout


def test_an_unchanged_block_page_is_served_when_another_save_chose_another_meanwhile(
    smoke_vm: SmokeVM, webui: WebUI
) -> None:
    """The page a save stores is the page DNSBL serves, whatever another save served while this one waited.

    Given: another block page is stored and served
    When:  a save posts it unchanged, and while that save waits for the config lock another save stores and serves the
           default page
    Then:  the save succeeds, config.xml names the other page, and the served page is the other page again
    """
    vm = smoke_vm
    with _other_block_page(vm):
        chosen = webui.post(DNSBL_PAGE, {"dnsbl_webpage": OTHER_PAGE}, allow_redirects=False, timeout=SAVE_TIMEOUT)
        assert _errors_text(chosen.text) == NO_INPUT_ERRORS, f"before-state save failed: {_errors_text(chosen.text)}"
        other_digest = _digest(vm, f"{WWW}/{OTHER_PAGE}")
        assert helpers.config_get(vm, BLOCK_PAGE_CFG) == OTHER_PAGE, "before-state: the other page must be stored"
        assert _digest(vm, ACTIVE) == other_digest, "before-state: the other page must be served"

        with ThreadPoolExecutor(max_workers=1) as pool:
            with helpers.config_lock_held(vm):
                saving = pool.submit(
                    webui.post, DNSBL_PAGE, {"dnsbl_webpage": OTHER_PAGE}, allow_redirects=False, timeout=SAVE_TIMEOUT
                )
                helpers.wait_until(lambda: _save_waits_for_the_lock(vm), timeout=60.0, interval=0.5)
                # Another save, holding the lock the page waits for: the default page stored and served
                helpers.config_set(vm, BLOCK_PAGE_CFG, DEFAULT_PAGE)
                copied = vm.ssh("cp", "-p", f"{WWW}/{DEFAULT_PAGE}", ACTIVE)
                assert copied.returncode == 0, f"serving the default page failed: {copied.stderr!r}"
                assert _digest(vm, ACTIVE) != other_digest, "the other save must serve another page"
            saved = saving.result(timeout=SAVE_TIMEOUT)

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, f"the save must succeed, not: {_errors_text(saved.text)}"
        assert helpers.config_get(vm, BLOCK_PAGE_CFG) == OTHER_PAGE, "the save stores the page it posted"
        assert _digest(vm, ACTIVE) == other_digest, "config.xml names the other page, so DNSBL must serve it"
