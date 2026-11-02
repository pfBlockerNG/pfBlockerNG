"""Reports > Alerts: whitelisting a TLD-blocked domain (issue #3647).

The hand icon on a row blocked by a TLD Blacklist entry asked to add the domain "to the TLD Whitelist"
-- a list that does not exist -- and its dialog code never assigned the button text, so on a fresh page
the dialog read an undefined variable. The domain is added to the DNSBL Whitelist.

* Tier A (``ui_render``): the rendered icon carries the TLD whitelist action and a plain-text prompt.
* Tier B (``ui_browser``): in a real browser on a fresh page, the icon opens the confirm, then a
  labelled whitelist dialog, then the description step of the DNSBL Whitelist flow. The flow is
  cancelled before it submits, so no whitelist entry is written; what the final submit carries is
  pinned hermetically by ``tests/js/alerts_whitelist_dialog.test.js``.

Both seed one ``DNSBL_TLD`` row into ``dnsbl.log`` and truncate it back afterwards.
"""

from __future__ import annotations

import html
import re
import subprocess
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .conftest import mask_page_identity
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .webui import looks_like_login_page, row_containing

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from ..helpers import SmokeVM
    from .webui import WebUI

ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"
CFG_DNSBL_ENABLE = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"

# Fixed, clearly synthetic timestamp (never the wall clock) so the row cannot collide with a real entry.
FIXED_TS = "2030-03-01 09:00:05"
JS_TIMEOUT_MS = 10_000

# dnsbl.log CSV shape: l_type,ts,domain,src_ip,agent,block_mode,group,evaluated,feed,dup,qtype
_ROW = "DNSBL-python,{ts},{domain},127.0.0.1,Python,DNSBL_TLD,TldGroup,{root},TLD,+,A\n"


@pytest.fixture
def tld_row(smoke_vm: SmokeVM, request: pytest.FixtureRequest) -> tuple[str, str]:
    """Seed a TLD-blocked row; restore log and toggle even if setup or another cleanup fails."""
    vm = smoke_vm
    root = helpers.unique_domain("ui3647tld")
    domain = f"www.{root}"

    prior_dnsbl = helpers.config_get(vm, CFG_DNSBL_ENABLE)
    exists = vm.ssh("test", "-f", DNSBL_LOG, timeout=15)
    assert exists.returncode in (0, 1), f"failed to check {DNSBL_LOG}: stderr={exists.stderr!r}"
    original_size = None
    if exists.returncode == 0:
        size_before = vm.ssh("stat", "-f", "%z", DNSBL_LOG, timeout=15)
        assert size_before.returncode == 0, f"failed to stat {DNSBL_LOG}: stderr={size_before.stderr!r}"
        original_size = size_before.stdout.strip()
        assert original_size.isdecimal(), f"invalid {DNSBL_LOG} size: {original_size!r}"

    def restore_dnsbl() -> None:
        helpers.config_set(vm, CFG_DNSBL_ENABLE, prior_dnsbl)
        assert helpers.config_get(vm, CFG_DNSBL_ENABLE) == prior_dnsbl, (
            f"pfb_dnsbl toggle restore did not take (wanted {prior_dnsbl!r}) -- leaked to sibling tests"
        )

    def restore_log() -> None:
        if original_size is None:
            restore = vm.ssh("rm", "-f", DNSBL_LOG, timeout=15)
            assert restore.returncode == 0, f"failed to remove fixture-created {DNSBL_LOG}: {restore.stderr!r}"
            absent = vm.ssh("test", "-e", DNSBL_LOG, timeout=15)
            assert absent.returncode == 1, f"fixture-created {DNSBL_LOG} remains: {absent.stderr!r}"
        else:
            restore = vm.ssh("truncate", "-s", original_size, DNSBL_LOG, timeout=15)
            assert restore.returncode == 0, f"failed to restore {DNSBL_LOG} size: stderr={restore.stderr!r}"
            size_after = vm.ssh("stat", "-f", "%z", DNSBL_LOG, timeout=15)
            assert size_after.returncode == 0 and size_after.stdout.strip() == original_size, (
                f"{DNSBL_LOG} restore did not take (before={original_size!r}, after={size_after.stdout.strip()!r})"
            )

    # Independent finalizers run even after setup fails or another finalizer raises; pytest reports
    # cleanup errors separately, preserving the original setup/test failure.
    request.addfinalizer(restore_dnsbl)
    request.addfinalizer(restore_log)
    helpers.ensure_dnsbl_vip(vm)
    helpers.set_dnsbl_enabled(vm, True)
    ensure = vm.ssh(f"mkdir -p {DNSBL_LOG.rsplit('/', 1)[0]} && touch {DNSBL_LOG}", timeout=15)
    assert ensure.returncode == 0, f"failed to ensure {DNSBL_LOG} exists: {ensure.stderr!r}"

    append = subprocess.run(
        vm.ssh_argv("tee", "-a", DNSBL_LOG),
        input=_ROW.format(ts=FIXED_TS, domain=domain, root=root),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert append.returncode == 0, f"failed to append the fixture row to {DNSBL_LOG}: stderr={append.stderr!r}"

    return domain, root


@pytest.mark.ui_render
def test_tld_row_prompt_names_the_dnsbl_whitelist(webui: WebUI, smoke_vm: SmokeVM, tld_row: tuple[str, str]) -> None:
    """Given a TLD-blocked row, its whitelist icon carries the TLD action and a plain-text prompt."""
    domain, root = tld_row
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(ALERTS_PAGE)
    assert not looks_like_login_page(resp.text), "alerts GET returned the login form (session lost)"
    result = evaluate_render(ALERTS_PAGE, resp.status_code, resp.text, ("Alert Settings",))
    assert result.ok, f"Tier-A render oracle failed for the Alerts page: {result.detail}"

    row = row_containing(resp.text, domain)
    icon_id = f"DNSBLWT|tld|{domain}|{root}"
    assert icon_id in row, f"the TLD whitelist icon {icon_id!r} is missing from the row: {row!r}"
    title = html.unescape(re.search(r'id="' + re.escape(icon_id) + r'" title="([^"]*)"', row).group(1))  # type: ignore[union-attr]
    assert title and "<" not in title, f"the confirm() prompt must be non-empty plain text: {title!r}"

    guard.assert_no_growth()


@pytest.mark.ui_browser
def test_tld_whitelist_dialog_opens_labelled_on_a_fresh_page(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
    tld_row: tuple[str, str],
) -> None:
    """On a fresh page the TLD icon opens the confirm, a labelled dialog, and the DNSBL Whitelist description step.

    Given a freshly loaded Alerts page (no other whitelist dialog has run) with a TLD-blocked row,
    When  the row's hand icon is clicked and the confirm accepted,
    Then  a confirm is shown, the dialog is titled and its buttons labelled for
          whitelisting, and choosing "2. Whitelist" opens the DNSBL Whitelist description step.
    """
    sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
    expect = sync_api.expect
    page = browser_page
    domain, root = tld_row

    page.goto(webui.url(ALERTS_PAGE), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, "Alerts GET showed the login form -- cookie not authenticated"

    confirms: list[str] = []

    def _accept(dialog: object) -> None:
        confirms.append(dialog.message)  # type: ignore[attr-defined]
        dialog.accept()  # type: ignore[attr-defined]

    page.on("dialog", _accept)

    icon = page.locator(f'[id="DNSBLWT|tld|{domain}|{root}"]')
    open_dialog = page.locator(".ui-dialog:visible")
    expect(icon).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(open_dialog).to_have_count(0)  # before-state: no dialog is open yet
    assert confirms == [], "a confirm fired before the icon was clicked"

    icon.click()

    expect(open_dialog.locator(".ui-dialog-title")).to_have_text("Domain Whitelisting:", timeout=JS_TIMEOUT_MS)
    assert len(confirms) == 1, f"expected exactly one confirm, saw {confirms!r}"
    buttons = open_dialog.locator(".ui-dialog-buttonpane button")
    expect(buttons).to_have_text(["1. Wildcard Whitelist", "2. Whitelist", "Cancel"])

    buttons.filter(has_text="2. Whitelist").click()

    expect(open_dialog.locator(".ui-dialog-title")).to_have_text("Whitelist description:", timeout=JS_TIMEOUT_MS)
    open_dialog.locator(".ui-dialog-buttonpane button", has_text="Cancel").click()
    expect(open_dialog).to_have_count(0, timeout=JS_TIMEOUT_MS)
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / "alerts_tld_whitelist_dialog.png"), full_page=True)
