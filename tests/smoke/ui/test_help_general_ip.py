"""Rendered help contracts for General, IP and generated GeoIP/Reputation pages.

Help must distinguish real controls, keep alternatives in valid lists, and put
safety warnings beside the setting they explain. No settings are changed here.
"""

from __future__ import annotations

import re
from html import unescape
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

    from .webui import WebUI

GENERAL = "/pfblockerng/pfblockerng_general.php"
IP = "/pfblockerng/pfblockerng_ip.php"
GEOIP = "/pfblockerng/pfblockerng_Europe.php"
REPUTATION = "/pfblockerng/pfblockerng_reputation.php"


@pytest.mark.ui_render
@pytest.mark.parametrize("path,control", [(GENERAL, "skipfeed"), (IP, "pfb_alias_delta_mode"), (GEOIP, "aliaslog")])
def test_help_emphasizes_the_displayed_select_choices(
    webui: WebUI, php_error_log_guard: PhpErrorLogGuard, path: str, control: str
) -> None:  # noqa: ARG001
    """Changing a choice's casing or losing its help emphasis breaks the real page contract."""
    response = webui.get(path)
    result = evaluate_render(path, response.status_code, response.text, (f'name="{control}"',))
    assert result.ok, f"{path}: {result.detail}"
    select = re.search(rf'<select\b[^>]*name="{control}"[^>]*>(.*?)</select>', response.text, re.DOTALL)
    assert select, f"{path}: missing select {control}"
    choices = [
        unescape(re.sub(r"<[^>]+>", "", text)).strip()
        for text in re.findall(r"<option\b[^>]*>(.*?)</option>", select[1], re.DOTALL)
    ]
    emphasized = {unescape(text).strip() for text in re.findall(r"<strong>([^<]+)</strong>", response.text)}
    # These are the options the help explains, not numeric threshold choices.
    explained = choices if control == "pfb_alias_delta_mode" else ["No Limit" if control == "skipfeed" else "Enabled"]
    assert set(explained) <= set(choices), f"{path}: explained options {explained!r} not in {choices!r}"
    assert set(explained) <= emphasized, (
        f"{path}: choices {explained!r} lack exact-case emphasis; found {sorted(emphasized)!r}"
    )


def _open(page: Page, webui: WebUI, path: str) -> None:
    response = page.goto(webui.url(path), wait_until="domcontentloaded")
    assert response is not None and response.status == 200, f"{path}: browser navigation failed"
    assert page.locator("#usernamefld").count() == 0, f"{path}: browser session is not authenticated"


def _row(page: Page, name: str) -> Locator:
    control = page.locator(f'[name="{name}"]')
    assert control.count() == 1, f"expected one control named {name}, found {control.count()}"
    return control.locator(
        'xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " form-group ")][1]'
    )


@pytest.mark.ui_browser
def test_keep_settings_warning_and_clear_procedure_stay_with_the_control(browser_page: Page, webui: WebUI) -> None:
    """A missing step, detached deletion warning, or stale control name makes the procedure unsafe."""
    _open(browser_page, webui, GENERAL)
    row = _row(browser_page, "pfb_keep")
    label = row.locator("label.control-label").inner_text().strip()
    assert label == "Keep Settings", f"unexpected retention control label: {label!r}"
    assert label in row.locator("strong").all_text_contents(), "retention help does not emphasize its own control"
    warning = row.locator("p").filter(has=browser_page.locator(".text-danger"))
    assert warning.count() == 1, f"expected one associated deletion warning, found {warning.count()}"
    text = warning.inner_text().lower()
    for consequence in ("remov", "upgrade", "settings", "logs", "lists"):
        assert consequence in text, f"retention warning omits {consequence!r}: {text!r}"
    steps = row.locator("ol > li")
    assert steps.count() == 3, f"expected three clear/restore/apply steps, found {steps.all_text_contents()!r}"
    master_label = _row(browser_page, "enable_cb").locator("label.control-label").inner_text().strip()
    assert steps.nth(0).locator("strong").all_text_contents() == [master_label, label], (
        "first step must identify both settings to turn off"
    )
    assert re.search(r"\boff\b", steps.nth(0).inner_text(), re.I), "first step must turn both settings off"
    assert re.search(r"\bon\b", steps.nth(1).inner_text(), re.I), "second step must restore both settings"
    assert {"Update", "Run Now"} <= set(steps.nth(2).locator("strong").all_text_contents()), (
        "last step must identify the immediate apply action"
    )


@pytest.mark.ui_browser
def test_ip_alternatives_and_firewall_warning_are_structured(browser_page: Page, webui: WebUI) -> None:
    """List choices stay paired with their actual options; NAT cases stay beside the self-traffic warning."""
    _open(browser_page, webui, IP)
    row = _row(browser_page, "pfb_alias_delta_mode")
    options = row.locator("option").all_text_contents()
    choices = row.locator("ul > li > strong").all_text_contents()
    assert choices == options, f"apply alternatives differ from actual options: help={choices!r}, options={options!r}"
    warning_row = _row(browser_page, "fw_self_outbound")
    warning = warning_row.locator("p").filter(has=browser_page.locator(".text-danger"))
    assert warning.count() == 1, "self-traffic control must carry its own connectivity warning"
    for consequence in ("updates", "downloads", "DNS", "VPN"):
        assert consequence in warning.inner_text(), f"connectivity warning omits {consequence!r}"
    cases = warning_row.locator("ul > li")
    assert cases.count() == 2, f"expected separate IPv4 NAT and IPv6 cases, found {cases.all_text_contents()!r}"
    assert "IPv4" in cases.nth(0).inner_text() and "NAT" in cases.nth(0).inner_text(), "IPv4 NAT case missing"
    assert "IPv6" in cases.nth(1).inner_text() and "NAT" in cases.nth(1).inner_text(), "IPv6 non-NAT case missing"
    assert "Outbound Firewall Rules" in cases.nth(0).locator("strong").all_text_contents(), (
        "NAT case must distinguish the actual interface setting"
    )


@pytest.mark.ui_browser
def test_generated_geoip_actions_have_valid_definitions(browser_page: Page, webui: WebUI) -> None:
    """Missing list terms or text fused to the alias link breaks the generated continent instructions."""
    _open(browser_page, webui, GEOIP)
    row = _row(browser_page, "action")
    definitions = row.locator("dl")
    assert definitions.count() == 1, "List Action help needs one definition list"
    assert definitions.locator(":scope > dt").count() == definitions.locator(":scope > dd").count() == 3, (
        "each action category needs its own definition"
    )
    options = set(row.locator("option").all_text_contents())
    references = definitions.locator("strong").all_text_contents()
    assert len(references) >= 8 and set(references) <= options, (
        f"action references must be complete actual option labels: {references!r}, {options!r}"
    )
    for name in ("aliasports_in", "aliasaddr_in"):
        help_row = _row(browser_page, name)
        assert help_row.locator('a[href^="/firewall_aliases.php"] + br').count() == 1, (
            f"{name}: alias link must be separated from the input warning"
        )


@pytest.mark.ui_browser
def test_generated_reputation_explains_related_choices_together(browser_page: Page, webui: WebUI) -> None:
    """Scattered single-item lists or invented control casing make Reputation's alternatives unreadable."""
    _open(browser_page, webui, REPUTATION)
    labels = {
        name: _row(browser_page, name).locator("label.control-label").inner_text().strip()
        for name in ("enable_pdup", "enable_dedup")
    }
    collective = browser_page.locator("ul").filter(
        has=browser_page.locator("li > strong", has_text=labels["enable_pdup"])
    )
    assert collective.count() == 1, "collective processes must share one list"
    assert collective.locator(":scope > li > strong").all_text_contents()[::2] == list(labels.values()), (
        "collective descriptions must use the displayed pMAX/dMAX labels"
    )
    choices = {
        text
        for name in ("ccwhite", "ccblack")
        for text in _row(browser_page, name).locator("option").all_text_contents()
    }
    alternatives = browser_page.locator("ul").filter(has=browser_page.locator("li > strong", has_text="Ignore"))
    assert alternatives.count() == 1, "country actions must share one list"
    assert set(alternatives.locator(":scope > li > strong").all_text_contents()) == choices, (
        "country actions must match their actual option labels"
    )
    assert (
        browser_page.locator("li", has_text="/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt").count() == 0
    ), "a lone file example is not a list of alternatives"
    assert (
        browser_page.locator("code", has_text="/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt").count()
        == 1
    ), "file example must remain readable literal input"


@pytest.mark.ui_browser
def test_reputation_literal_examples_wrap_on_narrow_screens(browser_page: Page, webui: WebUI) -> None:
    """A lost wrap affordance makes the complete file/URL examples unreachable on phones."""
    browser_page.set_viewport_size({"width": 414, "height": 896})
    _open(browser_page, webui, REPUTATION)
    tokens = (
        "/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt",
        "https://rules.emergingthreatspro.com/XXXXXXXXXXXXXXXX/reputation/iprepdata.txt.gz",
        "/var/db/pfblockerng/match/generated/pfB_Match_ET_v4.txt",
        "/var/db/pfblockerng/ET",
    )
    for token in tokens:
        example = browser_page.locator("code").filter(has_text=re.compile(rf"^{re.escape(token)}$"))
        assert example.count() == 1, f"expected one literal example for {token!r}, found {example.count()}"
        wrap = example.evaluate("(node) => getComputedStyle(node).overflowWrap")
        assert wrap == "anywhere", f"{token!r}: expected wrapping anywhere, got {wrap!r}"
