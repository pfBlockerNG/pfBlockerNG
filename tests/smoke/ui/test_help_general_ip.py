"""Rendered help contracts for the General, IP and generated GeoIP/Reputation pages.

Browser cases read the control row a help block belongs to. An option named in that help
keeps its displayed case and emphasis, instruction alternatives form lists, and a warning
sits in the row of the control it warns about. Render cases are health checks only: the
page renders and still offers the control its help explains.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_render_smoke import php_error_log_guard as php_error_log_guard

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

    from .webui import WebUI

GENERAL = "/pfblockerng/pfblockerng_general.php"
IP = "/pfblockerng/pfblockerng_ip.php"
GEOIP = "/pfblockerng/pfblockerng_Europe.php"
REPUTATION = "/pfblockerng/pfblockerng_reputation.php"


def _norm(text: str | None) -> str:
    return " ".join((text or "").split())


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


def _help(page: Page, name: str) -> Locator:
    help_block = _row(page, name).locator(".help-block")
    assert help_block.count() == 1, f"expected one help block for {name}, found {help_block.count()}"
    return help_block


def _strong_texts(scope: Locator) -> list[str]:
    return [_norm(text) for text in scope.locator("strong").all_text_contents()]


def _assert_option_references(help_block: Locator, options: list[str]) -> None:
    """Each named option appears only with its displayed case, and each mention is emphasized."""
    text = _norm(help_block.text_content())
    emphasized = _strong_texts(help_block)
    for option in options:
        exact = re.findall(re.escape(option), text)
        folded = re.findall(re.escape(option), text, re.IGNORECASE)
        assert exact, f"the help does not name the option {option!r}: {text!r}"
        assert len(folded) == len(exact), f"{option!r} appears with other casing in the help: {folded!r}"
        assert emphasized.count(option) == len(exact), (
            f"every mention of {option!r} must be emphasized on its own; emphasized={emphasized!r}, help={text!r}"
        )


@pytest.mark.ui_render
@pytest.mark.parametrize(
    ("path", "control"), [(GENERAL, "skipfeed"), (IP, "pfb_alias_delta_mode"), (GEOIP, "aliaslog")]
)
def test_help_page_renders_the_control_it_explains(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
    path: str,
    control: str,
) -> None:
    """Health only: the page renders cleanly and still offers the select its help explains."""
    response = webui.get(path)
    result = evaluate_render(path, response.status_code, response.text, (f'name="{control}"',))
    assert result.ok, f"{path}: {result.detail}"


@pytest.mark.ui_browser
@pytest.mark.parametrize(
    ("path", "control", "options"),
    [
        (GENERAL, "skipfeed", ("No Limit",)),
        (GEOIP, "aliaslog", ("Enabled",)),
        (IP, "pfb_alias_delta_mode", None),
    ],
    ids=["download-failure-threshold", "geoip-logging", "alias-apply-mode"],
)
def test_row_help_names_its_options_with_displayed_case(
    browser_page: Page,
    webui: WebUI,
    path: str,
    control: str,
    options: tuple[str, ...] | None,
) -> None:
    """An option the help names keeps its displayed case and emphasis wherever it is mentioned.

    ``None`` checks every option the select offers, so the displayed option labels are the reference.
    """
    _open(browser_page, webui, path)
    if options is None:
        options = tuple(_norm(text) for text in _row(browser_page, control).locator("option").all_text_contents())
    assert options, f"{control} offers no options to check"
    _assert_option_references(_help(browser_page, control), list(options))


@pytest.mark.ui_browser
def test_keep_settings_warning_and_clear_procedure_stay_with_the_control(browser_page: Page, webui: WebUI) -> None:
    """The removal warning and the clear procedure sit in the Keep Settings row and name the controls they use."""
    _open(browser_page, webui, GENERAL)
    row = _row(browser_page, "pfb_keep")
    label = _norm(row.locator("label.control-label").inner_text())
    assert label == "Keep Settings", f"unexpected retention control label: {label!r}"
    assert label in _strong_texts(row), "Keep Settings is not emphasized in its own help"

    warning = row.locator("p:has(.text-danger)")
    assert warning.count() == 1, f"expected one warning paragraph in the Keep Settings row, found {warning.count()}"
    assert label in _strong_texts(warning), "the warning does not name Keep Settings"

    steps = row.locator("ol > li")
    assert steps.count() == 3, f"expected three clear, restore and apply steps, found {steps.all_text_contents()!r}"
    master = _norm(_row(browser_page, "enable_cb").locator("label.control-label").inner_text())
    assert _strong_texts(steps.nth(0)) == [master, label], "the first step must name both settings it turns off"
    assert re.search(r"\boff\b", _norm(steps.nth(0).text_content()), re.IGNORECASE), "the first step turns settings off"
    assert re.search(r"\bon\b", _norm(steps.nth(1).text_content()), re.IGNORECASE), "the second step turns them back on"
    assert {"Update", "Run Now"} <= set(_strong_texts(steps.nth(2))), "the last step names the immediate apply action"


@pytest.mark.ui_browser
def test_ip_alternatives_and_firewall_warning_are_structured(browser_page: Page, webui: WebUI) -> None:
    """Alias apply choices form a list of the real options, and NAT cases sit with the self-traffic warning."""
    _open(browser_page, webui, IP)
    row = _row(browser_page, "pfb_alias_delta_mode")
    options = [_norm(text) for text in row.locator("option").all_text_contents()]
    choices = _strong_texts(row.locator("ul > li"))
    assert choices == options, (
        f"apply alternatives differ from the actual options: help={choices!r}, options={options!r}"
    )

    warning_row = _row(browser_page, "fw_self_outbound")
    warning = warning_row.locator("p:has(.text-danger)")
    assert warning.count() == 1, "the self-traffic control must carry its own warning paragraph"
    cases = warning_row.locator("ul > li")
    case_text = cases.all_text_contents()
    assert len(case_text) == 2, f"expected separate IPv4 NAT and IPv6 cases, found {case_text!r}"
    assert "IPv4" in case_text[0] and "NAT" in case_text[0], "the IPv4 NAT case is missing"
    assert "IPv6" in case_text[1] and "NAT" in case_text[1], "the IPv6 case is missing"
    assert "Outbound Firewall Rules" in _strong_texts(cases.nth(0)), "the NAT case must name the interface setting"


@pytest.mark.ui_browser
def test_generated_geoip_actions_have_valid_definitions(browser_page: Page, webui: WebUI) -> None:
    """The generated List Action help defines every displayed action, and each alias link is separated from its note."""
    _open(browser_page, webui, GEOIP)
    row = _row(browser_page, "action")
    definitions = row.locator("dl")
    assert definitions.count() == 1, "the List Action help needs one definition list"
    assert definitions.locator(":scope > dt").count() == definitions.locator(":scope > dd").count(), (
        "every action category needs one definition"
    )
    options = {_norm(text) for text in row.locator("option").all_text_contents()}
    assert options, "the List Action select offers no options to check"
    missing = options - set(_strong_texts(definitions))
    assert not missing, f"the list does not name these actions with their displayed labels: {sorted(missing)!r}"
    for name in ("aliasports_in", "aliasaddr_in"):
        help_row = _row(browser_page, name)
        assert help_row.locator('a[href^="/firewall_aliases.php"] + br').count() == 1, (
            f"{name}: the alias link must be separated from the input note"
        )


@pytest.mark.ui_browser
def test_generated_reputation_explains_related_choices_together(browser_page: Page, webui: WebUI) -> None:
    """Collective processes and country actions each form one list that uses the displayed labels."""
    _open(browser_page, webui, REPUTATION)
    labels = [
        _norm(_row(browser_page, name).locator("label.control-label").inner_text())
        for name in ("enable_pdup", "enable_dedup")
    ]
    collective = browser_page.locator("ul").filter(has=browser_page.locator("li > strong", has_text=labels[0]))
    assert collective.count() == 1, "the collective processes must share one list"
    assert [
        _norm(text) for text in collective.locator(":scope > li > strong:first-child").all_text_contents()
    ] == labels, "each collective process must lead its item with its displayed label"

    choices = {
        _norm(text)
        for name in ("ccwhite", "ccblack")
        for text in _row(browser_page, name).locator("option").all_text_contents()
    }
    alternatives = browser_page.locator("ul").filter(has=browser_page.locator("li > strong", has_text="Ignore"))
    assert alternatives.count() == 1, "the country actions must share one list"
    assert set(_strong_texts(alternatives.locator(":scope > li"))) == choices, (
        "the country actions must match their actual option labels"
    )
    lone_path = "/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt"
    assert browser_page.locator("li", has_text=lone_path).count() == 0, (
        "a single file example is not a list of alternatives"
    )
    assert browser_page.locator("code", has_text=lone_path).count() == 1, (
        "the file example must stay a readable literal"
    )


@pytest.mark.ui_browser
def test_reputation_literal_examples_wrap_on_narrow_screens(browser_page: Page, webui: WebUI) -> None:
    """Complete file and URL examples wrap inside a narrow viewport instead of overflowing it."""
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


@pytest.mark.ui_browser
def test_timeout_help_states_the_bounds_the_input_enforces(browser_page: Page, webui: WebUI) -> None:
    """The timeout help's numbers are the input's rendered bounds and default, not restated constants."""
    _open(browser_page, webui, GENERAL)
    field = browser_page.locator('[name="pfb_reentry_timeout"]')
    assert field.count() == 1, f"expected one timeout input, found {field.count()}"
    bounds = [field.get_attribute("min"), field.get_attribute("max"), field.get_attribute("placeholder")]
    assert None not in bounds, f"the timeout input lacks a rendered bound or default: {bounds!r}"
    numbers = set(re.findall(r"\d+", _norm(_help(browser_page, "pfb_reentry_timeout").text_content())))
    assert set(bounds) <= numbers, f"the help numbers {sorted(numbers)!r} omit the input bounds {bounds!r}"


@pytest.mark.ui_browser
def test_default_schedule_help_sits_inside_its_group(browser_page: Page, webui: WebUI) -> None:
    """The Default Schedule group holds its three selects and their help, and not the Apply Window toggle."""
    _open(browser_page, webui, GENERAL)
    group = (
        browser_page.locator("div.form-group")
        .filter(has=browser_page.locator('[name="pfb_schedule_weekday"]'))
        .filter(has=browser_page.locator('[name="pfb_schedule_minute"]'))
        .last
    )
    assert group.count() == 1, f"expected one Default Schedule group, found {group.count()}"
    for name in ("pfb_schedule_weekday", "pfb_schedule_hour", "pfb_schedule_minute"):
        assert group.locator(f'[name="{name}"]').count() == 1, f"{name} is outside the Default Schedule group"
    assert group.locator('[name="pfb_quiet_hours_enabled"]').count() == 0, (
        "the Automatic Apply Window toggle is inside the Default Schedule group"
    )
    # The group help plus one help block per schedule select.
    assert group.locator(".help-block").count() == 4, "the group help must render inside the Default Schedule group"


@pytest.mark.ui_browser
def test_apply_guidance_naming_run_now_renders_above_the_ip_form(browser_page: Page, webui: WebUI) -> None:
    """Apply guidance that names Run Now is rendered outside the IP form and before it in document order.

    Identity is the rendered text outside the form, not a print_callout class, so a markup
    change in the helper cannot silently select nothing.
    """
    _open(browser_page, webui, IP)
    placement = browser_page.evaluate(
        """() => {
            const field = document.querySelector('[name="enable_dup"]');
            const form = field ? field.closest('form') : null;
            if (!form) return { form: false, named: 0, above: false };
            const outside = [...document.body.querySelectorAll('*:not(script):not(style)')].filter(
                (el) => !el.contains(form) && !form.contains(el) && el.textContent.includes('Run Now')
            );
            const innermost = outside.filter((el) => !outside.some((other) => other !== el && el.contains(other)));
            const above = innermost.length > 0 && innermost.every(
                (el) => (el.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
            );
            return { form: true, named: innermost.length, above };
        }"""
    )
    assert placement["form"] is True, "the IP form carrying enable_dup is missing"
    assert placement["named"] > 0 and placement["above"] is True, (
        f"Run Now guidance must render outside and above the IP form: {placement!r}"
    )
