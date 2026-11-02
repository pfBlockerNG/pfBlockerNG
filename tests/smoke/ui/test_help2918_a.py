"""Rendered help contracts for General, IP, GeoIP/Reputation, Feeds, Category and DNSBL Category (#2918).

The checks pin structure and names, not sentences: a control named in help is emphasized
with the label or option text the UI actually renders, explained alternatives form real
lists, warnings sit with the control they warn about, structural closes leave no blank
paragraphs, and native ``title`` text stays plain.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_browser_feeds import _open
from .test_render_smoke import php_error_log_guard as php_error_log_guard

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

    from .webui import WebUI

GENERAL = "/pfblockerng/pfblockerng_general.php"
IP = "/pfblockerng/pfblockerng_ip.php"
GEOIP = "/pfblockerng/pfblockerng_Europe.php"
REPUTATION = "/pfblockerng/pfblockerng_reputation.php"
DNSBL = "/pfblockerng/pfblockerng_dnsbl.php"
BLACKLIST = "/pfblockerng/pfblockerng_blacklist.php"
CATEGORY = "/pfblockerng/pfblockerng_category.php"
FEEDS = "/pfblockerng/pfblockerng_feeds.php"
CATALOGUE = Path(__file__).resolve().parents[3] / "src/usr/local/www/pfblockerng/pfblockerng_feeds.json"

# Pages whose saved changes wait for an automatic apply (General applies on save).
DEFERRED_APPLY_PAGES = (
    IP,
    GEOIP,
    REPUTATION,
    BLACKLIST,
    f"{CATEGORY}?type=ipv4",
    f"{CATEGORY}?type=dnsbl",
    f"{CATEGORY}?type=geoip",
)


def _norm(text: str | None) -> str:
    return " ".join((text or "").split())


def _row(page: Page, name: str) -> Locator:
    control = page.locator(f'[name="{name}"]')
    assert control.count() == 1, f"expected one control named {name}, found {control.count()}"
    return control.locator(
        'xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " form-group ")][1]'
    )


def _label(page: Page, name: str) -> str:
    return _norm(_row(page, name).locator("label.control-label").first.inner_text())


def _labelled_row(page: Page, label: str) -> Locator:
    return page.locator("div.form-group").filter(
        has=page.locator("label.control-label", has_text=re.compile(rf"^\s*{re.escape(label)}\s*$"))
    )


def _help(page: Page, name: str) -> Locator:
    help_block = _row(page, name).locator(".help-block")
    assert help_block.count() == 1, f"expected one help block for {name}, found {help_block.count()}"
    return help_block


def _strong_texts(scope: Locator) -> list[str]:
    return [_norm(text) for text in scope.locator("strong").all_text_contents()]


def _options(page: Page, name: str) -> list[str]:
    return [_norm(text) for text in page.locator(f'[name="{name}"] option').all_text_contents()]


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


def _blank_paragraphs(scope: Locator) -> list[str]:
    """Outer HTML of every paragraph without text: what a stray or crossed close leaves behind."""
    return scope.evaluate_all(
        "(nodes) => nodes.flatMap((n) => [...n.querySelectorAll('p')])"
        ".filter((p) => p.textContent.trim() === '' && p.children.length === 0)"
        ".map((p) => p.outerHTML)"
    )


@pytest.mark.ui_browser
@pytest.mark.parametrize("path", DEFERRED_APPLY_PAGES)
def test_apply_callout_names_the_apply_window_and_run_now(browser_page: Page, webui: WebUI, path: str) -> None:
    """The apply callout names the General apply-window control and the Update page's Run Now action."""
    _open(browser_page, webui, GENERAL)
    window = _label(browser_page, "pfb_quiet_hours_enabled")
    _open(browser_page, webui, path)
    callout = browser_page.locator('[class*="callout"]').filter(has_text="Run Now")
    assert callout.count() == 1, f"{path}: expected one apply callout naming Run Now, found {callout.count()}"
    names = set(_strong_texts(callout))
    missing = {window, "General", "Update", "Run Now"} - names
    assert not missing, f"{path}: the apply callout lacks emphasized {sorted(missing)!r}; has {sorted(names)!r}"


@pytest.mark.ui_browser
def test_general_callout_says_general_applies_on_save(browser_page: Page, webui: WebUI) -> None:
    """General saves apply at once, so its callout names the page and Run Now but no apply window."""
    _open(browser_page, webui, GENERAL)
    window = _label(browser_page, "pfb_quiet_hours_enabled")
    callout = browser_page.locator('[class*="callout"]').filter(has_text="Run Now")
    assert callout.count() == 1, f"expected one General callout naming Run Now, found {callout.count()}"
    names = set(_strong_texts(callout))
    assert {"General", "Update", "Run Now"} <= names, f"General callout names: {sorted(names)!r}"
    assert window not in names, "General settings apply on save; its callout must not defer to the apply window"


@pytest.mark.ui_browser
def test_general_master_and_keep_settings_help_structure(browser_page: Page, webui: WebUI) -> None:
    """The master switch carries plain help; Keep Settings carries its removal warning and clear steps."""
    _open(browser_page, webui, GENERAL)
    master_row = _row(browser_page, "enable_cb")
    assert master_row.locator(".text-danger").count() == 0, "the master switch help is not a warning"
    assert master_row.locator(".infoblock").count() == 0, "the master switch help needs no sample infoblock"

    row = _row(browser_page, "pfb_keep")
    label = _label(browser_page, "pfb_keep")
    warning = row.locator("p:has(.text-danger)")
    assert warning.count() == 1, f"expected one warning paragraph in the Keep Settings row, found {warning.count()}"
    assert label in _strong_texts(warning), "the warning does not name Keep Settings"
    steps = row.locator("ol > li")
    assert steps.count() == 3, f"expected clear, restore and apply steps, found {steps.all_text_contents()!r}"
    master = _label(browser_page, "enable_cb")
    assert _strong_texts(steps.nth(0)) == [master, label], "the first step must name both settings it turns off"
    assert {"Update", "Run Now"} <= set(_strong_texts(steps.nth(2))), "the last step names the immediate apply action"


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
    """An option the help names keeps its displayed case and emphasis; ``None`` checks every option offered."""
    _open(browser_page, webui, path)
    if options is None:
        options = tuple(_options(browser_page, control))
    assert options, f"{control} offers no options to check"
    for option in options:
        assert option in _options(browser_page, control), f"{option!r} is not a displayed option of {control}"
    _assert_option_references(_help(browser_page, control), list(options))


@pytest.mark.ui_browser
def test_general_help_names_real_controls(browser_page: Page, webui: WebUI) -> None:
    """Trim Margin names the log caps by their column titles; the private-address switch names its exceptions."""
    _open(browser_page, webui, GENERAL)
    columns = {_norm(text) for text in browser_page.locator(".pfb-logcolhdr strong").all_text_contents()}
    assert len(columns) == 2, f"expected the two log cap column titles, found {sorted(columns)!r}"
    trim = browser_page.locator("div.form-group.pfb-logtrim .help-block")
    assert columns <= set(_strong_texts(trim)), "Trim Margin must emphasize the cap column titles it refers to"
    exceptions = _label(browser_page, "pfb_feed_internal_allowlist")
    assert exceptions in _strong_texts(_help(browser_page, "pfb_feed_internal_filter")), (
        "the private-address switch must point at its exceptions field by label"
    )


@pytest.mark.ui_browser
def test_timeout_help_states_the_bounds_the_input_enforces(browser_page: Page, webui: WebUI) -> None:
    """The timeout help's numbers are the input's rendered bounds and default, not restated constants."""
    _open(browser_page, webui, GENERAL)
    field = browser_page.locator('[name="pfb_reentry_timeout"]')
    bounds = [field.get_attribute("min"), field.get_attribute("max"), field.get_attribute("placeholder")]
    assert None not in bounds, f"the timeout input lacks a rendered bound or default: {bounds!r}"
    numbers = set(re.findall(r"\d+", _norm(_help(browser_page, "pfb_reentry_timeout").text_content())))
    assert set(bounds) <= numbers, f"the help numbers {sorted(numbers)!r} omit the input bounds {bounds!r}"


@pytest.mark.ui_browser
def test_ip_help_structures_alternatives_and_names_real_controls(browser_page: Page, webui: WebUI) -> None:
    """Apply modes form a list of the real options; the self-traffic warning lists its NAT cases with real names."""
    _open(browser_page, webui, GEOIP)
    actions = set(_options(browser_page, "action"))
    logging_label = _label(browser_page, "aliaslog")
    _open(browser_page, webui, IP)

    modes = _options(browser_page, "pfb_alias_delta_mode")
    choices = _strong_texts(_row(browser_page, "pfb_alias_delta_mode").locator("ul > li"))
    assert choices == modes, f"apply alternatives differ from the actual options: help={choices!r}, options={modes!r}"
    batch = set(_strong_texts(_help(browser_page, "pfb_alias_delta_batch")))
    assert batch and batch <= set(modes), f"the batch help must name apply modes by option label: {sorted(batch)!r}"

    warning_row = _row(browser_page, "fw_self_outbound")
    assert warning_row.locator("p:has(.text-danger)").count() == 1, "the self-traffic control needs its own warning"
    cases = warning_row.locator("ul > li")
    assert cases.count() == 2, f"expected separate IPv4 NAT and IPv6 cases, found {cases.all_text_contents()!r}"
    groups = {_norm(t) for t in browser_page.locator("div.form-group > label.control-label").all_text_contents()}
    named = set(_strong_texts(warning_row.locator(".help-block")))
    interface_groups = {"Inbound Firewall Rules", "Outbound Firewall Rules"}
    assert interface_groups <= groups, f"interface rule groups are missing from the page: {sorted(groups)!r}"
    assert interface_groups <= named, f"the warning must name both interface groups: {sorted(named)!r}"

    suppression = set(_strong_texts(_help(browser_page, "suppression")))
    assert "Permit Outbound" in suppression and "Permit Outbound" in actions, (
        f"the GeoIP workaround must name the real List Action option: help={sorted(suppression)!r}"
    )
    assert logging_label in _strong_texts(_help(browser_page, "enable_log")), (
        "Force Global IP Logging must name the per-list logging control it overrides"
    )


@pytest.mark.ui_browser
def test_schedule_references_name_the_general_default_schedule(browser_page: Page, webui: WebUI) -> None:
    """Extras and DNSBL Category timing help points at the real Default Schedule control on General."""
    _open(browser_page, webui, GENERAL)
    schedule = "Default Schedule"
    assert _labelled_row(browser_page, schedule).count() >= 1, "General no longer offers a Default Schedule control"
    _open(browser_page, webui, IP)
    attributions = _labelled_row(browser_page, "Attribution")
    assert attributions.count() == 2, f"expected the ASN and MaxMind attribution rows, found {attributions.count()}"
    for index in range(attributions.count()):
        assert schedule in _strong_texts(attributions.nth(index)), f"attribution row {index} must name {schedule!r}"
    _open(browser_page, webui, BLACKLIST)
    assert schedule in _strong_texts(_help(browser_page, "blacklist_freq")), (
        f"DNSBL Category Update Frequency must name {schedule!r}"
    )


@pytest.mark.ui_browser
def test_blacklist_help_names_the_wildcard_setting(browser_page: Page, webui: WebUI) -> None:
    """DNSBL Category points at the real Wildcard Blocking control for subdomain coverage."""
    _open(browser_page, webui, DNSBL)
    wildcard = "Wildcard Blocking"
    assert _labelled_row(browser_page, wildcard).count() >= 1, "DNS > DNSBL no longer offers Wildcard Blocking"
    _open(browser_page, webui, BLACKLIST)
    enable_help = _help(browser_page, "blacklist_enable")
    assert enable_help.locator(".text-danger").count() == 0, "routine DNSBL Category notes are not warnings"
    assert wildcard in _strong_texts(enable_help), f"the enable help must name {wildcard!r}"


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
    missing = set(_options(browser_page, "action")) - set(_strong_texts(definitions))
    assert not missing, f"the list does not name these actions with their displayed labels: {sorted(missing)!r}"
    assert row.locator("ul:not(:has(li))").count() == 0, "the List Action help has a list without items"
    for name in ("aliasports_in", "aliasaddr_in"):
        assert _row(browser_page, name).locator('a[href^="/firewall_aliases.php"] + br').count() == 1, (
            f"{name}: the alias link must be separated from the input note"
        )


@pytest.mark.ui_browser
def test_generated_reputation_explains_related_choices_together(browser_page: Page, webui: WebUI) -> None:
    """Collective processes and country actions each form one list that uses the displayed labels."""
    _open(browser_page, webui, REPUTATION)
    labels = [_label(browser_page, name) for name in ("enable_pdup", "enable_dedup")]
    collective = browser_page.locator("ul").filter(has=browser_page.locator("li > strong", has_text=labels[0]))
    assert collective.count() == 1, "the collective processes must share one list"
    leads = [_norm(text) for text in collective.locator(":scope > li > strong:first-child").all_text_contents()]
    assert leads == labels, f"each collective process must lead with its displayed label: {leads!r} vs {labels!r}"

    choices = set(_options(browser_page, "ccwhite")) | set(_options(browser_page, "ccblack"))
    alternatives = browser_page.locator("ul").filter(has=browser_page.locator("li > strong", has_text="Ignore"))
    assert alternatives.count() == 1, "the country actions must share one list"
    assert set(_strong_texts(alternatives.locator(":scope > li"))) == choices, (
        "the country actions must match their actual option labels"
    )
    lone_path = "/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt"
    assert browser_page.locator("li", has_text=lone_path).count() == 0, "a single file example is not a list"
    assert browser_page.locator("code", has_text=lone_path).count() == 1, "the file example must stay a literal"


@pytest.mark.ui_browser
def test_reputation_literal_examples_stay_inside_a_narrow_viewport(browser_page: Page, webui: WebUI) -> None:
    """Long file and URL examples wrap within a 390 px viewport instead of overflowing it."""
    browser_page.set_viewport_size({"width": 390, "height": 844})
    _open(browser_page, webui, REPUTATION)
    tokens = (
        "/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt",
        "https://rules.emergingthreatspro.com/XXXXXXXXXXXXXXXX/reputation/iprepdata.txt.gz",
        "/var/db/pfblockerng/match/generated/pfB_Match_ET_v4.txt",
    )
    for token in tokens:
        example = browser_page.locator("code").filter(has_text=re.compile(rf"^{re.escape(token)}$"))
        assert example.count() == 1, f"expected one literal example for {token!r}, found {example.count()}"
        # Collapsed sections and infoblocks are display:none; reveal the chain so the box is measurable.
        box = example.evaluate(
            "(node) => { for (let e = node; e; e = e.parentElement) { if (getComputedStyle(e).display === 'none')"
            " e.style.display = 'block'; } const r = node.getBoundingClientRect(); return [r.width, r.right]; }"
        )
        assert box[0] > 0, f"{token!r} did not render a measurable box: {box!r}"
        assert box[1] <= 390, f"{token!r} overflows the 390 px viewport (right edge {box[1]})"


@pytest.mark.ui_browser
@pytest.mark.parametrize(
    ("path", "region"),
    [
        (f"{FEEDS}?type=ipv4", "div.panel-body.bg-info, #pfb_table"),
        (f"{FEEDS}?type=dnsbl", "div.panel-body.bg-info, #pfb_table"),
        (f"{CATEGORY}?type=geoip", '[class*="callout"]'),
    ],
    ids=["feeds-ipv4", "feeds-dnsbl", "category-geoip"],
)
def test_help_regions_leave_no_blank_paragraphs(browser_page: Page, webui: WebUI, path: str, region: str) -> None:
    """Stray or crossed paragraph closes in help and feed rows must not leave empty paragraphs behind."""
    _open(browser_page, webui, path)
    scope = browser_page.locator(region)
    assert scope.count() >= 1, f"{path}: region {region!r} is missing"
    blanks = _blank_paragraphs(scope)
    assert not blanks, f"{path}: {len(blanks)} blank paragraph(s), first {blanks[:3]!r}"
    if "feeds" in path:
        intro = browser_page.locator("div.panel-body.bg-info")
        assert intro.locator("ul > li").count() > 0, f"{path}: the feed instructions must be a real list"


class _Titles(HTMLParser):
    """Every ``title`` attribute, plus the titles of feed status (bug) icons."""

    def __init__(self) -> None:
        super().__init__()
        self.titles: list[str] = []
        self.status_titles: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        title = values.get("title")
        if title is None:
            return
        self.titles.append(title)
        if tag == "i" and "fa-bug" in (values.get("class") or "").split():
            self.status_titles.append(title)


@pytest.mark.ui_render
@pytest.mark.parametrize("ftype", ["ipv4", "ipv6", "dnsbl"])
def test_feed_titles_are_plain_and_status_icons_name_the_status(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
    ftype: str,
) -> None:
    """Native feed tooltips carry no markup, and each status icon names the catalogue status it marks."""
    path = f"{FEEDS}?type={ftype}"
    response = webui.get(path)
    result = evaluate_render(path, response.status_code, response.text, ('id="pfb_table"',))
    assert result.ok, f"{path}: {result.detail}"
    parser = _Titles()
    parser.feed(response.text)
    assert parser.titles, f"feeds {ftype}: no native titles rendered"
    tagged = [title for title in parser.titles if re.search(r"<\s*/?\s*[a-zA-Z]", title)]
    assert not tagged, f"feeds {ftype}: native titles contain markup: {tagged[:3]!r}"

    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    statuses = {
        str(feed["status"]).lower()
        for feed in (
            entry
            for group in catalogue.get(ftype, {}).values()
            if isinstance(group, dict)
            for top in group.get("feeds", [])
            for entry in (top, *(top.get("alternate") or []))
        )
        if "status" in feed and str(feed["status"]).lower() != "discontinued"
    }
    rendered = [title.lower() for title in parser.status_titles]
    assert len(rendered) >= len(statuses), f"feeds {ftype}: status icons {rendered!r} for statuses {statuses!r}"
    unnamed = [title for title in rendered if not any(status in title for status in statuses)]
    assert not unnamed, f"feeds {ftype}: status icon titles {unnamed!r} do not name a status in {sorted(statuses)!r}"


@pytest.mark.ui_browser
def test_feeds_count_labels_match_tabs_and_disclaimer_emphasis(browser_page: Page, webui: WebUI) -> None:
    """Feed-count headings keep the tabs' displayed case, and only the disclaimer label is emphasized."""
    _open(browser_page, webui, f"{FEEDS}?type=ipv4")
    intro = browser_page.locator("div.panel-body.bg-info")
    counts = [_norm(t).rstrip(":") for t in intro.locator(":scope dl").first.locator("dt").all_text_contents()]
    tabs = {
        _norm(browser_page.locator(f'ul.nav a[href="{FEEDS}?type={kind}"]').last.inner_text())
        for kind in ("ipv4", "ipv6", "dnsbl")
    }
    assert set(counts) == tabs, f"count labels {counts!r} differ from actual tabs {sorted(tabs)!r}"
    disclaimer = intro.locator("p").filter(has=browser_page.locator("strong", has_text="Disclaimer:"))
    assert disclaimer.count() == 1, "the disclaimer needs its own paragraph with an emphasized label"
    assert _strong_texts(disclaimer) == ["Disclaimer:"], "only the disclaimer label should be emphasized"
    assert _norm(disclaimer.text_content()) != "Disclaimer:", "the disclaimer must retain its risk explanation"
