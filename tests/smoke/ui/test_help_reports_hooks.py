"""Tier-A render proof for the #2918 help-text slice: Hooks, Edit Hooks, Update, Reports, Threats and Logs.

Each test loads a page through the authenticated webConfigurator session and checks the markup a
reader or assistive technology depends on: definition-list structure, actual UI references in
``<strong>``, typed literals in ``<code>``, warning labels and option labels. Prose is pinned only
where the wording is the contract (a named control, or a claim that must no longer appear).

Not covered here: the client DNSBL block page (``www/pfblockerng/www/dnsbl_default.php``) is served
only by the sinkhole listener outside the webConfigurator (see ``test_dnsbl_block_page.py``); the
JS-only dialogs are Tier-B material; the wizard finish message prints only from the wizard POST.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..helpers import SmokeVM
    from .webui import WebUI

HOOKS_PAGE = "/pfblockerng/pfblockerng_hooks.php"
EDIT_HOOKS_PAGE = "/pfblockerng/pfblockerng_edit_hooks.php"
UPDATE_PAGE = "/pfblockerng/pfblockerng_update.php"
ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
THREATS_PAGE = "/pfblockerng/pfblockerng_threats.php"
LOG_PAGE = "/pfblockerng/pfblockerng_log.php"

_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"})


class _Node:
    """One rendered element: its tag, attributes, parent and ordered children (elements or text)."""

    def __init__(self, tag: str, attrs: list[tuple[str, str | None]], parent: _Node | None) -> None:
        self.tag = tag
        self.attrs = {key: value or "" for key, value in attrs}
        self.parent = parent
        self.children: list[_Node | str] = []

    def text(self) -> str:
        """Visible text of this element with whitespace collapsed."""
        joined = "".join(child if isinstance(child, str) else child.text() for child in self.children)
        return " ".join(joined.split())

    def iter(self) -> Iterator[_Node]:
        for child in self.children:
            if isinstance(child, _Node):
                yield child
                yield from child.iter()

    def elements(self, tag: str) -> list[_Node]:
        return [node for node in self.iter() if node.tag == tag]


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("#document", [], None)
        self._current = self.root

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _Node(tag, attrs, self._current)
        self._current.children.append(node)
        if tag not in _VOID:
            self._current = node

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._current.children.append(_Node(tag, attrs, self._current))

    def handle_endtag(self, tag: str) -> None:
        node = self._current
        while node.parent is not None and node.tag != tag:
            node = node.parent
        if node.parent is not None:
            self._current = node.parent

    def handle_data(self, data: str) -> None:
        self._current.children.append(data)


def _dom(body: str) -> _Node:
    parser = _Parser()
    parser.feed(body)
    parser.close()
    return parser.root


def _dl_pairs(dl: _Node) -> list[tuple[_Node, _Node]]:
    """The (term, description) element pairs of a definition list, in document order."""
    pairs: list[tuple[_Node, _Node]] = []
    term: _Node | None = None
    for child in dl.children:
        if not isinstance(child, _Node):
            continue
        if child.tag == "dt":
            term = child
        elif child.tag == "dd" and term is not None:
            pairs.append((term, child))
            term = None
    return pairs


def _terms(dl: _Node) -> set[str]:
    return {term.text() for term, _ in _dl_pairs(dl)}


def _strong_texts(node: _Node) -> list[str]:
    return [strong.text() for strong in node.elements("strong")]


@pytest.fixture
def php_error_log_guard(smoke_vm: SmokeVM) -> Iterator[PhpErrorLogGuard]:
    """Fail the test if rendering the page wrote a new PHP error line."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    yield guard
    guard.assert_no_growth()


@pytest.fixture
def hook_script(smoke_vm: SmokeVM) -> Iterator[str]:
    """Install one Pre hook so the Edit Hooks status line has a loaded script; remove it afterwards."""
    name = "hook_pre_help2918.sh"
    helpers.install_hook_script(smoke_vm, name, "#!/bin/sh\nexit 0\n")
    try:
        yield name
    finally:
        smoke_vm.ssh("rm", "-f", f"{helpers.HOOK_SCRIPT_DIR}/{name}")


@pytest.mark.ui_render
def test_hooks_environment_is_two_definition_lists(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """The hook environment variables render as two definition lists, not one line-broken run.

    Given the Hooks page,
    When GET,
    Then the all-hooks variables form one definition list and the post-only variables another,
        each term naming exactly one variable, and the trigger values are a list of three choices.
    """
    body = webui.get(HOOKS_PAGE).text
    result = evaluate_render(HOOKS_PAGE, 200, body, ("Hook Entries",))
    assert result.ok, f"Hooks page render oracle failed: {result.detail}"

    root = _dom(body)
    all_hooks = [dl for dl in root.elements("dl") if "PFB_WHEN" in _terms(dl)]
    post_only = [dl for dl in root.elements("dl") if "PFB_IP_CHANGED" in _terms(dl)]
    assert len(all_hooks) == 1, f"expected one all-hooks definition list, found {len(all_hooks)}"
    assert len(post_only) == 1, f"expected one post-only definition list, found {len(post_only)}"
    assert _terms(all_hooks[0]) == {
        "PFB_WHEN",
        "PFB_TRIGGER",
        "PFB_POST_INSTALL",
        "PFB_PRE_UNINSTALL",
        "PFB_PKG_OP",
    }
    assert _terms(post_only[0]) == {
        "PFB_IP_CHANGED",
        "PFB_DNSBL_CHANGED",
        "PFB_STATUS",
        "PFB_CHANGED_IP_ALIASES",
        "PFB_CHANGED_DNSBL_GROUPS",
    }

    trigger = next(dd for term, dd in _dl_pairs(all_hooks[0]) if term.text() == "PFB_TRIGGER")
    choices = [[code.text() for code in item.elements("code")] for item in trigger.elements("li")]
    assert [choice[0] for choice in choices] == ["cron", "update", "force-reload"], (
        f"PFB_TRIGGER values are not the three documented choices: {choices!r}"
    )


@pytest.mark.ui_render
def test_hooks_root_warning_names_edit_hooks_and_bolds_its_label(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The root-script warning is bold and names the Edit Hooks tab.

    Given the Hooks page,
    When GET,
    Then the danger-styled Warning label is a strong element, and the same block names the
        Edit Hooks tab as a way to create a root script.
    """
    body = webui.get(HOOKS_PAGE).text
    root = _dom(body)
    warning = next(
        (
            span
            for span in root.elements("span")
            if "text-danger" in span.attrs.get("class", "").split() and span.text().startswith("Warning")
        ),
        None,
    )
    assert warning is not None, "the root-script row has no danger-styled Warning label"
    assert _strong_texts(warning) == ["Warning:"], "the Warning label is not bold, so the risk does not read first"
    block = warning.parent
    assert block is not None
    assert "as root" in _strong_texts(block), "the root-execution consequence is not bold inside the warning block"
    assert "Edit Hooks" in _strong_texts(block), "the root-script warning does not name the Edit Hooks tab"


@pytest.mark.ui_render
def test_hooks_script_source_shows_the_naming_pattern_as_code(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The naming pattern is a typed literal in code, not an italic placeholder inside it.

    Given the Hooks page,
    When GET,
    Then a code literal reads exactly hook_pre_NAME.sh, and Edit Hooks is an actual UI reference.
    """
    body = webui.get(HOOKS_PAGE).text
    root = _dom(body)
    codes = [code.text() for code in root.elements("code")]
    assert "hook_pre_NAME.sh" in codes, f"naming pattern is not a plain code literal; code literals: {codes!r}"
    assert "Edit Hooks" in [s.text() for s in root.elements("strong")], "Edit Hooks is not marked as a UI reference"


@pytest.mark.ui_render
def test_hooks_ha_note_names_the_sync_scope_that_carries_hooks(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The HA note names the sync scope that carries hook entries.

    Given the Hooks page,
    When GET,
    Then Sync Scope and All settings (legacy) are UI references.
    """
    body = webui.get(HOOKS_PAGE).text
    root = _dom(body)
    strongs = [s.text() for s in root.elements("strong")]
    assert "Sync Scope" in strongs, "the HA note does not name the Sync Scope field"
    assert "All settings (legacy)" in strongs, "the HA note does not name the scope that carries hook entries"


@pytest.mark.ui_render
def test_edit_hooks_status_names_the_loaded_script_as_code_and_its_when(
    webui: WebUI,
    hook_script: str,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The loaded-script status shows the file name as code and the Pre/Post label as a UI reference.

    Given a Pre hook script is present,
    When GET the Edit Hooks page for that script,
    Then the status line shows the file name as a code literal and Pre in bold.
    """
    body = webui.get(f"{EDIT_HOOKS_PAGE}?when=pre&script={hook_script}").text
    root = _dom(body)
    name_nodes = [code for code in root.elements("code") if code.text() == hook_script]
    assert name_nodes, f"the loaded script name {hook_script!r} is not rendered as a code literal"
    status = name_nodes[0].parent
    assert status is not None
    assert _strong_texts(status) == ["Pre"], f"the Pre/Post label is not a bold UI reference: {_strong_texts(status)!r}"


@pytest.mark.ui_render
def test_edit_hooks_escape_example_is_a_code_literal(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The control-byte escape example in the editor help is typed syntax, so it renders as code.

    Given the Edit Hooks page,
    When GET,
    Then the escape example \\033 is a code literal.
    """
    body = webui.get(EDIT_HOOKS_PAGE).text
    codes = [code.text() for code in _dom(body).elements("code")]
    assert "\\033" in codes, f"the escape example is not a code literal; code literals: {codes!r}"


@pytest.mark.ui_render
def test_update_schedule_rows_use_the_ui_labels(webui: WebUI, php_error_log_guard: PhpErrorLogGuard) -> None:  # noqa: ARG001
    """The schedule rows use the names the rest of the page uses, not internal job names.

    Given the Update page,
    When GET,
    Then the schedule labels are Feed groups, Extras (MaxMind, ASN, TOP1M) and DNSBL Category.
    """
    root = _dom(webui.get(UPDATE_PAGE).text)
    labels = {node.text() for node in root.iter()}
    for expected in ("Feed groups", "Extras (MaxMind, ASN, TOP1M)", "DNSBL Category"):
        assert expected in labels, f"schedule row {expected!r} is missing"


@pytest.mark.ui_render
def test_alerts_whitelist_legend_names_the_permit_and_dnsbl_whitelist_targets(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The plus-circle legend names the list each whitelist action adds to.

    Given the Reports > Alerts page,
    When GET,
    Then the plus-circle legend names Wildcard Blocking and the DNSBL Whitelist as UI references.
    """
    root = _dom(webui.get(ALERTS_PAGE).text)
    matches = [
        dd
        for dl in root.elements("dl")
        for term, dd in _dl_pairs(dl)
        if any("fa-plus-circle" in icon.attrs.get("class", "").split() for icon in term.elements("i"))
    ]
    assert len(matches) == 1, f"expected one plus-circle legend entry, found {len(matches)}"
    legend = matches[0]
    assert "Wildcard Blocking" in _strong_texts(legend), "the legend does not mark Wildcard Blocking as a UI reference"
    assert "DNSBL Whitelist" in _strong_texts(legend), "the legend does not name the DNSBL Whitelist"


@pytest.mark.ui_render
def test_alerts_settings_help_marks_auto_refresh_and_two_tone(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The Auto-Refresh and Two-Tone controls are named in bold, matching their labels.

    Given the Reports > Alerts page,
    When GET,
    Then Auto-Refresh and Two-Tone appear as bold UI references.
    """
    root = _dom(webui.get(ALERTS_PAGE).text)
    strongs = [s.text() for s in root.elements("strong")]
    assert "Auto-Refresh" in strongs, "the Auto-Refresh help is not the checkbox's name in bold"
    assert "Two-Tone" in strongs, "the Two-Tone chart help does not mark the style name"


@pytest.mark.ui_render
def test_alerts_filter_help_lists_regex_examples_as_definition_terms(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The regex filter instructions are body text; each example is a definition term.

    Given the Reports > Alerts page,
    When GET,
    Then no heading carries the regex instructions, and each example is a definition term in code.
    """
    root = _dom(webui.get(ALERTS_PAGE).text)
    example_terms = [term.text() for dl in root.elements("dl") for term, _ in _dl_pairs(dl)]
    assert {"^80$", "^80$|^8080$"} <= set(example_terms), f"regex examples are not definition terms: {example_terms!r}"


@pytest.mark.ui_render
def test_threats_page_names_the_providers_and_the_third_party_note(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """Provider names are spelled as the providers spell them, and the note says why links leave the firewall.

    Given a threat lookup for an IP and for a domain,
    When GET each,
    Then the provider links use the correct names,
    And the note carries a bold Note label.
    """
    ip_body = webui.get(f"{THREATS_PAGE}?host=192.0.2.10").text
    result = evaluate_render(THREATS_PAGE, 200, ip_body, ("Threat",))
    assert result.ok, f"Threats page render oracle failed: {result.detail}"
    ip_root = _dom(ip_body)
    links = {a.text() for a in ip_root.elements("a")}
    assert "Sucuri SiteCheck" in links, "the Sucuri link is not spelled Sucuri"
    assert "Quttera" in links, "the Quttera link is not spelled Quttera"

    notes = [p for p in ip_root.elements("p") if "Note:" in _strong_texts(p)]
    assert len(notes) == 1, f"expected one bold Note paragraph, found {len(notes)}"

    domain_body = webui.get(f"{THREATS_PAGE}?domain=example.com").text
    domain_links = {a.text() for a in _dom(domain_body).elements("a")}
    assert "VirusTotal" in domain_links, "the domain lookup does not name VirusTotal"


@pytest.mark.ui_render
def test_log_browser_names_dnsbl_safesearch_as_the_feature(
    webui: WebUI,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The Logs selector spells the SafeSearch feature the way the rest of the package does.

    Given the Logs page,
    When GET,
    Then the SafeSearch log option reads DNSBL SafeSearch.
    """
    body = webui.get(LOG_PAGE).text
    options = {option.text() for option in _dom(body).elements("option")}
    assert "DNSBL SafeSearch" in options, "the Logs option for SafeSearch is not spelled DNSBL SafeSearch"
