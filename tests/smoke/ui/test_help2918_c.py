"""Help text on pfB-DNS, DNSBL, SafeSearch and the setup wizard (#2918): structure and real control names.

Tier A (``ui_render``) fetches each page from the live smoke VM and parses the shipped markup, so a ``<p>`` that
wraps a block element or a list without items is caught before the browser repairs it. Assertions pin structure
and control names, never sentences: every name a help text marks in ``<strong>`` must be the label of a control
that exists. One Tier B (``ui_browser``) check covers what only a browser shows: the pfB-DNS Enable summary is
visible while its detail stays folded, and the unfolded detail fits a 390 px phone screen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .render_oracle import evaluate_render

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from playwright.sync_api import Page

    from .webui import WebUI

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
SAFESEARCH_PAGE = "/pfblockerng/pfblockerng_safesearch.php"
UPDATE_PAGE = "/pfblockerng/pfblockerng_update.php"
GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"
WIZARD = "/wizard.php?xml=pfblockerng_wizard.xml&stepid={}"
# The wizard has five steps (stepid 0-4): welcome, components, IP, DNSBL, finish.
WIZARD_STEPS = range(5)
MARKERS = {
    DNS_PAGE: ("pfB-DNS Settings",),
    DNSBL_PAGE: ("DNSBL Webserver Configuration",),
    SAFESEARCH_PAGE: ("SafeSearch settings", "DNSBL SafeSearch"),
    UPDATE_PAGE: ("Run Scope",),
    GENERAL_PAGE: ("Default Schedule",),
    SYNC_PAGE: ("XMLRPC Sync Settings",),
}
# The wizard renders each step's own Form; its Skip button is on every step.
WIZARD_MARKER = ("pfb_wizard_disable",)

BLOCK_TAGS = frozenset({"p", "div", "ul", "ol", "dl", "table", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6"})
VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"})
PHONE_WIDTH = 390
JS_TIMEOUT_MS = 10_000


# ---- a minimal tree of the shipped markup (no browser repair) ---------------------------------------------------


@dataclass(eq=False)
class Node:
    tag: str
    attrs: dict[str, str]
    parent: Node | None = None
    children: list[Node | str] = field(default_factory=list)

    def classes(self) -> set[str]:
        return set(self.attrs.get("class", "").split())

    def elements(self) -> list[Node]:
        return [child for child in self.children if isinstance(child, Node)]

    def walk(self) -> Iterator[Node]:
        for child in self.elements():
            yield child
            yield from child.walk()

    def find(self, match: Callable[[Node], bool]) -> list[Node]:
        return [node for node in self.walk() if match(node)]

    def text(self) -> str:
        parts = [child if isinstance(child, str) else child.text() for child in self.children]
        return " ".join(" ".join(parts).split())

    def ancestors(self) -> Iterator[Node]:
        node = self.parent
        while node is not None:
            yield node
            node = node.parent


class _Tree(HTMLParser):
    """Builds :class:`Node` s exactly as the server sent them: an unclosed ``<p>`` keeps what follows inside it."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", {})
        self._open = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = Node(tag, {name: value or "" for name, value in attrs}, self._open[-1])
        self._open[-1].children.append(node)
        if tag not in VOID_TAGS:
            self._open.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open[-1].children.append(Node(tag, {name: value or "" for name, value in attrs}, self._open[-1]))

    def handle_endtag(self, tag: str) -> None:
        for depth in range(len(self._open) - 1, 0, -1):
            if self._open[depth].tag == tag:
                del self._open[depth:]
                return

    def handle_data(self, data: str) -> None:
        self._open[-1].children.append(data)


def _fetch(webui: WebUI, path: str, markers: tuple[str, ...]) -> Node:
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, markers)
    assert result.ok, f"render oracle failed for {path}: {result.detail}"
    tree = _Tree()
    tree.feed(resp.text)
    tree.close()
    return tree.root


def _page(webui: WebUI, path: str) -> Node:
    return _fetch(webui, path, MARKERS[path])


def _wizard(webui: WebUI, stepid: int) -> Node:
    return _fetch(webui, WIZARD.format(stepid), WIZARD_MARKER)


def _has_class(name: str) -> Callable[[Node], bool]:
    return lambda node: name in node.classes()


def _form_group(page: Node, name: str) -> Node:
    """The ``div.form-group`` holding the control named ``name`` (``name[]`` for a multi-select)."""
    controls = page.find(
        lambda n: n.tag in {"input", "select", "textarea"} and n.attrs.get("name") in (name, f"{name}[]")
    )
    assert controls, f"no control named {name!r} on the page"
    group = next((a for a in controls[0].ancestors() if a.tag == "div" and "form-group" in a.classes()), None)
    assert group is not None, f"control {name!r} is not inside a form-group"
    return group


def _help(page: Node, name: str) -> Node:
    blocks = _form_group(page, name).find(_has_class("help-block"))
    assert len(blocks) == 1, f"expected one help block for {name!r}, got {len(blocks)}"
    return blocks[0]


def _label(page: Node, name: str) -> str:
    labels = _form_group(page, name).find(lambda n: n.tag == "label" and "control-label" in n.classes())
    assert labels, f"control {name!r} has no control label"
    return labels[0].text()


def _labels(page: Node) -> set[str]:
    """Every control label, checkbox/radio caption and button text on the page: the names a user can find."""
    names = {node.text() for node in page.find(lambda n: n.tag in {"label", "button", "option"})}
    submits = page.find(lambda n: n.tag == "input" and n.attrs.get("type") == "submit")
    return (names | {n.attrs.get("value", "") for n in submits}) - {""}


def _item_heads(node: Node) -> list[str]:
    """The bold name each list item in ``node`` opens with, in order."""
    heads = []
    for item in node.find(lambda n: n.tag == "li"):
        lead = next((kid for kid in item.children if not isinstance(kid, str) or kid.strip()), None)
        if isinstance(lead, Node) and lead.tag == "strong":
            heads.append(lead.text())
    return heads


def _strong(node: Node, parent: str | None = None) -> list[str]:
    """Texts of ``<strong>`` in ``node``, only those whose parent is a ``parent`` element when given."""
    return [
        s.text()
        for s in node.find(lambda n: n.tag == "strong")
        if parent is None or (s.parent is not None and s.parent.tag == parent)
    ]


def _shape_problems(root: Node) -> list[str]:
    """Structural defects: a block inside a ``<p>``, a list without items or with stray content, an orphan item."""
    problems: list[str] = []
    for node in [root, *root.walk()]:
        parent = node.parent.tag if node.parent is not None else ""
        if node.tag in BLOCK_TAGS and any(a.tag == "p" for a in node.ancestors()):
            problems.append(f"<{node.tag}> inside <p>: {node.text()[:60]!r}")
        if node.tag in {"ul", "ol"}:
            items = [kid.tag for kid in node.elements()]
            stray = [kid.strip() for kid in node.children if isinstance(kid, str) and kid.strip()]
            if "li" not in items:
                problems.append(f"<{node.tag}> without items: {node.text()[:60]!r}")
            if any(tag != "li" for tag in items) or stray:
                problems.append(f"<{node.tag}> holds more than items: {node.text()[:60]!r}")
        if node.tag == "li" and parent not in {"ul", "ol"}:
            problems.append(f"<li> outside a list: {node.text()[:60]!r}")
        if node.tag == "dl" and not any(kid.tag == "dt" for kid in node.elements()):
            problems.append(f"<dl> without terms: {node.text()[:60]!r}")
        if node.tag in {"dt", "dd"} and parent != "dl":
            problems.append(f"<{node.tag}> outside a <dl>: {node.text()[:60]!r}")
    return problems


# ---- Tier A: pfB-DNS, DNSBL and SafeSearch pages ----------------------------------------------------------------


@pytest.mark.ui_render
def test_dns_pages_help_markup_is_well_formed(webui: WebUI) -> None:
    """No help on pfB-DNS, DNSBL or SafeSearch wraps a block in a paragraph or leaves a list without items."""
    problems: dict[str, list[str]] = {}
    for path in (DNS_PAGE, DNSBL_PAGE, SAFESEARCH_PAGE):
        page = _page(webui, path)
        groups = page.find(lambda n: n.tag == "div" and "form-group" in n.classes())
        assert groups, f"no form groups rendered on {path}"
        found = [problem for group in groups for problem in _shape_problems(group)]
        found += [problem for box in page.find(_has_class("bs-callout")) for problem in _shape_problems(box)]
        if found:
            problems[path] = found
    assert problems == {}, f"malformed help markup: {problems}"


@pytest.mark.ui_render
def test_pfb_dns_enable_help_opens_with_a_summary_and_folds_the_detail(webui: WebUI) -> None:
    """The pfB-DNS Enable help starts with a short paragraph naming pfB-DNS; the detail sits in one infoblock as lists.

    The detail names the Sync scope that copies transport settings by its real option label.
    """
    page = _page(webui, DNS_PAGE)
    label = _label(page, "pfb_dns")
    help_block = _help(page, "pfb_dns")
    first = help_block.elements()[0] if help_block.elements() else None
    assert first is not None and first.tag == "p", f"pfB-DNS Enable help does not open with a paragraph: {first}"
    assert label in _strong(first), f"the opening paragraph names {_strong(first)}, not the {label!r} control"
    infoblocks = help_block.find(_has_class("infoblock"))
    assert len(infoblocks) == 1, f"expected one detail infoblock, got {len(infoblocks)}"
    detail = infoblocks[0]
    assert first not in detail.ancestors() and detail not in first.walk(), "the summary and the detail overlap"
    resolver_changes = [item for ul in detail.find(lambda n: n.tag == "ul") for item in ul.elements()]
    ha_steps = [item for ol in detail.find(lambda n: n.tag == "ol") for item in ol.elements()]
    assert len(resolver_changes) >= 3, f"Resolver changes are {len(resolver_changes)} list items, expected 3 or more"
    assert len(ha_steps) == 2, f"the high-availability order is {len(ha_steps)} numbered steps, expected 2"
    scopes = {o.text() for o in _page(webui, SYNC_PAGE).find(lambda n: n.tag == "option")}
    named_scopes = [name for name in _strong(detail) if "(legacy)" in name or "local settings" in name]
    assert named_scopes, f"the detail names no Sync scope in bold; bold names: {_strong(detail)}"
    missing = [name for name in named_scopes if name not in scopes]
    assert missing == [], f"the detail names Sync scopes {missing} that the Sync page does not offer {sorted(scopes)}"


@pytest.mark.ui_render
@pytest.mark.parametrize(
    ("control", "label"),
    [
        ("pfb_py_nolog", "Log VIP blocks via web server"),
        ("pfb_idn_escalate_suspicious", "Block suspicious or malformed IDNs"),
        ("pfb_regex_cap", "Limit regex length to 200 characters"),
        ("global_log", "Global Logging/Blocking Mode"),
    ],
)
def test_dnsbl_control_label_says_what_it_does(webui: WebUI, control: str, label: str) -> None:
    """Each DNSBL control is labelled with what it actually does, under the name other help texts use."""
    assert _label(_page(webui, DNSBL_PAGE), control) == label


@pytest.mark.ui_render
def test_dnsbl_mode_help_lists_each_offered_mode_once(webui: WebUI) -> None:
    """The modes are explained once on the DNSBL page: one list item per offered mode, in the control's order."""
    page = _page(webui, DNSBL_PAGE)
    offered = [o.text() for o in _form_group(page, "global_log").find(lambda n: n.tag == "option")]
    assert len(offered) == 7, f"expected seven Logging/Blocking modes, got {offered}"
    named = _item_heads(_help(page, "global_log"))
    assert named == offered, f"the mode help lists {named}, expected the offered modes {offered}"
    explained = [name for name in _item_heads(page) if name in offered]
    assert explained == offered, f"modes explained as list items on the DNSBL page: {explained}, expected {offered}"


@pytest.mark.ui_render
def test_dnsbl_application_mode_help_lists_each_choice(webui: WebUI) -> None:
    """The Global Application Mode help explains each choice as a list item and names the mode control it applies."""
    page = _page(webui, DNSBL_PAGE)
    group = _form_group(page, "global_log_mode")
    choices = [o.text() for o in group.find(lambda n: n.tag == "option")]
    help_block = _help(page, "global_log_mode")
    heads = _item_heads(help_block)
    assert heads == choices, f"the help's list items open with {heads}, expected the choices {choices}"
    assert _label(page, "global_log") in _strong(help_block), "the help does not name the mode control it applies"


@pytest.mark.ui_render
def test_dnsbl_top1m_setup_list_names_its_controls(webui: WebUI) -> None:
    """The TOP1M help lists the setup steps by the controls of the TOP1M section, each a real label."""
    page = _page(webui, DNSBL_PAGE)
    steps = _strong(_help(page, "top1m_enable"), parent="li")
    needed = [_label(page, name) for name in ("top1m_enable", "top1m_source", "top1m_count", "top1m_inclusion")]
    assert [name for name in needed if name not in steps] == [], f"TOP1M setup list names {steps}, expected {needed}"


@pytest.mark.ui_render
def test_dnsbl_hsts_links_open_a_new_tab(webui: WebUI) -> None:
    """Both HSTS links name a valid new-tab target and do not give the opened page access to this one."""
    page = _page(webui, DNSBL_PAGE)
    links = _help(page, "pfb_hsts").find(lambda n: n.tag == "a")
    assert len(links) == 2, f"expected the two HSTS links, got {[a.attrs for a in links]}"
    for link in links:
        assert link.attrs.get("target") == "_blank", f"HSTS link has target {link.attrs.get('target')!r}"
        assert "noopener" in link.attrs.get("rel", "").split(), f"HSTS link lacks noopener: {link.attrs}"


@pytest.mark.ui_render
def test_dnsbl_permit_rules_help_names_the_setting_and_folds_the_scenario(webui: WebUI) -> None:
    """Permit Firewall Rules opens with a paragraph naming itself and its interface control; the scenario is folded."""
    page = _page(webui, DNSBL_PAGE)
    help_block = _help(page, "pfb_dnsbl_rule")
    first = help_block.elements()[0] if help_block.elements() else None
    assert first is not None and first.tag == "p", f"Permit Firewall Rules help does not open with a paragraph: {first}"
    expected = [_label(page, "pfb_dnsbl_rule"), _label(page, "dnsbl_allow_int")]
    assert [name for name in expected if name not in _strong(first)] == [], f"summary names {_strong(first)}"
    scenario = help_block.find(_has_class("infoblock"))
    assert len(scenario) == 1 and scenario[0].find(lambda n: n.tag == "p"), "the scenario is not folded paragraphs"


@pytest.mark.ui_render
def test_dnsbl_ip_list_action_help_defines_the_offered_actions(webui: WebUI) -> None:
    """The DNSBL IP List Action help is a definition list whose action names are the control's own options."""
    page = _page(webui, DNSBL_PAGE)
    offered = {o.text() for o in _form_group(page, "action").find(lambda n: n.tag == "option")}
    lists = _help(page, "action").find(lambda n: n.tag == "dl")
    assert len(lists) == 1, f"expected one definition list of actions, got {len(lists)}"
    named = _strong(lists[0])
    assert named, "the action list names no action"
    assert [name for name in named if name not in offered] == [], f"actions {named} not all offered {offered}"
    assert set(offered) <= set(named), f"offered actions {sorted(offered)} are not all explained: {named}"


@pytest.mark.ui_render
@pytest.mark.parametrize("path", [DNSBL_PAGE, SAFESEARCH_PAGE], ids=["dnsbl", "safesearch"])
def test_apply_callout_names_the_update_controls(webui: WebUI, path: str) -> None:
    """The apply callout names the Update page's Run Scope choices and Run Now button, each as it appears there."""
    callouts = _page(webui, path).find(_has_class("bs-callout"))
    assert len(callouts) == 1, f"expected one apply callout on {path}, got {len(callouts)}"
    named = _strong(callouts[0])
    update = _labels(_page(webui, UPDATE_PAGE))
    for name in ("Run Scope", "DNSBL", "Both", "Run Now"):
        assert name in named, f"the {path} callout does not name {name!r} in bold: {named}"
        assert name in update, f"{name!r} is not a control on the Update page"


# ---- Tier A: setup wizard ---------------------------------------------------------------------------------------


@pytest.mark.ui_render
def test_wizard_welcome_step_markup_is_well_formed(webui: WebUI) -> None:
    """The welcome heading is not inside a paragraph, and every paragraph of the step is closed before its list."""
    step = _wizard(webui, 0)
    headings = step.find(lambda n: n.tag == "h4" and "pfBlockerNG" in n.text())
    assert len(headings) == 1, f"expected one welcome heading, got {len(headings)}"
    group = next((a for a in headings[0].ancestors() if "form-group" in a.classes()), None)
    assert group is not None, "the welcome heading is not in the step description"
    assert _shape_problems(group) == [], f"welcome step markup is malformed: {_shape_problems(group)}"


@pytest.mark.ui_render
@pytest.mark.parametrize("stepid", [1, 4], ids=["components", "finish"])
def test_wizard_reset_warning_marks_the_risk_and_names_kept_settings(webui: WebUI, stepid: int) -> None:
    """The reset warning is marked as a warning and names, by their General labels, the settings the wizard keeps."""
    step = _wizard(webui, stepid)
    marked = step.find(lambda n: n.tag == "span" and "text-danger" in n.classes() and bool(_strong(n)))
    assert marked, f"wizard step {stepid}: the reset risk is not marked as a warning"
    general = _labels(_page(webui, GENERAL_PAGE))
    kept = ("Scheduled Feed Updates", "Default Schedule", "Download Failure Threshold")
    named = _strong(step)
    assert [name for name in kept if name not in named] == [], f"wizard step {stepid} names {named}, not {kept}"
    assert [name for name in kept if name not in general] == [], f"{kept} are not all General labels"


@pytest.mark.ui_render
@pytest.mark.parametrize("stepid", WIZARD_STEPS)
def test_wizard_skip_help_names_the_checkbox_and_button(webui: WebUI, stepid: int) -> None:
    """On every step the Do-not-show help names its own checkbox and the Skip button, as rendered on that step."""
    step = _wizard(webui, stepid)
    named = _strong(_help(step, "pfb_wizard_disable"))
    expected = [_label(step, "pfb_wizard_disable"), "Skip"]
    assert named == expected, f"wizard step {stepid}: help names {named}, expected {expected}"
    assert "Skip" in _labels(step), f"wizard step {stepid} has no Skip button"


@pytest.mark.ui_render
def test_wizard_dnsbl_step_refers_to_real_controls(webui: WebUI) -> None:
    """The DNSBL step's VIP help points at its Auto VIP checkbox; the step names DNSBL-page controls by their labels."""
    step = _wizard(webui, 3)
    auto_vip = _label(step, "pfb_dnsvip_auto")
    for selector in ("pfb_dnsvip4", "pfb_dnsvip6"):
        assert auto_vip in _strong(_help(step, selector)), f"{selector} help does not name {auto_vip!r} in bold"
    groups = step.find(lambda n: n.tag == "div" and "form-group" in n.classes())
    description = next((g for g in groups if not g.find(_has_class("help-block"))), None)
    assert description is not None, "the DNSBL step renders no description"
    known = _labels(step) | _labels(_page(webui, DNSBL_PAGE))
    named = _strong(description)
    assert auto_vip in named, f"the step description names {named}, not the {auto_vip!r} checkbox"
    assert [name for name in named if name not in known] == [], f"step names unknown controls: {named}"


# ---- Tier B: what only a browser shows --------------------------------------------------------------------------


@pytest.mark.ui_browser
def test_pfb_dns_enable_summary_shows_and_detail_fits_a_phone(browser_page: Page, webui: WebUI) -> None:
    """At 390 px the Enable summary is visible and its detail folded; unfolded, the page gains no side scroll."""
    pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
    from .test_browser_feeds import _open

    page = browser_page
    page.set_viewport_size({"width": PHONE_WIDTH, "height": 900})
    _open(page, webui, DNS_PAGE)
    help_block = page.locator("xpath=//*[@name='pfb_dns']/ancestor::div[contains(@class,'form-group')][1]")
    summary = help_block.locator(".help-block > p").first
    detail = help_block.locator(".help-block div[class^='infoblock']")
    assert summary.count() == 1 and summary.is_visible(), "the pfB-DNS Enable summary paragraph is not visible"
    assert detail.count() == 1, f"expected one folded detail block, got {detail.count()}"
    assert not detail.is_visible(), "the pfB-DNS Enable detail is open on load"
    help_block.locator("[id^='showinfo']").first.click()
    detail.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    overflow = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert overflow <= 0, f"the unfolded pfB-DNS detail widens the page by {overflow}px at {PHONE_WIDTH}px"
