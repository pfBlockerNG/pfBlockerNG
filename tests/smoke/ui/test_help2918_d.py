"""Live UI checks for the issue #2918 help review: shared help, the group editor and Sync.

Assertions read the HTML the appliance renders: list and definition structure, real control
names emphasised as <strong> (cross-checked against the rendered controls), typed literals in
<code>, plain native titles and the layout on a phone. Help prose is never pinned here.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_sync_dnsblip_warning import dnsblip_mismatch_config  # noqa: F401 - pytest fixture

if TYPE_CHECKING:
    from collections.abc import Iterator

    from playwright.sync_api import Page

    from ..conftest import SmokeVM
    from .webui import WebUI

DNSBL_TAB = "/pfblockerng/pfblockerng_dnsbl.php"
DNSBL_TAB_MARKER = "DNSBL Webserver Configuration"
EDITOR_DNSBL = "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl"
EDITOR_IPV4 = "/pfblockerng/pfblockerng_category_edit.php?type=ipv4"
EDITOR_MARKER = "Advanced Settings"
SYNC = "/pfblockerng/pfblockerng_sync.php"
SYNC_MARKER = "XMLRPC Sync Settings"
UPDATE = "/pfblockerng/pfblockerng_update.php"
UPDATE_MARKER = "Update Settings"
GENERAL = "/pfblockerng/pfblockerng_general.php"
GENERAL_MARKER = "Automatic Apply Window"
EDIT_HOOKS = "/pfblockerng/pfblockerng_edit_hooks.php"
EDIT_HOOKS_MARKER = "Load an Existing Hook Script"
PENDING_MARKER_FILE = "/usr/local/etc/pfb_pending_changes"
PHONE = {"width": 390, "height": 844}
JS_TIMEOUT_MS = 10_000

_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"})
_BLOCK = frozenset({"div", "dl", "ol", "p", "table", "ul", "h1", "h2", "h3", "h4", "h5", "h6"})

EDITORS = [
    pytest.param(EDITOR_DNSBL, id="group-editor-dnsbl"),
    pytest.param(EDITOR_IPV4, id="group-editor-ipv4"),
]


class _Node:
    def __init__(self, tag: str, attrs: dict[str, str | None], parent: _Node | None) -> None:
        self.tag = tag
        self.attrs = attrs
        self.parent = parent
        self.children: list[_Node | str] = []

    def text(self) -> str:
        return "".join(child if isinstance(child, str) else child.text() for child in self.children)

    def elements(self) -> Iterator[_Node]:
        for child in self.children:
            if isinstance(child, _Node):
                yield child
                yield from child.elements()

    def classes(self) -> list[str]:
        return (self.attrs.get("class") or "").split()


class _TreeBuilder(HTMLParser):
    """Element tree of the rendered page as written (no implied closes); end tags with no open element are kept."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("#document", {}, None)
        self.stray_end_tags: list[str] = []
        self._open: list[_Node] = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _Node(tag, dict(attrs), self._open[-1])
        self._open[-1].children.append(node)
        if tag not in _VOID:
            self._open.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open[-1].children.append(_Node(tag, dict(attrs), self._open[-1]))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self._open) - 1, 0, -1):
            if self._open[index].tag == tag:
                del self._open[index:]
                return
        self.stray_end_tags.append(tag)

    def handle_data(self, data: str) -> None:
        self._open[-1].children.append(data)


def _parse(body: str) -> _TreeBuilder:
    builder = _TreeBuilder()
    builder.feed(body)
    builder.close()
    return builder


def _all(root: _Node) -> list[_Node]:
    return [root, *root.elements()]


def _lists(root: _Node) -> list[_Node]:
    return [node for node in _all(root) if node.tag in ("ul", "ol")]


def _items(list_node: _Node) -> list[_Node]:
    return [child for child in list_node.children if isinstance(child, _Node) and child.tag == "li"]


def _leading_strong(item: _Node) -> str | None:
    """The text of the item's first element when that element is <strong> and no text precedes it."""
    for child in item.children:
        if isinstance(child, str):
            if child.strip():
                return None
            continue
        return child.text().strip() if child.tag == "strong" else None
    return None


def _texts(node: _Node, tag: str) -> list[str]:
    return [element.text().strip() for element in node.elements() if element.tag == tag]


def _help_regions(root: _Node) -> list[_Node]:
    """Help text containers: field help, infoblocks, callouts and notices."""
    return [
        node
        for node in _all(root)
        if any(cls == "help-block" or cls.startswith("infoblock") or cls == "alert" for cls in node.classes())
    ]


def _render(smoke_vm: SmokeVM, webui: WebUI, path: str, marker: str) -> _TreeBuilder:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    response = webui.get(path)
    result = evaluate_render(path, response.status_code, response.text, (marker,))
    assert result.ok, f"Tier-A render failed for {path}: {result.detail}"
    guard.assert_no_growth()
    return _parse(response.text)


def _select_options(root: _Node, name: str) -> list[str]:
    selects = [node for node in _all(root) if node.tag == "select" and node.attrs.get("name") == name]
    assert len(selects) == 1, f"expected one <select name={name!r}>; found {len(selects)}"
    return [option.text().strip() for option in selects[0].elements() if option.tag == "option"]


def _label_for(root: _Node, control_id: str) -> str:
    controls = [node for node in _all(root) if node.attrs.get("id") == control_id]
    assert len(controls) == 1, f"expected one #{control_id}; found {len(controls)}"
    group = controls[0].parent
    while group is not None and "form-group" not in group.classes():
        group = group.parent
    assert group is not None, f"#{control_id} has no form-group"
    labels = [node.text().strip() for node in group.elements() if "control-label" in node.classes()]
    assert labels, f"#{control_id} has no control label"
    return labels[0]


@pytest.mark.ui_render
@pytest.mark.parametrize(
    ("path", "marker", "select", "inherit"),
    [
        pytest.param(EDITOR_DNSBL, EDITOR_MARKER, "logging", "Default", id="group-editor"),
        pytest.param(DNSBL_TAB, DNSBL_TAB_MARKER, "global_log", None, id="dnsbl-tab"),
    ],
)
def test_mechanism_help_is_one_list_of_the_offered_mechanisms(
    smoke_vm: SmokeVM, webui: WebUI, path: str, marker: str, select: str, inherit: str | None
) -> None:
    """The shared mechanism help is a single list: one item per offered mechanism, led by its exact label."""
    root = _render(smoke_vm, webui, path, marker).root
    offered = [label for label in _select_options(root, select) if label != inherit]
    assert len(offered) == 7, f"expected the seven mechanisms on {path}; offered {offered!r}"
    leads = [[_leading_strong(item) for item in _items(node)] for node in _lists(root)]
    assert sum(lead == offered for lead in leads) == 1, (
        f"expected one list led by {offered!r} on {path}; lists are led by {leads!r}"
    )


@pytest.mark.ui_render
@pytest.mark.parametrize("path", EDITORS)
def test_group_editor_help_lists_have_items_and_paragraphs_hold_no_blocks(
    smoke_vm: SmokeVM, webui: WebUI, path: str
) -> None:
    root = _render(smoke_vm, webui, path, EDITOR_MARKER).root
    itemless = [node.tag for node in _lists(root) if not _items(node)]
    assert not itemless, f"{path} renders {len(itemless)} list(s) with no <li>: {itemless!r}"
    wrapped = [
        f"p>{child.tag}"
        for region in _help_regions(root)
        for p in _all(region)
        if p.tag == "p"
        for child in p.elements()
        if child.tag in _BLOCK
    ]
    assert not wrapped, f"{path} help puts block elements inside <p>: {wrapped!r}"


@pytest.mark.ui_render
@pytest.mark.parametrize("path", EDITORS)
def test_group_editor_guide_closes_only_the_definition_tags_it_opens(
    smoke_vm: SmokeVM, webui: WebUI, path: str
) -> None:
    """The Source Definitions guide is balanced for both IP and DNSBL groups (no stray </dd>, </dt> or </dl>)."""
    stray = [tag for tag in _render(smoke_vm, webui, path, EDITOR_MARKER).stray_end_tags if tag in ("dd", "dt", "dl")]
    assert not stray, f"{path} emits definition-list end tags with no open element: {stray!r}"


@pytest.mark.ui_render
def test_ipv4_guide_names_each_format_and_state_option(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Each Format and State choice the Source Definitions row offers is a guide term, spelt as the option."""
    root = _render(smoke_vm, webui, EDITOR_IPV4, EDITOR_MARKER).root
    terms = [_leading_strong(node) for node in _all(root) if node.tag == "dt"]
    for name in ("format-0", "state-0"):
        missing = [option for option in _select_options(root, name) if option not in terms]
        assert not missing, f"{name} options without a <dt><strong> guide term: {missing!r}; terms are {terms!r}"


@pytest.mark.ui_render
@pytest.mark.parametrize(
    ("path", "literals"),
    [
        pytest.param(EDITOR_DNSBL, ("# comment", "$important"), id="group-editor-dnsbl"),
        pytest.param(EDITOR_IPV4, ("pfb_", "pfB_", "172.16.1.0/24", "AS32934"), id="group-editor-ipv4"),
    ],
)
def test_group_editor_typed_literals_are_code(
    smoke_vm: SmokeVM, webui: WebUI, path: str, literals: tuple[str, ...]
) -> None:
    code = _texts(_render(smoke_vm, webui, path, EDITOR_MARKER).root, "code")
    missing = [literal for literal in literals if literal not in code]
    assert not missing, f"{path}: literals not in <code>: {missing!r}; <code> texts are {code!r}"


@pytest.mark.ui_render
def test_ipv4_custom_list_help_orders_its_two_input_types_and_maps_alias_roles(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Custom List: an ordered list of the two input types naming the real mode checkbox; the alias role note
    (#354) appears both in the Source Definitions guide and in the Custom List section."""
    root = _render(smoke_vm, webui, EDITOR_IPV4, EDITOR_MARKER).root
    checkbox = _label_for(root, "whois_convert")
    ordered = [node for node in _lists(root) if node.tag == "ol" and len(_items(node)) == 2]
    assert len(ordered) == 1, f"expected one two-item <ol> for Custom List input types; found {len(ordered)}"
    assert checkbox in _texts(_items(ordered[0])[1], "strong"), (
        f"the second input type must name the {checkbox!r} checkbox in <strong>; "
        f"item is {_items(ordered[0])[1].text()!r}"
    )
    infoblocks = [node for node in _all(root) if any(cls.startswith("infoblock") for cls in node.classes())]
    sections = [node for node in _all(root) if node.attrs.get("id") == "IPv4customlist"]
    assert sections, "the IPv4 Custom List section is not rendered"
    for where, scopes in (("Source Definitions guide", infoblocks), ("Custom List section", sections)):
        notes = [
            node
            for scope in scopes
            for node in _lists(scope)
            if node.tag == "ul"
            and len(_items(node)) == 3
            and node.parent is not None
            and "Custom List" in _texts(node.parent, "strong")
        ]
        assert notes, f"the {where} must carry the three-item alias role list after its Custom List note"


@pytest.mark.ui_render
def test_ipv4_action_help_defines_the_real_actions(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """The Action guide is a definition list whose emphasised names are actual Action choices, one per name."""
    root = _render(smoke_vm, webui, EDITOR_IPV4, EDITOR_MARKER).root
    actions = _select_options(root, "action")
    guides = [
        node
        for node in _all(root)
        if node.tag == "dl" and "Disabled" in [_leading_strong(dt) for dt in _items_of(node, "dt")]
    ]
    assert len(guides) == 1, f"expected one Action definition list led by 'Disabled'; found {len(guides)}"
    named = _texts(guides[0], "strong")
    unknown = [name for name in named if name not in actions]
    assert not unknown, f"Action guide emphasises names that are not Action choices: {unknown!r}; choices {actions!r}"
    for expected in ("Disabled", "Deny Inbound", "Deny Outbound", "Deny Both", "Alias Native"):
        assert expected in named, f"Action guide must name {expected!r} in <strong>; named {named!r}"


def _items_of(node: _Node, tag: str) -> list[_Node]:
    return [child for child in node.children if isinstance(child, _Node) and child.tag == tag]


@pytest.mark.ui_render
def test_dnsbl_group_logging_control_uses_the_shared_name(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Item 33: the per-group control is "Logging/Blocking Mode", the same spelling the help and other pages use."""
    root = _render(smoke_vm, webui, EDITOR_DNSBL, EDITOR_MARKER).root
    assert _label_for(root, "logging") == "Logging/Blocking Mode"


@pytest.mark.ui_render
def test_sync_scope_and_mode_choices_are_explained_as_list_items(smoke_vm: SmokeVM, webui: WebUI) -> None:
    root = _render(smoke_vm, webui, SYNC, SYNC_MARKER).root
    scope = _select_options(root, "syncscope")
    mode = _select_options(root, "varsynconchanges")[1:]  # the first choice turns sync off
    leads = [_leading_strong(item) for node in _lists(root) for item in _items(node)]
    for label in (*scope, *mode):
        assert leads.count(label) == 1, f"expected {label!r} to lead one list item; leads are {leads!r}"


@pytest.mark.ui_render
def test_sync_ha_notice_lists_its_remedies_and_names_the_scope(
    smoke_vm: SmokeVM,
    webui: WebUI,
    dnsblip_mismatch_config: None,  # noqa: F811 - pytest fixture
) -> None:
    root = _render(smoke_vm, webui, SYNC, SYNC_MARKER).root
    scope = _select_options(root, "syncscope")
    notices = [
        node for node in _all(root) if "alert-warning" in node.classes() and "pfB_DNSBLIP_v4" in _texts(node, "code")
    ]
    assert len(notices) == 1, f"expected one HA notice naming the pfB_DNSBLIP_v4 alias in <code>; found {len(notices)}"
    remedies = [node for node in _lists(notices[0]) if len(_items(node)) == 2]
    assert remedies, "the HA notice must list its two remedies"
    named = _texts(notices[0], "strong")
    assert "Lists and global settings only (legacy)" in scope, f"scope choices are {scope!r}"
    assert "Lists and global settings only (legacy)" in named, f"the notice must name the scope; names {named!r}"


@pytest.mark.ui_render
def test_sync_literals_are_code(smoke_vm: SmokeVM, webui: WebUI) -> None:
    code = _texts(_render(smoke_vm, webui, SYNC, SYNC_MARKER).root, "code")
    missing = [literal for literal in ("admins", "pfB_DNSBLIP_v4", "pfB_DNSBLIP_v6") if literal not in code]
    assert not missing, f"Sync literals not in <code>: {missing!r}; <code> texts are {code!r}"


def _pending_banners(root: _Node) -> list[_Node]:
    return [node for node in _all(root) if "alert-warning" in node.classes() and "Run Now" in _texts(node, "strong")]


@pytest.mark.ui_render
def test_pending_banner_names_the_apply_controls(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Given no pending marker there is no banner; with one, the banner on a settings page and on Update names
    Run Now and the General Automatic Apply Window, and only the settings page links to Update."""
    window = _label_for(_render(smoke_vm, webui, GENERAL, GENERAL_MARKER).root, "pfb_quiet_hours_enabled")
    try:
        smoke_vm.ssh("rm", "-f", PENDING_MARKER_FILE)
        assert not _pending_banners(_render(smoke_vm, webui, SYNC, SYNC_MARKER).root), "before: no banner"

        smoke_vm.ssh("touch", PENDING_MARKER_FILE)
        for path, marker, links in ((SYNC, SYNC_MARKER, True), (UPDATE, UPDATE_MARKER, False)):
            banners = _pending_banners(_render(smoke_vm, webui, path, marker).root)
            assert len(banners) == 1, f"{path}: expected one pending banner naming Run Now; found {len(banners)}"
            named = _texts(banners[0], "strong")
            assert window in named and "General" in named, f"{path}: banner must name {window!r} on General; {named!r}"
            hrefs = [node.attrs.get("href") for node in _all(banners[0]) if node.tag == "a"]
            assert (UPDATE in hrefs) is links, f"{path}: Update link expected={links}; links {hrefs!r}"
    finally:
        smoke_vm.ssh("rm", "-f", PENDING_MARKER_FILE)


@pytest.mark.ui_render
def test_edit_hooks_warning_names_the_hooks_tab(smoke_vm: SmokeVM, webui: WebUI) -> None:
    root = _render(smoke_vm, webui, EDIT_HOOKS, EDIT_HOOKS_MARKER).root
    tabs = [
        node.text().strip()
        for node in _all(root)
        if node.tag == "a" and "pfblockerng_hooks.php" in (node.attrs.get("href") or "")
    ]
    callouts = [node for node in _all(root) if any("callout" in cls and "danger" in cls for cls in node.classes())]
    assert len(callouts) == 1, f"expected one danger callout; found {len(callouts)}"
    named = _texts(callouts[0], "strong")
    assert "Hooks" in tabs and "Hooks" in named, f"the warning must name the Hooks tab {tabs!r}; names {named!r}"


@pytest.mark.ui_render
def test_regex_list_help_lists_its_rules_with_literals(smoke_vm: SmokeVM, webui: WebUI) -> None:
    root = _render(smoke_vm, webui, DNSBL_TAB, DNSBL_TAB_MARKER).root
    guides = [
        node
        for node in _lists(root)
        if node.tag == "ul"
        and len(_items(node)) >= 3
        and node.parent is not None
        and "Regex List" in _texts(node.parent, "strong")
        and {"#", "\\#", "^"} <= set(_texts(node.parent, "code"))
    ]
    assert len(guides) == 1, f"expected one Regex List rule list with its #, \\# and ^ literals; found {len(guides)}"


@pytest.mark.ui_render
@pytest.mark.parametrize(
    ("path", "marker"),
    [
        pytest.param(EDITOR_DNSBL, EDITOR_MARKER, id="group-editor-dnsbl"),
        pytest.param(EDITOR_IPV4, EDITOR_MARKER, id="group-editor-ipv4"),
        pytest.param(SYNC, SYNC_MARKER, id="sync"),
    ],
)
def test_native_titles_are_plain_text(smoke_vm: SmokeVM, webui: WebUI, path: str, marker: str) -> None:
    titles = [value for node in _all(_render(smoke_vm, webui, path, marker).root) if (value := node.attrs.get("title"))]
    markup = [title for title in titles if "<" in title or ">" in title]
    assert not markup, f"native titles on {path} must be plain text; found {markup!r}"


@pytest.mark.ui_browser
@pytest.mark.parametrize("path", [pytest.param(EDITOR_IPV4, id="group-editor-ipv4"), pytest.param(SYNC, id="sync")])
def test_opened_help_fits_a_phone(browser_page: Page, webui: WebUI, path: str) -> None:
    """With every help block opened, nothing on the page is wider than a 390 px phone screen."""
    from .test_browser_feeds import _open

    page = browser_page
    page.set_viewport_size(PHONE)
    _open(page, webui, path)
    opened = page.evaluate(
        """() => { const blocks = [...document.querySelectorAll("[class*='infoblock']")];
            blocks.forEach(b => { b.style.display = 'block'; }); return blocks.length; }"""
    )
    metrics = page.evaluate(
        """() => { const root = document.documentElement;
            const wide = [...document.querySelectorAll('.help-block, [class*="infoblock"], .alert, .callout')]
                .filter(el => el.getBoundingClientRect().right > root.clientWidth + 1)
                .map(el => el.className + ': ' + el.textContent.trim().slice(0, 60));
            return {overflow: root.scrollWidth - root.clientWidth, wide}; }"""
    )
    assert metrics["overflow"] == 0 and not metrics["wide"], (
        f"{path} at {PHONE['width']} px with {opened} help blocks open: {metrics!r}"
    )
