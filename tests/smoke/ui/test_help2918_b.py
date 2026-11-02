"""Live UI checks for the #2918 help-text review, area B (Reports, Hooks, Update, widget, Software).

Every check reads a real page from the smoke VM. Help is checked for structure (definition and
bullet lists, literals in ``<code>``, paragraphs that wrap no block) and for references to other
controls: a ``<strong>`` or a quoted name in a native title must equal the label the UI really
renders, read from the page that owns the control by its name, href or value. No assertion pins
an English sentence.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import body_has_php_error
from .test_browser_feeds import JS_TIMEOUT_MS, _open
from .test_dns_navigation import _chrome
from .test_render_smoke import software_panel_forced
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from playwright.sync_api import Page, ViewportSize

    from .webui import WebUI

DASHBOARD = "/index.php"
ALERTS = "/pfblockerng/pfblockerng_alerts.php"
DNS = "/pfblockerng/pfblockerng_dns.php"
BLACKLIST = "/pfblockerng/pfblockerng_blacklist.php"
SAFESEARCH = "/pfblockerng/pfblockerng_safesearch.php"
HOOKS = "/pfblockerng/pfblockerng_hooks.php"
EDIT_HOOKS = "/pfblockerng/pfblockerng_edit_hooks.php"
UPDATE = "/pfblockerng/pfblockerng_update.php"
LOG = "/pfblockerng/pfblockerng_log.php"
SYNC = "/pfblockerng/pfblockerng_sync.php"
SOFTWARE = "/pfblockerng/pfblockerng_software.php"

# The variables pfb_run_hooks() exports to every hook, then the ones only a Post hook receives.
ALL_HOOK_VARS = ["PFB_WHEN", "PFB_TRIGGER", "PFB_POST_INSTALL", "PFB_PRE_UNINSTALL", "PFB_PKG_OP"]
POST_HOOK_VARS = [
    "PFB_IP_CHANGED",
    "PFB_DNSBL_CHANGED",
    "PFB_STATUS",
    "PFB_CHANGED_IP_ALIASES",
    "PFB_CHANGED_DNSBL_GROUPS",
]
# The PFB_TRIGGER values, in the order the help explains them.
TRIGGER_VALUES = ["cron", "update", "force-reload"]
# A file-name pattern or template in hook help: ip_pre_*, hook_post_NAME, *.sh ...
_FILE_LITERAL = re.compile(r"\b\w+_(?:pre|post)_|\*\.(?:sh|py)\b")
_BLOCKS = frozenset({"p", "div", "dl", "ul", "ol", "table", "h1", "h2", "h3", "h4", "h5", "h6"})
_VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
)
PHONE: ViewportSize = {"width": 390, "height": 844}
DESKTOP: ViewportSize = {"width": 1440, "height": 900}


@dataclass(eq=False)
class _El:
    """One parsed element; ``children`` keeps text and elements in document order."""

    tag: str
    attrs: dict[str, str]
    parent: _El | None = None
    children: list[_El | str] = field(default_factory=list)

    def elements(self) -> list[_El]:
        return [child for child in self.children if isinstance(child, _El)]

    def iter(self) -> Iterator[_El]:
        for child in self.elements():
            yield child
            yield from child.iter()

    def find(self, match: Callable[[_El], bool]) -> list[_El]:
        return [el for el in self.iter() if match(el)]

    def classes(self) -> set[str]:
        return set(self.attrs.get("class", "").split())

    def ancestor(self, match: Callable[[_El], bool]) -> _El | None:
        node = self.parent
        while node is not None and not match(node):
            node = node.parent
        return node

    def text(self) -> str:
        parts: list[str] = []
        for child in self.children:
            parts.append(child if isinstance(child, str) else child.text())
        return " ".join("".join(parts).replace("\xa0", " ").split())


class _Tree(HTMLParser):
    """Builds an element tree without browser repair, so a ``<p>`` wrapping a list stays visible."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _El("#root", {})
        self._stack = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        el = _El(tag, {key: value or "" for key, value in attrs}, parent=self._stack[-1])
        self._stack[-1].children.append(el)
        if tag not in _VOID:
            self._stack.append(el)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._stack[-1].children.append(_El(tag, {key: value or "" for key, value in attrs}, parent=self._stack[-1]))

    def handle_endtag(self, tag: str) -> None:
        if any(el.tag == tag for el in self._stack[1:]):
            while self._stack.pop().tag != tag:
                pass

    def handle_data(self, data: str) -> None:
        self._stack[-1].children.append(data)


def _get(webui: WebUI, path: str) -> _El:
    resp = webui.get(path)
    assert resp.status_code == 200, f"GET {path} answered HTTP {resp.status_code}"
    assert not looks_like_login_page(resp.text), f"GET {path} showed the login form"
    tree = _Tree()
    tree.feed(resp.text)
    tree.close()
    error = body_has_php_error(resp.text)
    assert error is None, f"GET {path}: {error}"
    return tree.root


def _one(found: list[_El], what: str) -> _El:
    assert len(found) == 1, f"expected exactly one {what}, found {len(found)}"
    return found[0]


def _named(root: _El, tag: str, name: str) -> _El:
    return _one(root.find(lambda el: el.tag == tag and el.attrs.get("name") == name), f"<{tag} name={name!r}>")


def _group_of(el: _El) -> _El:
    group = el.ancestor(lambda node: node.tag == "div" and "form-group" in node.classes())
    assert group is not None, f"<{el.tag} {el.attrs!r}> sits in no form-group"
    return group


def _label_of(group: _El) -> str:
    return _one([el for el in group.elements() if el.tag == "label"], "form-group label").text()


def _row(root: _El, label: str) -> _El:
    """The content column of the form row whose label reads ``label``."""
    groups = root.find(
        lambda el: (
            "form-group" in el.classes()
            and any(child.tag == "label" and child.text() == label for child in el.elements())
        )
    )
    group = _one(groups, f"form row {label!r}")
    return _one([el for el in group.elements() if el.tag == "div"], f"content column of {label!r}")


def _texts(root: _El, tag: str) -> list[str]:
    return [el.text() for el in root.find(lambda el: el.tag == tag)]


def _tab(webui: WebUI, page: str, row: int, href: Callable[[str], bool]) -> str:
    rows = _chrome(webui, page).rows
    assert len(rows) > row, f"{page} renders {len(rows)} tab row(s); wanted row {row}"
    return _one_label([tab.label for tab in rows[row] if href(tab.href)], f"tab on {page} row {row}")


def _one_label(labels: list[str], what: str) -> str:
    assert len(labels) == 1, f"expected exactly one {what}, found {labels!r}"
    return labels[0]


def _assert_no_paragraph_wraps_a_block(scope: _El, where: str) -> None:
    wrapped = [
        (p.text()[:60], el.tag) for p in scope.find(lambda el: el.tag == "p") for el in p.iter() if el.tag in _BLOCKS
    ]
    assert wrapped == [], f"{where}: <p> wraps block elements: {wrapped!r}"


def _assert_definition_list(dl: _El, where: str) -> None:
    items = dl.elements()
    assert items, f"{where}: empty <dl>"
    assert [el.tag for el in items] == ["dt", "dd"] * (len(items) // 2) and len(items) % 2 == 0, (
        f"{where}: <dl> children must pair dt/dd, got {[el.tag for el in items]!r}"
    )
    for dt, dd in zip(items[::2], items[1::2], strict=True):
        assert [el.tag for el in dt.elements()] == ["code"], f"{where}: <dt> {dt.text()!r} must hold one <code> literal"
        assert dd.text(), f"{where}: <dd> after {dt.text()!r} is empty"


def _hooks_environment(root: _El) -> tuple[_El, list[_El]]:
    env = _row(root, "Environment")
    return env, env.find(lambda el: el.tag == "dl")


# --------------------------------------------------------------------------- Tier A: rendered HTML


@pytest.mark.ui_render
def test_hooks_environment_help_is_two_definition_lists(webui: WebUI) -> None:
    """Hook variables read as two lists, all hooks then Post only, with the trigger values listed."""
    env, dls = _hooks_environment(_get(webui, HOOKS))
    assert len(dls) == 2, f"Environment help must hold two <dl>, found {len(dls)}"
    for dl in dls:
        _assert_definition_list(dl, "Hooks Environment")
    listed = [[dt.text() for dt in dl.elements() if dt.tag == "dt"] for dl in dls]
    assert listed == [ALL_HOOK_VARS, POST_HOOK_VARS], f"variables per list: {listed!r}"

    items = dls[0].elements()
    trigger = items[items.index(next(dt for dt in items if dt.text() == "PFB_TRIGGER")) + 1]
    lists = trigger.find(lambda el: el.tag == "ul")
    values = [li.find(lambda el: el.tag == "code")[0].text() for li in _one(lists, "PFB_TRIGGER <ul>").elements()]
    assert values == TRIGGER_VALUES, f"PFB_TRIGGER list items must each start with its value: {values!r}"
    _assert_no_paragraph_wraps_a_block(env, "Hooks Environment")


@pytest.mark.ui_render
def test_hooks_help_marks_file_patterns_as_code(webui: WebUI) -> None:
    """Script name patterns in the Hooks help are typed literals, so they render as code."""
    root = _get(webui, HOOKS)
    env, _ = _hooks_environment(root)
    panel = env.ancestor(lambda el: "panel" in el.classes())
    assert panel is not None, "Hooks help is not inside a panel"
    loose = [
        text.strip()
        for el in [panel, *panel.iter()]
        for text in el.children
        if isinstance(text, str)
        and _FILE_LITERAL.search(text)
        and el.tag != "code"
        and el.ancestor(lambda node: node.tag == "code") is None
    ]
    assert loose == [], f"file patterns outside <code>: {loose!r}"


@pytest.mark.ui_render
def test_hooks_help_names_real_controls(webui: WebUI) -> None:
    """Bold references in the Hooks help equal the labels the Edit Hooks tab, Sync and Update pages render."""
    edit_hooks = _tab(webui, HOOKS, 1, lambda href: href.endswith(EDIT_HOOKS))
    sync_tab = _tab(webui, HOOKS, 0, lambda href: href.endswith(SYNC))
    sync = _get(webui, SYNC)
    scope = _named(sync, "select", "syncscope")
    scope_label = _label_of(_group_of(scope))
    all_settings = _one_label([o.text() for o in scope.elements() if o.attrs.get("value") == "all"], "'all' option")

    update = _get(webui, UPDATE)
    force_radios = update.find(lambda el: el.tag == "input" and el.attrs.get("name") == "pfb_force_mode")
    assert force_radios, "Update page renders no Force radios"
    update_labels = {_named(update, "button", "run").text(), _label_of(_group_of(force_radios[0]))}
    update_labels |= {radio.parent.text() for radio in force_radios if radio.parent is not None}

    root = _get(webui, HOOKS)
    env, dls = _hooks_environment(root)
    panel = env.ancestor(lambda el: "panel" in el.classes())
    assert panel is not None, "Hooks help is not inside a panel"
    strong = set(_texts(panel, "strong"))
    for label in (edit_hooks, sync_tab, scope_label, all_settings):
        assert label in strong, f"Hooks help must name {label!r} in <strong>; bold texts: {sorted(strong)!r}"

    assert dls, "Environment help renders no <dl>"
    items = dls[0].elements()
    trigger = items[items.index(next(dt for dt in items if dt.text() == "PFB_TRIGGER")) + 1]
    refs = set(_texts(trigger, "strong"))
    assert refs, "PFB_TRIGGER help names no Update control"
    assert refs <= update_labels, (
        f"PFB_TRIGGER names {sorted(refs - update_labels)!r}; Update renders {sorted(update_labels)!r}"
    )


@pytest.mark.ui_render
def test_edit_hooks_status_names_script_and_picker_label(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The loaded-script line shows the file as code and Pre/Post as the picker labels it."""
    name = helpers.install_hook_script(smoke_vm, f"hook_pre_pfb2918b_{uuid.uuid4().hex[:8]}.sh", "#!/bin/sh\nexit 0\n")
    try:
        root = _get(webui, f"{EDIT_HOOKS}?when=pre&script={name}")
        table = _one(root.find(lambda el: el.attrs.get("data-pfb-hook-table") == "pre"), "Pre picker table")
        pre_label = _label_of(_group_of(table))
        status = _row(root, "Now editing")
        assert _texts(status, "code") == [name], f"status must show the file as code: {status.text()!r}"
        assert _texts(status, "strong") == [pre_label], f"status must name {pre_label!r}: {status.text()!r}"
    finally:
        removed = smoke_vm.ssh("/bin/rm", "-f", f"{helpers.HOOK_SCRIPT_DIR}/{name}")
        assert removed.returncode == 0, f"could not remove {name}: {removed.stderr.strip()}"


@pytest.mark.ui_render
def test_update_schedule_row_uses_dnsbl_category_tab_name(webui: WebUI) -> None:
    """The Schedule row for the category job carries the DNSBL Category tab's own name."""
    category = _tab(webui, DNS, 1, lambda href: href.endswith(BLACKLIST))
    root = _get(webui, UPDATE)
    panel = _one(
        root.find(
            lambda el: (
                "panel" in el.classes()
                and any(
                    "panel-title" in h.classes() and h.text() == "Schedule"
                    for h in el.find(lambda node: node.tag == "h2")
                )
            )
        ),
        "Schedule panel",
    )
    rows = [_label_of(group) for group in panel.find(lambda el: "form-group" in el.classes())]
    assert category in rows, f"Schedule rows {rows!r} lack the {category!r} tab name"


@pytest.mark.ui_render
def test_alerts_filter_help_is_paragraph_and_example_list(webui: WebUI) -> None:
    """Filter instructions are a paragraph plus a list of example patterns, not headings."""
    root = _get(webui, ALERTS)
    infoblock = _one(
        root.find(
            lambda el: (
                "infoblock" in el.classes()
                and any(
                    a.attrs.get("href", "").startswith("https://regexr.com")
                    for a in el.find(lambda node: node.tag == "a")
                )
            )
        ),
        "filter help infoblock",
    )
    assert infoblock.find(lambda el: el.tag in {"h1", "h2", "h3", "h4", "h5", "h6"}) == [], (
        f"filter help uses headings for instructions: {infoblock.text()!r}"
    )
    assert infoblock.find(lambda el: el.tag == "p"), "filter help has no paragraph"
    _assert_definition_list(_one(infoblock.find(lambda el: el.tag == "dl"), "example <dl>"), "Alerts filter help")
    _assert_no_paragraph_wraps_a_block(infoblock, "Alerts filter help")
    apply_label = _named(root, "button", "filterlogentries_submit").text()
    assert apply_label in _texts(_group_of(infoblock), "strong"), f"filter row must name {apply_label!r} in <strong>"


@pytest.mark.ui_render
def test_alerts_auto_refresh_caption_matches_its_title(webui: WebUI) -> None:
    """The Auto-Refresh checkbox caption spells the control as its own tooltip does."""
    box = _named(_get(webui, ALERTS), "input", "alertrefresh")
    quoted = re.findall(r"'([^']+)'", box.attrs.get("title", ""))
    column = box.ancestor(lambda el: el.tag == "div" and bool(el.find(lambda node: "help-block" in node.classes())))
    assert column is not None, "Auto-Refresh checkbox renders no caption"
    caption = column.find(lambda el: "help-block" in el.classes())[0].text()
    assert caption in quoted, f"caption {caption!r} must equal the name quoted in its title {quoted!r}"


@pytest.mark.ui_render
def test_software_check_failure_names_its_button(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The failed-check notice names the Check now button by its rendered label."""
    with software_panel_forced(smoke_vm, "on"):
        root = _get(webui, f"{SOFTWARE}?check=failed")
    label = _named(root, "button", "pfb_sw_check").text()
    notices = root.find(lambda el: "alert" in el.classes())
    bold = {text for notice in notices for text in _texts(notice, "strong")}
    assert label in bold, f"failure notice must name {label!r} in <strong>; notices: {[n.text() for n in notices]!r}"


@pytest.mark.ui_render
def test_log_safesearch_option_matches_its_tab(webui: WebUI) -> None:
    """The Logs entry for SafeSearch files uses the DNSBL SafeSearch tab's own name."""
    tab = _tab(webui, DNS, 1, lambda href: href.endswith(SAFESEARCH))
    select = _named(_get(webui, LOG), "select", "logtype")
    option = _one_label(
        [o.text() for o in select.elements() if o.attrs.get("value") == "dnsbl_safe"], "dnsbl_safe option"
    )
    assert option == tab, f"Logs option {option!r} must equal the tab name {tab!r}"


@pytest.mark.ui_render
def test_widget_native_titles_name_real_tabs(webui: WebUI) -> None:
    """Widget link titles are plain text that quote the Reports and Logs tab names exactly."""
    reports = _tab(webui, f"{ALERTS}?view=unified", 0, lambda href: ALERTS in href)
    unified = _tab(webui, f"{ALERTS}?view=unified", 1, lambda href: href.endswith("view=unified"))
    alerts = _tab(webui, f"{ALERTS}?view=unified", 1, lambda href: href.endswith(ALERTS))
    logs = _tab(webui, f"{ALERTS}?view=unified", 0, lambda href: href.endswith(LOG))

    root = _get(webui, DASHBOARD)
    links = root.find(lambda el: el.tag == "a")
    heading = [
        span.attrs["title"]
        for a in links
        if "pfblockerng_alerts.php?view=unified" in a.attrs.get("href", "")
        for span in a.find(lambda el: "title" in el.attrs)
    ]
    expected = {
        _one_label(heading, "widget heading title"): [reports, unified],
        _one_label(
            [a.attrs.get("title", "") for a in links if a.attrs.get("href") == "pfblockerng/pfblockerng_log.php"],
            "widget Logs link title",
        ): [logs],
    }
    for a in links:
        if re.search(r"pfblockerng_alerts\.php\?filter(?:ip|dnsbl)=", a.attrs.get("href", "")):
            expected[a.attrs.get("title", "")] = [reports, alerts]
    for title, names in expected.items():
        assert "<" not in title, f"native title carries markup: {title!r}"
        assert re.findall(r'"([^"]+)"', title) == names, f"title {title!r} must quote {names!r}"


# --------------------------------------------------------------------------- Tier B: browser


@pytest.mark.ui_browser
def test_widget_clear_dialog_warns_with_button_names(browser_page: Page, webui: WebUI) -> None:
    """The Clear Packets dialog is two paragraphs; its warning names real buttons; Cancel clears nothing."""
    sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
    page = browser_page
    _open(page, webui, DASHBOARD)
    dialogs = page.locator(".ui-dialog:visible")
    assert dialogs.count() == 0, "a dialog is open before the clear icon is clicked"
    page.locator("#pfblockerngclearicon").click()
    dialog = dialogs.last
    sync_api.expect(dialog).to_be_visible(timeout=JS_TIMEOUT_MS)

    info = dialog.evaluate(
        """(d) => {
          const content = d.querySelector('.ui-dialog-content');
          const strong = Array.from(content.querySelectorAll('p strong'));
          return {
            paragraphs: content.querySelectorAll('p').length,
            warnings: content.querySelectorAll('p .text-danger strong').length,
            refs: strong.filter((s) => !s.closest('.text-danger')).map((s) => s.textContent.trim()),
            buttons: Array.from(d.querySelectorAll('.ui-dialog-buttonpane button')).map((b) => b.textContent.trim()),
          };
        }"""
    )
    assert info["paragraphs"] == 2, f"dialog body must be two paragraphs: {info!r}"
    assert info["warnings"] == 1, f"dialog must carry one marked warning: {info!r}"
    assert info["refs"], f"warning names no button: {info!r}"
    assert set(info["refs"]) <= set(info["buttons"]), f"warning names {info['refs']!r}; buttons are {info['buttons']!r}"

    url = page.url
    dialog.locator(".ui-dialog-buttonpane button", has_text="Cancel").click()
    sync_api.expect(dialog).to_be_hidden(timeout=JS_TIMEOUT_MS)
    assert page.url == url, f"Cancel navigated away: {page.url!r}"
    armed = page.evaluate(
        "() => ['pfblockerngclearall', 'pfblockerngclearip', 'pfblockerngcleardnsbl']"
        ".filter((id) => (document.getElementById(id) || {}).value === 'true')"
    )
    assert armed == [], f"Cancel armed a clear action: {armed!r}"


@pytest.mark.ui_browser
@pytest.mark.parametrize(("label", "viewport"), [("phone", PHONE), ("desktop", DESKTOP)])
def test_hooks_environment_lists_fit_the_viewport(
    browser_page: Page, webui: WebUI, label: str, viewport: ViewportSize
) -> None:
    """Every hook variable name and description stays whole and inside the viewport."""
    page = browser_page
    page.set_viewport_size(viewport)
    _open(page, webui, HOOKS)
    metrics = page.evaluate(
        """() => {
          const label = Array.from(document.querySelectorAll('.form-group > label'))
            .find((l) => l.textContent.trim() === 'Environment');
          if (!label) return null;
          const group = label.closest('.form-group');
          const width = document.documentElement.clientWidth;
          const items = Array.from(group.querySelectorAll('dl > dt, dl > dd'));
          return {
            lists: group.querySelectorAll('dl').length,
            clipped: items.filter((e) => e.scrollWidth > e.clientWidth + 1).map((e) => e.textContent.trim()),
            outside: items.filter((e) => e.getBoundingClientRect().right > width + 1).map((e) => e.textContent.trim()),
            groupOverflow: group.scrollWidth - group.clientWidth,
          };
        }"""
    )
    assert metrics is not None, "Hooks page renders no Environment row"
    assert metrics["lists"] == 2, f"[{label}] Environment must render two lists: {metrics!r}"
    assert metrics["clipped"] == [], f"[{label}] clipped entries: {metrics['clipped']!r}"
    assert metrics["outside"] == [], f"[{label}] entries past the viewport: {metrics['outside']!r}"
    assert metrics["groupOverflow"] <= 1, f"[{label}] Environment row scrolls sideways: {metrics!r}"
