"""Tier-A ``ui_render`` coverage for the #2918 help-text sweep, owned slice: the
category, DNSBL Category and Feeds catalogue pages.

Every assertion reads the RENDERED HTML the box serves, never source, and pins
structure rather than prose:

- a control named in an explanatory callout is a ``<strong>`` element with the
  control's exact visible label, so it is distinguishable from ordinary prose;
- every paragraph in the apply callouts opens and closes once;
- the Feeds management panel and feed table are well-formed: no crossed, stray or
  unclosed tags, no block element inside a paragraph, and instructions are a real
  list rather than a hand-bulleted ``&#8226;`` run;
- native ``title`` tooltips carry plain text, never markup;
- a feed status icon names the status it reports (``discontinued`` or
  ``suspended``), not a generic "temporarily unavailable".

Discontinued feeds are removed from the picker, so their unused tooltip text is
not part of this rendered-page coverage. This module is read-only and writes no
config.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

CATEGORY_IPV4 = "/pfblockerng/pfblockerng_category.php?type=ipv4"
CATEGORY_DNSBL = "/pfblockerng/pfblockerng_category.php?type=dnsbl"
CATEGORY_GEOIP = "/pfblockerng/pfblockerng_category.php?type=geoip"
BLACKLIST = "/pfblockerng/pfblockerng_blacklist.php"
FEEDS_IPV4 = "/pfblockerng/pfblockerng_feeds.php?type=ipv4"
FEEDS_IPV6 = "/pfblockerng/pfblockerng_feeds.php?type=ipv6"
FEEDS_DNSBL = "/pfblockerng/pfblockerng_feeds.php?type=dnsbl"
FEEDS_PAGES = (FEEDS_IPV4, FEEDS_IPV6, FEEDS_DNSBL)
CALLOUT_PAGES = (CATEGORY_IPV4, CATEGORY_DNSBL, CATEGORY_GEOIP, BLACKLIST)
TITLE_PAGES = CALLOUT_PAGES + FEEDS_PAGES
MARKERS = ("pfBlockerNG",)

# Tags whose nesting the structure check tracks. Table, row and cell markup is left
# out on purpose: pfSense chrome owns it, and the feed rows are checked through the
# paragraph and inline tags they contain.
_TRACKED = frozenset({"a", "dd", "dl", "dt", "div", "li", "ol", "p", "small", "span", "strong", "u", "ul"})
_VOID = frozenset({"br", "hr", "img", "input", "link", "meta"})
_BLOCK_IN_P = frozenset({"dl", "div", "ol", "p", "ul"})


class _NestingChecker(HTMLParser):
    """Records crossed, stray, unclosed and block-in-paragraph tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.open: list[str] = []
        self.problems: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:  # noqa: ARG002
        if tag not in _TRACKED or tag in _VOID:
            return
        if tag in _BLOCK_IN_P and "p" in self.open:
            self.problems.append(f"<{tag}> opened inside an open <p>")
        self.open.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag not in _TRACKED:
            return
        if tag not in self.open:
            self.problems.append(f"stray </{tag}>")
            return
        while self.open[-1] != tag:
            self.problems.append(f"</{tag}> closes over unclosed <{self.open.pop()}>")
        self.open.pop()


def _nesting_problems(fragment: str) -> list[str]:
    checker = _NestingChecker()
    checker.feed(fragment)
    checker.close()
    return checker.problems + [f"unclosed <{tag}>" for tag in checker.open]


def _page(webui: WebUI, path: str) -> str:
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, MARKERS)
    assert result.ok, f"Tier-A render oracle failed for {path}: {result.detail}"
    return resp.text


@pytest.fixture
def php_guard(smoke_vm: SmokeVM) -> Iterator[PhpErrorLogGuard]:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    yield guard
    guard.assert_no_growth()


@pytest.mark.parametrize(
    ("path", "labels"),
    [
        (CATEGORY_IPV4, ("Run Now", "Update")),
        (CATEGORY_GEOIP, ("Run Now", "Update")),
        (CATEGORY_DNSBL, ("Run Now", "Update", "Group Order")),
        (BLACKLIST, ("Run Now", "Update", "Group Order")),
    ],
)
def test_apply_callout_names_controls_as_strong_references(
    webui: WebUI, php_guard: PhpErrorLogGuard, path: str, labels: tuple[str, ...]
) -> None:
    """Controls named in the apply callout are <strong> elements with their exact label."""
    html = _page(webui, path)
    for label in labels:
        assert f"<strong>{label}</strong>" in html, f"{path}: control {label!r} must render as <strong>{label}</strong>"


@pytest.mark.parametrize("path", CALLOUT_PAGES)
def test_callout_paragraphs_open_and_close_once(webui: WebUI, php_guard: PhpErrorLogGuard, path: str) -> None:
    """A stray closing paragraph tag in a callout leaves the paragraph count unequal."""
    html = _page(webui, path)
    opened = len(re.findall(r"<p[\s>]", html))
    closed = html.count("</p>")
    assert opened == closed, f"{path}: {opened} <p> opened but {closed} </p> closed (stray or unclosed paragraph)"


@pytest.mark.parametrize("path", TITLE_PAGES)
def test_native_titles_carry_plain_text(webui: WebUI, php_guard: PhpErrorLogGuard, path: str) -> None:
    """A native title attribute is plain text: markup there is shown literally or breaks the attribute."""
    html = _page(webui, path)
    markup = [title for title in re.findall(r'title="([^"]*)"', html) if re.search(r"[<>]", title)]
    assert markup == [], f"{path}: native title attributes carry markup: {markup[:3]}"


def test_blacklist_mode_select_uses_the_category_mode_label(webui: WebUI, php_guard: PhpErrorLogGuard) -> None:
    """The DNSBL Category mode select carries the same label as the category pages."""
    html = _page(webui, BLACKLIST)
    assert re.search(r">\s*Logging/Blocking Mode\s*<", html), (
        "the DNSBL Category mode select must be labelled 'Logging/Blocking Mode'"
    )
    assert not re.search(r">\s*Logging\s*<", html), (
        "the bare label 'Logging' is still rendered on the DNSBL Category page"
    )


@pytest.mark.parametrize("path", (FEEDS_IPV4, FEEDS_DNSBL))
def test_feeds_management_panel_is_well_formed_and_listed(webui: WebUI, php_guard: PhpErrorLogGuard, path: str) -> None:
    """The management instructions are a well-formed list that names the Feeds tab."""
    html = _page(webui, path)
    end = html.find('id="pfb_table"')
    assert end != -1, f"{path}: feed table anchor missing (fixture gap)"
    start = html.rfind('class="panel panel-default"', 0, end)
    assert start != -1, f"{path}: feeds management panel missing (fixture gap)"
    panel = html[start:end]

    problems = _nesting_problems(panel)
    assert problems == [], f"{path}: feeds management panel markup: {problems}"
    assert "&#8226;" not in panel, f"{path}: instructions are hand-bulleted with &#8226; instead of a list"
    assert re.search(r"<ul[\s>]", panel) and re.search(r"<li[\s>]", panel), (
        f"{path}: management instructions must be a <ul> list"
    )
    assert "<strong>Feeds</strong>" in panel, f"{path}: the Feeds tab must render as <strong>Feeds</strong>"


@pytest.mark.parametrize("path", FEEDS_PAGES)
def test_feed_table_markup_is_well_formed(webui: WebUI, php_guard: PhpErrorLogGuard, path: str) -> None:
    """Every feed row closes its paragraphs; a second row cannot open inside an unclosed one."""
    html = _page(webui, path)
    start = html.find('<table id="pfb_table"')
    assert start != -1, f"{path}: feed table missing (fixture gap)"
    end = html.find("</table>", start)
    assert end != -1, f"{path}: feed table not closed"
    problems = _nesting_problems(html[start:end])
    assert problems == [], f"{path}: feed table markup: {problems}"


def test_status_icons_name_the_status(webui: WebUI, php_guard: PhpErrorLogGuard) -> None:
    """A feed status icon reports its status value, not a generic unavailable message."""
    titles: list[str] = []
    for path in FEEDS_PAGES:
        titles += re.findall(r'<i class="fa-solid fa-bug[^"]*" title="([^"]*)"', _page(webui, path))
    assert titles, (
        "no status icon on any feeds page: the suspended feed must render, so this is a fixture gap, not a pass"
    )
    wrong = [title for title in titles if not re.fullmatch(r"Feed (discontinued|suspended)", title)]
    assert wrong == [], f"status icon titles must name the status value, got {wrong}"


def test_status_legend_covers_both_statuses(webui: WebUI, php_guard: PhpErrorLogGuard) -> None:
    """The legend entry for the status icon names both statuses it can report."""
    html = _page(webui, FEEDS_IPV4)
    match = re.search(r'fa-bug"></i></span></dt>\s*<dd>(.*?)</dd>', html, re.DOTALL)
    assert match is not None, "status legend row missing (fixture gap)"
    legend = match.group(1).lower()
    assert "discontinued" in legend and "suspended" in legend, (
        f"the status legend must name both statuses, got {match.group(1)!r}"
    )
