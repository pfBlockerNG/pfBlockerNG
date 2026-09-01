"""Tier-B browser test (ADR-16 Phase 5): the Feeds IPv4/IPv6/DNSBL sub-tabs.

The visual replacement for the OLD maintainer manual smoke (ADR-16 §7): instead of
a human eyeballing the split Feeds page, a headless Chromium on the live ADR-04
smoke VM opens ``pfblockerng_feeds.php?type=ipv4|ipv6|dnsbl`` (reusing the Phase-1
authenticated session — the injected ``PHPSESSID`` cookie, no second login) and
asserts, per type:

* the SECOND sub-tab row ``[IPv4 | IPv6 | DNSBL]`` is present (all three sub-tab
  anchors, pointing at ``pfblockerng_feeds.php?type=...``), and
* the requested type's sub-tab is the ACTIVE one (its ``<li>`` carries pfSense's
  ``active`` class — emitted by ``display_top_tabs`` for the highlighted tab), and
* the page lists ONLY that type's feeds — proven by the type-scoped Feed Settings
  alias-name label (``IPv4/IPv6/DNSBL Alias name(s):``), which ``pfblockerng_feeds.php``
  renders for the ACTIVE type only (``pfb_feeds_render_aliasname_inputs($gtype)``,
  Phase 3) — so the other two types' labels are ABSENT from this tab's DOM, and

a per-tab full-page screenshot is written to the ``screenshot_dir`` artifact tree
(the visual record for review — an artifact, not an asserted baseline).

The split is the only ``src/`` change in ADR-16 (Phase 3); this test is the
``ui_browser`` half of its affected-flow coverage (the Tier-A render oracle —
``test_render_smoke.py`` ``feeds_ipv4``/``feeds_ipv6``/``feeds_dnsbl`` — is the
cheap/hermetic half). No ``src/`` change here.

DOM-FRAGILITY NOTE: ``display_top_tabs`` renders pfSense's standard ``nav-pills``
list; the load-bearing, version-tolerant handles are the anchor ``href`` (carries
``?type=``) and the ``active`` class on the highlighted ``<li>`` — NOT a brittle
DOM path. An ``href*="?type="`` match alone is NOT unique, though: by ADR-16 A4 the
main top bar's own "Feeds" tab AND the breadcrumb also carry ``?type=<active>``, so
the active type's query string appears in THREE anchors. The sub-tab row is the only
``<ul class="nav …">`` that contains ALL THREE type anchors at once — so we locate
that row first (``_subtab_nav``) and scope the presence/active assertions to it. The
Feed Settings section is ``COLLAPSIBLE|SEC_CLOSED`` (collapsed on load), so its
alias-name label is in the DOM but not visible — we assert DOM PRESENCE (``count()``),
not visibility, for the per-type label.

NO fixed sleeps: every assertion uses Playwright auto-waiting / ``count()`` after
``networkidle``. Playwright is imported lazily via ``pytest.importorskip`` so
collecting this module without it installed does not hard-error.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The Feeds page, split into ?type sub-tabs (ADR-16 Phase 3). The base path the three
# sub-tab anchors all point at (with a distinct ?type query each).
FEEDS_BASE = "/pfblockerng/pfblockerng_feeds.php"

# The three sub-tab types + the per-type Feed Settings alias-name label that renders
# for the ACTIVE type only (the type-scoped body) -- the "lists only its type" signal.
TYPE_LABELS = {
    "ipv4": "IPv4 Alias name(s):",
    "ipv6": "IPv6 Alias name(s):",
    "dnsbl": "DNSBL Alias name(s):",
}

# A short, explicit timeout (ms): the page renders server-side, so this is a flake
# ceiling for the post-load DOM, not a wait knob.
JS_TIMEOUT_MS = 10_000


def _rgb(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*[\d.]+)?\)", value)
    assert match is not None, f"expected computed rgb/rgba colour, got {value!r}"
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _relative_luminance(rgb: tuple[int, int, int]) -> float:
    channels = [channel / 255 for channel in rgb]
    linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_ratio(first: str, second: str) -> float:
    lighter, darker = sorted((_relative_luminance(_rgb(first)), _relative_luminance(_rgb(second))), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the (cookie-authenticated) page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form -- proving the injected
    session cookie authenticated the browser (no second login). Waits on
    ``networkidle`` so the page is fully rendered before any assertion.
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    # The login form carries #usernamefld; its absence proves we are authed.
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``.

    Value-redacts the Plus VM identity from the DOM first (ADR-24 ``mask_page_identity``);
    a strict no-op on a CE leg (empty redaction set), so CE shots are unchanged.
    """
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _subtab_nav(page: Page) -> Locator:
    """The SECOND ``display_top_tabs`` row -- the ``[IPv4 | IPv6 | DNSBL]`` sub-tab ``<ul>``.

    ``display_top_tabs`` renders every tab row as ``<ul class="nav nav-…">``; the page
    has TWO (the main top bar + this sub-tab row), and -- since ADR-16 A4 -- the main
    bar's own "Feeds" tab AND the breadcrumb also carry ``?type=<active>``. So a bare
    ``href*="?type="`` match is NOT unique (three hits for the active type). The sub-tab
    row is the ONLY nav that contains ALL THREE type anchors at once; filter on that.
    Version-tolerant (works for ``nav-pills`` or ``nav-tabs``, independent of the
    surrounding markup).
    """
    nav = page.locator("ul.nav")
    for t in ("ipv4", "ipv6", "dnsbl"):
        nav = nav.filter(has=page.locator(f'a[href*="{FEEDS_BASE}?type={t}"]'))
    return nav


def _subtab_anchor(nav: Locator, gtype: str) -> Locator:
    """The ``?type=<gtype>`` anchor WITHIN the sub-tab row ``nav`` (scoped, so unique)."""
    return nav.locator(f'a[href*="{FEEDS_BASE}?type={gtype}"]')


@pytest.mark.parametrize("gtype", ["ipv4", "ipv6", "dnsbl"])
def test_feeds_subtab_row_active_and_type_scoped(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
    gtype: str,
) -> None:
    """Each ``?type`` Feeds tab shows the [IPv4|IPv6|DNSBL] row, highlights itself,
    and lists ONLY its own type.

    Scenario (one parametrization per type -- all three sub-tabs are exercised, so
    this is full branch coverage of the ``?type`` switch, not just one tab):

    Given the Feeds page opened at ``?type=<gtype>``,
    Then all THREE sub-tab anchors (``?type=ipv4|ipv6|dnsbl``) are present (the second
      ``[IPv4 | IPv6 | DNSBL]`` row rendered),
    And the requested type's sub-tab is the ACTIVE one (its ``<li>`` carries the
      ``active`` class ``display_top_tabs`` puts on the highlighted tab) while the
      other two are NOT active -- so the highlight tracks ``?type`` (a real branch,
      not an always-active tab),
    And the page's Feed Settings shows the ``<gtype>`` alias-name label and NEITHER of
      the other two types' labels -- proving the body lists only the active type
      (the type-scoped render, ADR-16 Phase 3).
    A per-tab screenshot is written for the visual record (the manual-smoke replacement).
    """
    page = browser_page
    _open(page, webui, f"{FEEDS_BASE}?type={gtype}")

    # The second sub-tab row exists exactly once -- the only nav carrying all three
    # type anchors (A4 makes the top "Feeds" tab + the breadcrumb also carry ?type, so
    # a bare href match is not unique; scope to the sub-tab <ul>).
    nav = _subtab_nav(page)
    expect(nav).to_have_count(1, timeout=JS_TIMEOUT_MS)
    for t in ("ipv4", "ipv6", "dnsbl"):
        expect(_subtab_anchor(nav, t)).to_have_count(1, timeout=JS_TIMEOUT_MS)

    # The requested type's sub-tab is ACTIVE; the other two are not. pfSense's
    # display_top_tabs puts the `active` class on the highlighted tab's <li> (the
    # anchor's parent). Assert via the ancestor <li>'s class -- the version-tolerant
    # handle (the <li> wraps the <a>) -- scoped to the sub-tab row so the A4 self-links
    # in the top bar/breadcrumb don't confuse the match.
    active_li = _subtab_anchor(nav, gtype).locator("xpath=ancestor::li[1]")
    expect(active_li).to_have_class(re.compile(r"\bactive\b"), timeout=JS_TIMEOUT_MS)
    for other in (t for t in ("ipv4", "ipv6", "dnsbl") if t != gtype):
        other_li = _subtab_anchor(nav, other).locator("xpath=ancestor::li[1]")
        expect(other_li).not_to_have_class(re.compile(r"\bactive\b"), timeout=JS_TIMEOUT_MS)

    # The body lists ONLY this type: its Feed Settings alias-name label is in the DOM
    # (the section is COLLAPSIBLE|SEC_CLOSED, so present-but-collapsed -> assert
    # PRESENCE, not visibility), and the other two types' labels are ABSENT.
    own_label = page.get_by_text(TYPE_LABELS[gtype], exact=False)
    assert own_label.count() >= 1, f"{gtype} tab missing its own '{TYPE_LABELS[gtype]}' label (type-scoped body)"
    for other, label in TYPE_LABELS.items():
        if other == gtype:
            continue
        assert page.get_by_text(label, exact=False).count() == 0, (
            f"{gtype} tab wrongly shows the {other} label '{label}' -- the body is not type-scoped"
        )

    _shot(page, screenshot_dir, f"feeds_subtab_{gtype}")


# The dark theme is a per-box setting, not a property of the Feeds page: the browser
# fixture leaves whatever theme the box already carries (a fresh box is light), so the
# contrast probe below selects the theme it needs and puts the previous value back.
_THEME_CFG = "system/webgui/webguicss"
_DARK_THEME = "pfSense-dark.css"

# Four earlier ui_browser runs (33531836648, 33533391281, 33534796353, 33552741857) are NOT
# evidence about this change: ui-tests.yml's checkout_ref input governs only the test-code
# checkout, while the package under test is built from the workflow ref, and those runs were
# dispatched against devel. They installed a devel package -- without this page's changes --
# and ran this PR's tests against it, which is why an anchor read rgb(0, 150, 136) both
# before and after a production edit. The durable proof is the PR-triggered labeled ui-tests
# run, which builds the package from the PR merge ref.
# The split stands on its own: tests/php/FeedsPaintedRowLinkContrastTest.php owns the
# source-side proof (both row paths paint inline, and the page-local rules are scoped by that
# inline background), and this row owns what PHP cannot see -- the real cascade under the
# shipped pfSense-dark.css, over every genuine painted row the box happens to render plus one
# synthetic row per production background so all four are always measured. The synthetic rows
# carry only the inline background and text production emits, so they cannot pass by a route
# the live page lacks. No config list is mutated.
_PAINTED_BACKGROUNDS = ("#F5FBF6", "#EEF7EE", "#A0B8A0", "#B8B8B8")
_PROBE_HREF = "https://example.invalid/pfb3035-contrast-probe.txt"

# Anchors inside any inline-painted row of either Feeds table -- the production selector shape.
_PAINTED_ANCHORS = '#pfb_table tr[style*="background-color"] a, #pfb_table2 tr[style*="background-color"] a'

# One probe row per production background, appended to the real table#pfb_table tbody. The row
# carries ONLY what production emits inline (background + #212121 text) and one anchor: no
# class, so it cannot pass by a route the live page does not have.
_APPEND_PROBE_ROWS_JS = """
    ([backgrounds, href]) => {
      const body = document.querySelector('table#pfb_table tbody');
      if (!body) { return 0; }
      backgrounds.forEach((hex, index) => {
        const row = document.createElement('tr');
        row.setAttribute('style', 'background-color: ' + hex + '; color: #212121;');
        row.setAttribute('data-pfb-contrast-probe', hex);
        const cell = document.createElement('td');
        const anchor = document.createElement('a');
        anchor.setAttribute('href', href);
        anchor.textContent = 'contrast probe ' + index;
        cell.appendChild(anchor);
        row.appendChild(cell);
        body.appendChild(row);
      });
      return body.querySelectorAll('tr[data-pfb-contrast-probe]').length;
    }
"""

# Each painted row's anchor colour and its own row background, as the page resolves them.
_MEASURE_ANCHORS_JS = """
    anchors => anchors.map(anchor => ({
      color: getComputedStyle(anchor).color,
      background: getComputedStyle(anchor.closest('tr')).backgroundColor,
    }))
"""


def _hex_rgb_css(value: str) -> str:
    """``#RRGGBB`` in the ``rgb(r, g, b)`` form ``getComputedStyle`` reports."""
    red, green, blue = (int(value[index : index + 2], 16) for index in (1, 3, 5))
    return f"rgb({red}, {green}, {blue})"


def test_painted_feed_rows_scope_legible_link_foregrounds(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Painted Feeds rows override the dark theme's low-contrast anchor palette only where needed.

    Scenario:
      Given the box is switched to the real ``pfSense-dark.css`` theme (the theme whose
        explicit anchor palette overrides the row's inherited ``color: #212121``),
      And every genuine row the box painted inline is graded directly, then one probe row per
        production background is appended to the real Feeds table carrying only what
        production emits inline (background + ``#212121`` text) and one anchor, so all four
        backgrounds are measured even on a box that paints no row of its own,
      When the page's own stylesheet resolves those rows,
      Then every anchor inside an inline-painted row computes to the scoped ``#004D40`` and
        clears 4.5:1 against its own computed row background, all four production backgrounds
        are measured, and hover/focus computes to the scoped ``#003D33``.
      Finally the box's prior theme is restored exactly, including absence.
    """
    page = browser_page

    # Only the read-only snapshot happens before the try: every statement that can leave the
    # shared box on the dark theme -- the write itself and each assertion after it -- sits
    # inside the try, so the finally restore always runs.
    prior_theme = helpers.config_get_state(smoke_vm, _THEME_CFG)

    try:
        applied = helpers.php_eval(
            smoke_vm,
            f"config_set_path({helpers._php_str(_THEME_CFG)}, {helpers._php_str(_DARK_THEME)});\n"
            "write_config('pfBlockerNG smoke #3035: select the dark theme for the Feeds contrast probe');\n"
            "echo 'THEME-OK';",
        )
        assert applied.returncode == 0 and "THEME-OK" in applied.stdout, (
            f"failed to select {_DARK_THEME}: rc={applied.returncode} "
            f"stdout={applied.stdout!r} stderr={applied.stderr!r}"
        )

        stored = helpers.config_get(smoke_vm, _THEME_CFG)
        assert stored == _DARK_THEME, f"{_THEME_CFG} is {stored!r} after the switch, expected {_DARK_THEME!r}"

        _open(page, webui, f"{FEEDS_BASE}?type=ipv4")

        assert page.locator('link[rel="stylesheet"][href*="pfSense-dark.css"]').count() >= 1, (
            "the contrast proof must run against the real pfSense dark theme, but the page loaded no "
            f"pfSense-dark.css stylesheet even though {_THEME_CFG} is {_DARK_THEME!r} -- a per-user "
            "theme override outranks the system key"
        )

        real_styles = page.locator(_PAINTED_ANCHORS).evaluate_all(_MEASURE_ANCHORS_JS)
        for style in real_styles:
            assert style["color"] == "rgb(0, 77, 64)", (
                f"an anchor in a row the page itself painted computes {style['color']} "
                f"instead of the scoped rgb(0, 77, 64): {style}"
            )
            ratio = _contrast_ratio(style["color"], style["background"])
            assert ratio >= 4.5, f"real painted-row link contrast is {ratio:.3f}:1 for {style}"

        injected = page.evaluate(_APPEND_PROBE_ROWS_JS, [list(_PAINTED_BACKGROUNDS), _PROBE_HREF])
        assert injected == len(_PAINTED_BACKGROUNDS), (
            f"the probe rows were not appended to the real Feeds table (table#pfb_table tbody): attached {injected!r}"
        )

        links = page.locator(_PAINTED_ANCHORS)
        assert links.count() >= len(_PAINTED_BACKGROUNDS), (
            f"expected at least the {len(_PAINTED_BACKGROUNDS)} probe anchors, found {links.count()}"
        )
        computed = links.evaluate_all(_MEASURE_ANCHORS_JS)
        measured_backgrounds = {style["background"] for style in computed}
        for background in _PAINTED_BACKGROUNDS:
            assert _hex_rgb_css(background) in measured_backgrounds, (
                f"no measured painted row carried {background}; measured {sorted(measured_backgrounds)}"
            )
        for style in computed:
            assert style["color"] == "rgb(0, 77, 64)", style
            ratio = _contrast_ratio(style["color"], style["background"])
            assert ratio >= 4.5, f"painted-row link contrast is {ratio:.3f}:1 for {style}"

        first = links.first
        first.hover()
        expect(first).to_have_css("color", "rgb(0, 61, 51)", timeout=JS_TIMEOUT_MS)
        page.mouse.move(0, 0)
        first.focus()
        expect(first).to_have_css("color", "rgb(0, 61, 51)", timeout=JS_TIMEOUT_MS)
    finally:
        helpers.config_restore_state(smoke_vm, _THEME_CFG, prior_theme)
        restored_theme = helpers.config_get_state(smoke_vm, _THEME_CFG)
        assert restored_theme == prior_theme, f"{_THEME_CFG} restored as {restored_theme!r}, expected {prior_theme!r}"
