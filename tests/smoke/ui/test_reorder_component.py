"""ADR-63 Phase 2: the shared drag+anchor-click reorder component, proven standalone.

``pfb_reorder_init()``/``pfb_reorder_read_order()`` (``pfBlockerNG.js``) are
PRODUCTION-DORMANT -- no page calls them yet (Phase 3 wires ``category.php``,
Phase 4 ``category_edit.php``). This module proves the component's own contract
(drag, anchor-click before/shift-after, multi-row straddle, the order-read
helper's ``ids[]`` format) and -- ADR sec7 reject criterion 1 -- its composition
with core ``renumber()``/``add_row()``/``delete_row()`` -- against static
fixture pages served from the live VM's OWN vendor JS plus the shipped
``pfBlockerNG.js`` (fetched at the stable ``/pfblockerng/pfBlockerNG.js`` URL,
so this proves the real shipped code, not a copy).

Three fixture pages (uploaded to the webroot, removed in teardown) are kept
SEPARATE because ``pfSenseHelpers.js``'s ``renumber()``/``add_row()``/
``delete_row()`` all operate via GLOBAL ``$('.repeatable')`` selectors
(page-wide, not scoped to a container) -- confirmed by reading the real file on
the live VM: two independent repeatable clusters on ONE page would cross-talk
(``add_row()`` clones ``$('.repeatable:last')`` across the WHOLE page).

* ``FIXTURE_REPEAT`` (drag=true, 5 rows) -- scenarios a, b, c, d.
* ``FIXTURE_REPEAT_NODRAG`` (drag=false, 3 rows) -- the zero-checked/self-anchor
  hostile rows and the "no ``.sortable()`` instance" proof.
* ``FIXTURE_SORTABLE`` (``tr.sortable`` id=``pfb_rN``, 3 rows,
  ``pfb_reorder_init()`` never called) -- scenario e and the order-read
  parser's hostile-input rows.
"""

from __future__ import annotations

import re
import shlex
from typing import TYPE_CHECKING

import pytest

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")

if TYPE_CHECKING:
    from collections.abc import Iterator

    from playwright.sync_api import Locator, Page

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

JS_TIMEOUT_MS = 10_000

# The discovery page: any authenticated pfBlockerNG page loaded via foot.inc
# carries the same vendor <script src> set -- this one is already used
# elsewhere in the suite (test_post_array_scalar_guards.py), proven 200.
_DISCOVERY_PATH = "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl"
_SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+)["\']', re.IGNORECASE)

_REMOTE_REPEAT = "/pfb_reorder_fixture_repeat.html"
_REMOTE_REPEAT_NODRAG = "/pfb_reorder_fixture_repeat_nodrag.html"
_REMOTE_SORTABLE = "/pfb_reorder_fixture_sortable.html"
_ALL_REMOTE = (_REMOTE_REPEAT, _REMOTE_REPEAT_NODRAG, _REMOTE_SORTABLE)


def _discover_vendor_scripts(html: str) -> dict[str, str]:
    """Parse ``<script src=...>`` tags for jQuery/jQuery-UI/pfSenseHelpers.js.

    Never hardcodes a versioned filename (``jquery-X.Y.Z.min.js`` drifts) --
    matches by stable path prefix instead, exactly as served today.
    """
    urls = _SCRIPT_SRC_RE.findall(html)
    jquery = next((u for u in urls if "/vendor/jquery/jquery-" in u), None)
    jquery_ui = next((u for u in urls if "/vendor/jquery-ui/" in u), None)
    helpers_js = next((u for u in urls if "/js/pfSenseHelpers.js" in u), None)
    found = {"jquery": jquery, "jquery_ui": jquery_ui, "helpers": helpers_js}
    missing = [name for name, url in found.items() if url is None]
    if missing:
        raise RuntimeError(
            f"discovery page {_DISCOVERY_PATH} carried no <script src> for: {', '.join(missing)} "
            f"(found script srcs: {urls!r})"
        )
    return found  # type: ignore[return-value]


_PAGE_HEAD = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<script>var events = events || [];</script>
</head><body>
"""


def _repeatable_row_html(i: int) -> str:
    return f"""
<div class="form-group repeatable">
  <label class="col-sm-2 control-label">XXXX</label>
  <div class="col-sm-1"><sub class="pfb-gutter">{i + 1:02d}</sub></div>
  <div class="col-sm-2"><select id="format-{i}" name="format-{i}">
    <option value="auto" selected>Auto</option><option value="regex">Regex</option>
  </select></div>
  <div class="col-sm-2"><select id="state-{i}" name="state-{i}">
    <option value="Enabled" selected>Enabled</option><option value="Disabled">Disabled</option>
  </select></div>
  <div class="col-sm-4"><input type="text" id="url-{i}" name="url-{i}" value="row{i}-url"></div>
  <div class="col-sm-2"><input type="text" id="header-{i}" name="header-{i}" value="row{i}-header"></div>
  <div class="col-sm-1"><button type="button" id="deleterow{i}" class="btn btn-warning btn-xs">Delete</button></div>
</div>"""


def _fixture_repeat_html(scripts: dict[str, str], *, n_rows: int, drag_enabled: bool) -> str:
    rows = "\n".join(_repeatable_row_html(i) for i in range(n_rows))
    drag_js = "true" if drag_enabled else "false"
    return (
        _PAGE_HEAD.format(title="pfb reorder fixture (repeatable)")
        + f"""
<div id="pfb_repeat">
{rows}
</div>
<button type="button" id="addrow">Add</button>
<script src="{scripts["jquery"]}"></script>
<script src="{scripts["jquery_ui"]}"></script>
<script src="{scripts["helpers"]}"></script>
<script src="/pfblockerng/pfBlockerNG.js"></script>
<script>
window.pfbFixtureMoveCount = 0;

function pfbFixtureRefreshGutter() {{
    $('#pfb_repeat .form-group.repeatable').each(function(i) {{
        $(this).find('.pfb-gutter').text(String(i + 1).padStart(2, '0'));
    }});
}}

// Page-side glue (ADR-63 S2 Decision 4): the shared component stays minimal,
// gutter refresh + renumber() composition is this fixture's own job -- exactly
// what Phase 3/4 wiring on the real pages will do.
function pfbFixtureOnAfterMove() {{
    window.pfbFixtureMoveCount++;
    renumber();
    pfbFixtureRefreshGutter();
}}

pfb_reorder_init('#pfb_repeat', '.form-group.repeatable', pfbFixtureOnAfterMove, {drag_js});

// Delegated on the container (survives renumber()'s rewrite of #addrow's
// siblings): re-renumber after core add_row() so a same-session add with no
// prior move never leaves a stale/duplicate id (pfSenseHelpers.js's own
// bump_input_id() does not rewrite a plain <button>'s id -- only <input>/
// <select>/[id^=deleterow]).
$(document).on('click', '#addrow', function() {{
    renumber();
    pfbFixtureRefreshGutter();
    pfbFixtureBindDeleteRefresh();
}});

// NOT delegated on the container: core's delete_row() (bound directly on the
// button, fires first) REMOVES the row before the click finishes bubbling, so
// a container-delegated handler can miss it. Bind directly on each button
// instead -- same reason core itself rebinds after every clone (.clone()
// carries no handlers) -- so ours runs in the SAME dispatch pass, after core's.
function pfbFixtureBindDeleteRefresh() {{
    $('#pfb_repeat [id^=deleterow]').off('click.pfbFixtureGutter').on('click.pfbFixtureGutter', function() {{
        pfbFixtureRefreshGutter();
    }});
}}
pfbFixtureBindDeleteRefresh();

function pfbFixtureUrlOrder() {{
    return $('#pfb_repeat .form-group.repeatable input[id^=url-]').map(function() {{
        return this.value;
    }}).get();
}}

function pfbFixtureIdAudit() {{
    var n = $('#pfb_repeat .form-group.repeatable').length;
    var missing = [];
    ['format-', 'state-', 'url-', 'header-'].forEach(function(p) {{
        for (var i = 0; i < n; i++) {{
            if (!document.getElementById(p + i)) {{ missing.push(p + i); }}
        }}
    }});
    var counts = {{}};
    $('#pfb_repeat [id]').each(function() {{ counts[this.id] = (counts[this.id] || 0) + 1; }});
    var duplicates = Object.keys(counts).filter(function(k) {{ return counts[k] > 1; }});
    return {{rowCount: n, missing: missing, duplicates: duplicates}};
}}
</script>
</body></html>"""
    )


def _sortable_row_html(i: int) -> str:
    return f'<tr class="sortable" id="pfb_r{i}"><td>row{i}</td></tr>'


def _fixture_sortable_html(scripts: dict[str, str], *, n_rows: int) -> str:
    rows = "\n".join(_sortable_row_html(i) for i in range(n_rows))
    return (
        _PAGE_HEAD.format(title="pfb reorder fixture (sortable)")
        + f"""
<table id="pfb_table"><tbody id="pfb_table_body">
{rows}
</tbody></table>
<script src="{scripts["jquery"]}"></script>
<script src="{scripts["jquery_ui"]}"></script>
<script src="{scripts["helpers"]}"></script>
<script src="/pfblockerng/pfBlockerNG.js"></script>
</body></html>"""
    )


@pytest.fixture(scope="module")
def reorder_fixtures(deployed_vm: SmokeVM, webui: WebUI) -> Iterator[dict[str, str]]:
    """Write the 3 static fixture pages to the webroot; remove them in teardown.

    A failed removal WARNS loudly (helpers.py's ``php_fpm_probe`` idiom) rather
    than leaving a stray file silently in the webroot.
    """
    resp = webui.get(_DISCOVERY_PATH)
    if resp.status_code != 200:
        raise RuntimeError(f"discovery GET {_DISCOVERY_PATH} -> HTTP {resp.status_code}")
    scripts = _discover_vendor_scripts(resp.text)

    pages = {
        _REMOTE_REPEAT: _fixture_repeat_html(scripts, n_rows=5, drag_enabled=True),
        _REMOTE_REPEAT_NODRAG: _fixture_repeat_html(scripts, n_rows=3, drag_enabled=False),
        _REMOTE_SORTABLE: _fixture_sortable_html(scripts, n_rows=3),
    }
    written: list[str] = []
    try:
        for remote, html in pages.items():
            write = deployed_vm.ssh(f"printf '%s' {shlex.quote(html)} > /usr/local/www{remote}")
            if write.returncode != 0:
                raise RuntimeError(f"writing fixture {remote} failed: {(write.stderr or write.stdout).strip()!r}")
            written.append(remote)
        yield {
            "repeat": _REMOTE_REPEAT,
            "repeat_nodrag": _REMOTE_REPEAT_NODRAG,
            "sortable": _REMOTE_SORTABLE,
        }
    finally:
        for remote in written:
            rm = deployed_vm.ssh(f"/bin/rm -f /usr/local/www{remote}")
            if rm.returncode != 0:
                print(
                    f"[smoke] WARNING: failed to remove fixture {remote} "
                    f"(rc={rm.returncode}): {(rm.stderr or rm.stdout).strip()!r} -- stray file left in webroot"
                )


def _open(page: Page, webui: WebUI, path: str) -> None:
    page.goto(webui.url(path), wait_until="networkidle", timeout=JS_TIMEOUT_MS * 3)


def _rows(page: Page) -> Locator:
    return page.locator("#pfb_repeat .form-group.repeatable")


def _check_row(page: Page, i: int) -> None:
    _rows(page).nth(i).locator(".pfb-reorder-chk").check()


def _click_anchor(page: Page, i: int, *, shift: bool) -> None:
    _rows(page).nth(i).locator(".pfb-reorder-anchor").click(modifiers=["Shift"] if shift else None)


def _url_order(page: Page) -> list[str]:
    return page.evaluate("() => pfbFixtureUrlOrder()")


def _move_count(page: Page) -> int:
    return page.evaluate("() => window.pfbFixtureMoveCount")


_ORIGINAL_5 = ["row0-url", "row1-url", "row2-url", "row3-url", "row4-url"]


# --------------------------------------------------------------------------- #
# Scenario (a): drag
# --------------------------------------------------------------------------- #


def test_scenario_a_drag_reorders_rows_and_fires_on_after_move(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Dragging row 0 below row 2 relocates it there; the drag-stop callback fires.

    Given 5 rows in original order (identified by their unique ``row{i}-url``
    content, not by index -- ``renumber()`` may rewrite indices),
    When row 0 is dragged (real ``mouse.down``/``move(steps>=2)``/``up`` --
    jQuery UI sortable's ``distance:10`` threshold rules out ``drag_and_drop()``)
    from its own gutter to below row 2,
    Then row 0's content is now at index 2, no row was lost or duplicated, and
    ``onAfterMove`` (the ``stop`` callback) fired.
    """
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat"])

    before = _url_order(page)
    assert before == _ORIGINAL_5, f"unexpected initial order: {before}"

    # Grab the gutter, not the anchor button: jQuery UI sortable's default
    # `cancel` selector excludes input/select/button/option from starting a drag.
    handle = _rows(page).nth(0).locator(".pfb-gutter")
    target = _rows(page).nth(2)
    hb = handle.bounding_box()
    tb = target.bounding_box()
    assert hb is not None and tb is not None, "could not compute bounding boxes for drag handle/target"

    start_x, start_y = hb["x"] + hb["width"] / 2, hb["y"] + hb["height"] / 2
    page.mouse.move(start_x, start_y)
    page.mouse.down()
    # Clear the distance:10 threshold first, then move to the target in steps.
    page.mouse.move(start_x, start_y + 20, steps=5)
    page.mouse.move(tb["x"] + tb["width"] / 2, tb["y"] + tb["height"] + 5, steps=10)
    page.mouse.up()

    after = _url_order(page)
    assert after[2] == "row0-url", f"drag did not relocate row0 to index 2: before={before} after={after}"
    assert set(after) == set(before), f"drag lost or duplicated a row: before={before} after={after}"
    assert _move_count(page) >= 1, "onAfterMove (drag stop) never fired"


# --------------------------------------------------------------------------- #
# Scenario (b): anchor-click, single checked row, before / shift-after
# --------------------------------------------------------------------------- #


def test_scenario_b_anchor_click_before_moves_checked_row_ahead_of_anchor(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Plain anchor-click moves the single checked row immediately BEFORE the anchor."""
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat"])

    _check_row(page, 3)
    _click_anchor(page, 1, shift=False)

    after = _url_order(page)
    expected = ["row0-url", "row3-url", "row1-url", "row2-url", "row4-url"]
    assert after == expected, f"anchor-click 'before' produced {after}, expected {expected}"
    assert _move_count(page) >= 1, "onAfterMove never fired for anchor-click"


def test_scenario_b_shift_anchor_click_moves_checked_row_after_anchor(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Shift-anchor-click moves the single checked row immediately AFTER the anchor."""
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat"])

    _check_row(page, 1)
    _click_anchor(page, 3, shift=True)

    after = _url_order(page)
    expected = ["row0-url", "row2-url", "row3-url", "row1-url", "row4-url"]
    assert after == expected, f"shift-anchor-click produced {after}, expected {expected}"
    assert _move_count(page) >= 1, "onAfterMove never fired for shift-anchor-click"


# --------------------------------------------------------------------------- #
# Scenario (c): multi-row straddle
# --------------------------------------------------------------------------- #


def test_scenario_c_multiple_checked_rows_all_above_anchor(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Checked rows [0,1], anchor row 3 (before): both relocate ahead of it, in order."""
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat"])

    _check_row(page, 0)
    _check_row(page, 1)
    _click_anchor(page, 3, shift=False)

    after = _url_order(page)
    expected = ["row2-url", "row0-url", "row1-url", "row3-url", "row4-url"]
    assert after == expected, f"all-above straddle produced {after}, expected {expected}"


def test_scenario_c_multiple_checked_rows_all_below_anchor(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Checked rows [3,4], anchor row 1 (before): both relocate ahead of it, in order."""
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat"])

    _check_row(page, 3)
    _check_row(page, 4)
    _click_anchor(page, 1, shift=False)

    after = _url_order(page)
    expected = ["row0-url", "row3-url", "row4-url", "row1-url", "row2-url"]
    assert after == expected, f"all-below straddle produced {after}, expected {expected}"


def test_scenario_c_multiple_checked_rows_straddle_both_sides_of_anchor(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Checked rows [0,4] straddle anchor row 2 (before): both relocate ahead, in order.

    This is the multi-row straddle assertion the failability mutation (swap
    ``insertBefore``/``insertAfter``) is proven against -- see the module's
    RESULTS handoff for the pasted red/green runs.
    """
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat"])

    _check_row(page, 0)
    _check_row(page, 4)
    _click_anchor(page, 2, shift=False)

    after = _url_order(page)
    expected = ["row1-url", "row0-url", "row4-url", "row2-url", "row3-url"]
    assert after == expected, f"straddle-both-sides produced {after}, expected {expected}"
    assert set(after) == set(_ORIGINAL_5), f"straddle lost or duplicated a row: {after}"


# --------------------------------------------------------------------------- #
# Scenario (d): renumber composition (ADR sec7 reject criterion 1)
# --------------------------------------------------------------------------- #


def test_scenario_d_move_then_add_row_then_delete_row_keeps_fields_positional(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Stage a move, then core add_row(), then core delete_row(): fields stay positional.

    This is the ADR sec7 reject-criterion-1 probe: if core's renumber()/
    add_row()/delete_row() cannot keep the digit-suffixed field shape
    consistent under move+add+delete composition (collision, misnumbering, or
    value drift), the phase's whole premise is wrong.

    Scenario: 5 rows [0..4] (identified by content, indices renumber() may
    rewrite).
    """
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat"])

    audit = page.evaluate("() => pfbFixtureIdAudit()")
    assert audit == {"rowCount": 5, "missing": [], "duplicates": []}, f"initial id audit failed: {audit}"

    # WHEN: check row0, anchor-click row3 (before) -- onAfterMove fires renumber()+gutter refresh.
    _check_row(page, 0)
    _click_anchor(page, 3, shift=False)

    # THEN: positional field names 0..4, no collision, values/gutter reflect the new order.
    after_move = _url_order(page)
    expected_after_move = ["row1-url", "row2-url", "row0-url", "row3-url", "row4-url"]
    assert after_move == expected_after_move, f"after move: {after_move}, expected {expected_after_move}"
    audit = page.evaluate("() => pfbFixtureIdAudit()")
    assert audit == {"rowCount": 5, "missing": [], "duplicates": []}, f"post-move id audit failed: {audit}"
    gutter = page.evaluate("() => $('#pfb_repeat .pfb-gutter').map((i,e)=>e.textContent).get()")
    assert gutter == ["01", "02", "03", "04", "05"], f"post-move gutter mismatch: {gutter}"

    # WHEN: core add_row() clones the visually-last group (currently row4's
    # content) and clears its text-input values; the fixture's own delegated
    # handler re-renumbers so no injected control's id is left stale.
    page.locator("#addrow").click()

    # THEN: 6 positional rows, no collision, first 5 values unchanged in order,
    # new row's text inputs cleared (bump_input_id() clears <input>, not <select>).
    after_add = _url_order(page)
    assert after_add == [*expected_after_move, ""], f"after add_row: {after_add}"
    audit = page.evaluate("() => pfbFixtureIdAudit()")
    assert audit == {"rowCount": 6, "missing": [], "duplicates": []}, f"post-add id audit failed: {audit}"
    gutter = page.evaluate("() => $('#pfb_repeat .pfb-gutter').map((i,e)=>e.textContent).get()")
    assert gutter == ["01", "02", "03", "04", "05", "06"], f"post-add gutter mismatch: {gutter}"

    # WHEN: core delete_row() removes the row holding "row2-url" (self-renumbers).
    target_row = _rows(page).filter(has=page.locator('input[value="row2-url"]'))
    target_row.locator("button[id^=deleterow]").click()

    # THEN: 5 positional rows remain, no collision, "row2-url" is gone, order preserved otherwise.
    after_delete = _url_order(page)
    expected_after_delete = ["row1-url", "row0-url", "row3-url", "row4-url", ""]
    assert after_delete == expected_after_delete, f"after delete_row: {after_delete}"
    audit = page.evaluate("() => pfbFixtureIdAudit()")
    assert audit == {"rowCount": 5, "missing": [], "duplicates": []}, f"post-delete id audit failed: {audit}"
    gutter = page.evaluate("() => $('#pfb_repeat .pfb-gutter').map((i,e)=>e.textContent).get()")
    assert gutter == ["01", "02", "03", "04", "05"], f"post-delete gutter mismatch: {gutter}"


# --------------------------------------------------------------------------- #
# Scenario (e): order-read helper without .sortable() ever initialised
# (the "drag boolean = false" axis: pfb_reorder_init() is never called on
# either the .form-group.repeatable-nodrag fixture's read path or the
# tr.sortable fixture below, so .sortable() genuinely never exists here).
# --------------------------------------------------------------------------- #


def test_scenario_e_order_read_matches_real_sortable_serialize(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """The order-read helper is byte-format-identical to jQuery UI's own serialize()."""
    page = browser_page
    _open(page, webui, reorder_fixtures["sortable"])

    got = page.evaluate("() => pfb_reorder_read_order('#pfb_table_body', 'tr.sortable')")
    assert got == "ids[]=r0&ids[]=r1&ids[]=r2", f"unexpected order-read output: {got!r}"

    real = page.evaluate("""
        () => {
            $('#pfb_table_body').sortable({items: 'tr.sortable'});
            var s = $('#pfb_table_body').sortable('serialize', {key: 'ids[]'});
            $('#pfb_table_body').sortable('destroy');
            return s;
        }
    """)
    assert got == real, f"order-read {got!r} != real sortable('serialize') {real!r}"


def test_scenario_e_order_read_works_when_sortable_never_initialised(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """ADR sec1.8's serialize trap: sortable('serialize') THROWS pre-init; our helper doesn't.

    Given a container that never had ``.sortable()`` called on it,
    When the order-read helper runs,
    Then it returns the correct wire format, AND a direct
    ``sortable('serialize')`` call on the SAME never-initialised container
    throws -- proving the trap this helper exists to route around is real.
    """
    page = browser_page
    _open(page, webui, reorder_fixtures["sortable"])

    got = page.evaluate("() => pfb_reorder_read_order('#pfb_table_body', 'tr.sortable')")
    assert got == "ids[]=r0&ids[]=r1&ids[]=r2", f"unexpected order-read output: {got!r}"

    threw = page.evaluate("""
        () => {
            try {
                $('#pfb_table_body').sortable('serialize', {key: 'ids[]'});
                return false;
            } catch (e) {
                return true;
            }
        }
    """)
    assert threw is True, "sortable('serialize') on a never-initialised container did not throw -- trap not real?"


def test_scenario_e_order_read_empty_container_returns_empty_string(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """An empty container's order-read is '' -- matches category.php's own JS guard."""
    page = browser_page
    _open(page, webui, reorder_fixtures["sortable"])

    got = page.evaluate("""
        () => {
            var empty = document.createElement('tbody');
            document.body.appendChild(empty);
            var s = pfb_reorder_read_order(empty, 'tr.sortable');
            empty.remove();
            return s;
        }
    """)
    assert got == "", f"empty container should read as '', got {got!r}"


@pytest.mark.parametrize(
    ("row_id", "expected_token"),
    [
        pytest.param("foo", None, id="no-separator-skipped"),
        pytest.param("pfb_r_5", "5", id="multi-separator-splits-on-last"),
        pytest.param("row-a&b", "a%26b", id="metachar-token-url-encoded"),
    ],
)
def test_scenario_e_order_read_parser_hostile_inputs(
    browser_page: Page,
    webui: WebUI,
    reorder_fixtures: dict[str, str],
    row_id: str,
    expected_token: str | None,
) -> None:
    """The order-read parser's hostile-input rows (ADR-63 Phase 2 brief sec4).

    A row id with no ``-``/``=``/``_`` separator contributes no token (matches
    jQuery UI's own ``/(.+)[-=_](.+)/`` serialize regex, which would not match
    either); a row id with multiple separators splits on the LAST one; a token
    needing URL-encoding is percent-encoded, never emitted raw.
    """
    page = browser_page
    _open(page, webui, reorder_fixtures["sortable"])

    got = page.evaluate(
        """
        (rowId) => {
            var row = document.createElement('tr');
            row.id = rowId;
            var host = document.createElement('tbody');
            host.appendChild(row);
            document.body.appendChild(host);
            var s = pfb_reorder_read_order(host, 'tr');
            host.remove();
            return s;
        }
        """,
        row_id,
    )
    expected = "" if expected_token is None else f"ids[]={expected_token}"
    assert got == expected, f"row id {row_id!r}: got {got!r}, expected {expected!r}"


# --------------------------------------------------------------------------- #
# Hostile-input rows: the anchor-click move guard (drag=false fixture; also
# proves "drag boolean = false" never calls .sortable()).
# --------------------------------------------------------------------------- #


def test_anchor_click_drag_disabled_never_initialises_sortable_but_still_works(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """``dragEnabled=false``: no ``.sortable()`` instance exists, anchor-click still works."""
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat_nodrag"])

    has_instance = page.evaluate("() => $('#pfb_repeat').sortable('instance') !== undefined")
    assert has_instance is False, "dragEnabled=false must never call .sortable() on the container"

    _check_row(page, 2)
    _click_anchor(page, 0, shift=False)
    after = _url_order(page)
    assert after == ["row2-url", "row0-url", "row1-url"], f"anchor-click without drag produced {after}"


def test_anchor_click_zero_checked_is_a_noop_but_still_fires_callback(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Clicking an anchor with nothing checked leaves DOM order unchanged; onAfterMove still fires.

    Judgment call (recorded in the handoff): a "completed anchor-click" fires
    the callback even when it moved zero rows -- simpler contract than a
    special-cased silent no-op.
    """
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat_nodrag"])

    before = page.evaluate("() => $('#pfb_repeat .form-group.repeatable input[id^=url-]').map((i,e)=>e.value).get()")
    _click_anchor(page, 1, shift=False)
    after = page.evaluate("() => $('#pfb_repeat .form-group.repeatable input[id^=url-]').map((i,e)=>e.value).get()")

    assert after == before, f"zero-checked anchor-click must be a no-op: before={before} after={after}"
    fired = _move_count(page)
    assert fired >= 1, "onAfterMove must still fire on a zero-checked anchor-click"


def test_anchor_click_self_anchor_does_not_drop_or_duplicate_the_anchor_row(
    browser_page: Page, webui: WebUI, reorder_fixtures: dict[str, str]
) -> None:
    """Checking the anchor row itself: it stays put; other checked rows move around it.

    Given 3 rows, anchor row 1 is ALSO checked, plus row 2,
    When the anchor is clicked (before),
    Then row 1 (the anchor) does not move, row 2 relocates immediately before
    it, and no row is lost or duplicated.
    """
    page = browser_page
    _open(page, webui, reorder_fixtures["repeat_nodrag"])

    _check_row(page, 1)  # the anchor row itself
    _check_row(page, 2)
    _click_anchor(page, 1, shift=False)

    after = page.evaluate("() => $('#pfb_repeat .form-group.repeatable input[id^=url-]').map((i,e)=>e.value).get()")
    expected = ["row0-url", "row2-url", "row1-url"]
    assert after == expected, f"self-anchor case produced {after}, expected {expected}"
    assert set(after) == {"row0-url", "row1-url", "row2-url"}, f"self-anchor lost/duplicated a row: {after}"
