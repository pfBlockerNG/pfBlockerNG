"""issue #1129 -- category-edit row-move (Lmove/Xmove anchor) reorder guard, live.

``CategoryEditRowMoveTest`` (tests/php/) already pins the reorder algorithm as a
pure array transform extracted off-appliance. This file proves the SAME guard
end-to-end against the real box: a crafted POST that reaches the reorder block
(category_edit.php:930, the ``else`` of ``isset($_POST['save'])`` at :452 --
NOT the save handler) either persists a real reorder or, for a stale/hostile
Xmove, causes NO mutation at all -- observable only by re-fetching the box's
EFFECTIVE rendered state (never inferred from the algorithm alone), which is
why this is Tier B (``ui_e2e``), not ``ui_render``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard
from .test_category_edit import CFG_DNSBL, SAVE_TIMEOUT, _del_rowid, _dnsbl_payload, _free_rowid, _post_form
from .webui import extract_csrf_token, looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    import requests

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

CATEGORY_PAGE = "/pfblockerng/pfblockerng_category_edit.php"


def _three_row_payload(rowid: int, aliasname: str, headers: tuple[str, str, str]) -> dict[str, str]:
    """A 3-row, ``sort='no-sort'`` dnsbl save payload -- one Disabled row per header.

    ``sort='no-sort'`` is what makes ``pfblockerng_category_edit.php`` render the
    Lmove checkbox / Xmove anchor button per row (:1127) instead of auto-sorting
    on every render (:1091) -- the real precondition for the anchor UI to exist,
    confirmed by grep, not assumed. Extends ``_dnsbl_payload``'s one-row
    convention to 3 rows sharing its field set.
    """
    payload = _dnsbl_payload(rowid, aliasname, sort="no-sort")
    for i, header in enumerate(headers):
        payload[f"format-{i}"] = "auto"
        payload[f"state-{i}"] = "Disabled"
        payload[f"url-{i}"] = ""
        payload[f"header-{i}"] = header
    return payload


def _post_move(webui: WebUI, payload: dict[str, str]) -> requests.Response:
    """POST an anchor-move request with NO ``save`` field (fresh CSRF harvested).

    The reorder block lives in the ``else`` of ``isset($_POST['save'])``
    (category_edit.php:452/871/930) -- unlike ``_post_form``, this must NOT set
    ``save``, or the request routes into the SAVE handler instead of the move
    branch and never reaches the guard under test.
    """
    get = webui.get(CATEGORY_PAGE, params={"type": payload.get("type", "dnsbl")})
    assert not looks_like_login_page(get.text), "category GET returned the login form (session lost)"
    token = extract_csrf_token(get.text)
    data = dict(payload)
    data["__csrf_magic"] = token
    resp = webui.session.post(webui.url(CATEGORY_PAGE), data=data, verify=webui._verify, timeout=SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "category move POST returned the login form (session lost)"
    return resp


def _headers(webui: WebUI, rowid: int) -> tuple[str, str, str]:
    """Scrape ``header-0``/``header-1``/``header-2`` off a fresh GET of ``rowid``."""
    resp = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
    assert not looks_like_login_page(resp.text), "category GET (reload) returned the login form (session lost)"
    fields = scrape_form_fields(resp.text)
    return (fields.get("header-0", ""), fields.get("header-1", ""), fields.get("header-2", ""))


# --------------------------------------------------------------------------- #
# THE BUG, now fixed: a stale/hostile Xmove anchor must skip the whole reorder
# -- never silently drop the checked row (issue #1129's exact repro).
# --------------------------------------------------------------------------- #


def test_stale_xmove_anchor_does_not_drop_checked_row(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Scenario: a checked row plus a stale (nonexistent) anchor key.

    Given a 3-row no-sort DNSBL category with distinct headers per row,
    When a reorder POST checks the middle row (``Lmove[1]='1'``) but anchors on
      a row key that does not exist (``Xmove='999'`` -- the issue #1129 repro),
    Then the request answers HTTP 200 with no PHP-error-log growth, and a
      follow-up GET's ``header-0``/``header-1``/``header-2`` are IDENTICAL to
      the pre-move values -- the checked row was NOT silently dropped.

    Pre-fix, the reorder block had no anchor-existence guard: it entered
    unconditionally on ``isset($Lmove) && isset($Xmove)``, collected the
    checked row into ``$move`` for re-insertion, but the re-insertion branch
    (``$Xmove == $key``) never fires because no row key equals '999' -- so the
    checked row is skipped out of ``$final`` and never merged back in. The
    resulting 2-row ``$final`` is written via ``config_set_path`` +
    ``write_config()``: header-1 vanishes and header-2's slot shifts left. That
    is exactly what this test's final assertion would catch.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    headers = ("rowmoveA", "rowmoveB", "rowmoveC")
    try:
        _post_form(webui, _three_row_payload(rowid, "smokemvbug", headers))

        # BEFORE: the 3 rows landed exactly as saved (no-sort -> no reorder yet).
        before = _headers(webui, rowid)
        assert before == headers, f"3-row create did not persist as saved: got {before!r}"

        guard = PhpErrorLogGuard(vm)
        guard.snapshot()

        # WHEN: Lmove checks row key 1, Xmove anchors on a row key that does
        # not exist -- the issue #1129 repro.
        resp = _post_move(
            webui,
            {"type": "dnsbl", "rowid": str(rowid), "Lmove[1]": "1", "Xmove": "999"},
        )
        assert resp.status_code == 200, f"stale-anchor move POST -> HTTP {resp.status_code} (expected 200)"
        guard.assert_no_growth()

        # THEN: the row set is UNCHANGED -- the checked row was not dropped.
        after = _headers(webui, rowid)
        assert after == before, (
            f"a stale Xmove anchor must leave the row set unchanged, but it changed: {before!r} -> {after!r}"
        )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


# --------------------------------------------------------------------------- #
# Regression guard: a VALID anchor still performs the move (mirrors
# CategoryEditRowMoveTest::testValidMoveRelocatesCheckedRowNextToAnchor).
# --------------------------------------------------------------------------- #


def test_valid_xmove_anchor_relocates_checked_row(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Scenario: a checked row plus a real, existing anchor key.

    Given a 3-row no-sort DNSBL category with distinct headers per row,
    When a reorder POST checks the middle row (``Lmove[1]='1'``) and anchors on
      the LAST row's own key (``Xmove='2'``, an existing row),
    Then the row set is REORDERED (not merely preserved): the checked row
      relocates to just after the anchor row -- ``[row0, row2, row1]``, the
      same placement ``CategoryEditRowMoveTest`` pins off-appliance -- proving
      the #1129 fix's guard does not also block the legitimate case.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    headers = ("rowmoveX", "rowmoveY", "rowmoveZ")
    try:
        _post_form(webui, _three_row_payload(rowid, "smokemvok", headers))

        # BEFORE: the 3 rows landed exactly as saved.
        before = _headers(webui, rowid)
        assert before == headers, f"3-row create did not persist as saved: got {before!r}"

        # WHEN: Lmove checks row key 1, Xmove anchors on row key 2 (exists).
        resp = _post_move(
            webui,
            {"type": "dnsbl", "rowid": str(rowid), "Lmove[1]": "1", "Xmove": "2"},
        )
        assert resp.status_code == 200, f"valid move POST -> HTTP {resp.status_code} (expected 200)"

        # THEN: row1 relocated to sit right after the anchor row2 -- all three
        # headers survive, reordered (not the before-state -- proves the POST
        # CAUSED the move, matching CategoryEditRowMoveTest's pinned placement).
        after = _headers(webui, rowid)
        assert after != before, "a valid anchor move must change the row order, but it stayed the same"
        assert after == (headers[0], headers[2], headers[1]), (
            f"row1 must land adjacent to anchor row2 ([h0, h2, h1]), got {after!r}"
        )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)
