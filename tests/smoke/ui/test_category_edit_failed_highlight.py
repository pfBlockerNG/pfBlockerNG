"""issue #2931 -- the failed-download row's highlight has no live coverage.

``pfblockerng_category_edit.php`` paints the failed row's Header/Label input from
``$failed_bg``, which is non-empty only inside::

    if ($folder && file_exists("{$folder}/{$row['header']}{$suffix}.fail")) {

On the hermetic Tier-A harness no feed has ever failed, so that branch never fires and the
input renders ``style=""``. ``test_theme_legibility_render.py``'s
``test_no_inline_style_paints_an_unpaired_background`` is therefore a real guard for every
OTHER inline background those pages emit, but it cannot go red for this one -- the state it
would grade is unreachable from a clean box.

The pairing itself is judged with that test's OWN patterns, imported rather than restated,
so the two tiers cannot drift into disagreeing about what counts as a background.

Seeding the sidecar is a fixture, not a line: the path is
``{folder}/{row['header']}{suffix}.fail``, where ``$folder`` follows the alias action and
``$row['header']`` comes from a CONFIGURED feed, and a clean smoke box has no feeds. So this
case creates the alias first, then seeds.

``EXCLUDED_FROM_TIER_A`` is the wrong shape for the gap: it records whole PAGES kept out of
the sweep, and this page IS in the sweep -- it is one row's STATE that is unreachable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import body_has_php_error
from .test_category_edit import (
    CATEGORY_PAGE,
    CFG_IPV4,
    _del_rowid,
    _free_rowid,
    _input_tag,
    _ipv4_payload,
    _post_form,
)
from .test_theme_legibility_render import _FOREGROUND, _INLINE_STYLE, _OPAQUE_BACKGROUND
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

# Tier B: the state under test only exists after a mutating save plus an on-box sidecar
# write, neither of which the hermetic Tier-A render sweep can produce. Tier A coverage of
# this page stays exactly what it is (test_render_smoke.py / test_category_edit.py) -- this
# case exists so the ONE row state that sweep cannot reach is graded somewhere.
pytestmark = pytest.mark.ui_e2e

# A `Deny_*` action resolves $folder to $pfb['denydir'] = "{$pfb['dbdir']}/deny", and the IP
# loop names each on-disk feed file `{row.header}{vtype}`, so an IPv4 feed's marker carries
# `_v4` (helpers.force_ip_refetch documents the identical naming for `.update`).
_DENY_DIR = f"{helpers.PFB_DBDIR}/deny"

# The Header/Label field the page paints. One configured row -> $r_id 0.
_HEADER_FIELD = "header-0"

# The legend the same branch emits beside the row, at pfblockerng_category_edit.php:1275.
_LEGEND = "Failed download(s) highlighted in yellow."


def _style_of(tag: str) -> str:
    r"""The tag's ``style`` value, '' when it has none.

    ``_INLINE_STYLE`` rather than a local pattern: a bare ``\bstyle=`` also fires on the
    ``-``-to-``s`` transition inside ``data-style=``, so a decoy attribute would be read as
    this element's own style. That is the trap the imported pattern's negative lookbehind
    exists to close, and this file has no reason to re-learn it.
    """
    m = _INLINE_STYLE.search(tag)
    return m.group("value") if m else ""


def _render_editor(webui: WebUI, rowid: int) -> tuple[str, str]:
    """GET the IPv4 editor for ``rowid``; return its Header/Label input tag and the body."""
    resp = webui.get(CATEGORY_PAGE, params={"type": "ipv4", "rowid": str(rowid)})
    assert not looks_like_login_page(resp.text), "category GET returned the login form (session lost)"
    diagnostic = body_has_php_error(resp.text)
    assert diagnostic is None, f"the category editor rendered a PHP diagnostic: {diagnostic}"
    tag = _input_tag(resp.text, _HEADER_FIELD)
    assert tag, (
        f'the editor for rowid {rowid} rendered no <input name="{_HEADER_FIELD}"> '
        "-- the configured source row is missing, so the highlight cannot be graded"
    )
    return tag, resp.text


def test_failed_download_row_paints_a_paired_highlight(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Scenario: an IPv4 feed whose last download failed is highlighted legibly.

    Given a saved Deny_Both IPv4 alias carrying one configured source row, and no failure
      sidecar for that row on the box,

    When ``{denydir}/{header}_v4.fail`` is created and the editor is reloaded,

    Then the row's Header/Label input, which carried NO inline style before, now carries one
      that sets BOTH a background and a foreground -- an opaque background with no paired
      foreground is illegible under a theme that paints its own text colour -- and the
      legend the same branch emits beside it appears too, since it carries a background of
      its own and is invisible to the sweep for exactly the same reason.

    The before-state assertion is what makes green mean something: it proves the sidecar
    CAUSED the paint, rather than the input having been styled all along.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_IPV4)
    header = f"Smokefail{rowid}"
    sidecar = f"{_DENY_DIR}/{header}_v4.fail"
    try:
        payload = _ipv4_payload(rowid, f"smokefail{rowid}", action="Deny_Both")
        # `state-0` stays Disabled so no feed is ever downloaded: the sidecar is what this
        # case seeds, and a real fetch would make the run non-hermetic.
        payload[_HEADER_FIELD] = header
        _post_form(webui, payload)
        stored = helpers.config_get(vm, f"{CFG_IPV4}/{rowid}/row/0/header")
        assert stored == header, (
            f"the source row did not persist at {CFG_IPV4}/{rowid}/row/0/header: got {stored!r}, expected {header!r}"
        )

        # BEFORE: no sidecar -> the branch does not fire -> style=""
        removed = vm.ssh("/bin/rm", "-f", sidecar, timeout=30.0)
        assert removed.returncode == 0, f"could not clear {sidecar}: {removed.stderr!r}"
        tag, body = _render_editor(webui, rowid)
        before = _style_of(tag)
        assert before == "", f"expected no inline style on {_HEADER_FIELD} before the sidecar exists, got {before!r}"
        assert _LEGEND not in body, f"the legend is rendered with no {sidecar} present"

        # WHEN: the failure marker the download path writes.
        seeded = vm.ssh(f"/bin/mkdir -p {_DENY_DIR} && /usr/bin/touch {sidecar}", timeout=30.0)
        assert seeded.returncode == 0, f"could not seed {sidecar}: {seeded.stderr!r}"

        # THEN: highlighted, and legibly. The patterns are the Tier-A sweep's own, so the two
        # tiers cannot drift into disagreeing about what a background or a foreground is.
        tag, body = _render_editor(webui, rowid)
        after = _style_of(tag)
        assert _OPAQUE_BACKGROUND.search(after), f"the failed row must carry an opaque background; got style={after!r}"
        assert _FOREGROUND.search(after), (
            "the failed row's background must be paired with a foreground, or the theme's own "
            f"text colour is left to fight it; got style={after!r}"
        )
        assert _LEGEND in body, f"seeding {sidecar} rendered the highlight but not its legend"
    finally:
        # Reported, never asserted: a cleanup failure must not replace the body's own.
        swept = vm.ssh("/bin/rm", "-f", sidecar, timeout=30.0)
        if swept.returncode != 0:
            print(f"WARNING: {sidecar} was left behind: {swept.stderr!r}")
        _del_rowid(vm, CFG_IPV4, rowid)
