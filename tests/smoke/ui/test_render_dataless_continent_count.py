"""Tier-A ``ui_render`` coverage for issue #1507: a data-less continent renders count 0.

``pfblockerng_get_countries()`` (the ``gc`` verb) writes each continent page with
``$options_countries4_cnt``/``$options_countries6_cnt`` rendered as the ``size``
attribute of the ``countries4``/``countries6`` selects (pfblockerng.php:2002/2011).
``$ftotal4``/``$ftotal6`` are assigned only inside the per-type coptions-guarded
build block, so before the #1507 fix a continent whose file yields NO country
entries rendered the PREVIOUS continent's count beside an empty list. The seeded
MaxMind test corpus gives every one of the 9 continents at least one entry (e.g.
``Antarctica [6697173] AQ (0)``), so the ``PAGE_TABLE`` sweep never drives the
stays-empty path -- this module manufactures it on the live box.

The data-less continent is manufactured as a header-ONLY continent file
(``# Continent IPv{4,6}:`` + ``# Continent en:`` lines kept, all country blocks
stripped), NOT a missing file: with a missing file ``$continent_en`` carries over
from the previous continent (a distinct pre-existing defect, out of #1507's
scope) and the regenerated page would be written to the WRONG path. Header-only
keeps the page's own name/title correct and isolates exactly the ``$ftotal``
carry.

Fail-before / pass-after: pre-fix, the mutated ``gc`` run regenerates the
Antarctica page with Africa's (the previous continent's) nonzero counts as the
select sizes, so the ``size="0"`` assertions fail; they pass only with the
per-continent reset. The off-appliance red run is executed and pinned by
``tests/php/PfbOptionsHeredocMultiContinentTest.php``.

AUTHORED, NOT EXECUTED this session (no live VM) -- run via
``pytest tests/smoke/ui -m ui_render --override-ini="addopts="`` on the fan-out VM.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

_CC_DIR = "/usr/local/share/GeoIP/cc"
_ANTARCTICA_V4 = f"{_CC_DIR}/Antarctica_v4.txt"
_ANTARCTICA_V6 = f"{_CC_DIR}/Antarctica_v6.txt"
_BAK_SUFFIX = ".pfb1507bak"

_AFRICA_PAGE = "/pfblockerng/pfblockerng_Africa.php"
_ANTARCTICA_PAGE = "/pfblockerng/pfblockerng_Antarctica.php"


def _select_size(body: str, name: str, page: str) -> str:
    """The ``size`` attribute of the ``<select name="{name}[]">`` on ``page``'s body."""
    tag = re.search(rf'<select\b[^>]*name="{re.escape(name)}(?:\[\])?"[^>]*>', body)
    assert tag is not None, f"{page}: no <select> named {name!r} in the rendered body"
    size = re.search(r'size="(\d+)"', tag.group(0))
    assert size is not None, f"{page}: the {name!r} select carries no numeric size attribute: {tag.group(0)!r}"
    return size.group(1)


def test_dataless_continent_renders_zero_counts(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """issue #1507: a continent with no country entries renders count 0, not a stale carry.

    Scenario:
      Given the seeded corpus (baseline Antarctica renders a nonzero select size),
        and Antarctica's continent files stripped to their headers (no country
        blocks -- the "MaxMind data gap" producer from the issue),
      When  ``gc`` regenerates the continent pages,
      Then  the Antarctica page still passes the Tier-A oracle and BOTH its
            country selects render ``size="0"`` -- while Africa (the continent
            whose counts a stale ``$ftotal4``/``$ftotal6`` carry would have
            leaked here) renders nonzero sizes in the same run.
    """
    resp = webui.get(_ANTARCTICA_PAGE)
    result = evaluate_render(_ANTARCTICA_PAGE, resp.status_code, resp.text, ("Continent - Antarctica",))
    assert result.ok, f"baseline Antarctica render oracle failed: {result.detail}"
    baseline_size4 = _select_size(resp.text, "countries4", _ANTARCTICA_PAGE)
    assert baseline_size4 != "0", (
        "before-state anchor: seeded Antarctica must render a nonzero IPv4 select size "
        "(every corpus continent carries at least one entry), else the final size=0 proves nothing"
    )

    mutated = False
    try:
        backup = smoke_vm.ssh(
            f"cp -p {_ANTARCTICA_V4} {_ANTARCTICA_V4}{_BAK_SUFFIX}"
            f" && cp -p {_ANTARCTICA_V6} {_ANTARCTICA_V6}{_BAK_SUFFIX}"
        )
        assert backup.returncode == 0, (
            f"failed to back up Antarctica cc files: rc={backup.returncode} {backup.stderr!r}"
        )
        mutated = True

        strip = smoke_vm.ssh(
            f"grep '^# Continent' {_ANTARCTICA_V4}{_BAK_SUFFIX} > {_ANTARCTICA_V4}"
            f" && grep '^# Continent' {_ANTARCTICA_V6}{_BAK_SUFFIX} > {_ANTARCTICA_V6}"
        )
        assert strip.returncode == 0, (
            f"failed to strip Antarctica cc files to headers: rc={strip.returncode} {strip.stderr!r}"
        )

        gc = smoke_vm.ssh(helpers.PHP_BIN, helpers.PFB_CLI, "gc", timeout=600)
        assert gc.returncode == 0, (
            f"gc on header-only Antarctica failed: rc={gc.returncode} {gc.stderr!r} {gc.stdout!r}"
        )

        guard = PhpErrorLogGuard(smoke_vm)
        guard.snapshot()

        africa = webui.get(_AFRICA_PAGE)
        africa_result = evaluate_render(_AFRICA_PAGE, africa.status_code, africa.text, ("Continent - Africa",))
        assert africa_result.ok, f"Africa render oracle failed after the mutated gc: {africa_result.detail}"
        assert _select_size(africa.text, "countries4", _AFRICA_PAGE) != "0", (
            "non-vacuity anchor: Africa (the previous continent in $geoip_files order) must render a "
            "nonzero IPv4 size in this very gc run -- the value a stale $ftotal4 carry would leak into Antarctica"
        )
        assert _select_size(africa.text, "countries6", _AFRICA_PAGE) != "0", (
            "non-vacuity anchor: Africa must render a nonzero IPv6 size in this very gc run -- the value a "
            "stale $ftotal6 carry would leak into Antarctica"
        )

        resp = webui.get(_ANTARCTICA_PAGE)
        result = evaluate_render(_ANTARCTICA_PAGE, resp.status_code, resp.text, ("Continent - Antarctica",))
        assert result.ok, f"data-less Antarctica render oracle failed: {result.detail}"
        assert _select_size(resp.text, "countries4", _ANTARCTICA_PAGE) == "0", (
            "issue #1507: a data-less continent's IPv4 select must render size=0, "
            "not the previous continent's stale $ftotal4"
        )
        assert _select_size(resp.text, "countries6", _ANTARCTICA_PAGE) == "0", (
            "issue #1507: a data-less continent's IPv6 select must render size=0, "
            "not the previous continent's stale $ftotal6"
        )

        guard.assert_no_growth()
    finally:
        if mutated:
            restore = smoke_vm.ssh(
                f"mv {_ANTARCTICA_V4}{_BAK_SUFFIX} {_ANTARCTICA_V4}"
                f" && mv {_ANTARCTICA_V6}{_BAK_SUFFIX} {_ANTARCTICA_V6}"
            )
            if restore.returncode != 0:
                raise AssertionError(
                    f"failed to restore Antarctica cc files: rc={restore.returncode} {restore.stderr!r}"
                )
            regen = smoke_vm.ssh(helpers.PHP_BIN, helpers.PFB_CLI, "gc", timeout=600)
            if regen.returncode != 0:
                raise AssertionError(
                    f"gc after restore failed: rc={regen.returncode} {regen.stderr!r} {regen.stdout!r}"
                )

    # Loud self-encapsulation check: the restore + regen must actually take, so
    # later tests (the PAGE_TABLE sweep, the seeded-csv needles) see the
    # original pages regardless of ordering.
    resp = webui.get(_ANTARCTICA_PAGE)
    assert _select_size(resp.text, "countries4", _ANTARCTICA_PAGE) == baseline_size4, (
        "post-restore Antarctica IPv4 select size did not return to its baseline -- the restore/regen did not take"
    )
