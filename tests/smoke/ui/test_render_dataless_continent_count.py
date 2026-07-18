"""Tier-A coverage for issue #1507: a data-less continent gets generated count 0.

``pfblockerng_get_countries()`` (the ``gc`` verb) writes
``$options_countries4_cnt``/``$options_countries6_cnt`` into each generated
continent page. pfSense's ``Form_Select`` clamps an empty select's rendered
``size`` to its minimum row count, so the HTML attribute is not an oracle for
those raw generated values. This module reads the assignments from the generated
pages on the live box instead.

``$ftotal4``/``$ftotal6`` are assigned only inside the per-type coptions-guarded
build block, so before the #1507 fix a continent whose file yields NO country
entries inherited the PREVIOUS continent's count. The seeded MaxMind test corpus
gives every one of the 9 continents at least one entry, so the ``PAGE_TABLE``
sweep never drives the stays-empty path -- this module manufactures it live.

The data-less continent is manufactured as a header-ONLY continent file
(``# Continent IPv{4,6}:`` + ``# Continent en:`` lines kept, all country blocks
stripped), NOT a missing file: with a missing file ``$continent_en`` carries over
from the previous continent (a distinct pre-existing defect, out of #1507's
scope) and the regenerated page would be written to the WRONG path. Header-only
keeps the page's own name/title correct and isolates exactly the ``$ftotal``
carry.

The authenticated requests still verify that the regenerated pages render
cleanly. Direct generated-file assertions carry the count regression contract.
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
_AFRICA_GENERATED_PAGE = "/usr/local/www/pfblockerng/pfblockerng_Africa.php"
_ANTARCTICA_GENERATED_PAGE = "/usr/local/www/pfblockerng/pfblockerng_Antarctica.php"


def _generated_count(smoke_vm: SmokeVM, page: str, variable: str) -> str:
    """Return one raw generated count assignment from ``page``."""
    generated = smoke_vm.ssh("/bin/cat", page, timeout=15)
    assert generated.returncode == 0, (
        f"failed to read generated page {page}: rc={generated.returncode} {generated.stderr!r}"
    )
    assignment = re.search(rf'^\${re.escape(variable)}\s*=\s*"(\d+)";$', generated.stdout, re.MULTILINE)
    assert assignment is not None, f"{page}: no numeric ${variable} assignment in generated page"
    return assignment.group(1)


def test_dataless_continent_renders_zero_counts(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """issue #1507: a continent with no country entries renders count 0, not a stale carry.

    Scenario:
      Given the seeded corpus (baseline Antarctica generates nonzero counts),
        and Antarctica's continent files stripped to their headers (no country
        blocks -- the "MaxMind data gap" producer from the issue),
      When  ``gc`` regenerates the continent pages,
      Then  the Antarctica page still passes the Tier-A oracle and BOTH its
            raw generated country counts equal ``0`` -- while Africa (the
            continent whose counts a stale ``$ftotal4``/``$ftotal6`` carry would
            have leaked here) generates nonzero counts in the same run.
    """
    resp = webui.get(_ANTARCTICA_PAGE)
    result = evaluate_render(_ANTARCTICA_PAGE, resp.status_code, resp.text, ("Continent - Antarctica",))
    assert result.ok, f"baseline Antarctica render oracle failed: {result.detail}"
    baseline_count4 = _generated_count(smoke_vm, _ANTARCTICA_GENERATED_PAGE, "options_countries4_cnt")
    baseline_count6 = _generated_count(smoke_vm, _ANTARCTICA_GENERATED_PAGE, "options_countries6_cnt")
    assert baseline_count4 != "0" and baseline_count6 != "0", (
        "before-state anchor: seeded Antarctica must generate nonzero IPv4 and IPv6 counts "
        "(every corpus continent carries entries), else the final zeros prove nothing"
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
        assert _generated_count(smoke_vm, _AFRICA_GENERATED_PAGE, "options_countries4_cnt") != "0", (
            "non-vacuity anchor: Africa (the previous continent in $geoip_files order) must render a "
            "nonzero IPv4 count in this very gc run -- the value a stale $ftotal4 carry would leak into Antarctica"
        )
        assert _generated_count(smoke_vm, _AFRICA_GENERATED_PAGE, "options_countries6_cnt") != "0", (
            "non-vacuity anchor: Africa must render a nonzero IPv6 count in this very gc run -- the value a "
            "stale $ftotal6 carry would leak into Antarctica"
        )

        resp = webui.get(_ANTARCTICA_PAGE)
        result = evaluate_render(_ANTARCTICA_PAGE, resp.status_code, resp.text, ("Continent - Antarctica",))
        assert result.ok, f"data-less Antarctica render oracle failed: {result.detail}"
        assert _generated_count(smoke_vm, _ANTARCTICA_GENERATED_PAGE, "options_countries4_cnt") == "0", (
            "issue #1507: a data-less continent's raw generated IPv4 count must be 0, "
            "not the previous continent's stale $ftotal4"
        )
        assert _generated_count(smoke_vm, _ANTARCTICA_GENERATED_PAGE, "options_countries6_cnt") == "0", (
            "issue #1507: a data-less continent's raw generated IPv6 count must be 0, "
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
    result = evaluate_render(_ANTARCTICA_PAGE, resp.status_code, resp.text, ("Continent - Antarctica",))
    assert result.ok, f"restored Antarctica render oracle failed: {result.detail}"
    assert _generated_count(smoke_vm, _ANTARCTICA_GENERATED_PAGE, "options_countries4_cnt") == baseline_count4, (
        "post-restore Antarctica IPv4 count did not return to its baseline -- the restore/regen did not take"
    )
    assert _generated_count(smoke_vm, _ANTARCTICA_GENERATED_PAGE, "options_countries6_cnt") == baseline_count6, (
        "post-restore Antarctica IPv6 count did not return to its baseline -- the restore/regen did not take"
    )
