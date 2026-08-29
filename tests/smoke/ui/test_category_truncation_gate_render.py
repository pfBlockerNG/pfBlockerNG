"""Truncation gates must measure raw characters, not escaped bytes.

The Category alias/description gates compared ``strlen()`` of the HTML-ESCAPED value,
so entity expansion crossed the threshold while the raw value was still under it. The
cell then rendered with an ellipsis although ``mb_substr()`` removed nothing — the
displayed value was complete, with ``...`` appended (issue #2078).

These gates are inline template code rather than functions, so no
``tests/php/*Loader.php`` extraction reaches them; the rendered page is the only place
the behaviour is observable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..helpers import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

CATEGORY_PAGE = "/pfblockerng/pfblockerng_category.php?type=ipv4"
CFG_ROWS = "installedpackages/pfblockernglistsv4/config"

# Raw lengths sit UNDER the 20-character gate; escaped lengths cross it. Exactly the
# shape issue #2078 reports (raw 14 / escaped 18, raw 15 / escaped 31).
SHORT_ALIAS = "aaaaaaaaaaaaa&"
SHORT_DESC = "aaaaaaaaaaa&&&&"
# Control: genuinely over the gate, so the ellipsis is correct and must survive.
LONG_VALUE = "abcdefghijklmnopqrstuvwxyz"


@pytest.fixture
def _seeded_rows(smoke_vm: SmokeVM) -> Iterator[None]:
    """Seed the entity-heavy short row and the long control row; restore the section."""
    vm = smoke_vm

    prior = helpers.php_eval(
        vm,
        f"echo base64_encode(serialize(config_get_path('{CFG_ROWS}', [])));\n",
    )
    assert prior.returncode == 0, f"failed to read {CFG_ROWS}: stderr={prior.stderr!r}"
    prior_b64 = prior.stdout.strip()

    seed = helpers.php_eval(
        vm,
        f"$rows = config_get_path('{CFG_ROWS}', []);\n"
        "$base = $rows[0] ?? [];\n"
        f"$base['aliasname'] = '{SHORT_ALIAS}';\n"
        f"$base['description'] = '{SHORT_DESC}';\n"
        "$rows[0] = $base;\n"
        "$long = $base;\n"
        f"$long['aliasname'] = '{LONG_VALUE}';\n"
        f"$long['description'] = '{LONG_VALUE}';\n"
        "$rows[1] = $long;\n"
        f"config_set_path('{CFG_ROWS}', $rows);\n"
        "write_config('pfBlockerNG smoke #2078: seed truncation-gate rows');\n"
        "echo 'SEED-OK';\n",
    )
    assert seed.returncode == 0 and "SEED-OK" in seed.stdout, (
        f"failed to seed {CFG_ROWS}: stdout={seed.stdout!r} stderr={seed.stderr!r}"
    )

    yield

    restore = helpers.php_eval(
        vm,
        f"config_set_path('{CFG_ROWS}', unserialize(base64_decode('{prior_b64}')));\n"
        "write_config('pfBlockerNG smoke #2078: restore truncation-gate rows');\n"
        "echo 'RESTORE-OK';\n",
    )
    assert restore.returncode == 0 and "RESTORE-OK" in restore.stdout, (
        f"failed to restore {CFG_ROWS}: stdout={restore.stdout!r} stderr={restore.stderr!r}"
    )


def test_entity_heavy_short_values_render_without_an_ellipsis(
    smoke_vm: SmokeVM, webui: WebUI, _seeded_rows: None
) -> None:
    """Under the gate by raw characters, over it by escaped bytes -> no ellipsis (#2078)."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(CATEGORY_PAGE)
    # ?type=ipv4 never renders "Category" — the word reaches the body only from the DNSBL branch.
    result = evaluate_render(CATEGORY_PAGE, resp.status_code, resp.text, ("IPv4 Summary",))
    assert result.ok, f"Tier-A render oracle failed for the Category page: {result.detail}"

    body = resp.text
    escaped_alias = "aaaaaaaaaaaaa&amp;"
    escaped_desc = "aaaaaaaaaaa&amp;&amp;&amp;&amp;"

    # Fixture sanity: a page that never rendered the rows would pass vacuously.
    assert escaped_alias in body, "the seeded alias did not render at all -- fixture broken, not a #2078 signal"

    # The bug appended '...' directly after the complete escaped value.
    assert f"{escaped_alias}..." not in body, (
        "the alias rendered with an ellipsis although it is under the gate by raw "
        "characters -- the gate is measuring escaped bytes (issue #2078)"
    )
    assert f"{escaped_desc}..." not in body, (
        "the description rendered with an ellipsis although it is under the gate by raw "
        "characters -- the gate is measuring escaped bytes (issue #2078)"
    )

    # The control must still truncate, so the fix did not simply disable truncation.
    assert "abcdefghijklmno..." in body, "a 26-character value no longer truncates -- the gate fix went too far"
    assert f'title="{LONG_VALUE}"' in body, "the truncated cell lost its full-value title attribute"

    guard.assert_no_growth()
