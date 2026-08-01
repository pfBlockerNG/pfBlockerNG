"""Tier-A ``ui_render`` coverage for issue #1792: a stored textarea value of
literally ``"0"`` survives to the re-rendered form.

The DNSBL page prefilled its base64 textareas through
``base64_decode($x) ?: ''`` — and ``base64_decode('MA==') === '0'``, which is
falsy, so a Whitelist list holding exactly ``0`` re-rendered as an EMPTY
textarea (saving the form again would then silently erase the stored value).
The #1792 sweep moved the prefill onto ``pfb_b64_text()``, which only degrades
to ``''`` on a FALSE (malformed) decode.

Self-encapsulated: the config node is restored to its exact prior value in
teardown. ``"0"`` is inert here — the page render never resolves it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
CFG_WHITELIST = "installedpackages/pfblockerngdnsblsettings/config/0/whitelist"
ZERO_B64 = "MA=="  # base64_encode('0')


@pytest.fixture
def _seeded_zero_whitelist(smoke_vm: SmokeVM) -> Iterator[None]:
    vm = smoke_vm
    prior = helpers.config_get(vm, CFG_WHITELIST)
    write = helpers.php_eval(
        vm,
        f"config_set_path('{CFG_WHITELIST}', '{ZERO_B64}');\n"
        "write_config('pfBlockerNG smoke #1792: seed zero whitelist');\n"
        "echo 'SEED-OK';\n",
    )
    assert write.returncode == 0 and "SEED-OK" in write.stdout, (
        f"failed to seed the whitelist node: stdout={write.stdout!r} stderr={write.stderr!r}"
    )
    yield
    restore = helpers.php_eval(
        vm,
        f"config_set_path('{CFG_WHITELIST}', '{prior}');\n"
        "write_config('pfBlockerNG smoke #1792: restore whitelist');\n"
        "echo 'RESTORE-OK';\n",
    )
    assert restore.returncode == 0 and "RESTORE-OK" in restore.stdout, (
        f"failed to restore the whitelist node: stdout={restore.stdout!r} stderr={restore.stderr!r}"
    )
    assert helpers.config_get(vm, CFG_WHITELIST) == prior, (
        "whitelist config restore did not take -- the seeded '0' leaked to sibling tests"
    )


def test_stored_zero_whitelist_prefills_the_textarea(
    smoke_vm: SmokeVM, webui: WebUI, _seeded_zero_whitelist: None
) -> None:
    """A DNSBL Whitelist holding exactly "0" re-renders as "0", never empty."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"

    m = re.search(r'name="whitelist"[^>]*>(.*?)</textarea>', resp.text, re.DOTALL)
    assert m is not None, "whitelist textarea not found on the DNSBL page -- fixture broken, not a #1792 signal"
    assert m.group(1).strip() == "0", (
        f"a stored '0' whitelist list must prefill as '0', got {m.group(1).strip()!r} "
        "-- the base64 prefill is eating falsy decodes again (issue #1792)"
    )

    guard.assert_no_growth()
