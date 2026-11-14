"""Issues #3916, #3936 and #3947: DNSBL saves of the Permit Firewall Rules multi-select log no PHP diagnostic.

A browser sends nothing for a ``multiple`` select with no selection, so ``dnsbl_allow_int`` is absent from
the POST. PHP 8.5 deprecates the null key its validator then passed to ``array_key_exists()`` (#3916), and
reading the absent key logged ``Undefined array key`` (#3936), a class ``PhpErrorLogGuard`` reports but
does not gate, so it is counted here. A crafted POST nesting an array in it threw ``TypeError`` (#3947).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PHP_ERROR_LOG_CANDIDATES, PhpErrorLogGuard, input_errors_block
from .webui import scrape_form_fields

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
_ALLOW_INT = "installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_allow_int"


def _allow_int_undefined_key_count(vm: SmokeVM) -> int:
    """``Undefined array key "dnsbl_allow_int"`` lines raised in the DNSBL page, over every candidate php_error.log.

    Scoped to the key: the page's re-render logs other, unrelated keys of the same class.
    """
    logs = " ".join(PHP_ERROR_LOG_CANDIDATES)
    result = vm.ssh(
        f"cat {logs} 2>/dev/null | grep -F 'Undefined array key \"dnsbl_allow_int\"' | grep -c 'pfblockerng_dnsbl.php'"
    )
    return int(result.stdout.strip() or 0)


def test_dnsbl_save_without_allow_interface_logs_no_php_diagnostic(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """The POST omits dnsbl_allow_int and stops at a validation error, so the save writes nothing."""
    original = helpers.config_get_state(smoke_vm, _ALLOW_INT)
    try:
        helpers.config_set(smoke_vm, _ALLOW_INT, "")
        assert "dnsbl_allow_int[]" not in scrape_form_fields(webui.get(DNSBL_PAGE).text), (
            "fixture: no interface selected, so the form must submit no dnsbl_allow_int"
        )
        guard = PhpErrorLogGuard(smoke_vm)
        guard.snapshot()
        undefined_keys = _allow_int_undefined_key_count(smoke_vm)
        response = webui.post(DNSBL_PAGE, {"pfb_py_cache_max": "not-a-number"}, allow_redirects=False)
        assert response.status_code == 200, f"invalid POST must re-render, not redirect: {response.status_code}"
        errors = input_errors_block(response.text)
        assert errors and "Decision cache max entries" in errors, (
            f"POST must reach the save validator: {response.text[-4000:]}"
        )
        guard.assert_no_growth()
        assert _allow_int_undefined_key_count(smoke_vm) == undefined_keys, (
            'the save logged Undefined array key "dnsbl_allow_int" in pfblockerng_dnsbl.php'
        )
    finally:
        helpers.config_restore_state(smoke_vm, _ALLOW_INT, original)


def test_dnsbl_save_nested_multiselect_values_are_input_errors(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Crafted nested values past a valid one get the page's input errors, log no PHP error, and write nothing.

    ``dnsbl_allow_int`` is seeded with ``lan``, so a save that got through would reset it to the default ``""``.
    """
    original = helpers.config_get_state(smoke_vm, _ALLOW_INT)
    try:
        helpers.config_set(smoke_vm, _ALLOW_INT, "lan")
        assert scrape_form_fields(webui.get(DNSBL_PAGE).text).get("dnsbl_allow_int[]") == ["lan"], (
            "fixture: lan selected, so the form submits dnsbl_allow_int[0]=lan ahead of the crafted [1]"
        )
        guard = PhpErrorLogGuard(smoke_vm)
        guard.snapshot()
        response = webui.post(
            DNSBL_PAGE,
            {"dnsbl_allow_int[1][]": "x", "safesearch_doh_list[1][]": "x"},
            allow_redirects=False,
        )
        assert response.status_code == 200, f"invalid POST must re-render, not redirect: {response.status_code}"
        errors = input_errors_block(response.text) or ""
        for field in ("dnsbl_allow_int", "safesearch_doh_list"):
            assert f"the {field} selection is invalid" in errors, (
                f"nested {field} must be refused with an input error: {response.text[-4000:]}"
            )
        guard.assert_no_growth()
        assert helpers.config_get_state(smoke_vm, _ALLOW_INT) == (True, "lan"), "the refused save wrote the config"
    finally:
        helpers.config_restore_state(smoke_vm, _ALLOW_INT, original)


def test_dnsbl_save_port_posted_as_array_is_an_input_error(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """issue #4000: a crafted ``pfb_dnsport[]`` gets the page's input error and logs no PHP error.

    pfSense's ``is_port()`` handed the array to ``getservbyname()``, which threw ``TypeError`` (a 500).
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    response = webui.post(DNSBL_PAGE, {"pfb_dnsport[]": "8081"}, allow_redirects=False)
    assert response.status_code == 200, f"invalid POST must re-render, not redirect: {response.status_code}"
    errors = input_errors_block(response.text) or ""
    assert "DNSBL Port is invalid!" in errors, (
        f"an array port must be refused with an input error: {response.text[-4000:]}"
    )
    guard.assert_no_growth()
