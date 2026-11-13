"""Issue #3916: a DNSBL save with no Permit Firewall Rules interface selected logs no PHP diagnostic.

A browser sends nothing for a ``multiple`` select with no selection, so ``dnsbl_allow_int`` is absent from
the POST. PHP 8.5 deprecates the null key its validator then passed to ``array_key_exists()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, input_errors_block
from .webui import scrape_form_fields

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
_ALLOW_INT = "installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_allow_int"


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
        response = webui.post(DNSBL_PAGE, {"pfb_py_cache_max": "not-a-number"}, allow_redirects=False)
        assert response.status_code == 200, f"invalid POST must re-render, not redirect: {response.status_code}"
        errors = input_errors_block(response.text)
        assert errors and "Decision cache max entries" in errors, (
            f"POST must reach the save validator: {response.text[-4000:]}"
        )
        guard.assert_no_growth()
    finally:
        helpers.config_restore_state(smoke_vm, _ALLOW_INT, original)
