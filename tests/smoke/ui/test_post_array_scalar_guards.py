"""issue #1070 -- array-valued $_POST fields must not 500 the settings saves.

Three settings-save handlers passed request fields straight into string
functions with no scalar coercion; in PHP 8 an array argument
(``field[]=x``, valid CSRF) throws ``TypeError`` BEFORE the input-errors
gate -- an HTTP 500 plus a fatal in ``php_error.log``:

* ``pfblockerng_sync.php`` rowhelper loop (``varsyncusername-0[]=x`` hit
  ``preg_match``/``strlen``) -- now rejects non-scalars up front, mirroring
  the ``hooks.php`` guard;
* ``pfblockerng_ip.php`` suppression textareas (``explode``/``base64_encode``)
  -- now rejected as an input error and blanked;
* ``pfblockerng_general.php`` feed-host allowlist (``trim``) -- now rejected
  as an input error before the save gate.

Each save must instead respond like any validation failure: HTTP 200, no
login bounce, and NOT ONE new byte in any candidate ``php_error.log``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from .webui import WebUI

# Tier B: mutating POST flows whose failure mode (a logged fatal + HTTP 500)
# is observable only end-to-end against the live php_error.log. Tier A render
# coverage of all three pages already exists (test_render_smoke.py).
pytestmark = pytest.mark.ui_e2e

_POST_TIMEOUT = 120.0


def _post_with_array_field(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    page: str,
    array_field: str,
) -> None:
    """Scrape the page's own form, replace one field with an array value, POST.

    Scenario: an authenticated save whose ``{array_field}[]`` carries an array.
      Given the page's own scraped field set (valid CSRF token included),
      When the field is re-sent in PHP array syntax and the save is POSTed,
      Then the handler answers HTTP 200 (a normal validation reject, never a
        TypeError-driven 500), the session survives, and no candidate
        ``php_error.log`` gained a byte during the request.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    got = webui.get(page)
    assert got.status_code == 200, f"GET {page} -> HTTP {got.status_code}"
    assert not looks_like_login_page(got.text), f"GET {page} bounced to the login form"

    payload = scrape_form_fields(got.text)
    payload.pop(array_field, None)
    payload[f"{array_field}[]"] = "crafted"
    payload["save"] = "Save"

    resp = webui.session.post(webui.url(page), data=payload, verify=webui._verify, timeout=_POST_TIMEOUT)

    assert resp.status_code == 200, (
        f"POST {page} with {array_field}[]=crafted -> HTTP {resp.status_code} "
        "(expected a graceful validation reject, not a TypeError 500)"
    )
    assert not looks_like_login_page(resp.text), f"POST {page} bounced to the login form"
    guard.assert_no_growth()


def test_sync_rowhelper_array_field_rejected_gracefully(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    _post_with_array_field(webui, smoke_vm, "/pfblockerng/pfblockerng_sync.php", "varsyncusername-0")


def test_ip_suppression_array_field_rejected_gracefully(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    _post_with_array_field(webui, smoke_vm, "/pfblockerng/pfblockerng_ip.php", "v4suppression")


def test_general_allowlist_array_field_rejected_gracefully(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    _post_with_array_field(webui, smoke_vm, "/pfblockerng/pfblockerng_general.php", "pfb_feed_internal_allowlist")
