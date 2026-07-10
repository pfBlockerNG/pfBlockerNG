"""issue #1070 -- array-valued $_POST fields must not 500 the settings saves.

The Sync/IP/General settings handlers passed request fields into string
functions with no scalar coercion; in PHP 8 an array argument (``field[]=x``,
valid CSRF) throws ``TypeError`` BEFORE the input-errors gate -- an HTTP 500
plus a fatal in ``php_error.log``. Two guard layers close it for these pages:

* the shared ``pfb_filter()`` rejects an array as invalid up front, so every
  ``ON_OFF``/``WORD``/``NUM``-filtered field (the bulk of the sites) is safe
  in one place;
* the three fields that bypass ``pfb_filter`` (the sync rowhelper loop, the IP
  suppression textareas' ``explode``/``base64_encode``, the General allowlist
  ``trim``) plus the IP ``array_key_exists`` site get inline scalar guards.

Scope: this closes issue #1070's enumerated pages plus the ``pfb_filter``
root for every filter-routed caller. ``pfblockerng_category_edit.php`` has a
separate cluster of direct-string sinks that bypass ``pfb_filter`` -- tracked
in #1106, not covered here.

Each save must respond like any validation failure: HTTP 200, no login
bounce, and NOT ONE new byte in any candidate ``php_error.log``.
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


# (page, field) covering every array-TypeError class the theme spans (issue #1070):
# the 3 directly-guarded fields (explode/base64/trim), plus representatives of the
# pfb_filter-routed classes closed by the shared guard -- ON_OFF, WORD, NUM -- and
# the array_key_exists site. All resolve to the same graceful-reject assertion.
_ARRAY_FIELD_CASES = [
    ("/pfblockerng/pfblockerng_sync.php", "varsyncusername-0"),  # rowhelper loop
    ("/pfblockerng/pfblockerng_sync.php", "varsynctimeout"),  # pfb_filter NUM (pre-loop)
    ("/pfblockerng/pfblockerng_ip.php", "v4suppression"),  # explode/base64
    ("/pfblockerng/pfblockerng_ip.php", "enable_dup"),  # pfb_filter ON_OFF
    ("/pfblockerng/pfblockerng_ip.php", "asn_token"),  # pfb_filter WORD
    ("/pfblockerng/pfblockerng_ip.php", "pfb_alias_delta_mode"),  # array_key_exists
    ("/pfblockerng/pfblockerng_general.php", "pfb_feed_internal_allowlist"),  # trim
    ("/pfblockerng/pfblockerng_general.php", "enable_cb"),  # pfb_filter ON_OFF
]


@pytest.mark.parametrize(("page", "field"), _ARRAY_FIELD_CASES)
def test_array_valued_field_rejected_gracefully(webui: WebUI, smoke_vm: helpers.SmokeVM, page: str, field: str) -> None:
    _post_with_array_field(webui, smoke_vm, page, field)
