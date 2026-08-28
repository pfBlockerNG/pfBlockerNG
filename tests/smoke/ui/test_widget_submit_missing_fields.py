"""issue #1064 -- the widget's ``pfb_submit`` save must survive a POST with per-field keys omitted.

The ``pfb_submit`` branch (``pfblockerng.widget.php`` ~76-122) read every per-field
key (``pfb_popup``, ``pfb_sortcolumn``, ``pfb_dnsblquery``, ...) unguarded: the outer
``isset($_POST['pfb_submit'])`` gates the branch, not the keys, so a crafted POST
missing a field -- or a NORMAL save with a checkbox unchecked (an unchecked checkbox
posts no key at all) -- logged one PHP 8.3 "Undefined array key" warning per field.
Same crafted-POST class: a submitted request omits expected per-field keys; the
``pfblockerngack`` guard was fixed on PR #1061.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from .webui import WebUI

# Tier B: a mutating POST flow whose failure mode is a logged-but-not-echoed PHP
# warning -- observable only end-to-end against the live php_error.log. Tier A's
# plain-GET render coverage of this page already exists (test_render_smoke.py).
pytestmark = pytest.mark.ui_e2e

WIDGET_PAGE = "/widgets/widgets/pfblockerng.widget.php"


def test_widget_save_missing_per_field_keys_does_not_warn(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A ``pfb_submit`` POST with every per-field key omitted must not raise
    "Undefined array key" PHP warnings (issue #1064).

    Can't use ``WebUI.post()`` -- it always resends the page's OWN scraped field
    set, so it can never OMIT one; this replicates its scrape-then-POST shape with
    the per-field keys deleted first; ``$nocsrf = TRUE`` on this page means no
    ``__csrf_magic`` token exists to scrape.

    Scenario: widget save survives a POST carrying only the submit marker.
      Background: pfBlockerNG deployed; webConfigurator authenticated.

    Given the widget page's own scraped field set,

    When every ``pfb_*`` per-field key is deleted from it (simulating a crafted/
      truncated client request; a real save with all checkboxes unchecked omits
      the checkbox keys the same way) and ``pfb_submit`` alone is posted,

    Then the response is a save success (the handler redirects to ``/``; never a
      server error), the session is still authenticated (no bounce to the login
      form), AND no candidate ``php_error.log`` gained a gated-class diagnostic
      during the request (the guard that catches a logged-but-not-echoed PHP
      warning). #1218: the ``Undefined array key`` class this fault emitted is
      REPORTED rather than gated, so the save-success and session assertions are
      what this test rests on, not the log guard.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    page = webui.get(WIDGET_PAGE)
    assert page.status_code == 200, f"GET {WIDGET_PAGE} -> HTTP {page.status_code} (expected 200)"
    assert not looks_like_login_page(page.text), "pre-save GET bounced to the login page -- not authenticated"

    payload = scrape_form_fields(page.text)
    for key in [k for k in payload if k.startswith("pfb_")]:
        del payload[key]
    payload["pfb_submit"] = "save"

    # issue #1650: pfb_widget_post_allowed() is default-deny on an absent
    # Sec-Fetch-Site; emulate the modern browser's same-origin form POST.
    resp = webui.session.post(
        webui.url(WIDGET_PAGE),
        data=payload,
        headers={"Sec-Fetch-Site": "same-origin"},
        timeout=30,
    )

    assert resp.status_code == 200, (
        f"POST {WIDGET_PAGE} pfb_submit (fields omitted) -> HTTP {resp.status_code} "
        "(expected 200 after the handler's redirect to /)"
    )
    assert not looks_like_login_page(resp.text), "save POST bounced to the login page -- session not authenticated"
    guard.assert_no_growth()
