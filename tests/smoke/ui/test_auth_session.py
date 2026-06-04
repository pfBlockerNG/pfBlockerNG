"""Pin the authenticated-WebUI session contract on the live smoke VM (ADR-14 P1).

Marker ``ui_render`` -- collected only by the smoke/ui workflow
(``pytest tests/smoke -m ui_render --override-ini="addopts="``); the whole
``tests/smoke`` tree is ``--ignore``d in the default ``python -m pytest`` run, so
this never affects the default suite.

What it pins (the ADR §2 "Auth session is reusable + correct" contract):

* the CSRF form login succeeds and establishes a ``PHPSESSID`` session;
* an AUTHENTICATED GET of a known pfBlockerNG page returns HTTP 200 with a
  page-specific content marker and is NOT the login form;
* an UNAUTHENTICATED GET of that same protected page shows the login form
  instead (pfSense renders the login form in place at HTTP 200 -- it does not
  302-redirect; see tests.smoke.ui.webui).

Both sides of the auth toggle are asserted on the SAME page (logged-out shows
the login form / not the page; logged-in shows the page / not the login form),
so a green proves the session is what makes the page reachable.
"""

from __future__ import annotations

import pytest

from .webui import SESSION_COOKIE, WebUI, looks_like_login_page

pytestmark = pytest.mark.ui_render

# A stable, hermetic pfBlockerNG page to probe (no feed download to render).
PFB_PAGE = "/pfblockerng/pfblockerng_general.php"
# Markers present on a rendered pfBlockerNG page's chrome (the breadcrumb +
# tab labels emitted by pfblockerng_general.php's $pgtitle / $tab_array). Any
# one present (and the login form absent) proves the real page rendered.
PFB_PAGE_MARKERS = ("pfBlockerNG", "DNSBL")


def test_login_establishes_session(webui: WebUI) -> None:
    """The CSRF login yields an authenticated ``PHPSESSID`` session.

    The ``webui`` fixture already calls ``login()``; assert the observable
    result -- a session cookie is set.
    """
    cookie = webui.session_cookie()
    assert cookie, f"expected a {SESSION_COOKIE} cookie after login, got {cookie!r}"


def test_authenticated_get_returns_pfblockerng_page(webui: WebUI) -> None:
    """An authenticated GET of a pfBlockerNG page returns 200 + a content marker."""
    resp = webui.get(PFB_PAGE)
    assert resp.status_code == 200, f"GET {PFB_PAGE} -> HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert not looks_like_login_page(body), (
        f"authenticated GET {PFB_PAGE} unexpectedly returned the login form "
        f"(status {resp.status_code}) -- the session is not authenticated"
    )
    assert any(marker in body for marker in PFB_PAGE_MARKERS), (
        f"GET {PFB_PAGE} body missing all page markers {PFB_PAGE_MARKERS!r}"
    )


def test_unauthenticated_get_shows_login_form(webui: WebUI) -> None:
    """An UNAUTHENTICATED GET of the same protected page shows the login form.

    Before-state for the auth toggle: with no session, pfSense renders the login
    form in place (HTTP 200) rather than the page. Paired with
    ``test_authenticated_get_returns_pfblockerng_page`` (logged-in shows the
    page), this proves the session is what unlocks the page -- not that the page
    is reachable unauthenticated.
    """
    resp = webui.get_unauthenticated(PFB_PAGE)
    # pfSense renders the login form in place at HTTP 200 (no 302) -- assert the
    # status too, symmetric with the authenticated case, so a future redirect or
    # error status is caught rather than silently passing on body shape alone.
    assert resp.status_code == 200, (
        f"unauthenticated GET {PFB_PAGE} -> HTTP {resp.status_code} (expected 200; pfSense renders login in place)"
    )
    body = resp.text
    assert looks_like_login_page(body), (
        f"unauthenticated GET {PFB_PAGE} (status {resp.status_code}) did not return the "
        f"login form -- the page must not be reachable without a session"
    )
    assert not any(marker in body for marker in PFB_PAGE_MARKERS), (
        f"unauthenticated GET {PFB_PAGE} leaked page content (markers {PFB_PAGE_MARKERS!r}) without a session"
    )
