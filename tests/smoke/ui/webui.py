"""A reusable authenticated webConfigurator session client (ADR-14 Phase 1).

The pfSense WebUI is CSRF-protected (``csrf-magic``) and form-login only, so a
test that drives a page must first log in like a browser:

1. GET the login page -> the ``csrf-magic`` output filter has injected a hidden
   ``__csrf_magic`` input (value ``sid:<hash>,<timestamp>``) into the POST form;
2. POST ``__csrf_magic`` + ``usernamefld`` + ``passwordfld`` back to the SAME
   URL -> on success the server establishes the PHP session (``PHPSESSID``
   cookie) and returns the requested page;
3. subsequent GETs carry that cookie -> authenticated.

Field/cookie names are pfSense-core facts confirmed against upstream
``pfsense/pfSense`` (see ``.ADRs/ADR_14_UI_UX_Testing/RESULTS/01_Results.txt``):

* login form fields ``usernamefld`` / ``passwordfld`` -- ``src/etc/inc/authgui.inc``
  ``display_login_form()`` (``<input name="usernamefld" ...>`` /
  ``<input name="passwordfld" ...>``);
* CSRF hidden input ``__csrf_magic`` -- ``src/usr/local/www/csrf/csrf-magic.php``
  (``$GLOBALS['csrf']['input-name'] = '__csrf_magic';``), injected after every
  ``method="post"`` form by ``csrf_ob_handler()``, value prefixed ``sid:``;
* the login form is ``<form method="post" ... class="login">`` with NO action ->
  it posts back to the requested URL;
* an UNAUTHENTICATED request to a protected page renders the login form IN PLACE
  with HTTP 200 (``authgui.inc``: ``if (!session_auth()) { display_login_form();
  exit; }``) -- it does NOT 302-redirect. So "logged out" is detected by the
  presence of the login form (the ``Sign In`` form-title / the login fields),
  not by an HTTP status. :data:`LOGIN_MARKERS` captures that.

The WebUI protocol on the smoke image is plain HTTP (``wait_ready.sh`` polls
``curl -fsSL http://...:8080/`` with no forced HTTPS redirect, and
``config.xml`` ``<system><webgui><protocol>`` is confirmed in Phase 1 RECON).
:class:`WebUI` defaults to ``http`` but accepts ``scheme="https"`` +
``verify=False`` for a throwaway HTTPS image.

``requests`` is imported lazily (inside ``__init__``), mirroring how the smoke
suite defers ``dnspython`` -- so importing this module during default collection
(which never runs it) needs no third-party dep. ``requests`` is listed in
``tests/smoke/requirements.txt``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import requests

# csrf-magic hidden input name (src/usr/local/www/csrf/csrf-magic.php:
# $GLOBALS['csrf']['input-name'] = '__csrf_magic';). The output filter injects
# <input type='hidden' name='__csrf_magic' value="sid:..."> after each POST form.
CSRF_FIELD = "__csrf_magic"

# Login form field names (src/etc/inc/authgui.inc display_login_form()).
USERNAME_FIELD = "usernamefld"
PASSWORD_FIELD = "passwordfld"

# PHP session cookie. pfSense uses PHP's default session name; the cookie the
# webConfigurator sets on a successful login is PHPSESSID.
SESSION_COOKIE = "PHPSESSID"

# Substrings that, when present in a response body, mean the login form is being
# shown (i.e. the request was NOT authenticated). pfSense renders the login form
# in place (HTTP 200) for an unauthenticated protected GET, so this -- not the
# status code -- is the logged-out signal. The form-title 'Sign In' and the two
# field ids come straight from display_login_form().
LOGIN_MARKERS = ("Sign In", 'id="usernamefld"', 'id="passwordfld"')

# Pull the hidden __csrf_magic token out of the login page HTML. Matches either
# quote style and is tolerant of attribute order (name before/after value).
_CSRF_RE = re.compile(
    r"""<input\b[^>]*\bname=['"]__csrf_magic['"][^>]*\bvalue=['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_CSRF_RE_VALUE_FIRST = re.compile(
    r"""<input\b[^>]*\bvalue=['"]([^'"]+)['"][^>]*\bname=['"]__csrf_magic['"]""",
    re.IGNORECASE,
)


class WebUILoginError(RuntimeError):
    """Raised when the CSRF login does not yield an authenticated session."""


def extract_csrf_token(html: str) -> str:
    """Return the ``__csrf_magic`` hidden-input value from a page's HTML.

    Raises :class:`WebUILoginError` if the token is absent (e.g. the page was
    not the login form, or csrf-magic did not run).
    """
    match = _CSRF_RE.search(html) or _CSRF_RE_VALUE_FIRST.search(html)
    if match is None:
        raise WebUILoginError("no __csrf_magic token found in page HTML")
    return match.group(1)


def looks_like_login_page(html: str) -> bool:
    """True iff ``html`` shows the webConfigurator login form (logged-out)."""
    return any(marker in html for marker in LOGIN_MARKERS)


class WebUI:
    """An authenticated webConfigurator HTTP session for the smoke VM.

    Build it from a :class:`tests.smoke.conftest.SmokeVM`'s host/web-port plus
    the admin credentials, call :meth:`login` once, then :meth:`get` any path.
    The underlying :class:`requests.Session` (and thus the ``PHPSESSID`` cookie)
    is exposed via :attr:`session` / :meth:`session_cookie` so a later phase can
    inject the cookie into a Playwright browser context (avoids a second login).
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        scheme: str = "http",
        verify: bool = True,
        timeout: float = 30.0,
    ) -> None:
        # Lazy import: keep the third-party dep out of default collection (the
        # smoke suite is --ignore'd there). Mirrors conftest.resolve_a deferring
        # dnspython into the call.
        import requests

        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._scheme = scheme
        self._verify = verify
        self._timeout = timeout
        self._session: requests.Session = requests.Session()
        self._logged_in = False

    @property
    def base_url(self) -> str:
        """``<scheme>://<host>:<port>`` -- the webConfigurator root."""
        return f"{self._scheme}://{self._host}:{self._port}"

    @property
    def session(self) -> requests.Session:
        """The underlying ``requests`` session (cookie jar included)."""
        return self._session

    def url(self, path: str) -> str:
        """Absolute URL for a site-relative ``path`` (leading ``/`` optional)."""
        return f"{self.base_url}/{path.lstrip('/')}"

    def session_cookie(self) -> str | None:
        """The current ``PHPSESSID`` value, or ``None`` before login.

        This is the cookie a browser-tier phase injects to reuse the session.
        """
        return self._session.cookies.get(SESSION_COOKIE)

    def login(self, login_path: str = "/index.php") -> None:
        """Perform the CSRF form login; raise on failure.

        GETs ``login_path`` to harvest ``__csrf_magic`` (and seed the session
        cookie), then POSTs the credentials back to the SAME URL. Verifies the
        result is authenticated -- the response body must NOT still be the login
        form (pfSense returns the login form at HTTP 200 on bad creds, so a
        status check alone is insufficient).
        """
        get_resp = self._session.get(
            self.url(login_path),
            verify=self._verify,
            timeout=self._timeout,
        )
        token = extract_csrf_token(get_resp.text)
        post_resp = self._session.post(
            self.url(login_path),
            data={
                CSRF_FIELD: token,
                USERNAME_FIELD: self._username,
                PASSWORD_FIELD: self._password,
            },
            verify=self._verify,
            timeout=self._timeout,
            allow_redirects=True,
        )
        if looks_like_login_page(post_resp.text):
            raise WebUILoginError(
                f"login POST to {self.url(login_path)} still returned the login form "
                f"(status {post_resp.status_code}) -- bad credentials or no session established"
            )
        if self.session_cookie() is None:
            raise WebUILoginError(f"login POST to {self.url(login_path)} set no {SESSION_COOKIE} cookie")
        self._logged_in = True

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        """Authenticated GET of ``path`` (call :meth:`login` first).

        Extra keyword args pass through to ``requests`` (e.g. ``allow_redirects``).
        ``verify``/``timeout`` default to the client's configured values.
        """
        if not self._logged_in:
            raise WebUILoginError("get() called before login()")
        kwargs.setdefault("verify", self._verify)
        kwargs.setdefault("timeout", self._timeout)
        return self._session.get(self.url(path), **kwargs)

    def get_unauthenticated(self, path: str, **kwargs: Any) -> requests.Response:
        """GET ``path`` on a FRESH cookie-less session (no login).

        Used to assert that a protected page shows the login form when not
        authenticated. Does not touch this client's logged-in session.
        """
        import requests

        kwargs.setdefault("verify", self._verify)
        kwargs.setdefault("timeout", self._timeout)
        with requests.Session() as anon:
            return anon.get(self.url(path), **kwargs)
