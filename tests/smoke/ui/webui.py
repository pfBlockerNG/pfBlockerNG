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
``pfsense/pfSense`` (see ``legacy/ADRs/ADR_14_UI_UX_Testing/RESULTS/01_Results.txt``):

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
pyproject's ``smoke`` dependency group.
"""

from __future__ import annotations

import html
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
# The submit button. pfSense GATES the credential check on this field's presence
# -- `if (isset($_POST['login']))` in authgui.inc -- so a POST of only the
# username/password/CSRF is NEVER authenticated; the form just re-renders at 200.
# The value is immaterial (isset, not a value compare); send the button's label.
LOGIN_FIELD = "login"
LOGIN_VALUE = "Sign In"

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


def looks_like_login_page(page_html: str) -> bool:
    """True iff ``page_html`` shows the webConfigurator login form (logged-out)."""
    return any(marker in page_html for marker in LOGIN_MARKERS)


# --------------------------------------------------------------------------- #
# Form scraping — reconstruct a page's CURRENT field values from its rendered
# HTML so a functional POST mirrors a browser submit: every field is sent at its
# present value and only the target field is overridden. Re-posting the page's
# own state is what keeps the box clean (no field is silently reset to a `?:`
# default by the save handler because an input was omitted). The csrf-magic
# output filter rewrites the form on each render, so the token AND the field set
# must both be re-scraped per POST (CSRF rotates per session; see RESULTS/01).
# --------------------------------------------------------------------------- #

# A self-closing/void <input ...>; attributes are pulled out by _attrs().
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
# A <select ...>...</select> block (its options parsed separately).
_SELECT_RE = re.compile(r"<select\b([^>]*)>(.*?)</select>", re.IGNORECASE | re.DOTALL)
# A <textarea ...>...</textarea> block (inner text is the value).
_TEXTAREA_RE = re.compile(r"<textarea\b([^>]*)>(.*?)</textarea>", re.IGNORECASE | re.DOTALL)
# One <option ...>...</option> inside a <select>.
_OPTION_RE = re.compile(r"<option\b([^>]*)>(.*?)</option>", re.IGNORECASE | re.DOTALL)
# name="x" / name='x' / name=x — tolerant of quote style.
_ATTR_RE = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")


def _attrs(tag_body: str) -> dict[str, str]:
    """Parse an HTML tag's attribute string into a ``{name: value}`` dict.

    Boolean attributes (``disabled`` / ``checked`` / ``selected`` / ``multiple``
    with no ``=value``) are NOT captured by the value regex; presence is tested
    separately with :func:`_has_flag`. Values are HTML-unescaped so a stored
    ``&amp;`` round-trips back to ``&``.
    """
    out: dict[str, str] = {}
    for match in _ATTR_RE.finditer(tag_body):
        name = match.group(1).lower()
        value = match.group(2) or match.group(3) or match.group(4) or ""
        out[name] = html.unescape(value)
    return out


def _has_flag(tag_body: str, flag: str) -> bool:
    """True iff a boolean attribute ``flag`` (``checked``/``disabled``/...) is present.

    Matches both the valued form (``disabled="disabled"``) and the bare form
    (``disabled``), but ONLY as an attribute NAME -- never the same token sitting
    inside another attribute's value (e.g. ``value="checked"`` or
    ``data-x="disabled-state"``), which a naive ``\\bflag\\b`` over the raw tag
    would wrongly match and misclassify the field during form reconstruction.
    """
    # Valued form: _attrs() already parses name="value" pairs, keyed lower-case.
    if flag.lower() in _attrs(tag_body):
        return True
    # Bare form: strip quoted values first so a token inside a value can't match,
    # then require the flag to stand as its own attribute name (start/space before,
    # space/=/end after).
    without_values = re.sub(r"\"[^\"]*\"|'[^']*'", "", tag_body)
    return re.search(rf"(?:^|\s){re.escape(flag)}(?=\s|=|/|>|$)", without_values, re.IGNORECASE) is not None


def scrape_form_fields(page_html: str) -> dict[str, str]:
    """Reconstruct the submittable ``{field: value}`` set from a rendered form.

    Mirrors what a browser would send on submit, so a functional POST that
    overrides ONE field leaves every other field at its current value:

    * ``<input>`` — text/hidden/etc. contribute ``name -> value``; a
      checkbox/radio contributes ONLY when ``checked`` (an unchecked box sends
      nothing, exactly like a browser — so an off checkbox is absent from the
      dict, and toggling it on is `overrides={name: value}`);
    * ``<select>`` — the ``selected`` option's value (or the first option's, the
      browser default when none is marked);
    * ``<textarea>`` — its inner text (HTML-unescaped).

    ``disabled`` controls are skipped (a disabled control is not submitted — this
    is why the ADR-13 auto-VIP dropdowns drop out of the POST when auto is on).
    Nameless controls and the submit buttons are left for the caller to add.
    Includes the ``__csrf_magic`` hidden input, so the returned dict already
    carries the per-render token.
    """
    fields: dict[str, str] = {}

    for body in _INPUT_RE.findall(page_html):
        attrs = _attrs(body)
        name = attrs.get("name")
        if not name or _has_flag(body, "disabled"):
            continue
        itype = attrs.get("type", "text").lower()
        if itype in ("checkbox", "radio"):
            if _has_flag(body, "checked"):
                fields[name] = attrs.get("value", "on")
        elif itype in ("submit", "button", "image", "reset", "file"):
            # Submit/button values are added explicitly by the caller (the save
            # action), not harvested — a browser sends only the clicked button.
            continue
        else:
            fields[name] = attrs.get("value", "")

    for body, inner in _SELECT_RE.findall(page_html):
        attrs = _attrs(body)
        name = attrs.get("name")
        if not name or _has_flag(body, "disabled"):
            continue
        # A multi-select can submit several values; the smoke flows target only
        # single-value selects, so take the first selected (or first option).
        selected: str | None = None
        first: str | None = None
        for opt_body, _label in _OPTION_RE.findall(inner):
            opt = _attrs(opt_body)
            value = opt.get("value", "")
            if first is None:
                first = value
            if _has_flag(opt_body, "selected"):
                selected = value
                break
        chosen = selected if selected is not None else first
        if chosen is not None:
            fields[name] = chosen

    for body, inner in _TEXTAREA_RE.findall(page_html):
        attrs = _attrs(body)
        name = attrs.get("name")
        if not name or _has_flag(body, "disabled"):
            continue
        fields[name] = html.unescape(inner)

    return fields


# --------------------------------------------------------------------------- #
# Row isolation -- locate the single <tr>...</tr> block around a marker
# --------------------------------------------------------------------------- #


def row_containing(html_body: str, needle: str) -> str:
    """Return the single ``<tr ...>...</tr>`` block containing ``needle`` (row-isolated).

    Alert-page renderers (e.g. ``convert_dnsbl_log()``, alerts.php:2571/2593) print one
    ``<tr>`` per event row with every cell/icon inside it. A fixed byte-distance window
    around a match can straddle a neighbouring row when rows are dense, false-matching
    (or false-missing) a marker that belongs to a different row -- isolating by the
    enclosing ``<tr>`` avoids that entirely.
    """
    idx = html_body.find(needle)
    assert idx != -1, f"{needle!r} not found in rendered HTML"
    tr_start = html_body.rfind("<tr", 0, idx)
    assert tr_start != -1, f"no opening <tr found before {needle!r}"
    tr_end = html_body.find("</tr>", idx)
    assert tr_end != -1, f"no closing </tr> found after {needle!r}"
    return html_body[tr_start : tr_end + len("</tr>")]


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
                # Without the submit field pfSense's `isset($_POST['login'])` gate
                # is false -> it skips auth and re-renders the form (a silent
                # "bad credentials" that is really "auth never attempted").
                LOGIN_FIELD: LOGIN_VALUE,
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

    def post(
        self,
        path: str,
        overrides: dict[str, str],
        *,
        submit: tuple[str, str] = ("save", "save"),
        **kwargs: Any,
    ) -> requests.Response:
        """Drive a webConfigurator form: GET ``path`` -> re-scrape its current
        fields + the ``__csrf_magic`` token -> apply ``overrides`` -> POST back.

        One call performs the full browser-faithful round-trip the CSRF design
        requires (RESULTS/01: the token is injected by the output filter per
        render, so it must be re-extracted on the freshly-GET'd form, never
        cached). The POSTed payload is the page's OWN current field set
        (:func:`scrape_form_fields`) with ``overrides`` applied, so every field
        not being changed is sent at its present value -- the save handler then
        rewrites config with only the intended delta and the box is left clean
        apart from the override.

        ``submit`` is the save button's ``(name, value)`` pair (pfBlockerNG save
        handlers gate on ``isset($_POST['save'])``); it is added to the payload
        so the handler's save branch runs. Returns the POST response (typically
        the post-redirect page); callers assert EFFECTIVE state (config.xml /
        pfctl / unbound), NOT this body (ADR §1 fact 3).
        """
        if not self._logged_in:
            raise WebUILoginError("post() called before login()")
        kwargs.setdefault("verify", self._verify)
        kwargs.setdefault("timeout", self._timeout)
        form_page = self._session.get(self.url(path), verify=self._verify, timeout=self._timeout)
        if looks_like_login_page(form_page.text):
            raise WebUILoginError(f"GET {self.url(path)} returned the login form -- session not authenticated")
        payload = scrape_form_fields(form_page.text)
        # The token comes from scrape_form_fields (it harvests the hidden input),
        # but assert it explicitly so a form that rendered without csrf-magic
        # fails loudly here rather than as an opaque "CSRF check failed" page.
        if CSRF_FIELD not in payload:
            payload[CSRF_FIELD] = extract_csrf_token(form_page.text)
        payload.update(overrides)
        payload[submit[0]] = submit[1]
        return self._session.post(self.url(path), data=payload, **kwargs)

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
