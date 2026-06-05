"""Fixtures for the ADR-14 Web-UI tier (built on the ADR-04 ``smoke_vm``).

These fixtures only ever run under the smoke/ui workflow (the whole
``tests/smoke`` tree is ``--ignore``d in default collection), so importing
``requests`` here -- deferred into :class:`tests.smoke.ui.webui.WebUI` -- never
touches a default ``python -m pytest`` run.

Credentials: the pfSense ``admin`` password is the ADR-04 baked
``SMOKE_ADMIN_PASSWORD`` (bcrypt in ``config.xml``, plaintext in the secret).
It is NOT yet exported to pytest by ``smoke.yml`` (ADR-04 used SSH-key auth and
reachability-only WebUI). :func:`admin_credentials` reads it from the
environment and SKIPS (not fails) when absent, so a local ``pytest -m ui_render``
without the secret skips cleanly. Phase 5 wires ``SMOKE_ADMIN_PASSWORD`` (and an
optional ``SMOKE_ADMIN_USER``) into the workflow's pytest ``env:`` block -- this
phase does NOT edit any workflow.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ..conftest import SmokeVM
from .webui import SESSION_COOKIE, WebUI

if TYPE_CHECKING:
    from playwright.sync_api import BrowserContext, Page

# A pfBlockerNG GUI page used as the webConfigurator-readiness probe after deploy
# (see `webui`). Any package page works; general.php is the lightest and always
# present.
PFB_READY_PATH = "/pfblockerng/pfblockerng_general.php"
# Bound for the readiness poll: pfSense brings a freshly-installed package's GUI
# pages online a moment AFTER `pkg add` returns (POST-INSTALL reconfigures the
# webConfigurator/menu); install-pkg.sh only waits on Unbound, a PROXY signal.
# 60 x 2s = 120s headroom; a real never-served page still fails (raises), not masks.
PFB_READY_ATTEMPTS = 60
PFB_READY_DELAY = 2.0

# Env var carrying the baked admin password (ADR-04 SMOKE_ADMIN_PASSWORD).
ADMIN_PASSWORD_ENV = "SMOKE_ADMIN_PASSWORD"
# Optional override of the admin username; pfSense's default is "admin".
ADMIN_USER_ENV = "SMOKE_ADMIN_USER"
DEFAULT_ADMIN_USER = "admin"

# Where the Tier-B browser screenshots are written. Overridable so CI can point
# it at the job's artifact dir; defaults to a repo-relative build-output tree
# (git-ignored, never committed). Laid out <root>/<version>/<page>.png by the
# browser tests; the <version> sub-dir is set from SMOKE_UI_VERSION (the pfSense
# image ref/version the matrix leg runs), defaulting to "unknown".
SCREENSHOT_DIR_ENV = "SMOKE_UI_SCREENSHOT_DIR"
SCREENSHOT_VERSION_ENV = "SMOKE_UI_VERSION"
DEFAULT_SCREENSHOT_ROOT = "test-results/ui-screenshots"
DEFAULT_SCREENSHOT_VERSION = "unknown"


@pytest.fixture(scope="session")
def admin_credentials() -> tuple[str, str]:
    """``(username, password)`` for the webConfigurator, from the environment.

    Skips when ``SMOKE_ADMIN_PASSWORD`` is unset so a credential-less local run
    is a clean skip rather than a login failure.
    """
    password: str | None = os.environ.get(ADMIN_PASSWORD_ENV)
    if not password:
        pytest.skip(f"{ADMIN_PASSWORD_ENV} not set -- no webConfigurator admin password")
    assert password is not None  # narrow for the type checker (pytest.skip is NoReturn)
    username = os.environ.get(ADMIN_USER_ENV) or DEFAULT_ADMIN_USER
    return username, password


@pytest.fixture(scope="session")
def webgui_protocol(smoke_vm: SmokeVM) -> str:
    """The live webConfigurator protocol from ``config.xml`` (RECON, not assumed).

    Reads ``<system><webgui><protocol>`` via the pfSense config API over SSH
    (``config_get_path('system/webgui/protocol')``), the source of truth per
    CLAUDE.md. Evidence says ``http`` (``wait_ready.sh`` polls plain HTTP with no
    forced HTTPS redirect); this confirms it on the actual image. Empty/absent
    defaults to ``http`` (pfSense's own default when the key is unset).
    """
    from .. import helpers

    proto = helpers.config_get(smoke_vm, "system/webgui/protocol").strip().lower()
    return proto or "http"


@pytest.fixture(scope="session")
def deployed_vm(smoke_vm: SmokeVM) -> SmokeVM:
    """The smoke VM with the branch pfBlockerNG ``.pkg`` installed (once/session).

    ``smoke_vm`` only pulls/boots the base pfSense image; the ADR-04 smoke matrix
    tests each call :func:`tests.smoke.helpers.deploy` themselves. The UI tiers
    need pfBlockerNG's webConfigurator pages PRESENT, so deploy here -- otherwise
    every pfBlockerNG page 404s (pfSense core, e.g. the login page, still serves),
    which reads as a UI failure but is really "the package was never installed".
    ``pkg add`` resolves RUN_DEPENDS from the baked image offline (ADR-04), so no
    egress is required.
    """
    from .. import helpers

    helpers.deploy(smoke_vm)
    return smoke_vm


# general.php?wizard=disable: the "Do not show this again" action. A fresh pfBlockerNG
# install AUTO-LAUNCHES its setup wizard -- pfblockerng_general.php 302-redirects to
# wizard.php until `pfb_wizard_skip` is 'on' (or config/0 is populated), so a UI test
# that GETs general.php on a fresh box lands on the WIZARD, not General settings
# (pfb_wizard_suppress_autolaunch, pfblockerng.inc:1759). The readiness probe accepts the
# wizard's 200, so it passes uninformed.
WIZARD_DISMISS_PATH = PFB_READY_PATH + "?wizard=disable"


def _dismiss_pfblockerng_wizard(client: WebUI) -> None:
    """GET general.php?wizard=disable once so the first-run wizard stops shadowing it.

    The `disable` action persists `pfb_wizard_skip='on'` (general.php:38) AND renders the
    real General page on the same request (pfb_wizard_suppress_autolaunch reads the
    just-written flag), so one authenticated GET makes general.php deterministic for the
    whole session -- exactly what an admin clicking "Do not show this again" does. Raises
    on a non-200 so a failed dismiss surfaces precisely here rather than as a confusing
    "field not found" in every general.php test downstream.
    """
    resp = client.get(WIZARD_DISMISS_PATH)
    if resp.status_code != 200:
        raise RuntimeError(f"wizard-dismiss GET {WIZARD_DISMISS_PATH} -> HTTP {resp.status_code}")


def _wait_pfblockerng_pages_served(client: WebUI) -> None:
    """Block until the webConfigurator actually SERVES a pfBlockerNG GUI page.

    ``deploy()`` (install-pkg.sh) returns as soon as ``unbound-control status``
    answers -- a PROXY: pfSense brings a freshly-installed package's GUI pages
    online a moment LATER (POST-INSTALL reconfigures the webConfigurator/menu).
    A test that GETs a pfBlockerNG page inside that window gets a 404 even though
    the package installed fine (its backend + Unbound wiring are already up). That
    race is leg-dependent -- the render tier, the quickest to GET a page after
    deploy, loses it most often (every page 404s; pfSense core still serves the
    login form at 200) while the slower functional/browser tiers settle in time.

    So poll the REAL readiness signal here -- the package page returning HTTP 200
    (served; authenticated -> the real page, but ANY 200 means the file is now
    routed, vs 404 while it is not) -- before any test runs. A page that is never
    served raises (a genuine deploy/GUI failure), it is not masked.
    """
    last = ""
    for _ in range(PFB_READY_ATTEMPTS):
        try:
            resp = client.get(PFB_READY_PATH)
        except Exception as exc:  # noqa: BLE001 -- transient HTTP error during GUI reconfigure; retry
            last = f"GET error: {exc!r}"
        else:
            if resp.status_code == 200:
                return
            last = f"HTTP {resp.status_code}"
        time.sleep(PFB_READY_DELAY)
    raise RuntimeError(
        f"webConfigurator never served {PFB_READY_PATH} (last: {last}) after "
        f"{PFB_READY_ATTEMPTS}x{PFB_READY_DELAY}s -- pfBlockerNG GUI pages not online post-deploy"
    )


@pytest.fixture(scope="session")
def webui(deployed_vm: SmokeVM, admin_credentials: tuple[str, str], webgui_protocol: str) -> Iterator[WebUI]:
    """A logged-in :class:`WebUI` against the smoke VM's webConfigurator.

    Honours the RECON'd protocol: HTTPS on the throwaway image is driven with
    ``verify=False`` (self-signed cert). Yields AFTER a successful CSRF login AND
    after the webConfigurator is confirmed to be serving pfBlockerNG's GUI pages
    (:func:`_wait_pfblockerng_pages_served` -- closes the post-deploy GUI-readiness
    race, see its docstring), so every consuming test starts authenticated against
    a GUI that actually serves the package pages. The session cookie is reusable
    via :meth:`WebUI.session_cookie` for a later browser phase.
    """
    username, password = admin_credentials
    https = webgui_protocol == "https"
    client = WebUI(
        host=deployed_vm.host,
        port=deployed_vm.web_port,
        username=username,
        password=password,
        scheme="https" if https else "http",
        verify=not https,
    )
    client.login()
    # Login hits pfSense CORE (always up); the package's own GUI pages come online
    # slightly later -- wait for one to actually serve before yielding to tests.
    _wait_pfblockerng_pages_served(client)
    # On a fresh install general.php auto-launches the setup wizard (redirects to
    # wizard.php); dismiss it once so every general.php test sees the real page.
    _dismiss_pfblockerng_wizard(client)
    yield client


# --------------------------------------------------------------------------- #
# Tier B — browser (ADR-14 Phase 4). Headless Chromium reusing the Phase-1
# authenticated session: the `webui` PHPSESSID cookie is injected into the
# browser context so the browser never logs in a second time (a second login is
# a second flake source — ADR §2 "inject the session cookie to avoid a second
# login"). Playwright is imported lazily/guarded so collecting this package
# without it installed does NOT hard-error (it is a dev-only smoke dep added to
# tests/smoke/requirements.txt; the Chromium binary download is a Phase-5 CI
# setup step). All fixtures here run only under the smoke/ui override.
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def screenshot_dir() -> Path:
    """The per-version screenshot output dir (created); artifacts, not committed.

    Layout ``<root>/<version>/`` — root from ``SMOKE_UI_SCREENSHOT_DIR`` (default
    ``test-results/ui-screenshots``, git-ignored), version from
    ``SMOKE_UI_VERSION`` (the image ref the matrix leg runs; default
    ``unknown``). The browser tests write ``<page>.png`` into it.
    """
    root = os.environ.get(SCREENSHOT_DIR_ENV) or DEFAULT_SCREENSHOT_ROOT
    version = os.environ.get(SCREENSHOT_VERSION_ENV) or DEFAULT_SCREENSHOT_VERSION
    out = Path(root) / version
    out.mkdir(parents=True, exist_ok=True)
    return out


@pytest.fixture(scope="session")
def browser_context(webui: WebUI, smoke_vm: SmokeVM) -> Iterator[BrowserContext]:
    """A headless-Chromium context carrying the Phase-1 session cookie.

    Skips cleanly (never errors) when Playwright is not installed, so collecting
    this package on a host without the browser tier's dep does not break — the
    import is deferred here, behind ``importorskip``. Launches one headless
    Chromium for the session and injects the ``PHPSESSID`` cookie harvested from
    the authenticated :class:`WebUI` session so the browser is already logged in
    (no second login). HTTPS on the throwaway image uses ``ignore_https_errors``
    to match the ``verify=False`` the HTTP client uses for the self-signed cert.
    """
    sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")

    cookie = webui.session_cookie()
    if cookie is None:
        pytest.skip("no PHPSESSID on the webui session -- cannot inject the browser cookie")

    https = webui.base_url.startswith("https://")
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=https)
        # Inject the authenticated session cookie so the browser reuses the
        # Phase-1 login. Scope it to the VM host so it rides every request.
        context.add_cookies(
            [
                {
                    "name": SESSION_COOKIE,
                    "value": cookie,
                    "domain": smoke_vm.host,
                    "path": "/",
                }
            ]
        )
        try:
            yield context
        finally:
            context.close()
            browser.close()


@pytest.fixture
def browser_page(browser_context: BrowserContext) -> Iterator[Page]:
    """A fresh page on the session-scoped authenticated context (per test)."""
    page = browser_context.new_page()
    try:
        yield page
    finally:
        page.close()
