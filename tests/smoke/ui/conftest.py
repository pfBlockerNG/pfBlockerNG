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
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ..conftest import SmokeVM
from .webui import SESSION_COOKIE, WebUI

if TYPE_CHECKING:
    from playwright.sync_api import BrowserContext, Page

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
def webui(smoke_vm: SmokeVM, admin_credentials: tuple[str, str], webgui_protocol: str) -> Iterator[WebUI]:
    """A logged-in :class:`WebUI` against the smoke VM's webConfigurator.

    Honours the RECON'd protocol: HTTPS on the throwaway image is driven with
    ``verify=False`` (self-signed cert). Yields AFTER a successful CSRF login so
    every consuming test starts authenticated; the session cookie is reusable
    via :meth:`WebUI.session_cookie` for a later browser phase.
    """
    username, password = admin_credentials
    https = webgui_protocol == "https"
    client = WebUI(
        host=smoke_vm.host,
        port=smoke_vm.web_port,
        username=username,
        password=password,
        scheme="https" if https else "http",
        verify=not https,
    )
    client.login()
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
