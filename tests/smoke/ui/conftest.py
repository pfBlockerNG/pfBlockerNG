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

import pytest

from ..conftest import SmokeVM
from .webui import WebUI

# Env var carrying the baked admin password (ADR-04 SMOKE_ADMIN_PASSWORD).
ADMIN_PASSWORD_ENV = "SMOKE_ADMIN_PASSWORD"
# Optional override of the admin username; pfSense's default is "admin".
ADMIN_USER_ENV = "SMOKE_ADMIN_USER"
DEFAULT_ADMIN_USER = "admin"


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
