"""Credential-gate decision for the UI tier — a pure, dependency-free helper.

Kept in its own module (no ``requests``/VM imports) so the default unit suite can
import and test it; ``tests/smoke`` itself is ``--ignore``d by the default
``python -m pytest``, so a meta-test must live under ``tests/`` and import THIS.

The point: a missing ``SMOKE_ADMIN_PASSWORD`` must NOT let the UI tier skip and still
report green (a false pass). The UI tests literally cannot run without the webConfigurator
admin password, so an unset password is a hard FAILURE everywhere — CI and local alike;
skipping the tier is never a pass.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

# Env var carrying the baked webConfigurator admin password (ADR-04 SMOKE_ADMIN_PASSWORD).
ADMIN_PASSWORD_ENV = "SMOKE_ADMIN_PASSWORD"


def admin_password_decision(env: Mapping[str, str]) -> tuple[Literal["ok", "fail"], str]:
    """Decide how the ``admin_credentials`` fixture resolves the admin password.

    Returns ``(action, value)``:

    * ``("ok", password)``  — the password is set; use it.
    * ``("fail", message)`` — the password is unset (or empty): the UI tests cannot run
      without the webConfigurator admin password, and skipping the tier would report a
      false pass, so it FAILS loudly. This holds EVERYWHERE — CI and local alike; a
      credential-less run is a setup error to fix, not a tier to silently skip.
    """
    password = env.get(ADMIN_PASSWORD_ENV)
    if password:
        return ("ok", password)
    return (
        "fail",
        f"{ADMIN_PASSWORD_ENV} not set — the UI tier requires the webConfigurator admin "
        "password; UI tests cannot run without it and skipping is not passing.",
    )
