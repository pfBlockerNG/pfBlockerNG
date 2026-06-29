"""Credential-gate decision for the UI tier — a pure, dependency-free helper.

Kept in its own module (no ``requests``/VM imports) so the default unit suite can
import and test it; ``tests/smoke`` itself is ``--ignore``d by the default
``python -m pytest``, so a meta-test must live under ``tests/`` and import THIS.

The point: a missing ``SMOKE_ADMIN_PASSWORD`` must NOT let the whole UI tier skip and
still report the job green (a false pass). Off-CI (a credential-less local run) a skip is
correct; under CI the secret is required, so an unset password is a hard failure.
"""

from __future__ import annotations

from collections.abc import Mapping

# Env var carrying the baked webConfigurator admin password (ADR-04 SMOKE_ADMIN_PASSWORD).
ADMIN_PASSWORD_ENV = "SMOKE_ADMIN_PASSWORD"


def admin_password_decision(env: Mapping[str, str]) -> tuple[str, str]:
    """Decide how the ``admin_credentials`` fixture resolves the admin password.

    Returns ``(action, value)``:

    * ``("ok", password)``  — the password is set; use it.
    * ``("fail", message)`` — the password is unset AND we are running under CI
      (``CI`` or ``GITHUB_ACTIONS`` set): a required secret is misconfigured, so the
      UI tier must FAIL loudly rather than skip the whole tier and report green.
    * ``("skip", message)`` — the password is unset off-CI (a credential-less local
      run): a clean skip, as before.
    """
    password = env.get(ADMIN_PASSWORD_ENV)
    if password:
        return ("ok", password)
    if env.get("CI") or env.get("GITHUB_ACTIONS"):
        return (
            "fail",
            f"{ADMIN_PASSWORD_ENV} not set in CI — the UI tier requires the webConfigurator "
            "admin password; refusing to skip the tier and report a false pass.",
        )
    return ("skip", f"{ADMIN_PASSWORD_ENV} not set -- no webConfigurator admin password")
