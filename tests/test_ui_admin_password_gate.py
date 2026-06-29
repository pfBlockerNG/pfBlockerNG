"""The UI tier must not skip-as-pass when its required secret is missing in CI.

Pins :func:`tests.smoke.ui.credgate.admin_password_decision`: the pure decision the
``admin_credentials`` fixture acts on. ``tests/smoke`` is ``--ignore``d by the default
``python -m pytest`` (it needs a live VM), so this meta-test lives under ``tests/`` to run
in the PR unit gate — exactly where the false-green would otherwise hide.

Red->green: before the fix the fixture unconditionally ``pytest.skip``ed on an unset
password, so a CI run with the secret missing skipped the whole UI tier and the job still
reported success. Now an unset password under CI maps to ``"fail"`` (a hard failure);
off-CI it still maps to ``"skip"``.
"""

from __future__ import annotations

from tests.smoke.ui.credgate import ADMIN_PASSWORD_ENV, admin_password_decision


def test_password_present_is_ok() -> None:
    """A set password yields ('ok', password) regardless of CI."""
    action, value = admin_password_decision({ADMIN_PASSWORD_ENV: "hunter2"})
    assert action == "ok", f"expected 'ok' with the password set, got {action!r}"
    assert value == "hunter2", f"expected the password back, got {value!r}"


def test_present_password_wins_even_in_ci() -> None:
    """The password being set short-circuits the CI-required check."""
    action, value = admin_password_decision({ADMIN_PASSWORD_ENV: "pw", "CI": "true"})
    assert action == "ok" and value == "pw", f"set password under CI must be 'ok'/pw, got {action!r}/{value!r}"


def test_unset_password_in_ci_fails() -> None:
    """Unset password + CI marker => hard FAIL (no skip-as-pass).

    This is the regression guard: with `CI`/`GITHUB_ACTIONS` set, a missing secret must
    NOT skip the tier. Pre-fix this returned a skip (false green).
    """
    for ci_env in ({"CI": "true"}, {"GITHUB_ACTIONS": "true"}, {"CI": "1", "GITHUB_ACTIONS": "true"}):
        action, msg = admin_password_decision(ci_env)
        assert action == "fail", f"unset password under {ci_env!r} must FAIL, got {action!r}"
        assert ADMIN_PASSWORD_ENV in msg, f"failure message should name the env var, got {msg!r}"


def test_unset_password_off_ci_skips() -> None:
    """Unset password with no CI marker => clean skip (credential-less local run)."""
    action, msg = admin_password_decision({})
    assert action == "skip", f"unset password off-CI must skip, got {action!r}"
    assert ADMIN_PASSWORD_ENV in msg, f"skip message should name the env var, got {msg!r}"


def test_empty_password_treated_as_unset() -> None:
    """An empty-string password is not a real credential — treated as unset."""
    action, _ = admin_password_decision({ADMIN_PASSWORD_ENV: ""})
    assert action == "skip", f"empty password off-CI must skip (treated as unset), got {action!r}"
    action, _ = admin_password_decision({ADMIN_PASSWORD_ENV: "", "CI": "true"})
    assert action == "fail", f"empty password under CI must fail (treated as unset), got {action!r}"
