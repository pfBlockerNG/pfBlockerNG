"""Strict PHP error reporting on the smoke VM (BBcan177) — evidence tests.

Marker ``ui_render`` — collected by the smoke/ui workflow
(``pytest tests/smoke -m ui_render --override-ini="addopts="``), the same PR gate
as the render sweep. These pin the two halves of the change that makes the render
tier's ``php_error.log`` guard meaningful:

* The session VM is set to Netgate's beta ``error_reporting`` mask
  (``E_ALL ^ (E_WARNING | E_NOTICE | E_DEPRECATED)``, ``enable_strict_php_error_reporting``
  in the ``smoke_vm`` fixture) — the level Netgate runs on their betas, so a structural
  diagnostic is generated and logged instead of silently masked. On the stock ``-RELEASE``
  image the level is ``E_ERROR | E_PARSE`` (= 5), so
  :func:`test_smoke_vm_php_error_reporting_is_strict` is red without the raise.
* :class:`~tests.smoke.ui.render_oracle.PhpErrorLogGuard` watches the file PHP
  actually logs to. :func:`test_render_log_guard_catches_a_logged_diagnostic` proves
  a warning logged at a raised level grows a watched file (and one suppressed at the
  minimal level does not) — so the guard is not a no-op reading an unwritten path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PHP_ERROR_LOG_CANDIDATES, PhpErrorLogGuard

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render


def test_smoke_vm_php_error_reporting_is_strict(deployed_vm: SmokeVM) -> None:
    """The session VM runs at Netgate's beta error-reporting level, and it survives deploy.

    Netgate raises ``error_reporting`` on their betas to catch latent PHP issues; the
    ``smoke_vm`` fixture sets every smoke VM to that same mask
    (``E_ALL ^ (E_WARNING | E_NOTICE | E_DEPRECATED)``) for the same reason. This pins
    that the raise TOOK and still holds after the package deploy — on the stock
    ``-RELEASE`` image the level is ``E_ERROR | E_PARSE`` (= 5), so this fails without
    :func:`~tests.smoke.helpers.enable_strict_php_error_reporting` (the before/after
    evidence) and would also fail if a deploy/reload path clobbered php.ini.
    """
    expected = helpers.php_constant(deployed_vm, helpers.STRICT_PHP_ERROR_REPORTING)
    actual = helpers.php_effective_error_reporting(deployed_vm)
    assert actual == expected, (
        f"expected strict error_reporting {helpers.STRICT_PHP_ERROR_REPORTING} ({expected}) "
        f"but the guest reports {actual} — the enable_strict_php_error_reporting raise "
        f"did not take or did not survive deploy"
    )


def test_webconfigurator_php_fpm_runs_strict(webui: WebUI, deployed_vm: SmokeVM) -> None:
    """The php-fpm (GUI) workers run at the strict level too — not just the CLI SAPI.

    The render tier's whole value is that GUI pages log at the raised level; a reload
    that delivered its SIGUSR2 but left workers on the stale php.ini would leave the GUI
    weak with the sweep catching nothing (a false green the coverage mandate forbids). T1
    proves only the CLI SAPI (bare ``php -r`` reads php.ini directly, independent of fpm).
    Here we read the FPM SAPI's effective ``error_reporting`` by GETting a probe served
    through nginx → php-fpm, and pin it to the same masked level.
    """
    expected = helpers.php_constant(deployed_vm, helpers.STRICT_PHP_ERROR_REPORTING)
    actual = helpers.php_fpm_effective_error_reporting(deployed_vm, webui.get)
    assert actual == expected, (
        f"php-fpm (GUI) error_reporting is {actual}, expected the beta mask ({expected}) — "
        f"the SIGUSR2 reload did not move fpm workers to the strict level"
    )


def test_render_log_guard_catches_a_logged_diagnostic(deployed_vm: SmokeVM) -> None:
    """The log guard watches where PHP logs, and the strict level gates what is logged.

    Scenario: a PHP diagnostic is caught by :class:`PhpErrorLogGuard` only when the
    strict level is active.

      Given the guest's effective ``ini_get('error_log')`` is a file the guard watches
      When an ``E_USER_WARNING`` fires under the minimal ``E_ERROR | E_PARSE`` level
      Then the watched log does NOT grow — the diagnostic is suppressed (off branch)
      When the same ``E_USER_WARNING`` fires under ``E_ALL``
      Then the watched log grows and the guard fails — the catch (on branch)

    The path assertion is the anti-no-op guard: if PHP logged somewhere unwatched the
    growth check could never fire, so this pins ``error_log`` INTO the candidate set.
    """
    off_tag = "pfb-strict-smoke-off"
    on_tag = "pfb-strict-smoke-on"

    # Given: the guard must watch wherever the guest's PHP actually writes errors.
    log_path = helpers.php_error_log_path(deployed_vm)
    assert log_path in PHP_ERROR_LOG_CANDIDATES, (
        f"guest php error_log target {log_path!r} is not watched by PhpErrorLogGuard "
        f"(candidates: {list(PHP_ERROR_LOG_CANDIDATES)}) — a logged diagnostic would be missed"
    )

    guard = PhpErrorLogGuard(deployed_vm)

    # When/Then (off branch): under the minimal RELEASE level the E_USER_WARNING is
    # suppressed, so OUR tagged line never reaches the log. Tag-scoped (not whole-file
    # size) so incidental churn from another process cannot mask a real regression.
    helpers.php_trigger_user_warning(deployed_vm, level="E_ERROR | E_PARSE", tag=off_tag)
    assert not helpers.guest_file_contains(deployed_vm, log_path, off_tag), (
        f"E_USER_WARNING {off_tag!r} was logged at the minimal level E_ERROR|E_PARSE "
        f"(expected suppressed) in {log_path}"
    )

    # When/Then (on branch): at E_ALL the same warning IS logged — the size-based guard
    # the render sweep uses catches the growth, AND our tagged line is in the verified
    # error_log (so the growth is proven to be our warning, not candidate churn).
    guard.snapshot()
    helpers.php_trigger_user_warning(deployed_vm, level="E_ALL", tag=on_tag)
    with pytest.raises(AssertionError, match="php_error.log gained new lines"):
        guard.assert_no_growth()
    assert helpers.guest_file_contains(deployed_vm, log_path, on_tag), (
        f"E_USER_WARNING {on_tag!r} was not logged at E_ALL (expected logged) in {log_path}"
    )
