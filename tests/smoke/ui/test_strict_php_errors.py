"""Strict PHP error reporting on the smoke VM — evidence tests.

Marker ``ui_render`` — collected by the smoke/ui workflow
(``pytest tests/smoke -m ui_render --override-ini="addopts="``), the same PR gate
as the render sweep. These pin the two halves of what makes the render tier's
``php_error.log`` guard meaningful:

* The session VM is set to a true ``E_ALL`` (``enable_strict_php_error_reporting``
  in the ``smoke_vm`` fixture), so EVERY diagnostic class is generated and logged
  instead of silently masked — including the runtime ``E_WARNING`` / ``E_NOTICE`` /
  ``E_DEPRECATED`` class that issue #1218 found unobservable, which made every
  "this page no longer warns" assertion vacuous. On the stock ``-RELEASE`` image the
  level is ``E_ERROR | E_PARSE`` (= 5), so
  :func:`test_smoke_vm_php_error_reporting_is_strict` is red without the raise.
* :class:`~tests.smoke.ui.render_oracle.PhpErrorLogGuard` watches the file PHP
  actually logs to, and gates on the diagnostic's ORIGINATING file.
  :func:`test_render_log_guard_gates_on_our_files_only` proves both branches live on
  the box: a real ``E_WARNING`` raised in a pfBlockerNG file fails the guard, the same
  warning raised outside the package is logged but does not — so the guard is neither
  a no-op reading an unwritten path nor a tripwire for pfSense-core noise.
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
    """The session VM reports EVERY diagnostic class, and that survives deploy.

    The ``smoke_vm`` fixture raises every smoke VM to a true ``E_ALL`` so no class is
    masked out of the log — the defect issue #1218 documents was a masked class making
    warning-class assertions vacuous, and the mask is the only thing standing between a
    raised diagnostic and the guard. This pins that the raise TOOK and still holds after
    the package deploy — on the stock ``-RELEASE`` image the level is ``E_ERROR | E_PARSE``
    (= 5), so this fails without
    :func:`~tests.smoke.helpers.enable_strict_php_error_reporting` (the before/after
    evidence) and would also fail if a deploy/reload path clobbered php.ini, or if the
    runtime classes were ever masked back out.
    """
    expected = helpers.php_constant(deployed_vm, helpers.STRICT_PHP_ERROR_REPORTING)
    actual = helpers.php_effective_error_reporting(deployed_vm)
    assert actual == expected, (
        f"expected strict error_reporting {helpers.STRICT_PHP_ERROR_REPORTING} ({expected}) "
        f"but the guest reports {actual} — the enable_strict_php_error_reporting raise "
        f"did not take or did not survive deploy"
    )


def test_webconfigurator_php_fpm_logs_diagnostic_to_watched_path(webui: WebUI, deployed_vm: SmokeVM) -> None:
    """php-fpm runs strict AND its diagnostics reach a watched log candidate.

    The render sweep's value is that a GUI page emitting a PHP diagnostic under the raised
    level trips ``PhpErrorLogGuard``. That needs two facts a bare ``php -r`` cannot show: the
    php-fpm WORKERS run strict, and php-fpm logs to a path the guard WATCHES. Fire a tagged
    ``E_USER_WARNING`` from an fpm-served probe (the real GUI SAPI at the box's configured
    level), then assert the fpm ``error_reporting`` is the mask AND the tagged line landed in a
    watched candidate. If php-fpm's pool ever redirected ``error_log`` off the candidate list
    this fails loudly — otherwise the sweep would silently miss every real page error (T1 and
    the CLI log-catch below cannot see that: they read the CLI SAPI, not fpm's worker path).
    """
    expected = helpers.php_constant(deployed_vm, helpers.STRICT_PHP_ERROR_REPORTING)
    tag = "pfb-fpm-smoke-diag"
    level = helpers.php_fpm_probe(deployed_vm, webui.get, warn_tag=tag)
    assert level == expected, (
        f"php-fpm (GUI) error_reporting is {level}, expected a true E_ALL ({expected}) — "
        f"the SIGUSR2 reload did not move fpm workers to the strict level"
    )
    assert any(helpers.guest_file_contains(deployed_vm, c, tag) for c in PHP_ERROR_LOG_CANDIDATES), (
        f"an fpm-logged diagnostic {tag!r} reached none of the watched candidates "
        f"{list(PHP_ERROR_LOG_CANDIDATES)} — the render sweep's PhpErrorLogGuard would miss real page errors"
    )


def test_render_log_guard_gates_on_our_files_only(deployed_vm: SmokeVM) -> None:
    """The runtime warning class is observable on the box, and only OUR files gate.

    Scenario: the sweep fails on a pfBlockerNG diagnostic and ignores pfSense-core noise.

      Given the guest's effective ``ini_get('error_log')`` is a file the guard watches
      When a real ``E_WARNING`` (undefined variable) is raised from a file OUTSIDE the package
      Then it IS logged, and the guard passes — core noise never gates (off branch)
      When the same ``E_WARNING`` is raised from a file inside the package directory
      Then the guard fails, naming that line — our regression gates (on branch)

    Both halves are load-bearing. The off branch asserts the line was LOGGED before
    asserting the guard ignored it, so "does not gate" can never pass because nothing
    was written — the vacuous-green shape issue #1218 was opened about. The on branch is
    the proof the runtime ``E_WARNING`` class now reaches the guard at all: under the old
    ``E_ALL ^ (E_WARNING | E_NOTICE | E_DEPRECATED)`` mask it was never dispatched to the
    log, so this assertion could not have been satisfied.

    The path assertion is the anti-no-op guard: if PHP logged somewhere unwatched neither
    branch could fire, so this pins ``error_log`` INTO the candidate set.
    """
    outside_tag = "pfb_smoke_warn_outside"
    owned_tag = "pfb_smoke_warn_owned"
    # A path with no "pfblockerng" in it stands in for pfSense core; the package dir is
    # the real shipped root, so the owned probe proves ownership the way a page would.
    outside_probe = "/tmp/smoke_core_warn_probe.php"
    owned_probe = "/usr/local/pkg/pfblockerng/pfb_smoke_warn_probe.php"

    # Given: the guard must watch wherever the guest's PHP actually writes errors.
    log_path = helpers.php_error_log_path(deployed_vm)
    assert log_path in PHP_ERROR_LOG_CANDIDATES, (
        f"guest php error_log target {log_path!r} is not watched by PhpErrorLogGuard "
        f"(candidates: {list(PHP_ERROR_LOG_CANDIDATES)}) — a logged diagnostic would be missed"
    )

    # When/Then (off branch): a warning from outside the package is logged but ignored.
    guard = PhpErrorLogGuard(deployed_vm)
    guard.snapshot()
    helpers.php_trigger_undefined_variable_warning(deployed_vm, path=outside_probe, tag=outside_tag)
    assert helpers.guest_file_contains(deployed_vm, log_path, outside_tag), (
        f"E_WARNING for ${outside_tag} from {outside_probe} never reached {log_path} — the guest is not "
        f"logging the runtime warning class, so the 'core noise does not gate' half proves nothing"
    )
    guard.assert_no_growth()

    # When/Then (on branch): the same warning from an owned file fails the sweep, and the
    # failure names the offending line so a real red is actionable from the message alone.
    guard = PhpErrorLogGuard(deployed_vm)
    guard.snapshot()
    helpers.php_trigger_undefined_variable_warning(deployed_vm, path=owned_probe, tag=owned_tag)
    with pytest.raises(AssertionError, match="pfBlockerNG PHP diagnostics") as caught:
        guard.assert_no_growth()
    assert owned_tag in str(caught.value), (
        f"the guard failed but did not report the offending line (expected {owned_tag!r}): {caught.value}"
    )
