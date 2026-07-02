"""Live-VM smoke: pfBlockerNG sync with DNSBL enabled but the DNS Resolver DISABLED (#703).

``sync_package_pfblockerng()`` derives ``$mode`` from an if/elseif that does not cover
every enable-state: with the master switch ON and DNSBL ON but Unbound disabled
(``$pfb['unbound_state'] == ''``), neither branch matches. Pre-fix ``$mode`` stayed
UNDEFINED (null) and the typed ``pfb_manage_dnsbl_vip(string $mode)`` raised a
``TypeError`` that aborted the whole sync pass — every Update/save-sync crashed until
the resolver was re-enabled. The fix defaults ``$mode = ''`` (a no-op mode for every
consumer).

Red→green: pre-fix the measured sync exits non-zero with the TypeError on stdout (the
CLI fatal); post-fix it completes cleanly.

The resolver toggle is config-only (``$pfb['unbound_state']`` reads
``config_path_enabled('unbound')``), so the test flips ``unbound/enable`` in config —
and RESTORES it in a ``finally`` with a loud check, so a mid-test failure cannot leave
the shared session VM without its resolver for later modules.

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    python -m pytest tests/smoke/test_smoke_resolver_off_sync.py -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``); without
these the cases skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke


def _resolver_enabled(vm: SmokeVM, *, timeout: float = 60.0) -> bool:
    """Whether the DNS Resolver is enabled in config — the exact source
    ``$pfb['unbound_state']`` reads (``config_path_enabled('unbound')``)."""
    r = h.php_eval(vm, "echo config_path_enabled('unbound') ? 'ENABLED' : 'DISABLED';", timeout=timeout)
    out = r.stdout
    if "ENABLED" in out and "DISABLED" not in out:
        return True
    if "DISABLED" in out:
        return False
    raise RuntimeError(f"_resolver_enabled: unexpected output rc={r.returncode} {out!r} {r.stderr!r}")


def _set_resolver_enabled(vm: SmokeVM, on: bool, *, timeout: float = 60.0) -> None:
    """Flip the DNS Resolver's config enable key (presence-based, like the GUI checkbox)."""
    stmt = "config_set_path('unbound/enable', '');" if on else "config_del_path('unbound/enable');"
    snippet = f"{stmt}\nwrite_config('pfBlockerNG smoke: resolver toggle');\necho 'OK';"
    r = h.php_eval(vm, snippet, timeout=timeout)
    if r.returncode != 0 or "OK" not in r.stdout:
        raise RuntimeError(f"_set_resolver_enabled({on}) failed: rc={r.returncode} {r.stderr!r} {r.stdout!r}")


@pytest.fixture(scope="module")
def dnsbl_on_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg with the #703 trigger preconditions: master ON + DNSBL ON.

    Given: the smoke VM is booted and the branch .pkg is available.
    When:  we deploy, provision the sinkhole VIP, and switch on the master enable and the
           DNSBL component (no lists needed — the $mode derivation crashes before any
           feed work).
    Then:  the module VM is one resolver-disable away from the pre-fix crash state.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.set_package_enabled(smoke_vm, True)
    h.set_dnsbl_enabled(smoke_vm, True)
    yield smoke_vm


def test_sync_with_resolver_disabled_completes_without_typeerror(dnsbl_on_vm: SmokeVM) -> None:
    """A sync with DNSBL on but the Resolver disabled completes instead of crashing (#703).

    Given: master ON + DNSBL ON + Resolver ENABLED, and a baseline sync that SUCCEEDS
           (proves the rig itself is green before the flip — the failure below is then
           attributable to the resolver state alone).
    When:  the Resolver is disabled in config and the same sync runs again.
    Then:  the sync completes with rc 0 and no TypeError/Fatal on its output — pre-fix,
           $mode was undefined for pfb_manage_dnsbl_vip(string $mode) and the pass
           aborted with 'TypeError ... must be of type string' (rc 255).
    Finally: the Resolver is restored (loud check) so later modules keep working DNS.
    """
    vm = dnsbl_on_vm

    # Given: the resolver is enabled — the before-state of the transition.
    assert _resolver_enabled(vm), "precondition: the DNS Resolver must start ENABLED in config"

    # Given (control): the baseline sync is green with the resolver ON.
    h.reload(vm, "update")

    try:
        # When: disable the resolver (config only — $pfb['unbound_state'] reads config).
        _set_resolver_enabled(vm, False)
        assert not _resolver_enabled(vm), "resolver disable did not take in config"

        # When/Then: the measured sync. Drive the CLI directly so stdout is assertable —
        # a PHP fatal (the pre-fix TypeError) lands on stdout with a non-zero rc.
        r = vm.ssh(h.PHP_BIN, h.PFB_CLI, "pfb_trigger", "scope=both", "force=false", "trigger=cron", timeout=600)
        assert r.returncode == 0, (
            f"sync with the Resolver disabled must complete, got rc={r.returncode}\n"
            f"  stdout: {r.stdout[-2000:]!r}\n  stderr: {r.stderr!r}"
        )
        for marker in ("TypeError", "Fatal error", "Uncaught"):
            assert marker not in r.stdout, (
                f"sync output must not contain {marker!r} with the Resolver disabled\n  stdout: {r.stdout[-2000:]!r}"
            )
    finally:
        # Restore the resolver for the rest of the session VM — and prove it took.
        _set_resolver_enabled(vm, True)
        h.reload(vm, "update")  # waits on unbound readiness — a dead resolver fails here loudly

    assert _resolver_enabled(vm), "teardown: the DNS Resolver must be re-enabled in config"
