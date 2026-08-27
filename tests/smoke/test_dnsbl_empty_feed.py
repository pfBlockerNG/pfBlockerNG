"""Smoke leg: DNSBL enabled with no feeds must not churn Unbound on a steady-state pass.

Proves the §2 fix from issue #546 on a real pfSense CE VM:

  An enabled DNSBL with zero feeds configured reaches a stable fingerprint after
  the first sync pass.  Subsequent passes detect that empty→empty is unchanged and
  skip the reload: no "Stopping Unbound Resolver", "Clearing all DNSBL Feeds", or
  "Missing DNSBL stats and/or Unbound DNSBL files - Rebuilding" appear in the pass-2
  log slice.

  On pre-fix code, "Stopping Unbound Resolver" appears in BOTH passes because the
  empty-feed branch deleted pfb_py_data/pfb_py_wh/manifest each pass, so every
  fingerprint compare hit the missing-files fallback and forced a reload.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml).  Run only by the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture and ``SMOKE_PKG``; without them the module
skips cleanly.  No feed server is required: this test configures DNSBL with zero feed
rows and asserts on log content.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

# --------------------------------------------------------------------------- #
# Log strings whose presence in a pass-2 slice indicates churn (regression)
# --------------------------------------------------------------------------- #

_CHURN_STRINGS = (
    "Stopping Unbound Resolver",
    "Clearing all DNSBL Feeds",
    "Missing DNSBL stats and/or Unbound DNSBL files - Rebuilding",
)

# --------------------------------------------------------------------------- #
# Module-scoped fixture: deploy once, then run the churn assertion
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for this module and configure DNSBL with zero feeds.

    DNSBL is enabled (enable_cb=on, pfb_dnsbl=on, VIP injected, ports set) but the
    DNSBL feed list is left empty.  The trigger verb is ``update`` (Force Update →
    ``sync_package_pfblockerng('cron')``), which runs the full DNSBL sync path
    including the fingerprint gate — exactly the path the #546 fix touches.

    ``cron`` is intentionally NOT used here: with zero DNSBL rows ``pfblockerng_sync_cron``
    sets ``update_cron=FALSE`` and calls ``sync_package_pfblockerng('noupdates')``, which
    sets ``$pfb['save']=TRUE`` and bypasses all DNSBL processing — so the churn strings
    can never appear and the test would be vacuously true.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.set_package_enabled(smoke_vm, on=True)
    h.set_dnsbl_enabled(smoke_vm, on=True)
    yield smoke_vm


# --------------------------------------------------------------------------- #
# Test case
# --------------------------------------------------------------------------- #


def test_no_unbound_restart_on_no_feed_steady_state_pass(deployed_vm: SmokeVM) -> None:
    """Scenario — no-feed DNSBL steady state: a second sync pass must not churn Unbound.

    Given:
      - DNSBL enabled (enable_cb=on, pfb_dnsbl=on, VIP injected), zero feeds.

    When (pass 1):
      - Run a full sync pass (``update`` verb → ``sync_package_pfblockerng('cron')``).
        This is the settle pass: allowed to emit churn strings on the initial install
        state (files may be absent; the fix materialises them on exit).

    When (pass 2):
      - Capture the per-churn-string occurrence count in the pfBlockerNG log as the
        delta baseline (one ``count_log_marker`` call per string, BEFORE pass 2 runs).
      - Run a second full sync pass (same ``update`` verb).

    Then:
      - For each churn string, the post-pass-2 count equals the pre-pass-2 count —
        i.e. the string did NOT appear in the pass-2 log slice.
      - On failure, print each string that appeared with its pre- and post-count so the
        reader knows which churn marker fired and how many times.
    """
    vm = deployed_vm

    # --- Given: already configured by the deployed_vm fixture ---

    # --- When (pass 1 — settle) ---
    h.reload(vm, "update")

    # --- When (pass 2 — steady state) ---
    # Capture per-string occurrence counts BEFORE pass 2 runs.
    before = {s: h.count_log_marker(vm, h.PFB_LOG, s) for s in _CHURN_STRINGS}

    h.reload(vm, "update")

    # Capture counts AFTER pass 2.
    after = {s: h.count_log_marker(vm, h.PFB_LOG, s) for s in _CHURN_STRINGS}

    # --- Then ---
    churn_found = [s for s in _CHURN_STRINGS if after[s] > before[s]]
    if churn_found:
        lines = [
            "AFTER pass 2, the following churn strings appeared in the pfBlockerNG log",
            f"  (log: {h.PFB_LOG}):",
        ]
        for s in churn_found:
            new_count = after[s] - before[s]
            lines.append(f"  PRESENT ({new_count}x new): {s!r}")
        for s in _CHURN_STRINGS:
            if s not in churn_found:
                lines.append(f"  absent (ok):            {s!r}")
        lines.append(
            "Expected: NONE of the churn strings in the pass-2 log slice.\n"
            "This means the fix in issue #546 is not effective on this build."
        )
        pytest.fail("\n".join(lines))
