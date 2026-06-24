"""Tier-B e2e tests for the Software-page Uninstall confirm gate (issue #485).

Marker ``ui_e2e`` — daily / on-demand; NOT in the PR gate and NOT in the default
``python -m pytest`` run (the whole ``tests/smoke`` tree is ``--ignore``d there).
Run with: ``pytest tests/smoke -m ui_e2e --override-ini="addopts="``.

What these tests cover
-----------------------
Step 1 of issue #485 added an Uninstall section to ``pfblockerng_software.php``:

* a privilege gate (``isAllowedPage('pkg_mgr_installed.php')``);
* a confirm checkbox ``id="pfb_sw_uninstall_confirm"`` (default UNCHECKED);
* an Uninstall button ``id="pfb_sw_uninstall"`` (rendered ``disabled`` by default);
* a POST handler for ``pfb_sw_action=uninstall`` that re-checks the confirm field
  server-side — if ``pfb_sw_uninstall_confirm`` is absent it emits the refusal
  status ``"Uninstall not confirmed"`` without running ``pkg delete``.

The browser-tier confirm gate (disabled→enabled on checkbox tick) is in
``test_browser_misc.py::test_software_uninstall_confirm_gate``.

Out-of-CI limitations (ADR-04 §7 / CLAUDE.md "ADR acceptance")
----------------------------------------------------------------
Two branches are intentionally NOT exercised in CI:

1. **Successful uninstall** (``pkg delete`` removes pfBlockerNG + redirect to
   ``/pkg_mgr_installed.php``) — executing this removes the SUT from the smoke VM
   and breaks every subsequent test in the run. Only the NON-destructive branches
   are tested here.

2. **Privilege-denial** (``isAllowedPage`` returns false, redirects to
   ``/index.php``) — the smoke session authenticates as admin (uid 0), which
   passes ``isAllowedPage`` unconditionally. Exercising the denial branch requires
   a non-admin user holding the pfBlockerNG GUI priv but NOT the Package Manager
   Installed priv; the smoke harness has no such fixture. The *authorised* branch
   IS covered — every render/e2e/browser test reaches the page as admin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .test_render_smoke import _SOFTWARE_PAGE, software_panel_forced

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e


def test_software_uninstall_server_rejects_without_confirm(
    smoke_vm: SmokeVM,
    webui: WebUI,
) -> None:
    """Server-side confirm re-check rejects an uninstall POST with no confirm field.

    Scenario: the Uninstall handler refuses when the confirm checkbox is absent.

      Given the Software page forced on (``software_panel_forced(smoke_vm, 'on')``)
        and an authenticated admin session (``webui``),

      When the Software page is POSTed with ``pfb_sw_action=uninstall`` but WITHOUT
        ticking ``pfb_sw_uninstall_confirm`` — ``webui.post`` with an empty overrides
        dict uses ``submit=('pfb_sw_action', 'uninstall')``; ``scrape_form_fields``
        omits the unchecked checkbox (exactly like a browser), so ``pfb_sw_uninstall_confirm``
        is absent from the payload — the unconfirmed case,

      Then the response body contains ``"Uninstall not confirmed"`` (the server-side
        refusal status emitted by the handler when the field is absent);
      And pfBlockerNG is STILL installed — ``pkg query -g %n 'pfSense-pkg-pfBlockerNG*'``
        returns rc 0 with a non-empty package name — proving ``pkg delete`` did NOT run.

    Fail-before / pass-after: the POST handler and the refusal status string were added
    in issue #485 Step 1. Pre-Step-1 the page had no POST handler for
    ``pfb_sw_action=uninstall``, so the response body would NOT contain the refusal
    string, failing the ``in body`` assertion.
    """
    with software_panel_forced(smoke_vm, "on"):
        resp = webui.post(
            _SOFTWARE_PAGE,
            {},
            submit=("pfb_sw_action", "uninstall"),
        )

    status = resp.status_code
    body = resp.text
    refusal_string = "Uninstall not confirmed"
    refusal_found = refusal_string in body

    # pkg query for the installed package (rc 0 + non-empty stdout = still installed).
    pkg_result = smoke_vm.ssh(
        "/usr/local/sbin/pkg",
        "query",
        "-g",
        "%n",
        "pfSense-pkg-pfBlockerNG*",
    )
    pkg_installed = pkg_result.returncode == 0 and bool(pkg_result.stdout.strip())
    pkg_stdout = pkg_result.stdout.strip()

    assert refusal_found, (
        f"Expected refusal string {refusal_string!r} in POST response body but it was absent.\n"
        f"  HTTP status : {status}\n"
        f"  Body excerpt: {body[:500]!r}"
    )
    assert pkg_installed, (
        f"pfBlockerNG package unexpectedly gone after unconfirmed uninstall POST.\n"
        f"  pkg query rc    : {pkg_result.returncode}\n"
        f"  pkg query stdout: {pkg_stdout!r}\n"
        f"  (Expected the package to still be installed; pkg delete must NOT have run.)"
    )
