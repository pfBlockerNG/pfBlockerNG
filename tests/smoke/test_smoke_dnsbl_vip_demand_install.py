"""Issue #3539 — a package reinstall must not start the DNSBL web server while no block needs the VIP.

Companion of ``test_smoke_dnsbl_vip_demand.py``. The post-install hook (``pfblockerng_install.inc``) starts
lighttpd on its own, outside the apply, so it gets its own live proof. It needs the ``repo_vm`` fixture
(the package installed from our ``file://`` repo, which a forced reinstall requires), so it carries the
``repo`` marker, like ``test_pkg_op_teardown.py`` whose ``pkg install -f`` leg it reuses::

    scripts/local-smoke.sh --marker repo --filter vip_demand

Needs the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``); without them it skips cleanly.
"""

from __future__ import annotations

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_pkg_op_teardown import pkg_reinstall_force
from .test_repo_install import (  # noqa: F401 -- repo_vm is a fixture re-export (pytest resolves fixtures per module)
    NETGATE_REPO_NAME,
    OURS_REPO_DIR,
    PKG_NAME,
    pkg_delete,
    pkg_install_from_repo,
    pkg_installed_version,
    pkg_update,
    repo_priority,
    repo_vm,
    write_repo_conf,
)
from .test_smoke_dnsbl_vip_demand import (
    _expect_no_problems,
    _lighty_state,
    _reach_no_demand_web_stopped,
    _restoring_baseline,
    _web_down_problems,
)

pytestmark = pytest.mark.repo


@pytest.mark.timeout(900)
def test_reinstall_does_not_start_web_server_without_vip_demand(repo_vm: SmokeVM) -> None:  # noqa: F811
    """Scenario: ``pkg install -f`` over a box where no block needs the VIP leaves lighttpd off.

    Given the package installed from our repo, DNSBL on with one group answering 0.0.0.0 and the
      auto-VIP on (no VIP demand), applied, with lighttpd stopped,
    When ``pkg install -f`` reinstalls the same build,
    Then lighttpd is not running.
    """
    vm = repo_vm
    pfsense_prio = repo_priority(vm, NETGATE_REPO_NAME)
    try:
        pkg_delete(vm)
        write_repo_conf(vm, OURS_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(vm)
        assert pkg_installed_version(vm) is None, f"{PKG_NAME} unexpectedly present before the install"
        pkg_install_from_repo(vm)
        assert pkg_installed_version(vm) is not None, "the from-repo install did not register the package"

        # The baseline (feed group, managed VIP, DNSBL state, manual VIP) is restored while the package is still
        # installed: its Force Update and reset need it, and pkg_delete below would strand the config otherwise.
        with _restoring_baseline(vm):
            feed = h.write_local_feed(vm, "smoke_vip_demand_install.txt", f"{h.unique_domain('vipinstall')}\n")
            h.ensure_dnsbl_vip(vm)
            _reach_no_demand_web_stopped(vm, feed)

            pkg_reinstall_force(vm)
            h.wait_unbound_ready(vm)

            _expect_no_problems(vm, "after `pkg install -f` with no VIP demand", _web_down_problems(_lighty_state(vm)))
    finally:
        pkg_delete(vm)
