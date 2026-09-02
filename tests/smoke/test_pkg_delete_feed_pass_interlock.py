"""issue #3090 — ``pkg delete`` waits for an in-flight feed pass before tearing down.

The pre-deinstall tears down the Unbound chroot, the generated DNSBL files and the pfB
services. Its disable pass takes the feed-pass lock non-blocking and DEFERS on
contention, and the teardown after it used to run regardless — on top of a scheduled
pass still publishing into the chroot. Since #3090 the pre-deinstall takes the same
bounded hold the install path takes (#3062) before the disable pass. The controller runs
a real sync plus pfctl/exec teardown, so it is exercised here on the live VM only.

The in-flight pass is a REAL one: an enabled ``pre`` update hook parks the pass — inside
the feed-pass lock, where ``pfb_run_hooks('pre')`` fires — until the test releases it.
With the pass parked, ``pkg delete`` runs in the background and must log that it is
waiting, without having started the teardown; once the hook is released the pass
finishes and the uninstall proceeds to completion.

NOT A SMOKE TEST: like ``test_pkg_op_teardown`` this is a *lifecycle* mechanic, so it
carries the ``repo`` marker and reuses ``repo_vm``. Runs only via::

    python -m pytest tests/smoke -m repo --override-ini="addopts="
"""

from __future__ import annotations

import contextlib

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_pkg_op_teardown import _TEARDOWN_LINE

# ``repo_vm`` is re-exported (not just imported): pytest resolves fixtures PER-MODULE, so
# the name must be present here for the case below to request it.
from .test_repo_install import (  # noqa: F401
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

pytestmark = pytest.mark.repo

_DIR = "/tmp/pfb_smoke_3090"
_STARTED = f"{_DIR}/started"  # the parked pass's pre hook is running (lock held)
_GO = f"{_DIR}/go"  # release the parked hook
_PASS_OUT = f"{_DIR}/pass.out"
_DELETE_OUT = f"{_DIR}/delete.out"

# pfb_install_feed_pass_hold() with $op='uninstall' (pfblockerng.inc): the wait line goes
# to pfblockerng.log; the update_status() progress lines go to pkg's own stdout, where the
# logger's line interleaves between "Serialising..." and its " done." / give-up suffix.
_WAITING_LINE = "Package uninstall: waiting up to"
_SERIALISING_LINE = "Serialising against any in-flight pfBlockerNG feed pass..."
_HOLD_GIVEN_UP = "lock not taken; continuing anyway"

# The parking hook: on a normal pass it marks itself started and waits for the release
# file (self-terminating at 180 s so an orphan can never wedge the box; the hook's own
# config timeout is wider than that). On the uninstall's disable pass
# (PFB_PRE_UNINSTALL=1) it exits at once, so the uninstall itself never waits on it.
_HOOK = {
    "script": "hook_pre_smoke3090.sh",
    "_body": (
        "#!/bin/sh\n"
        '[ "$PFB_PRE_UNINSTALL" = "1" ] && exit 0\n'
        f"touch {_STARTED}\n"
        "i=0\n"
        f'while [ ! -f {_GO} ] && [ "$i" -lt 1800 ]; do sleep 0.1; i=$((i+1)); done\n'
    ),
    "when": "pre",
    "enabled": "on",
    "description": "smoke 3090 parked pass",
    "timeout": "240",
}


def _run_in_background(vm: SmokeVM, command: str, out: str) -> None:
    """Start one simple ``command`` on the guest detached from this ssh session; output + ``RC=<n>`` land in ``out``."""
    vm.ssh(f"nohup /bin/sh -c '{command} > {out} 2>&1; echo RC=$? >> {out}' >/dev/null 2>&1 &")


def _finished(vm: SmokeVM, out: str) -> bool:
    """TRUE once the background process behind ``out`` has appended its ``RC=`` line (or never started)."""
    return not h.hook_marker_exists(vm, out) or "RC=" in h.read_log_file(vm, out)


@pytest.mark.timeout(900)  # install + parked pass + pkg delete; budget ~15 min
def test_pkg_delete_waits_for_the_in_flight_feed_pass(repo_vm: SmokeVM) -> None:
    """UNINSTALL INTERLOCK (#3090): ``pkg delete`` waits for a running feed pass.

    Given pfBlockerNG installed from our repo with a ``pre`` hook that parks the pass,
      and a feed pass parked in that hook (it holds the feed-pass lock),
    When ``pkg delete`` runs,
    Then it logs the uninstall's waiting line while the pass is still parked, and has
      NOT started the teardown (no teardown line on its output yet);
    When the hook is released,
    Then the pass completes, and the uninstall reports the hold taken, tears down,
      exits 0 and removes the package.
    """
    vm = repo_vm
    pfsense_prio = repo_priority(vm, NETGATE_REPO_NAME)

    try:
        # ---- GIVEN: install from our repo + the parking hook ------------------- #
        pkg_delete(vm)
        write_repo_conf(vm, OURS_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(vm)
        assert pkg_installed_version(vm) is None, f"{PKG_NAME} unexpectedly present before the install"
        pkg_install_from_repo(vm)
        assert pkg_installed_version(vm) is not None, "the from-repo install did not register the package"

        vm.ssh(f"rm -rf {_DIR} && mkdir -p {_DIR}")
        h.set_update_hooks(vm, [_HOOK])
        h.wait_no_active_pfb_task(vm)

        # AND: a feed pass parked in its pre hook — inside the feed-pass lock.
        _run_in_background(vm, f"{h.PHP_BIN} {h.PFB_CLI} pfb_trigger scope=both force=true trigger=force", _PASS_OUT)
        try:
            h.wait_until(lambda: h.hook_marker_exists(vm, _STARTED), timeout=120.0, interval=1.0)
        except RuntimeError as exc:
            raise AssertionError(
                f"test setup: the feed pass never reached its pre hook; pass output: {h.read_log_file(vm, _PASS_OUT)!r}"
            ) from exc

        # ---- WHEN: pkg delete while the pass is parked ------------------------- #
        waiting_before = h.count_log_marker(vm, h.PFB_LOG, _WAITING_LINE)
        _run_in_background(vm, f"env ASSUME_ALWAYS_YES=yes pkg delete -y {PKG_NAME}", _DELETE_OUT)

        # THEN: the uninstall says it is waiting for the pass. The event consumed here is
        # "the uninstall reacted": either it logged the wait (fixed) or it went ahead and
        # tore down / finished without waiting (pre-#3090) -- one of the two always happens,
        # so the salvage cap only reports a genuinely stuck box.
        def _uninstall_reacted() -> bool:
            out = h.read_log_file(vm, _DELETE_OUT)
            return (
                h.count_log_marker(vm, h.PFB_LOG, _WAITING_LINE) > waiting_before
                or _TEARDOWN_LINE in out
                or "RC=" in out
            )

        h.wait_until(_uninstall_reacted, timeout=60.0, interval=1.0)
        delete_so_far = h.read_log_file(vm, _DELETE_OUT)
        assert h.count_log_marker(vm, h.PFB_LOG, _WAITING_LINE) > waiting_before, (
            f"`pkg delete` did not log {_WAITING_LINE!r} while a feed pass held the lock — the uninstall "
            f"is not serialised against an in-flight pass (issue #3090).\npkg delete output so far:\n{delete_so_far}"
        )
        # ... and has NOT torn anything down yet: the pass is still parked in its hook.
        assert _TEARDOWN_LINE not in delete_so_far, (
            f"`pkg delete` reached {_TEARDOWN_LINE!r} while the feed pass was still running — "
            f"the hold did not block the teardown:\n{delete_so_far}"
        )

        # ---- WHEN: the parked pass is released --------------------------------- #
        vm.ssh("touch", _GO)
        h.wait_until(lambda: "RC=" in h.read_log_file(vm, _DELETE_OUT), timeout=400.0, interval=2.0)
        delete_out = h.read_log_file(vm, _DELETE_OUT)
        pass_out = h.read_log_file(vm, _PASS_OUT)

        # THEN: the pass completed, and the uninstall took the hold, tore down and exited 0.
        assert pass_out.rstrip().endswith("RC=0"), f"the released feed pass did not exit 0:\n{pass_out}"
        assert 0 <= delete_out.find(_SERIALISING_LINE) < delete_out.find(_TEARDOWN_LINE), (
            f"expected {_SERIALISING_LINE!r} before {_TEARDOWN_LINE!r} on pkg delete's output:\n{delete_out}"
        )
        assert _HOLD_GIVEN_UP not in delete_out, (
            f"the uninstall gave up its wait instead of taking the hold:\n{delete_out}"
        )
        assert delete_out.rstrip().endswith("RC=0"), f"`pkg delete` exited non-zero:\n{delete_out}"
        assert pkg_installed_version(vm) is None, "`pkg delete` did not remove the package"
    finally:
        # Release anything still parked and let both background processes finish, then leave
        # the box as the sibling modules expect (no hook row, no package).
        vm.ssh(f"mkdir -p {_DIR}; touch {_GO}")
        with contextlib.suppress(RuntimeError):
            h.wait_until(lambda: _finished(vm, _PASS_OUT) and _finished(vm, _DELETE_OUT), timeout=400.0, interval=2.0)
        vm.ssh(f"rm -f {h.HOOK_SCRIPT_DIR}/{_HOOK['script']}; rm -rf {_DIR}")
        h.clear_update_hooks(vm)
        pkg_delete(vm)
