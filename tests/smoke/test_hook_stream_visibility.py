"""ADR-12 / #693 — a hook's output must STREAM to the GUI while the hook runs, not
appear as one block only after it exits.

``test_lifecycle_hook_visibility`` proves a hook's output ENDS UP in the GUI log; this
proves it gets there PROGRESSIVELY. Today ``pfb_run_hooks()`` runs the hook to completion
under a blocking ``exec()`` (its output redirected to a file so a spawned daemon can't hang
the pass, #662) and only then mirrors the whole delta to stdout (``pfb_mirror_hook_output``)
— so a slow hook (e.g. a 30 s HAProxy reload printing progress) shows BLANK on the pkg
Software page the whole time, then dumps everything at the end.

This pins the streaming contract without a browser: install a hook that prints LINE1, then
BLOCKS on a test-controlled "proceed" file (a signal, not a sleep — deterministic), then
prints LINE2. While the hook is still blocked, LINE1 must already be visible in the GUI-tailed
log. RED against the block-behavior (LINE1 absent mid-hook); GREEN once the hook output streams.
"""

from __future__ import annotations

import time

import pytest

from . import helpers as h
from .conftest import SmokeVM
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

PFSENSE_UPGRADE = "/usr/local/sbin/pfSense-upgrade"
GUI_LOG = "/tmp/pfb_gui_stream.txt"
WAITING = "/tmp/pfb_hook_waiting"  # hook touches this after printing LINE1, before blocking
PROCEED = "/tmp/pfb_hook_proceed"  # test touches this to release the hook to print LINE2
LINE1 = "PFB_STREAM_LINE1"
LINE2 = "PFB_STREAM_LINE2"


def _streaming_hook(token: str) -> dict[str, str]:
    """A post hook: print LINE1, signal 'waiting', BLOCK on PROCEED (bounded), print LINE2.

    The block is a busy-wait on a test-created file — a signal, not a fixed sleep — so the
    test releases the hook deterministically and never races a timer. The 30 s inner bound
    (150 * 0.2 s) is a self-guard so the hook can never outlive its own timeout budget.
    """
    body = (
        "#!/bin/sh\n"
        f"echo '{LINE1}'\n"
        f": > {WAITING}\n"
        f"i=0\nwhile [ ! -f {PROCEED} ] && [ $i -lt 150 ]; do sleep 0.2; i=$((i + 1)); done\n"
        f"echo '{LINE2}'\n"
        f"rm -f {WAITING}\n"
    )
    return {
        "script": f"hook_post_{token}_stream.sh",
        "_body": body,
        "when": "post",
        "enabled": "on",
        "description": f"smoke {token} stream",
        "timeout": "120",  # must exceed the block window so the wait is not killed
    }


def _wait_for_guest_file(vm: SmokeVM, path: str, *, deadline_s: float, poll_s: float = 1.0) -> bool:
    """Poll until ``path`` exists on the guest or the deadline passes. Returns True iff it appeared.

    A bounded poll on a REMOTE file the hook creates — the only side we cannot signal — with a
    hard deadline (never an open wait). This is the sanctioned last-resort poll, kept loud: the
    caller asserts the return.
    """
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if vm.ssh("/bin/test", "-f", path).returncode == 0:
            return True
        time.sleep(poll_s)
    return False


def _wait_upgrade_gone(vm: SmokeVM, *, deadline_s: float, poll_s: float = 2.0) -> bool:
    """Poll (bounded) until no pfSense-upgrade process remains. Returns True iff it drained.

    The test launches pfSense-upgrade DETACHED, so the wrapping pkg transaction (and its pkg
    lock) outlives the hook itself. Wait for it to exit before touching the package again; a
    bounded wait, never open-ended (pgrep rc 1 = none left).
    """
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if vm.ssh("/bin/sh", "-c", "pgrep -f pfSense-upgrade >/dev/null").returncode != 0:
            return True
        time.sleep(poll_s)
    return False


@pytest.mark.timeout(1200)
def test_hook_output_streams_to_gui_while_running(repo_vm: SmokeVM) -> None:
    """A hook's stdout is visible in the GUI log WHILE the hook is still running.

    Scenario: a slow hook's progress must stream to the pkg Software page, not appear only
      after it finishes.
      Background: our NONE-signed file:// repo above the Netgate repo (repo_vm).

    Given pfBlockerNG installed with a post hook that prints LINE1, then blocks on a
      test-controlled signal file, then prints LINE2,
    When the GUI "Update now" wrapper (``pfSense-upgrade -i <name> -f``) runs it — launched
      detached so we can observe mid-flight — and the hook signals it has printed LINE1 and is
      now blocked,
    Then LINE1 is ALREADY present in the GUI-tailed log (``-l`` file) while LINE2 is NOT — the
      hook's output streamed. (RED against today's block-behavior: the whole hook body is
      mirrored only after the hook exits, so LINE1 is absent here.)
    When the hook is released and the op completes,
    Then BOTH LINE1 and LINE2 are in the GUI log — the tail drained to completion.
    """
    vm = repo_vm
    pfsense_prio = repo_priority(vm, NETGATE_REPO_NAME)
    token = "streamvis"

    try:
        # ---- GIVEN: install from our repo + the block-on-signal streaming hook ----- #
        pkg_delete(vm)
        write_repo_conf(vm, OURS_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(vm)
        assert pkg_installed_version(vm) is None, f"{PKG_NAME} unexpectedly present before install"
        pkg_install_from_repo(vm)
        assert pkg_installed_version(vm) is not None, "the from-repo install did not register the package"

        h.set_update_hooks(vm, [_streaming_hook(token)])
        vm.ssh("/bin/rm", "-f", GUI_LOG, WAITING, PROCEED)

        # ---- WHEN: launch the GUI reinstall DETACHED so we can watch mid-hook ------- #
        # nohup + & so ssh returns immediately; pfSense-upgrade keeps running on the guest.
        vm.ssh(
            "/bin/sh",
            "-c",
            f"nohup {PFSENSE_UPGRADE} -y -l {GUI_LOG} -i {PKG_NAME} -f >/dev/null 2>&1 &",
        )

        # The hook fires late in the resync; wait (bounded) for it to print LINE1 and block.
        assert _wait_for_guest_file(vm, WAITING, deadline_s=300.0), (
            "the streaming hook never reached its wait state within 300s — the reinstall resync "
            "did not fire the post hook (was pfSense-upgrade -i -f run and the hook configured?)"
        )

        # ---- THEN (streaming): LINE1 visible mid-hook, LINE2 not yet --------------- #
        # The hook is provably still blocked: it touched WAITING (removed only after LINE2),
        # and PROCEED is not created until below — so nothing releases it during this window.
        # Streaming has inherent lag (the on-box tail polls every 200ms, then pfSense-upgrade
        # tees), so poll (bounded) for LINE1 rather than a single racy read. A hook whose output
        # only appears AFTER it exits (block-behaviour) never shows LINE1 here — the hook cannot
        # exit until PROCEED, which is created only after this loop.
        mid = ""
        end = time.monotonic() + 20.0
        while time.monotonic() < end:
            mid = vm.ssh("cat", GUI_LOG).stdout
            if LINE1 in mid:
                break
            time.sleep(1.0)
        assert vm.ssh("/bin/test", "-f", WAITING).returncode == 0, (
            "the hook left its wait state before LINE1 was checked — timing invariant broken"
        )
        assert LINE1 in mid, (
            f"the hook's first line {LINE1!r} did NOT reach the GUI log while the hook is still "
            f"blocked — its output is buffered until the hook exits instead of streaming to the pkg "
            f"Software page. GUI log so far:\n{mid[-3000:]}"
        )
        assert LINE2 not in mid, (
            f"{LINE2!r} appeared before the hook was released — the block-on-signal setup is "
            f"broken (the hook did not actually wait). GUI log:\n{mid[-3000:]}"
        )

        # ---- WHEN: release the hook, let the op finish ----------------------------- #
        vm.ssh("/usr/bin/touch", PROCEED)
        assert _wait_for_guest_file(vm, GUI_LOG, deadline_s=60.0), "GUI log vanished after release"

        # Wait (bounded) for LINE2 to land — the op is done once the final line is mirrored.
        end = time.monotonic() + 120.0
        final = ""
        while time.monotonic() < end:
            final = vm.ssh("cat", GUI_LOG).stdout
            if LINE2 in final:
                break
            time.sleep(1.0)

        # ---- THEN: both lines present at the end ----------------------------------- #
        assert LINE1 in final and LINE2 in final, (
            f"after releasing the hook, the GUI log is missing a line (LINE1={LINE1 in final}, "
            f"LINE2={LINE2 in final}):\n{final[-3000:]}"
        )

        # LINE2 means the HOOK finished, but the wrapping detached pfSense-upgrade keeps its pkg
        # lock through the rest of the resync. Drain it before cleanup so pkg_delete() below (in
        # finally) doesn't race the still-held lock. Assert (loud timeout): if it never exits the
        # test is not deterministic — surface that rather than proceed into a lock race.
        assert _wait_upgrade_gone(vm, deadline_s=120.0), (
            "pfSense-upgrade did not exit within 120s after the hook finished — cleanup would race "
            "its still-held pkg lock"
        )
    finally:
        vm.ssh("/usr/bin/touch", PROCEED)  # never leave a blocked hook behind
        _wait_upgrade_gone(vm, deadline_s=60.0)  # let a failed-path run release its pkg lock too
        h.clear_update_hooks(vm)
        vm.ssh("/bin/rm", "-f", GUI_LOG, WAITING, PROCEED)
        pkg_delete(vm)
