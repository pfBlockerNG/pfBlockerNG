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

import sys
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


def _wait_for_guest_file(vm: SmokeVM, path: str, *, deadline_s: float, poll_s: float = 1.0) -> None:
    """Poll until ``path`` exists on the guest or raise a salvage-only expiry.

    A bounded poll on a REMOTE file the hook creates — the only side we cannot signal — with a
    hard deadline (never an open wait). This is the sanctioned last-resort poll.
    """
    end = time.monotonic() + deadline_s
    result = None
    while True:
        result = vm.ssh("/bin/test", "-f", path)
        if result.returncode == 0:
            return
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"salvage cap expired / stuck or environment: guest file {path!r} expected test -f rc=0; "
                f"actual rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        time.sleep(min(poll_s, remaining))


def _wait_upgrade_gone(vm: SmokeVM, *, deadline_s: float, poll_s: float = 2.0) -> None:
    """Poll (bounded) until no pfSense-upgrade process remains or raise expiry.

    The test launches pfSense-upgrade DETACHED, so the wrapping pkg transaction (and its pkg
    lock) outlives the hook itself. Wait for it to exit before touching the package again; a
    bounded wait, never open-ended (pgrep rc 1 = none left).
    """
    end = time.monotonic() + deadline_s
    result = None
    while True:
        result = vm.ssh("/bin/sh", "-c", "pgrep -f pfSense-upgrade >/dev/null")
        if result.returncode == 1:
            return
        if result.returncode != 0:
            raise RuntimeError(
                "salvage cap expired / stuck or environment: _wait_upgrade_gone expected pgrep rc=0 "
                f"(running) or rc=1 (gone); actual rc={result.returncode} "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                "salvage cap expired / stuck or environment: _wait_upgrade_gone expected pgrep rc!=0; "
                f"actual rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        time.sleep(min(poll_s, remaining))


def _cleanup_hook_run(vm: SmokeVM) -> None:
    """Release the hook and clean up without hiding the test's primary failure."""
    primary_error = sys.exception()
    cleanup_errors: list[Exception] = []
    upgrade_running = False
    try:
        vm.ssh("/usr/bin/touch", PROCEED)
    except Exception as exc:
        cleanup_errors.append(exc)
        upgrade_running = True
    else:
        try:
            _wait_upgrade_gone(vm, deadline_s=60.0)
        except Exception as exc:
            cleanup_errors.append(exc)
            upgrade_running = True
    try:
        h.clear_update_hooks(vm)
    except Exception as exc:
        cleanup_errors.append(exc)
    try:
        vm.ssh("/bin/rm", "-f", GUI_LOG, WAITING, PROCEED)
    except Exception as exc:
        cleanup_errors.append(exc)
    if not upgrade_running:
        try:
            pkg_delete(vm)
        except Exception as exc:
            cleanup_errors.append(exc)
    if cleanup_errors:
        if primary_error is not None:
            for cleanup_error in cleanup_errors:
                primary_error.add_note(f"hook cleanup: {cleanup_error}")
        else:
            for cleanup_error in cleanup_errors[1:]:
                cleanup_errors[0].add_note(f"additional hook cleanup failure: {cleanup_error}")
            raise cleanup_errors[0]


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
        _wait_for_guest_file(vm, WAITING, deadline_s=300.0)

        # ---- THEN (streaming): LINE1 visible mid-hook, LINE2 not yet --------------- #
        # The hook is provably still blocked: it touched WAITING (removed only after LINE2),
        # and PROCEED is not created until below — so nothing releases it during this window.
        # Streaming has inherent lag (the on-box tail polls every 200ms, then pfSense-upgrade
        # tees), so poll (bounded) for LINE1 rather than a single racy read. A hook whose output
        # only appears AFTER it exits (block-behaviour) never shows LINE1 here — the hook cannot
        # exit until PROCEED, which is created only after this loop.
        mid = ""

        def line1_observed() -> bool:
            nonlocal mid
            mid = vm.ssh("cat", GUI_LOG).stdout
            return LINE1 in mid

        try:
            h.wait_until(line1_observed, timeout=20.0, interval=1.0)
        except RuntimeError as exc:
            raise RuntimeError(
                f"salvage cap expired / stuck or environment: hook GUI log expected marker {LINE1!r}; "
                f"observed tail={mid[-3000:]!r}"
            ) from exc
        assert vm.ssh("/bin/test", "-f", WAITING).returncode == 0, (
            "the hook left its wait state before LINE1 was checked — timing invariant broken"
        )
        assert LINE2 not in mid, (
            f"{LINE2!r} appeared before the hook was released — the block-on-signal setup is "
            f"broken (the hook did not actually wait). GUI log:\n{mid[-3000:]}"
        )

        # ---- WHEN: release the hook, let the op finish ----------------------------- #
        vm.ssh("/usr/bin/touch", PROCEED)

        # Wait (bounded) for LINE2 to land — the op is done once the final line is mirrored.
        final = ""

        def line2_observed() -> bool:
            nonlocal final
            final = vm.ssh("cat", GUI_LOG).stdout
            return LINE2 in final

        try:
            h.wait_until(line2_observed, timeout=120.0, interval=1.0)
        except RuntimeError as exc:
            raise RuntimeError(
                f"salvage cap expired / stuck or environment: hook GUI log expected marker {LINE2!r}; "
                f"observed tail={final[-3000:]!r}"
            ) from exc

        # ---- THEN: both lines present at the end ----------------------------------- #
        assert LINE1 in final, f"after releasing the hook, GUI log missing {LINE1!r}:\n{final[-3000:]}"

        # LINE2 means the HOOK finished, but the wrapping detached pfSense-upgrade keeps its pkg
        # lock through the rest of the resync. Drain it before cleanup so pkg_delete() below (in
        # finally) doesn't race the still-held lock. Assert (loud timeout): if it never exits the
        # test is not deterministic — surface that rather than proceed into a lock race.
        _wait_upgrade_gone(vm, deadline_s=120.0)
    finally:
        _cleanup_hook_run(vm)
