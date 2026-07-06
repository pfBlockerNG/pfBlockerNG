"""ADR-12 + #690/#697 — a pfSense pkg lifecycle op fires the update hooks with the
right context, AND the hook's own output is what the GUI Package Manager shows.

Two gaps neither ``test_smoke_hooks`` (normal cron/force update passes) nor
``test_pkg_op_teardown`` (the #697 teardown DECISION, asserted via the pkg-delete
process's own captured stdout/stderr) cover:

* A GUI **reinstall** ("Update now") drives ``pfSense-upgrade -i <name> -f``, not a bare
  ``pkg install -f`` — does the install-side resync inside THAT wrapper still fire the
  update hooks with ``PFB_POST_INSTALL=1``?
* ``pfSense-upgrade`` runs ``pkg-static <op> 2>/dev/null | tee -a <log>`` (drops stderr,
  tees only stdout to the log file the GUI page displays as ``<LOGBASE>.txt``). A hook
  mirrors its output to stdout during a pkg lifecycle callback (#690), but nothing before
  this file proves that output actually SURVIVES the drop+tee and lands in the file the
  GUI would render.

Both tests drive ``/usr/local/sbin/pfSense-upgrade`` directly (the same binary
``pkg_mgr_install.php`` shells out to for "Update now" / "Remove"), reproducing what the
GUI page shows WITHOUT a browser (Tier B territory otherwise). NOT A SMOKE TEST — like
``test_pkg_op_teardown`` / ``test_repo_install`` this validates *distribution / lifecycle*
mechanics, so it carries the ``repo`` marker (NOT ``smoke``) and reuses ``repo_vm``.
DESELECTED from the default ``python -m pytest``; runs only via::

    python -m pytest tests/smoke -m repo --override-ini="addopts="
"""

from __future__ import annotations

import pytest

from . import helpers as h
from .conftest import SmokeVM

# _TEARDOWN_LINE (the pre-deinstall teardown log line) and _enable_dnsbl (the DNSBL-enable
# setup) are exactly what test 2 needs and already live in the sibling lifecycle test — import
# rather than duplicate. Underscore-private, so a rename there surfaces here at collection;
# acceptable coupling between two tests that exercise the same pre-deinstall path.
from .test_pkg_op_teardown import _TEARDOWN_LINE, _enable_dnsbl

# ``repo_vm`` is re-exported (not just imported): pytest resolves fixtures PER-MODULE, so
# importing the helpers does NOT register the fixture in this module's namespace — the
# name must be present here for the case params below to request it. noqa keeps the
# (module-level "unused") fixture import.
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
# pfSense-upgrade writes the `-l` argument VERBATIM (pkg_mgr_install.php passes
# `-l {logfilename}.txt` and then displays that exact file), so the `-l` value and the
# path we read back MUST be identical — include the `.txt`. Distinct paths per test so
# neither leg reads a stale file left by the other.
GUI_LOG_REINSTALL = "/tmp/pfb_gui_reinstall.txt"
GUI_LOG_DELETE = "/tmp/pfb_gui_delete.txt"


def _stdout_marker_line(token: str, when: str) -> str:
    """The unique one-line stdout marker a visibility hook echoes — the GUI-visibility grep target."""
    return f"PFB_HOOKVIS_{token}_{when}"


def _visibility_hook(token: str, when: str) -> dict[str, str]:
    """A hook whose script BOTH echoes a unique stdout marker AND env-dumps to a marker file.

    Combines ``env_dump_hook``'s env-capture with a leading stdout echo so one script
    proves two things at once: it ran with the right lifecycle context (the ``PFB_*``
    env dump), and its own stdout is exactly what a GUI log tail would show —
    ``pfSense-upgrade`` runs ``pkg-static <op> 2>/dev/null | tee -a <log>``, dropping
    stderr and teeing only stdout, so a hook's output reaches the GUI only via stdout.
    """
    marker = h.hook_marker_path(token, when)
    line = _stdout_marker_line(token, when)
    return {
        "script": f"hook_{when}_{token}_vis.sh",
        "_body": f"#!/bin/sh\necho '{line}'\n/usr/bin/env > {marker}\n",
        "when": when,
        "enabled": "on",
        "description": f"smoke {token} {when} visibility",
        "timeout": "60",
    }


def _visibility_hooks(token: str) -> list[dict[str, str]]:
    """A pre+post pair of ``_visibility_hook`` entries sharing one token."""
    return [_visibility_hook(token, "pre"), _visibility_hook(token, "post")]


def _gui_log_tail(vm: SmokeVM, logpath: str, *, chars: int = 3000) -> str:
    """Tail of the pfSense-upgrade GUI log (the exact `-l` path).

    Surface a `cat` failure explicitly instead of returning ''. A missing log file
    (e.g. an `-l`-semantics regression, the exact bug this file already hit once) then
    reads as an obvious diagnostic rather than looking identical to an empty tail —
    so a failing assertion distinguishes "log was never created" from "hook did not run".
    """
    r = vm.ssh("cat", logpath)
    if r.returncode != 0:
        return f"<cat {logpath} failed rc={r.returncode}: {r.stderr.strip()}>"
    return r.stdout[-chars:]


@pytest.mark.timeout(900)  # install + terminal reinstall + GUI reinstall; budget ~15 min
def test_update_hooks_fire_and_are_gui_visible_on_reinstall(repo_vm: SmokeVM) -> None:
    """An ADR-12 update hook fires with ``PFB_POST_INSTALL=1`` on a reinstall, both via
    the bare pkg CLI AND the GUI "Update now" path, and its stdout reaches the GUI log.

    Scenario: a forced reinstall's install-side resync fires the update hooks, and the
      GUI wrapper does not swallow a hook's own output.
      Background: our NONE-signed file:// repo above the Netgate repo (repo_vm).

    Given pfBlockerNG installed from our repo with a pre+post visibility hook configured,
    When ``pkg install -f -y <name>`` reinstalls it (the terminal op ``pkg_op_teardown``
      calls "reinstall"),
    Then both hooks fire with ``PFB_POST_INSTALL=1`` and their stdout marker lines appear
      in the captured terminal output.
    When the SAME reinstall runs via the GUI's own wrapper, ``pfSense-upgrade -y -l
      <log> -i <name> -f`` (what "Update now" shells out to),
    Then both hooks fire again with ``PFB_POST_INSTALL=1``, AND their stdout marker lines
      appear in ``<log>.txt`` — proving a hook's output survives pfSense-upgrade's
      stderr-drop + tee and is exactly what the GUI page would render.
    """
    vm = repo_vm
    pfsense_prio = repo_priority(vm, NETGATE_REPO_NAME)
    token = "reinstallvis"
    pre_marker = h.hook_marker_path(token, "pre")
    post_marker = h.hook_marker_path(token, "post")
    pre_line = _stdout_marker_line(token, "pre")
    post_line = _stdout_marker_line(token, "post")

    try:
        # ---- GIVEN: install from our repo + configure pre/post visibility hooks --- #
        pkg_delete(vm)
        write_repo_conf(vm, OURS_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(vm)
        assert pkg_installed_version(vm) is None, f"{PKG_NAME} unexpectedly present before the install"
        pkg_install_from_repo(vm)
        assert pkg_installed_version(vm) is not None, "the from-repo install did not register the package"

        h.set_update_hooks(vm, _visibility_hooks(token))
        h.clear_hook_markers(vm, token)
        vm.ssh("/bin/rm", "-f", GUI_LOG_REINSTALL)
        assert not h.hook_marker_exists(vm, pre_marker), "pre marker present before reinstall (stale state?)"
        assert not h.hook_marker_exists(vm, post_marker), "post marker present before reinstall (stale state?)"

        # ---- WHEN (terminal): pkg install -f -y <name> (op 'reinstall') ----------- #
        proc = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", "-f", "-y", PKG_NAME, timeout=600)
        combined = proc.stdout + proc.stderr

        pre_env = h.read_hook_env(vm, pre_marker)
        post_env = h.read_hook_env(vm, post_marker)
        assert pre_env is not None, (
            f"pre hook did NOT fire on terminal `pkg install -f` (no marker).\n{combined[-3000:]}"
        )
        assert post_env is not None, (
            f"post hook did NOT fire on terminal `pkg install -f` (no marker).\n{combined[-3000:]}"
        )
        assert pre_env.get("PFB_POST_INSTALL") == "1", f"pre PFB_POST_INSTALL wrong on reinstall: {pre_env}"
        assert post_env.get("PFB_POST_INSTALL") == "1", f"post PFB_POST_INSTALL wrong on reinstall: {post_env}"
        assert pre_env.get("PFB_WHEN") == "pre", f"pre PFB_WHEN wrong: {pre_env}"
        assert post_env.get("PFB_WHEN") == "post", f"post PFB_WHEN wrong: {post_env}"
        assert pre_line in combined, (
            f"terminal `pkg install -f` output is missing the pre hook's stdout marker "
            f"{pre_line!r}:\n{combined[-3000:]}"
        )
        assert post_line in combined, (
            f"terminal `pkg install -f` output is missing the post hook's stdout marker "
            f"{post_line!r}:\n{combined[-3000:]}"
        )

        # ---- WHEN (GUI): pfSense-upgrade -i <name> -f ("Update now" shortcut) ------ #
        h.clear_hook_markers(vm, token)
        assert not h.hook_marker_exists(vm, pre_marker), "pre marker present before GUI reinstall (stale state?)"
        assert not h.hook_marker_exists(vm, post_marker), "post marker present before GUI reinstall (stale state?)"

        gui_proc = vm.ssh(PFSENSE_UPGRADE, "-y", "-l", GUI_LOG_REINSTALL, "-i", PKG_NAME, "-f", timeout=600)
        gui_log = _gui_log_tail(vm, GUI_LOG_REINSTALL)
        assert gui_proc.returncode == 0, (
            f"the GUI 'Update now' wrapper (pfSense-upgrade -i -f) exited non-zero "
            f"(rc={gui_proc.returncode}):\nstdout:\n{gui_proc.stdout[-2000:]}\n"
            f"stderr:\n{gui_proc.stderr[-2000:]}\nGUI log:\n{gui_log}"
        )

        pre_env2 = h.read_hook_env(vm, pre_marker)
        post_env2 = h.read_hook_env(vm, post_marker)
        diag = f"pfSense-upgrade -i -f rc={gui_proc.returncode}\nGUI log tail:\n{gui_log}\n{h.deinstall_debug(vm)}"
        assert pre_env2 is not None, f"pre hook did NOT fire on GUI reinstall (no marker).\n{diag}"
        assert post_env2 is not None, f"post hook did NOT fire on GUI reinstall (no marker).\n{diag}"
        assert pre_env2.get("PFB_POST_INSTALL") == "1", (
            f"pre PFB_POST_INSTALL wrong on GUI reinstall: {pre_env2}\n{diag}"
        )
        assert post_env2.get("PFB_POST_INSTALL") == "1", (
            f"post PFB_POST_INSTALL wrong on GUI reinstall: {post_env2}\n{diag}"
        )

        assert pre_line in gui_log, (
            f"the pre hook's stdout marker {pre_line!r} is MISSING from the GUI log "
            f"({GUI_LOG_REINSTALL}) — pfSense-upgrade tees pkg-static's stdout there and "
            f"drops stderr, so a hook whose output does not reach stdout is invisible to the "
            f"GUI:\n{gui_log}"
        )
        assert post_line in gui_log, (
            f"the post hook's stdout marker {post_line!r} is MISSING from the GUI log ({GUI_LOG_REINSTALL}):\n{gui_log}"
        )
    finally:
        h.clear_update_hooks(vm)
        h.clear_hook_markers(vm, token)
        pkg_delete(vm)


@pytest.mark.timeout(900)  # install + DNSBL enable/reload + GUI delete + DNS probes; budget ~15 min
def test_uninstall_runs_hook_tears_down_and_is_gui_visible(repo_vm: SmokeVM) -> None:
    """A REAL uninstall via the GUI "Remove" path runs the hooks with
    ``PFB_PRE_UNINSTALL=1``, TEARS pfBlockerNG DOWN, and its stdout reaches the GUI log.

    Scenario: ``pfSense-upgrade -r`` drives the SAME pre-deinstall + hook pass a GUI
      "Remove" click does.
      Background: our NONE-signed file:// repo above the Netgate repo (repo_vm).

    Given pfBlockerNG installed from our repo with a live DNSBL block (a
      ``unique_domain()`` name resolves to the sinkhole VIP) and pre+post visibility
      hooks configured,
    When the GUI delete path (``pfSense-upgrade -y -l <log> -r <name>``) removes the
      package,
    Then both hooks fire with ``PFB_PRE_UNINSTALL=1`` (the disable-pass context); the
      package is gone; the DNSBL block is torn down (the domain no longer resolves to
      the VIP); the pfB log shows the teardown line; AND each hook's stdout marker line
      appears in the GUI log — proving the uninstall hook's own output is what "Remove"
      would show.
    """
    vm = repo_vm
    pfsense_prio = repo_priority(vm, NETGATE_REPO_NAME)
    token = "deletevis"
    pre_marker = h.hook_marker_path(token, "pre")
    post_marker = h.hook_marker_path(token, "post")
    pre_line = _stdout_marker_line(token, "pre")
    post_line = _stdout_marker_line(token, "post")
    domain = h.unique_domain("lchookvis")

    try:
        # ---- GIVEN: install from our repo + a live DNSBL block -------------------- #
        pkg_delete(vm)
        write_repo_conf(vm, OURS_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(vm)
        assert pkg_installed_version(vm) is None, f"{PKG_NAME} unexpectedly present before the install"
        pkg_install_from_repo(vm)
        assert pkg_installed_version(vm) is not None, "the from-repo install did not register the package"

        feed = h.write_local_feed(vm, "lifecycle_hook_vis.txt", f"{domain}\n")
        _enable_dnsbl(vm)
        h.ensure_dnsbl_vip(vm)
        spec = h.DnsblCase(
            aliasname="LcHookVis",
            feed_url=feed,
            mode=h.DnsblMode.VIP,
            header="lchookvis",
            hsts=False,
        )
        h.inject(vm, spec)
        h.reload(vm, "updatednsbl")

        given = h.dns_probe(vm, domain, "A")
        assert h.is_vip(given), (
            f"GIVEN: DNSBL was not live before the uninstall for {domain!r}; "
            f"got rcode={given.rcode!r} records={given.records!r}"
        )

        # ---- AND: pre/post visibility hooks configured ----------------------------- #
        h.set_update_hooks(vm, _visibility_hooks(token))
        h.clear_hook_markers(vm, token)
        vm.ssh("/bin/rm", "-f", GUI_LOG_DELETE)
        assert not h.hook_marker_exists(vm, pre_marker), "pre marker present before uninstall (stale state?)"
        assert not h.hook_marker_exists(vm, post_marker), "post marker present before uninstall (stale state?)"

        # ---- WHEN: GUI delete path (op 'delete' -> pre-deinstall disable pass) ---- #
        gui_proc = vm.ssh(PFSENSE_UPGRADE, "-y", "-l", GUI_LOG_DELETE, "-r", PKG_NAME, timeout=600)
        gui_log = _gui_log_tail(vm, GUI_LOG_DELETE)
        diag = f"pfSense-upgrade -r rc={gui_proc.returncode}\nGUI log tail:\n{gui_log}\n{h.deinstall_debug(vm)}"
        assert gui_proc.returncode == 0, f"the GUI 'Remove' wrapper (pfSense-upgrade -r) exited non-zero.\n{diag}"

        # THEN: both hooks fired with the uninstall lifecycle context.
        pre_env = h.read_hook_env(vm, pre_marker)
        post_env = h.read_hook_env(vm, post_marker)
        assert pre_env is not None, f"pre hook did NOT fire on GUI uninstall (no marker).\n{diag}"
        assert post_env is not None, f"post hook did NOT fire on GUI uninstall (no marker).\n{diag}"
        assert pre_env.get("PFB_PRE_UNINSTALL") == "1", f"pre PFB_PRE_UNINSTALL wrong: {pre_env}\n{diag}"
        assert post_env.get("PFB_PRE_UNINSTALL") == "1", f"post PFB_PRE_UNINSTALL wrong: {post_env}\n{diag}"
        assert pre_env.get("PFB_WHEN") == "pre", f"pre PFB_WHEN wrong: {pre_env}\n{diag}"
        assert post_env.get("PFB_WHEN") == "post", f"post PFB_WHEN wrong: {post_env}\n{diag}"

        # THEN: the uninstall actually TORE DOWN pfBlockerNG.
        assert pkg_installed_version(vm) is None, f"pfSense-upgrade -r did not remove {PKG_NAME}.\n{diag}"
        h.wait_unbound_ready(vm)
        after = h.dns_probe(vm, domain, "A")
        assert not h.is_vip(after), (
            f"AFTER uninstall: {domain!r} still resolved to the DNSBL VIP — teardown did not "
            f"remove the DNSBL block; got rcode={after.rcode!r} records={after.records!r}\n{diag}"
        )
        assert _TEARDOWN_LINE in gui_log, (
            f"the GUI log does not show the teardown line {_TEARDOWN_LINE!r} after uninstall — the "
            f"pre-deinstall's update_status() output must reach the GUI-tailed log:\n{gui_log}"
        )

        # THEN: each hook's stdout marker reached the GUI log.
        assert pre_line in gui_log, (
            f"the pre hook's stdout marker {pre_line!r} is MISSING from the GUI log "
            f"({GUI_LOG_DELETE}) — pfSense-upgrade tees pkg-static's stdout there and drops "
            f"stderr, so a hook whose output does not reach stdout is invisible to the GUI:\n{gui_log}"
        )
        assert post_line in gui_log, (
            f"the post hook's stdout marker {post_line!r} is MISSING from the GUI log ({GUI_LOG_DELETE}):\n{gui_log}"
        )
    finally:
        h.clear_update_hooks(vm)
        h.clear_hook_markers(vm, token)
        pkg_delete(vm)  # best-effort — the package may already be gone
