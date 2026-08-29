"""#697 — the pre-deinstall pkg-operation teardown gate, end-to-end on the live VM.

pfSense reaches pfBlockerNG's ``custom_php_pre_deinstall_command`` for BOTH a genuine
uninstall AND an in-place package reinstall/upgrade, with no ``upgrade`` signal in the
argument it passes. #697 tells the two apart by reading the pkg/pkg-static ANCESTOR's
argv (``pfb_pkg_operation`` -> ``pfb_pkg_op_tears_down``): a real uninstall (and a major
OS upgrade's mass-removal) is ``pkg delete`` -> op ``delete`` -> TEAR DOWN; the GUI
"Update now" / a ``pkg upgrade`` / a forced reinstall is ``pkg install -f`` /
``pkg upgrade`` -> op ``install|reinstall|upgrade`` -> SKIP the teardown (keep
pfBlockerNG live; the package's own post-install resync re-applies).

``tests/php/PfbPkgOperationTest.php`` unit-tests the parser + the gate over synthetic
``ps`` output. This case is the LIVE proof that the detector reads a REAL pkg process
tree correctly during an actual pkg operation and that the gate flips pfBlockerNG's
runtime state accordingly — the half a pure unit test cannot cover.

NOT A SMOKE TEST. Like ``test_repo_install.py`` / ``test_upgrade_config_stability.py``
this validates a *distribution / lifecycle* mechanic, so it carries the ``repo`` marker
(NOT ``smoke``) and reuses that module's ``repo_vm`` fixture + helpers. It is DESELECTED
from the default ``python -m pytest`` and runs only via its own dispatch::

    python -m pytest tests/smoke -m repo --override-ini="addopts="

TWO LEGS (the gate's two branches, with the runtime effect asserted for each):

* ``pkg install -f`` (forced reinstall — the GUI Update path, op ``reinstall``):
  the pre-deinstall logs its KEEP-LIVE decision and does NOT tear down, and a
  DNSBL-blocked ``unique_domain()`` name STILL returns the VIP block shape
  immediately afterwards WITHOUT a reload. On the pre-#697 code the pre-deinstall
  always tore down here (there was no gate), so both the log line and the
  still-blocked probe FAIL against it — the red→green discriminator.

* ``pkg delete`` (a real uninstall, op ``delete``): the pre-deinstall TEARS DOWN
  (turns pfBlockerNG off, removes live objects), and the same domain no longer
  resolves to the VIP — the other branch, so "keep live" above is provably
  op-driven, not an always-live artefact.

Needs the booted ``repo_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``); without
them it skips cleanly via ``repo_vm``.
"""

from __future__ import annotations

import subprocess

import pytest

import tests.smoke.helpers as h

from .conftest import SmokeVM

# ``repo_vm`` is re-exported (not just imported): pytest resolves fixtures PER-MODULE,
# so importing the helpers does NOT register the fixture in this module's namespace —
# the name must be present here for the case below to request it. noqa keeps the
# (module-level "unused") fixture import; the matching F811 ("redefinition" by the case
# param) is suppressed for this file in pyproject.
from .test_repo_install import (  # noqa: F401
    NETGATE_REPO_NAME,
    OURS_REPO_DIR,
    PKG_NAME,
    build_guest_repo,
    pkg_delete,
    pkg_install_from_repo,
    pkg_installed_version,
    pkg_update,
    repo_priority,
    repo_vm,
    write_repo_conf,
)

pytestmark = pytest.mark.repo

# The gate's two status lines (pfblockerng.inc:17154 / :17167). Matched as substrings so
# the reinstall leg is agnostic to the exact op word in the keep-live line.
_KEEP_LIVE_LINE = "Keeping pfBlockerNG active across the package"
_TEARDOWN_LINE = "Removing pfBlockerNG..."

# #738 F7: the deferred-settings marker the deinstall teardown must clear (and a
# keep-live reinstall must NOT touch). Host path — the marker lives outside the
# Unbound chroot, plain /bin/sh access.
_PENDING_MARKER = "/usr/local/etc/pfb_pending_changes"


def _marker_exists(vm: SmokeVM) -> bool:
    """TRUE iff the pending-changes marker file exists on the box."""
    probe = vm.ssh("/bin/sh", "-c", f"test -f {_PENDING_MARKER} && echo YES || echo NO")
    return probe.stdout.strip() == "YES"


def _enable_dnsbl(vm: SmokeVM) -> None:
    """Set the DNSBL master enable chain (enable_cb + pfb_dnsbl) in config.xml.

    ``h.inject`` writes the DNSBL LIST/settings config but not the two master switches;
    ``h.ensure_dnsbl_vip`` + a reload then make the block live. Mirrors the enable chain
    ``test_upgrade_config_stability._write_representative_config`` sets.
    """
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"$s = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        "$s['pfb_dnsbl'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $s);\n"
        "write_config('pfBlockerNG #697 pkg-op smoke: enable DNSBL');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_enable_dnsbl failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def pkg_reinstall_force(vm: SmokeVM, *, timeout: float = 600.0) -> subprocess.CompletedProcess[str]:
    """``pkg install -f -y <name>`` — force a reinstall of the installed build (op ``reinstall``).

    The exact op the GUI "Update now" shortcut runs (``mode=reinstallpkg`` ->
    ``pfSense-upgrade -i -f`` -> ``pkg install -f``). Returns the CompletedProcess so the
    caller can read the pre-deinstall's keep-live line off the combined output.
    """
    result = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", "-f", "-y", PKG_NAME, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"pkg install -f {PKG_NAME} failed: rc={result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def pkg_delete_capture(vm: SmokeVM, *, timeout: float = 300.0) -> subprocess.CompletedProcess[str]:
    """``pkg delete -y <name>`` returning the process (op ``delete`` -> pre-deinstall tears down)."""
    result = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y", PKG_NAME, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"pkg delete {PKG_NAME} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


@pytest.mark.timeout(900)  # install + reload + reinstall + delete + DNS probes; budget ~12 min
def test_pkg_reinstall_keeps_live_delete_tears_down(repo_vm: SmokeVM) -> None:
    """PRE-DEINSTALL GATE (#697): a forced reinstall keeps pfBlockerNG LIVE; a real
    uninstall TEARS IT DOWN — the op-detector decides, read from the live pkg process tree.

    Scenario: the pre-deinstall must not disable pfBlockerNG on a package upgrade.
      Background: our NONE-signed file:// repo (built by repo_vm) above the Netgate repo.

    Given pfBlockerNG installed from our repo with a live DNSBL block (a
      unique_domain() name returns the sinkhole VIP on-box),

    When ``pkg install -f`` reinstalls the SAME build (op ``reinstall``),
    Then the pre-deinstall logs the keep-live decision (``{_KEEP_LIVE_LINE}``) and does
      NOT log the teardown line, AND the domain STILL returns the VIP with NO reload —
      the reinstall left pfBlockerNG live. (Pre-#697 the pre-deinstall always tore down
      here, so both checks fail against it.)

    When ``pkg delete`` then removes the package (op ``delete``),
    Then the pre-deinstall logs the teardown line (not the keep-live line) and the SAME
      domain no longer resolves to the VIP — teardown ran, proving the keep-live above is
      op-driven, not always-live.
    """
    vm = repo_vm
    pfsense_prio = repo_priority(vm, NETGATE_REPO_NAME)
    domain = h.unique_domain("pkgop697")
    feed = h.write_local_feed(vm, "pkg_op_teardown.txt", f"{domain}\n")

    try:
        # ---- GIVEN: install from our repo + a live DNSBL block ------------------ #
        pkg_delete(vm)
        write_repo_conf(vm, OURS_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(vm)
        assert pkg_installed_version(vm) is None, f"{PKG_NAME} unexpectedly present before the install"
        pkg_install_from_repo(vm)
        assert pkg_installed_version(vm) is not None, "the from-repo install did not register the package"

        _enable_dnsbl(vm)
        h.ensure_dnsbl_vip(vm)
        spec = h.DnsblCase(
            aliasname="PkgOp697",
            feed_url=feed,
            mode=h.DnsblMode.VIP,
            header="pkg-op-697",
            hsts=False,
        )
        h.inject(vm, spec)
        h.reload(vm, "updatednsbl")

        given = h.dns_probe(vm, domain, "A")
        assert h.is_vip(given), (
            f"GIVEN: DNSBL was not live before the reinstall for {domain!r}; "
            f"got rcode={given.rcode!r} records={given.records!r}"
        )

        # AND: a deferred-settings "pending changes" marker exists (#738 F7). The
        # reinstall leg must KEEP it (pending changes stay valid across an upgrade,
        # the #697 keep-live branch); the delete leg below must CLEAR it.
        vm.ssh("/bin/sh", "-c", f"touch {_PENDING_MARKER}")
        assert _marker_exists(vm), f"setup: could not create {_PENDING_MARKER} on the box"

        # ---- WHEN (1): forced reinstall (op 'reinstall') ----------------------- #
        proc = pkg_reinstall_force(vm)
        combined = proc.stdout + proc.stderr

        # THEN: the gate logged keep-live and did NOT tear down ...
        assert _KEEP_LIVE_LINE in combined, (
            "pre-deinstall did not log the keep-live decision on `pkg install -f` — the pkg-op "
            f"detector did not skip teardown for a reinstall (expected {_KEEP_LIVE_LINE!r}):\n{combined[-3000:]}"
        )
        assert _TEARDOWN_LINE not in combined, (
            "pre-deinstall TORE DOWN on `pkg install -f` — a reinstall must keep pfBlockerNG live "
            f"(unexpected {_TEARDOWN_LINE!r}):\n{combined[-3000:]}"
        )

        # ... and DNSBL is STILL live WITHOUT a reload (pre-#697 tore down here -> not VIP).
        h.wait_unbound_ready(vm)
        after_reinstall = h.dns_probe(vm, domain, "A")
        assert h.is_vip(after_reinstall), (
            f"AFTER `pkg install -f`: the DNSBL block for {domain!r} was lost — the pre-deinstall "
            "tore pfBlockerNG down on a reinstall instead of keeping it live; "
            f"got rcode={after_reinstall.rcode!r} records={after_reinstall.records!r}"
        )

        # ... and the pending-changes marker SURVIVED the reinstall (#738 F7: the clear
        # sits past the #697 early return, so an upgrade keeps a genuinely-pending change).
        assert _marker_exists(vm), (
            f"AFTER `pkg install -f`: {_PENDING_MARKER} was cleared — the deinstall-side marker "
            "clear must not run on a keep-live (reinstall/upgrade) pass"
        )

        # ---- WHEN (2): real uninstall (op 'delete') ---------------------------- #
        del_proc = pkg_delete_capture(vm)
        del_combined = del_proc.stdout + del_proc.stderr

        # THEN: the gate tore down (not keep-live), and the domain no longer blocks.
        assert _TEARDOWN_LINE in del_combined, (
            "pre-deinstall did not tear down on `pkg delete` — a real uninstall must turn pfBlockerNG "
            f"OFF (expected {_TEARDOWN_LINE!r}):\n{del_combined[-3000:]}"
        )
        assert _KEEP_LIVE_LINE not in del_combined, (
            "pre-deinstall SKIPPED teardown on `pkg delete` — a real uninstall must NOT keep pfBlockerNG "
            f"live (unexpected {_KEEP_LIVE_LINE!r}):\n{del_combined[-3000:]}"
        )
        assert pkg_installed_version(vm) is None, "`pkg delete` did not remove the package"

        h.wait_unbound_ready(vm)
        after_delete = h.dns_probe(vm, domain, "A")
        assert not h.is_vip(after_delete), (
            f"AFTER `pkg delete`: {domain!r} still resolved to the DNSBL VIP — teardown did not remove "
            f"the DNSBL block; got rcode={after_delete.rcode!r} records={after_delete.records!r}"
        )

        # AND: the pending-changes marker is GONE (#738 F7: a genuine uninstall clears it,
        # so a later reinstall shows no false "pending changes" banner).
        assert not _marker_exists(vm), (
            f"AFTER `pkg delete`: {_PENDING_MARKER} survived the uninstall — the pre-deinstall "
            "teardown must clear the deferred-settings marker (#738 F7)"
        )
    finally:
        vm.ssh("/bin/sh", "-c", f"rm -f {_PENDING_MARKER}")
        pkg_delete(vm)
