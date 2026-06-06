"""The rc.packages install-hook MUST succeed (info.xml <name> regression guard).

Closes a false-pass: ``test_repo_install.py`` only checks files-landed / ``%R`` /
deps, never whether ``rc.packages`` (``install_package_xml``) actually SUCCEEDED.
A regression had templated ``info.xml <name>`` to the FULL ``${PORTNAME}``
(``pfSense-pkg-pfBlockerNG-devel``), but pfSense looks it up by the
``pfSense-pkg-``-PREFIX-STRIPPED name (``get_package_id``) — so the full name made
the hook ABORT ("The pfBlockerNG-devel package is not installed. Installation
aborted."), leaving the menu/config UNregistered while DNSBL (wired from the
on-disk python module) still worked. Netgate ships the SHORT ``<name>``; the fix
(``${PORTNAME:S/pfSense-pkg-//}``) restores it. This test ships the branch
``.pkg`` to the guest, installs it, and asserts the hook ran the FULL pfBlockerNG
install with NO abort.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from .conftest import SmokeVM

pytestmark = pytest.mark.repo

_ABORT_PHRASES = ("is not installed", "Installation aborted", "Failed to install package")
_SUCCESS_PHRASES = ("Executing custom_php_install_command", "Menu items")

_REMOTE_PKG = "/tmp/pfb-hook-verify.pkg"

# One self-contained script over STDIN (ssh_argv is unquoted — never `sh -c "A; B"`).
# The .pkg is scp'd to a fixed path first; derive its registered NAME from the file so
# the clean-slate delete + the final cleanup target the right package regardless of
# channel (-devel / -nightly / stable).
_HOOK_SH = r"""
set -u
P=/tmp/pfb-hook-verify.pkg
echo "PKG=$P"
NAME=$(pkg query -F "$P" %n 2>/dev/null)
echo "NAME=$NAME"
# Clean slate so the rc.packages POST-INSTALL hook runs FRESH (ignore errors).
env ASSUME_ALWAYS_YES=yes pkg delete -y "$NAME" >/dev/null 2>&1 || true
sleep 2
echo "=== pkg add (runs rc.packages POST-INSTALL) ==="
env ASSUME_ALWAYS_YES=yes pkg add "$P" 2>&1
echo "rc=$?"
# Leave the VM clean for the repo-install module (which expects the pkg ABSENT).
env ASSUME_ALWAYS_YES=yes pkg delete -y "$NAME" >/dev/null 2>&1 || true
"""


def _scp_to_guest(vm: SmokeVM, local: Path, remote: str, *, timeout: float = 120.0) -> None:
    """Copy a local file to the guest via ``scp`` (mirrors test_repo_install)."""
    argv = [
        "scp",
        "-i",
        vm.ssh_key_path,
        "-P",
        str(vm.ssh_port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "BatchMode=yes",
        str(local),
        f"{vm.ssh_target}:{remote}",
    ]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"scp {local} -> {remote} failed: rc={result.returncode} {result.stderr!r}")


@pytest.mark.timeout(600)
def test_install_hook_succeeds(smoke_vm: SmokeVM) -> None:
    """The branch install runs the full pfBlockerNG setup hook (no abort).

    Scenario: a fresh install of the branch .pkg.
      Given the short-name info.xml fix (ports + the builder :S modifier),
      When ``pkg add`` of the branch .pkg runs rc.packages POST-INSTALL,
      Then the hook SUCCEEDS — it runs custom_php_install_command + registers the
        menu (NO "is not installed"/"Installation aborted"/"Failed to install").
    """
    pkg = os.environ.get("SMOKE_PKG")
    if not pkg or not Path(pkg).is_file():
        pytest.skip("SMOKE_PKG not set / not a file — no built .pkg to install")
    assert pkg  # for the type-checker: pytest.skip above is NoReturn
    vm = smoke_vm
    _scp_to_guest(vm, Path(pkg), _REMOTE_PKG)

    r = subprocess.run(
        vm.ssh_argv("/bin/sh"),
        input=_HOOK_SH,
        capture_output=True,
        text=True,
        timeout=540,
        check=False,
    )
    out = r.stdout
    subprocess.run(
        vm.ssh_argv("/usr/bin/tee", "/var/log/pfb_install_hook_verify.txt"),
        input=out,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    print("\n\n##### ADR-18 INSTALL-HOOK VERIFY #####\n" + out + "\n#####\n")

    assert "NAME=pfSense-pkg-pfBlockerNG" in out, f"branch .pkg not queryable on the VM:\n{out}"
    aborted = [p for p in _ABORT_PHRASES if p in out]
    assert not aborted, (
        f"rc.packages install hook ABORTED ({aborted}) — the full-name info.xml regression "
        f"is NOT fixed (get_package_id looks up the prefix-stripped name):\n{out}"
    )
    ran = [p for p in _SUCCESS_PHRASES if p in out]
    assert ran, f"the install hook did not run the full pfBlockerNG setup:\n{out}"
