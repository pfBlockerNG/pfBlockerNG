"""install-from-repo.sh registers pfBlockerNG on a fresh box (issue #3277).

The rsync installer is the one path that registers the package WITHOUT ``pkg``:
it templates ``info.xml`` itself and runs ``php -f /etc/rc.packages <PORTNAME>
POST-INSTALL``. Until #3277 it registered the retired ``pfSense-pkg-pfBlockerNG-devel``
identity and put the FULL port name in ``info.xml <name>``, which pfSense does not
look up (``get_package_id`` uses the prefix-stripped name). The script itself cannot
tell: ``rc.packages`` exits 0 after "Installation aborted", so the installer prints
``Done`` either way. This case therefore inspects the hook's OUTPUT and the box
state, not the script exit code.

#3277 pins identity only. On a fresh CE 2.8.1 smoke image, POST-INSTALL then
throws ``unable to restore settings family`` at ``pfblockerng.inc:79`` — the same
throw on ``devel``, so it is out of scope here. Do not require ``Menu items`` or
exit 0; print those for the live citation.

Scenario: a fresh boot, no pfBlockerNG package present.
  When ``scripts/install-from-repo.sh`` runs against the guest,
  Then there is no retired-identity abort, the share directory and ``<name>``
    carry the canonical identity, and ``config.xml`` registers the short name.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from . import helpers
from .conftest import SMOKE_DIR, SmokeVM

pytestmark = pytest.mark.smoke

INSTALL_FROM_REPO_SH = SMOKE_DIR.parent.parent / "scripts" / "install-from-repo.sh"

_ABORT_PHRASES = ("is not installed", "Installation aborted", "Failed to install package")

# One self-contained probe over STDIN (ssh_argv is unquoted — never `sh -c "A; B"`).
_PROBE_SH = r"""
set -u
echo "=== share dirs ==="
ls -d /usr/local/share/pfSense-pkg-pfBlockerNG* 2>&1
echo "=== info.xml name ==="
grep '<name>' /usr/local/share/pfSense-pkg-pfBlockerNG/info.xml 2>&1
echo "=== config registration ==="
php -r '
require_once "config.inc";
$pkgs = config_get_path("installedpackages/package", []);
foreach ($pkgs as $p) { echo "REGISTERED=" . ($p["name"] ?? "") . "\n"; }
'
"""

_SERVICES_SH = r"""
php -r '
require_once "config.inc";
foreach (config_get_path("installedpackages/service", []) as $s) { echo "SERVICE=" . ($s["name"] ?? "") . "\n"; }
'
"""


def _run_on_guest(vm: SmokeVM, script: str, *, timeout: float = 120.0) -> str:
    run = subprocess.run(
        vm.ssh_argv("/bin/sh"), input=script, capture_output=True, text=True, timeout=timeout, check=False
    )
    return run.stdout + run.stderr


def _install_from_repo(vm: SmokeVM) -> subprocess.CompletedProcess[str]:
    argv = [
        "sh",
        str(INSTALL_FROM_REPO_SH),
        vm.ssh_target,
        "--port",
        str(vm.ssh_port),
        "--ssh-key",
        vm.ssh_key_path,
    ]
    return subprocess.run(argv, capture_output=True, text=True, timeout=780, check=False)


@pytest.mark.timeout(900)
def test_install_from_repo_registers_canonical_package(smoke_vm: SmokeVM) -> None:
    vm = smoke_vm
    try:
        run = _install_from_repo(vm)
        out = run.stdout + run.stderr
        probe = subprocess.run(
            vm.ssh_argv("/bin/sh"), input=_PROBE_SH, capture_output=True, text=True, timeout=60, check=False
        )
        state = probe.stdout + probe.stderr
    finally:
        helpers.undeploy(vm)

    print(
        "\n\n##### INSTALL-FROM-REPO (#3277) #####\n"
        f"install-from-repo.sh exit={run.returncode}\n"
        f"menu_items={'Menu items' in out}\n"
        f"custom_php={'Executing custom_php_install_command' in out}\n"
        + out
        + "\n----- box state -----\n"
        + state
        + "\n#####\n"
    )

    aborted = [p for p in _ABORT_PHRASES if p in out]
    assert not aborted, f"rc.packages install hook ABORTED ({aborted}):\n{out}"
    assert "/usr/local/share/pfSense-pkg-pfBlockerNG-devel" not in state, f"retired -devel share dir created:\n{state}"
    assert "<name>pfBlockerNG</name>" in state, f"info.xml <name> is not the short canonical name:\n{state}"
    assert "REGISTERED=pfBlockerNG" in state, f"pfBlockerNG not registered in config.xml under its short name:\n{state}"
    assert "REGISTERED=pfBlockerNG-devel" not in state, f"retired -devel identity registered:\n{state}"


@pytest.mark.timeout(900)
def test_cleanup_lets_the_next_deploy_register_the_services(smoke_vm: SmokeVM) -> None:
    """The module cleanup must leave a box on which the next ``deploy()`` registers pfb_filter/pfb_dnsbl (#3724).

    Given the branch package is installed and install-from-repo.sh registered it under its short name on top,
    When this module's cleanup runs,
    Then a following ``deploy()`` registers the package services again (a ``pkg add`` that finds the package
    still in pkg's database says "already installed" and registers nothing, so every later module's
    start_service/restart_service silently does nothing).
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    vm = smoke_vm
    try:
        helpers.deploy(vm)
        installed = _install_from_repo(vm)
        assert installed.returncode == 0, (
            f"install-from-repo.sh exit={installed.returncode}\n"
            f"stdout:\n{installed.stdout}\nstderr:\n{installed.stderr}"
        )
        overlaid = _run_on_guest(vm, _PROBE_SH)
        assert "REGISTERED=pfBlockerNG\n" in overlaid + "\n", (
            f"install-from-repo.sh did not register the package:\n{overlaid}"
        )
        helpers.undeploy(vm)
        helpers.deploy(vm)
        services = _run_on_guest(vm, _SERVICES_SH)
    finally:
        helpers.undeploy(vm)

    missing = [name for name in ("pfb_filter", "pfb_dnsbl") if f"SERVICE={name}\n" not in services + "\n"]
    assert not missing, f"services {missing} not registered after cleanup + deploy; box lists:\n{services}"
