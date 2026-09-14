"""install-from-repo.sh registers pfBlockerNG on a fresh box (issue #3277).

The rsync installer is the one path that registers the package WITHOUT ``pkg``:
it templates ``info.xml`` itself and runs ``php -f /etc/rc.packages <PORTNAME>
POST-INSTALL``. Until #3277 it registered the retired ``pfSense-pkg-pfBlockerNG-devel``
identity and put the FULL port name in ``info.xml <name>``, which pfSense does not
look up (``get_package_id`` uses the prefix-stripped name). The script itself cannot
tell: ``rc.packages`` exits 0 after "Installation aborted", so the installer prints
``Done`` either way. This case therefore inspects the hook's OUTPUT, not the exit code.

Scenario: a fresh boot, no pfBlockerNG package present.
  When ``scripts/install-from-repo.sh`` runs against the guest,
  Then the ``rc.packages`` hook runs the full pfBlockerNG setup — it executes
    ``custom_php_install_command`` and registers the menu — with NO abort phrase,
    the share directory and ``<name>`` carry the canonical identity, and the package
    is registered in ``config.xml`` under the short name.
"""

from __future__ import annotations

import subprocess

import pytest

from .conftest import SMOKE_DIR, SmokeVM

pytestmark = pytest.mark.smoke

INSTALL_FROM_REPO_SH = SMOKE_DIR.parent.parent / "scripts" / "install-from-repo.sh"

_ABORT_PHRASES = ("is not installed", "Installation aborted", "Failed to install package")
_SUCCESS_PHRASES = ("Executing custom_php_install_command", "Menu items")

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

# Leave the session VM as the fresh boot left it: the package's own DEINSTALL hooks drop
# the menu/config registration, and the share directory goes with it. The next module's
# ``pkg add`` then registers from scratch exactly as on a clean image.
_CLEANUP_SH = r"""
php -f /etc/rc.packages pfSense-pkg-pfBlockerNG DEINSTALL >/dev/null 2>&1 || true
php -f /etc/rc.packages pfSense-pkg-pfBlockerNG POST-DEINSTALL >/dev/null 2>&1 || true
rm -rf /usr/local/share/pfSense-pkg-pfBlockerNG /usr/local/share/pfSense-pkg-pfBlockerNG-devel
"""


@pytest.mark.timeout(900)
def test_install_from_repo_registers_canonical_package(smoke_vm: SmokeVM) -> None:
    vm = smoke_vm
    argv = [
        "sh",
        str(INSTALL_FROM_REPO_SH),
        vm.ssh_target,
        "--port",
        str(vm.ssh_port),
        "--ssh-key",
        vm.ssh_key_path,
    ]
    try:
        run = subprocess.run(argv, capture_output=True, text=True, timeout=780, check=False)
        out = run.stdout + run.stderr
        probe = subprocess.run(
            vm.ssh_argv("/bin/sh"), input=_PROBE_SH, capture_output=True, text=True, timeout=60, check=False
        )
        state = probe.stdout + probe.stderr
    finally:
        subprocess.run(
            vm.ssh_argv("/bin/sh"), input=_CLEANUP_SH, capture_output=True, text=True, timeout=120, check=False
        )

    print("\n\n##### INSTALL-FROM-REPO (#3277) #####\n" + out + "\n----- box state -----\n" + state + "\n#####\n")

    assert run.returncode == 0, f"install-from-repo.sh exited {run.returncode}:\n{out}"
    aborted = [p for p in _ABORT_PHRASES if p in out]
    assert not aborted, f"rc.packages install hook ABORTED ({aborted}):\n{out}"
    ran = [p for p in _SUCCESS_PHRASES if p in out]
    assert ran, f"the install hook did not run the full pfBlockerNG setup:\n{out}"
    assert "/usr/local/share/pfSense-pkg-pfBlockerNG-devel" not in state, f"retired -devel share dir created:\n{state}"
    assert "<name>pfBlockerNG</name>" in state, f"info.xml <name> is not the short canonical name:\n{state}"
    assert "REGISTERED=pfBlockerNG" in state, f"pfBlockerNG not registered in config.xml under its short name:\n{state}"
    assert "REGISTERED=pfBlockerNG-devel" not in state, f"retired -devel identity registered:\n{state}"
