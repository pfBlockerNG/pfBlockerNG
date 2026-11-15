"""#4022: Core death cannot interrupt a locked platform apply or its native Kea service.

Run through scripts/local-smoke.sh --ref <ref> --filter test_core_independent_update.
The fixture uses private configuration, empty DHCP interfaces/subnets, real Unix
control readiness and the installed native mwexec_bg/unlock implementation.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from . import helpers
from .conftest import SmokeVM
from .test_smoke_core_api import CORE_BIN
from .test_smoke_dns_gateway import _upload

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(240)]


@pytest.mark.parametrize("family", ["4", "6"], ids=["kea4", "kea6"])
@pytest.mark.parametrize("signal", ["15", "9"], ids=["term", "kill"])
@pytest.mark.parametrize("restart", ["running", "finished"])
def test_core_independent_update(smoke_vm: SmokeVM, family: str, signal: str, restart: str) -> None:
    """An actual Core stop leaves apply locked until normal completion, even across restart."""
    helpers.deploy(smoke_vm)
    directory = f"/root/pfb-independent-{uuid4().hex}"
    fixture = Path(__file__).parent / "fixtures" / "independent_update.php"
    created = smoke_vm.ssh(f"mkdir -m 700 {directory}", timeout=30)
    assert created.returncode == 0, created.stderr
    try:
        _upload(smoke_vm, fixture, f"{directory}/fixture.php", "root:wheel")
        run = smoke_vm.ssh(
            f"/usr/local/bin/php {directory}/fixture.php control {directory} {CORE_BIN} {family} {signal} {restart}",
            timeout=150,
        )
        print(run.stdout)
        print(run.stderr)
        diagnostics = smoke_vm.ssh(
            f"find {directory} -type f -maxdepth 2 -not -name fixture.php "
            '-not -name update.sh -exec sh -c \'echo === "$1"; cat "$1"\' sh {} \\;',
            timeout=30,
        )
        print(diagnostics.stdout)
        helpers.DIAG_DIR.mkdir(parents=True, exist_ok=True)
        (helpers.DIAG_DIR / f"independent-{family}-{signal}-{restart}.log").write_text(
            f"rc={run.returncode}\n{run.stdout}\n{run.stderr}\n{diagnostics.stdout}\n{diagnostics.stderr}",
            encoding="utf-8",
        )
        assert run.returncode == 0, f"native independent transaction failed:\n{run.stdout}\n{run.stderr}"
        assert "LOCK_REACQUIRED" in run.stdout
        assert f"INDEPENDENT_TRANSACTION_PASS family={family} signal={signal} restart={restart}" in run.stdout
        assert "OWNED_SERVICE_CLEANUP_COMPLETE" in run.stdout
    finally:
        cleanup = smoke_vm.ssh(f"rm -rf {directory}", timeout=30)
        assert cleanup.returncode == 0, cleanup.stderr


def test_native_kea_foreground_setup(smoke_vm: SmokeVM) -> None:
    """SETUP DIAGNOSIS: foreground Kea with this fixture's private JSON and env. Not launcher RED."""
    helpers.deploy(smoke_vm)
    directory = f"/root/pfb-independent-{uuid4().hex}"
    fixture = Path(__file__).parent / "fixtures" / "independent_update.php"
    created = smoke_vm.ssh(f"mkdir -m 700 {directory}", timeout=30)
    assert created.returncode == 0, created.stderr
    try:
        _upload(smoke_vm, fixture, f"{directory}/fixture.php", "root:wheel")
        run = smoke_vm.ssh(f"/usr/local/bin/php {directory}/fixture.php diagnose {directory} 4", timeout=60)
        print(run.stdout)
        print(run.stderr)
        assert "FOREGROUND_EXIT=" in run.stdout, run.stderr
        assert run.returncode == 0, run.stderr
    finally:
        cleanup = smoke_vm.ssh(f"rm -rf {directory}", timeout=30)
        assert cleanup.returncode == 0, cleanup.stderr
