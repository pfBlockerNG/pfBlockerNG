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


def test_private_core_shows_live_php_script_output_cap(smoke_vm: SmokeVM) -> None:
    """A private Core's API exposes the installed PHP hook/list runner's bounded live transcript."""
    helpers.deploy(smoke_vm)
    directory = f"/root/pfb-native-output-{uuid4().hex}"
    fixture = Path(__file__).parent / "fixtures" / "native_script_output_cap.php"
    created = smoke_vm.ssh(f"mkdir -m 700 {directory}", timeout=30)
    assert created.returncode == 0, created.stderr
    try:
        _upload(smoke_vm, fixture, f"{directory}/fixture.php", "root:wheel")
        run = smoke_vm.ssh(
            f"/usr/local/bin/php {directory}/fixture.php control {CORE_BIN} {directory}",
            timeout=210,
        )
        diagnostics = (run.stdout + run.stderr)[-2000:]
        assert run.returncode == 0, f"native PHP output-cap proof failed:\n{diagnostics}"
        assert run.stdout.startswith("NATIVE_SCRIPT_OUTPUT_CAP_PASS "), diagnostics
    finally:
        cleanup_safe = smoke_vm.ssh(f"test -f {directory}/cleanup.safe", timeout=30)
        assert cleanup_safe.returncode == 0, (
            f"private Core worker completion/lease release was not proven; retained {directory}: {cleanup_safe.stderr}"
        )
        cleanup = smoke_vm.ssh(f"rm -rf {directory}", timeout=30)
        assert cleanup.returncode == 0, cleanup.stderr
