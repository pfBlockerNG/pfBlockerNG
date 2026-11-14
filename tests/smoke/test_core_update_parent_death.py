"""issue #4003: on FreeBSD the kernel KILLs Core's Update program when Core dies (procctl ``PROC_PDEATHSIG_CTL``).

``go/pfb_core/update``'s ``TestTheProgramDiesWithACoreThatIsKilled`` proves the tie on Linux: the test binary turns
itself into a Core running one Update of ``exec sleep 300``, is SIGKILLed, and the program must be gone. This runs that
same test, built for the box, on a real pfSense box.

DESELECTED from the default ``python -m pytest``. Run it on the pool::

    scripts/local-smoke.sh --ref <branch or sha> --filter test_core_update_parent_death
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from .conftest import SmokeVM
from .test_smoke_dns_gateway import (  # noqa: F401 -- pytest fixture re-export
    GoToolchain,
    _goarch,
    _upload,
    go_toolchain,
)

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(900)]

GO_DIR = Path(__file__).resolve().parents[2] / "go" / "pfb_core"
GUEST_BINARY = "/root/pfb_smoke_update.test"
TEST = "TestTheProgramDiesWithACoreThatIsKilled"


def test_the_update_program_dies_with_a_core_that_is_killed(
    smoke_vm: SmokeVM,
    go_toolchain: GoToolchain,  # noqa: F811 -- the fixture imported above
    tmp_path: Path,
) -> None:
    """Red when: the program a SIGKILLed Core ran keeps running on FreeBSD (no parent-death signal on the child)."""
    binary = tmp_path / "update.test"
    built = subprocess.run(
        [str(go_toolchain.go), "test", "-c", "-o", str(binary), "./update"],
        cwd=GO_DIR,
        env={**go_toolchain.env, "GOOS": "freebsd", "GOARCH": _goarch(smoke_vm, "pfSense")},
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert built.returncode == 0, f"go test -c ./update for FreeBSD failed:\n{built.stdout}\n{built.stderr}"
    _upload(smoke_vm, binary, GUEST_BINARY, "root:wheel")
    try:
        run = smoke_vm.ssh(f"{GUEST_BINARY} -test.v -test.count=1 -test.run '^{TEST}$'", timeout=120)
    finally:
        smoke_vm.ssh(f"rm -f {GUEST_BINARY}")
    assert run.returncode == 0, f"the test failed on the box: rc={run.returncode}\n{run.stdout}\n{run.stderr}"
    assert f"--- PASS: {TEST}" in run.stdout, f"the test did not run:\n{run.stdout}"
