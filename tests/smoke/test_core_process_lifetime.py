"""issue #4020: Core's process lifetimes proved on a real pfSense box.

The Linux unit suites prove these lifetimes in CI. This builds the same Go test binaries for the box and runs them
there: the strict runner (``internal/process``: a pre-script's attached descendants are gone when the run returns,
the leader keeps its TERM grace, and Core's death cleans the transient group), the feed pre-script cases built on
it, and the Update's apply program hosted independently (its exit status, its result descriptor, and a child it
leaves running).

DESELECTED from the default ``python -m pytest``. Run it on the pool::

    scripts/local-smoke.sh --ref <branch or sha> --filter test_core_process_lifetime
"""

from __future__ import annotations

import re
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
# Case id -> (Go package, the tests that must each report PASS on the box).
CASES: dict[str, tuple[str, tuple[str, ...]]] = {
    "prescript": (
        "./feedparse",
        (
            "TestPreScriptKillsAnIgnoringChildAfterItsLeaderDiesOnTerm",
            "TestPreScriptImmediatelyCleansAnAttachedChildAfterSuccessfulLeaderExit",
            "TestPreScriptKeepsTheRunningLeadersTermGrace",
            "TestPreScriptAllowsAnIntentionallyDetachedSurvivor",
            "TestPreScriptCleansAttachedChildBeforeSuccessfulReturn",
            "TestPreScriptDetachedDescendantOutlivesGroupAndWaitDelay",
        ),
    ),
    "runner": (
        "./internal/process",
        (
            "TestWatchdogReadinessAndControlDescriptors",
            "TestWatchdogWithFailedReadinessExits",
            "TestDeadWatchdogKeepsItsGroupIdentityUntilReaped",
            "TestRunPreservesTerminalExitStatus",
            "TestRunKillsAttachedDescendantBeforeReturning",
            "TestRunIndependentLeavesAnAttachedChildRunningAndKeepsTheExitStatus",
            "TestRunCancellationAllowsCooperativeTermGrace",
            "TestRunEscalatesWhenTheLeaderIgnoresTerm",
            "TestRunCancellationAfterExitBeforeReapPreservesExitStatus",
            "TestUnexpectedWatchdogDeathCleansTheProgramGroup",
            "TestUnrelatedHangupDoesNotAbandonTheGroup",
            "TestRunKeepsStartErrorAndAlreadyCancelledCause",
            "TestCoreDeathCleansAttachedGroup",
        ),
    ),
    "update": (
        "./update",
        (
            "TestANonZeroExitIsAnErrorNamingTheStatusAndStillReturnsAValidResult",
            "TestAnExitOf75IsErrDeferredAndReportsNothing",
            "TestAValidResultOnFd3IsReturned",
            "TestANormalExitLeavesAChildOfTheProgramRunning",
            "TestAGrandchildHoldingTheLogAndTheResultFdDoesNotDelayRun",
        ),
    ),
    # FreeBSD /dev/fd paths do not report descriptor types; this case checks the actual files.
    "fstat": ("./update", ("TestTheProgramReceivesFourRegularFilesByFstatAndReportsItsResult",)),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_core_process_lifetime_on_freebsd(
    smoke_vm: SmokeVM,
    go_toolchain: GoToolchain,  # noqa: F811 -- the fixture imported above
    tmp_path: Path,
    case: str,
) -> None:
    """Prove one group of Core's process-lifetime contracts on real FreeBSD."""
    package, tests = CASES[case]
    guest_binary = f"/root/pfb_smoke_{case}.test"
    binary = tmp_path / f"{case}.test"
    built = subprocess.run(
        [str(go_toolchain.go), "test", "-c", "-o", str(binary), package],
        cwd=GO_DIR,
        env={**go_toolchain.env, "GOOS": "freebsd", "GOARCH": _goarch(smoke_vm, "pfSense")},
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert built.returncode == 0, f"go test -c {package} for FreeBSD failed:\n{built.stdout}\n{built.stderr}"
    try:
        _upload(smoke_vm, binary, guest_binary, "root:wheel")
        run = smoke_vm.ssh(f"{guest_binary} -test.v -test.count=1 -test.run '^({'|'.join(tests)})$'", timeout=180)
    finally:
        smoke_vm.ssh(f"rm -f {guest_binary}")
    print(run.stdout)
    assert run.returncode == 0, f"the test failed on the box: rc={run.returncode}\n{run.stdout}\n{run.stderr}"
    for test in tests:
        # Anchored: a subtest's line or a longer test name must not stand in for this test.
        assert re.search(rf"^--- PASS: {re.escape(test)}( |$)", run.stdout, re.MULTILINE), (
            f"{test} did not pass at top level:\n{run.stdout}"
        )
