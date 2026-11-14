"""issue #4003: on FreeBSD a Core killed outright takes its Update's whole process group with it (procctl
``PROC_PDEATHSIG_CTL``).

``go/pfb_core/update``'s ``TestTheProgramDiesWithACoreThatIsKilled`` and
``TestTheProgramsChildDiesWithACoreThatIsKilled`` prove it on Linux: the test binary turns itself into a Core running
one Update (``exec sleep 300``; a program that starts ``sleep 300`` and waits), is SIGKILLed, and the program, and the
child it started, must be gone. This runs those same tests, built for the box, on a real pfSense box, with the Update
watcher's other FreeBSD paths: a TERM-ignoring and a TERM-handling child when Core dies, a HUP inside the group,
program signal deaths and exit statuses, and cancellation after a successful exit without killing its daemons.

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
TESTS = (
    "TestTheProgramDiesWithACoreThatIsKilled",
    "TestTheProgramsChildDiesWithACoreThatIsKilled",
    "TestAChildIgnoringTermIsKilledWhenCoreIsKilled",
    "TestAChildHandlingTermGetsItsGraceWhenCoreIsKilled",
    "TestAHangupInsideTheGroupIsNotTakenForCoresDeath",
    "TestASignalEndsRunAsItEndedTheProgram",
    "TestANonZeroExitIsAnErrorNamingTheStatusAndStillReturnsAValidResult",
    "TestAnExitOf75IsErrDeferredAndReportsNothing",
    "TestAContextEndingWhileTheSupervisorOutlivesTheProgramLeavesTheGroupAndTheSuccess",
    "TestAContextEndingAfterTheProgramExitedLeavesItsDescendantsAndTheSuccess",
    "TestAValidResultOnFd3IsReturned",
    "TestANormalExitLeavesAChildOfTheProgramRunning",
    "TestAGrandchildHoldingTheLogAndTheResultFdDoesNotDelayRun",
    "TestAContextEndingWithTheWatcherStoppedAfterTheProgramExitedPreservesItsDaemon",
    "TestTheUpdateProgramIsCoresOwnChildInTheWatchdogsGroup",
    "TestAnUnexpectedWatchdogDeathEndsTheUnprotectedUpdateAndItsChildren",
    "TestCoresDeathBeforeCompletionCleansTheGroupButAfterRunLeavesItsDaemon",
    "TestAProgramThatCannotStartReturnsAnErrorWithoutLeavingAWatchdog",
    "TestTheWatchdogAcknowledgesReadinessWithItsOwnProcessGroupEstablished",
    "TestAStoppedWatchdogsAcknowledgementTimeoutLeavesTheSuccessfulProgramsDaemon",
    "TestAWatchdogThatCannotReportReadinessExitsInsteadOfWaitingForCompletion",
    "TestEveryTerminalProgramResultCommitsCompletionWithoutKillingItsDaemon",
    "TestADeadWatchdogKeepsItsGroupIdentityUntilCleanupCanNoLongerSignalIt",
    "TestUnexpectedWatchdogDeathIsTheCauseOfPromptGroupCleanup",
    "TestAStartFailureLeavesNoUnwaitedOwnedChildAndProcessInspectionMustWork",
    "TestWatchdogDeathCleanupFinishesBeforeTheIndependentSalvageContextFires",
)


# FreeBSD /dev/fd paths do not report descriptor types; the fstat case checks the actual files.
@pytest.mark.parametrize(
    "tests",
    [TESTS, ("TestTheProgramReceivesFourRegularFilesByFstatAndReportsItsResult",)],
    ids=["lifetime", "fstat"],
)
def test_the_update_program_dies_with_a_core_that_is_killed(
    smoke_vm: SmokeVM,
    go_toolchain: GoToolchain,  # noqa: F811 -- the fixture imported above
    tmp_path: Path,
    tests: tuple[str, ...],
) -> None:
    """Prove the Update's group/lifetime or descriptor contracts on real FreeBSD."""
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
        run = smoke_vm.ssh(f"{GUEST_BINARY} -test.v -test.count=1 -test.run '^({'|'.join(tests)})$'", timeout=180)
    finally:
        smoke_vm.ssh(f"rm -f {GUEST_BINARY}")
    print(run.stdout)
    assert run.returncode == 0, f"the test failed on the box: rc={run.returncode}\n{run.stdout}\n{run.stderr}"
    for test in tests:
        assert f"--- PASS: {test}" in run.stdout, f"{test} did not run:\n{run.stdout}"
