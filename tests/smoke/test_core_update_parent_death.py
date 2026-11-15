"""issue #4003: on FreeBSD a Core killed outright takes its Update's whole process group with it (procctl
``PROC_PDEATHSIG_CTL``).

``go/pfb_core/update``'s ``TestTheProgramDiesWithACoreThatIsKilled`` and
``TestTheProgramsChildDiesWithACoreThatIsKilled`` prove it on Linux: the test binary turns itself into a Core running
one Update (``exec sleep 300``; a program that starts ``sleep 300`` and waits), is SIGKILLed, and the program, and the
child it started, must be gone. This runs the Update and shared process lifetime suites, built for the box, on a
real pfSense box: a TERM-ignoring and a TERM-handling child when Core dies, a HUP inside the group, program signal
deaths and exit statuses, and cancellation after a successful exit without killing its daemons.

DESELECTED from the default ``python -m pytest``. Run it on the pool::

    scripts/local-smoke.sh --ref <branch or sha> --filter test_core_update_parent_death
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from . import helpers
from .conftest import SmokeVM
from .test_smoke_dns_gateway import (  # noqa: F401 -- pytest fixture re-export
    GoToolchain,
    _goarch,
    _upload,
    go_toolchain,
)

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(900)]

GO_DIR = Path(__file__).resolve().parents[2] / "go" / "pfb_core"
UPDATE_TESTS = (
    "TestTheProgramDiesWithACoreThatIsKilled",
    "TestTheProgramsChildDiesWithACoreThatIsKilled",
    "TestAChildIgnoringTermIsKilledWhenCoreIsKilled",
    "TestAChildHandlingTermGetsItsGraceWhenCoreIsKilled",
    "TestAHangupInsideTheGroupIsNotTakenForCoresDeath",
    "TestASignalEndsRunAsItEndedTheProgram",
    "TestANonZeroExitIsAnErrorNamingTheStatusAndStillReturnsAValidResult",
    "TestAnExitOf75IsErrDeferredAndReportsNothing",
    "TestAContextEndingAfterTheProgramExitedLeavesItsDescendantsAndTheSuccess",
    "TestAValidResultOnFd3IsReturned",
    "TestANormalExitLeavesAChildOfTheProgramRunning",
    "TestAGrandchildHoldingTheLogAndTheResultFdDoesNotDelayRun",
    "TestTheUpdateProgramIsCoresOwnChildInTheWatchdogsGroup",
    "TestAnUnexpectedWatchdogDeathEndsTheUnprotectedUpdateAndItsChildren",
    "TestAProgramThatCannotStartReturnsAnErrorWithoutLeavingAWatchdog",
    "TestEveryTerminalProgramResultCommitsCompletionWithoutKillingItsDaemon",
    "TestUnexpectedWatchdogDeathIsTheCauseOfPromptGroupCleanup",
    "TestAStartFailureLeavesNoUnwaitedOwnedChildAndProcessInspectionMustWork",
)
PROCESS_TESTS = (
    "TestRunPreservesTerminalStatusAndAttachedDescendants",
    "TestRunKeepsStartErrorAndAlreadyCancelledCause",
    "TestLateCancellationUsesActualExitBeforeReap",
    "TestCancellationCleansAnIgnoringChildAndPreservesWaitStatus",
    "TestUnexpectedWatchdogDeathCleansTheGroup",
    "TestTheWatchdogAcknowledgesReadinessWithItsOwnProcessGroupEstablished",
    "TestAStoppedWatchdogsAcknowledgementTimeoutLeavesTheSuccessfulProgramsDaemon",
    "TestAWatchdogThatCannotReportReadinessExitsInsteadOfWaitingForCompletion",
    "TestADeadWatchdogKeepsItsGroupIdentityUntilCleanupCanNoLongerSignalIt",
    "TestUnrelatedHUPDoesNotAbandonTheGroup",
    "TestCoreDeathCleansTheProgram",
    "TestRunLeavesCallerDescriptorsAndPipeHoldingDescendantAlone",
    "TestAContextEndingAfterTheProgramExitedButBeforeItsReapLeavesTheGroupAndTheSuccess",
    "TestAContextEndingWhileTheSupervisorOutlivesTheProgramLeavesTheGroupAndTheSuccess",
    "TestAContextEndingWithTheWatcherStoppedAfterTheProgramExitedPreservesItsDaemon",
    "TestCoresDeathBeforeCompletionCleansTheGroupButAfterRunLeavesItsDaemon",
    "TestWatchdogDeathCleanupFinishesBeforeTheIndependentSalvageContextFires",
    "TestStrictRunClosesDescendantHeldCaptureBeforeReapAndIODrain",
    "TestExitedRecognizesAnUnreapedZombie",
    "TestExitedRejectsUnavailablePS",
    "TestUpdateFixtureExitedRecognizesAnUnreapedZombie",
    "TestUpdateFixtureExitedRejectsUnavailablePS",
    "TestNativeReloadSurvivesUpdateCancellation",
    "TestNativeGeneratedTailPipelineSurvivesUpdateCancellation",
    "TestNativeGeneratedClogPipelineSurvivesUpdateCancellation",
)
LIFETIME_SUITES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("./update", UPDATE_TESTS),
    ("./internal/process", PROCESS_TESTS),
)


# FreeBSD /dev/fd paths do not report descriptor types; the fstat case checks the actual files.
@pytest.mark.parametrize(
    "suites",
    [LIFETIME_SUITES, (("./update", ("TestTheProgramReceivesFourRegularFilesByFstatAndReportsItsResult",)),)],
    ids=["lifetime", "fstat"],
)
def test_the_update_program_dies_with_a_core_that_is_killed(
    smoke_vm: SmokeVM,
    go_toolchain: GoToolchain,  # noqa: F811 -- the fixture imported above
    tmp_path: Path,
    suites: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    """Prove the Update's group/lifetime or descriptor contracts on real FreeBSD."""
    helpers.deploy(smoke_vm)
    goarch = _goarch(smoke_vm, "pfSense")
    for package, tests in suites:
        binary = tmp_path / f"{Path(package).name}.test"
        built = subprocess.run(
            [str(go_toolchain.go), "test", "-c", "-o", str(binary), package],
            cwd=GO_DIR,
            env={**go_toolchain.env, "GOOS": "freebsd", "GOARCH": goarch},
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        print(built.stdout)
        print(built.stderr)
        assert built.returncode == 0, f"go test -c {package} for FreeBSD failed:\n{built.stdout}\n{built.stderr}"
        guest_binary = f"/root/pfb_smoke_{Path(package).name}_{uuid4().hex}.test"
        try:
            _upload(smoke_vm, binary, guest_binary, "root:wheel")
            run = smoke_vm.ssh(
                f"{guest_binary} -test.v -test.count=1 -test.timeout=150s -test.run '^({'|'.join(tests)})$'",
                timeout=180,
            )
            print(run.stdout)
            print(run.stderr)
            assert run.returncode == 0, f"{package} failed on the box: rc={run.returncode}\n{run.stdout}\n{run.stderr}"
            for test in tests:
                assert re.search(rf"^--- PASS: {re.escape(test)} \(", run.stdout, re.MULTILINE), (
                    f"{package}: {test} did not pass:\n{run.stdout}"
                )
            assert run.stdout.rstrip().splitlines()[-1:] == ["PASS"], f"{package} lacks final PASS:\n{run.stdout}"
        finally:
            cleanup = smoke_vm.ssh(f"rm -f {guest_binary} {guest_binary}.new", timeout=30)
            assert cleanup.returncode == 0, f"removing owned guest binary/staging file failed: {cleanup.stderr}"
