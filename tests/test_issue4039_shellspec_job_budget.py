"""Issue #4039: the ShellSpec job's time limit leaves room for a slow runner's passing run.

The same tree took 4, 10 and 19 minutes on different runners, so the spread is the runner, not
the suite. A passing run that the 20-minute limit cancelled also failed the `All tests passed`
aggregate with nothing red in the suite. The limit stays a cap on a hung job (below), not pacing.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"

# Slowest observed job that still passed, kcov step included (psl-refresh/auto 7c5d19afb, #4039).
SLOWEST_PASSING_JOB_MINUTES = 19.3
# A slow runner may be slower still; the limit leaves room for twice the slowest passing run.
HEADROOM = 2
# Above this the limit no longer ends a hung job in reasonable time.
HUNG_JOB_CAP_MINUTES = 60


def _job_limit_minutes() -> int:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["shell-tests"]["timeout-minutes"]


def test_the_shellspec_job_limit_leaves_room_for_the_slowest_passing_run() -> None:
    limit = _job_limit_minutes()
    needed = SLOWEST_PASSING_JOB_MINUTES * HEADROOM
    assert limit >= needed, (
        f"the shellspec job limit must fit {HEADROOM}x the slowest passing run.\n"
        f"  expected: >= {needed:.1f} min\n"
        f"  actual:   {limit} min"
    )


def test_the_shellspec_job_limit_still_ends_a_hung_job() -> None:
    limit = _job_limit_minutes()
    assert limit <= HUNG_JOB_CAP_MINUTES, (
        f"the shellspec job limit is a cap on a hung job, not pacing.\n"
        f"  expected: <= {HUNG_JOB_CAP_MINUTES} min\n"
        f"  actual:   {limit} min"
    )
