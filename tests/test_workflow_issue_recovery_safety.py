"""Recovery ordering metadata fails closed and survives manual drills."""

from pathlib import Path

import pytest

from tests.test_workflow_issue_dedup_contract import WORKFLOWS, _run_script
from tests.test_workflow_issue_recovery_order import _run_recovery


@pytest.mark.parametrize(
    ("workflow", "title"),
    [
        ("nightly-failure-alert.yml", "[nightly-red] Smoke failing on devel"),
        ("top1m-healthcheck.yml", "[top1m-healthcheck] provider URL unhealthy"),
    ],
)
def test_malformed_failure_order_never_closes(
    tmp_path: Path,
    workflow: str,
    title: str,
) -> None:
    assert (
        _run_recovery(
            WORKFLOWS / workflow,
            tmp_path,
            title=title,
            failure_run="18446744073709551616 1",
            run_number="100",
            run_attempt="1",
        )
        == []
    )


def test_manual_drill_never_overwrites_a_real_failure_tracker(tmp_path: Path) -> None:
    assert (
        _run_script(
            WORKFLOWS / "nightly-failure-alert.yml",
            "Open or update the tracking issue",
            tmp_path,
            opened='[{"number":42,"title":"[nightly-red] Smoke failing on devel","state":"OPEN"}]',
            extra_env={
                "WF_NAME": "Smoke",
                "RUN_URL": "https://example.invalid/run",
                "HEAD_SHA": "deadbeef",
                "BRANCH": "devel",
                "DRILL": "1",
                "RUN_NUMBER": "",
                "RUN_ATTEMPT": "",
            },
        )
        == []
    )
