"""VM test jobs run on GitHub-hosted runners with their native cache."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_TARGETS = {
    "build-image.yml": (("publish-image", 0), ("verify-image", 0)),
    "image-refresh.yml": (("refresh", 0),),
    "smoke-single.yml": (("smoke", 4),),
    "ui-tests.yml": (("ui", 2),),
    "version-tracker.yml": (("reconcile", 0),),
}


def _job_block(text: str, job: str) -> str:
    match = re.search(rf"^  {re.escape(job)}:\s*$", text, re.MULTILINE)
    assert match is not None, f"missing job {job}"
    end = re.search(r"^  [A-Za-z0-9_.-]+:\s*$", text[match.end() :], re.MULTILINE)
    return text[match.start() : match.end() + (end.start() if end else len(text))]


def test_vm_test_jobs_use_github_hosted_runners_and_cache() -> None:
    for workflow, jobs in _TARGETS.items():
        text = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
        for job, expected_cache_steps in jobs:
            block = _job_block(text, job)

            assert "runs-on: ubuntu-latest" in block
            assert "runs-on: [self-hosted" not in block
            assert "PFB_LAN_REGISTRY" not in block
            assert block.count("uses: actions/cache/") == expected_cache_steps
