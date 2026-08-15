"""Issue #2389: live Pages pkg install is an after-publish gate, not 08:00."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _extract_job(text: str, job_name: str) -> str:
    match = re.search(rf"^  {re.escape(job_name)}:\n", text, re.MULTILINE)
    assert match is not None, f"job {job_name!r} not found"
    start = match.end()
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\n", text[start:], re.MULTILINE)
    end = start + nxt.start() if nxt else len(text)
    return text[start:end]


def test_nightly_post_publish_passes_live_identity() -> None:
    job = _extract_job(_workflow("nightly.yml"), "validate-live-pages-install")
    assert "needs: [prepare, publish-pkg-repo]" in job
    assert "uses: ./.github/workflows/smoke-single.yml" in job
    assert "pytest_marker: repo" in job
    assert "smoke_nightly_live_url: https://pfblockerng.github.io/pkg/nightly" in job
    assert "smoke_nightly_expected_source_sha: ${{ needs.prepare.outputs.source_sha }}" in job
    assert "smoke_nightly_expected_version: ${{ needs.prepare.outputs.pkg_version }}" in job
    assert "smoke_repo_live_url: https://pfblockerng.github.io/pkg/nightly" in job
    assert "smoke_repo_expected_source_sha: ${{ needs.prepare.outputs.source_sha }}" in job
    assert "smoke_repo_expected_version: ${{ needs.prepare.outputs.pkg_version }}" in job


def test_scheduled_repo_install_does_not_pass_live_urls() -> None:
    workflow = _workflow("repo-install.yml")
    for name in (
        "smoke_repo_live_url:",
        "smoke_nightly_live_url:",
        "SMOKE_REPO_LIVE_URL",
        "SMOKE_NIGHTLY_LIVE_URL",
    ):
        assert name not in workflow
