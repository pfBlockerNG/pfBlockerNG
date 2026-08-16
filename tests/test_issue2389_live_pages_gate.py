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
    assert "pytest_filter: test_install_from_live_nightly_url" in job
    assert "smoke_nightly_live_url: https://pfblockerng.github.io/pkg/nightly" in job
    assert "smoke_nightly_expected_source_sha: ${{ needs.prepare.outputs.source_sha }}" in job
    assert "smoke_nightly_expected_version: ${{ needs.prepare.outputs.pkg_version }}" in job
    # smoke_repo_* is the GENERIC channel input (smoke-single.yml declares it,
    # issue #2389) -- Nightly simply never passes it: its own URL rides
    # smoke_nightly_*, and Nightly stays publish-then-gate (out of #2389 scope),
    # never staged, so it has no staging_prefix to build a smoke_repo_live_url from.
    assert "smoke_repo_live_url:" not in job


def test_scheduled_repo_install_does_not_pass_live_urls() -> None:
    workflow = _workflow("repo-install.yml")
    for name in (
        "smoke_repo_live_url:",
        "smoke_nightly_live_url:",
        "SMOKE_REPO_LIVE_URL",
        "SMOKE_NIGHTLY_LIVE_URL",
    ):
        assert name not in workflow


# --------------------------------------------------------------------------- #
# release-published.yml: stage -> live-install gate -> promote (issue #2389)
# --------------------------------------------------------------------------- #


def test_release_published_stages_before_gate() -> None:
    job = _extract_job(_workflow("release-published.yml"), "publish-pkg-repo")
    # Anchored to the real env: line, not a doc comment mentioning the same text --
    # a substring check here would pass on a comment alone even if the actual
    # PUBLISH_STAGE value drifted away from "stage" (issue #2389).
    assert re.search(r"^\s+PUBLISH_STAGE: stage\s*$", job, re.MULTILINE), job
    assert "id: stage" in job
    # route_matrix is NOT a publish-pkg-repo output any more (issue #2450 step 3):
    # promote-pkg-repo no longer reads it (publish-pkg-repo.sh's promote arm never
    # required ROUTE_MATRIX), so the job stopped exporting an output nothing consumes.
    for out in ("staging_prefix", "touched", "noop"):
        assert re.search(rf"^      {out}:", job, re.MULTILINE), f"publish-pkg-repo missing output {out!r}:\n{job}"
    assert not re.search(r"^      route_matrix:", job, re.MULTILINE), job


def test_release_published_resolve_exports_gate_identity() -> None:
    job = _extract_job(_workflow("release-published.yml"), "resolve")
    for out in ("source_sha", "portversion", "channel"):
        assert re.search(rf"^      {out}:", job, re.MULTILINE), f"resolve missing output {out!r}:\n{job}"
    assert 'echo "source_sha=${COMMIT}"' in job


def test_release_published_live_gate_installs_from_staged_url_per_leg() -> None:
    job = _extract_job(_workflow("release-published.yml"), "validate-live-pages-install")
    assert "needs: [resolve, publish-pkg-repo, prepare-live-gate]" in job
    assert "uses: ./.github/workflows/smoke-single.yml" in job
    assert "pytest_marker: repo" in job
    assert "pytest_filter: test_install_from_live_pages_url" in job
    assert "staging_prefix }}/${{ matrix.channel }}" in job
    assert "smoke_repo_expected_source_sha: ${{ needs.resolve.outputs.source_sha }}" in job
    assert "smoke_repo_expected_version: ${{ needs.resolve.outputs.portversion }}" in job
    assert "smoke_repo_expected_channel: ${{ needs.resolve.outputs.channel }}" in job
    assert "fromJson(needs.prepare-live-gate.outputs.matrix)" in job
    assert "fail-fast: false" in job


def test_release_published_promotes_only_after_green_gate() -> None:
    job = _extract_job(_workflow("release-published.yml"), "promote-pkg-repo")
    assert "needs: [resolve, publish-pkg-repo, prepare-live-gate, validate-live-pages-install]" in job
    assert "if: always() && needs.publish-pkg-repo.result == 'success'" in job
    assert "'promote'" in job
    assert "'discard'" in job
    assert "STAGING_PREFIX: ${{ needs.publish-pkg-repo.outputs.staging_prefix }}" in job
    assert "exit 1" in job


def test_release_published_promote_env_never_supplies_assets_dir() -> None:
    """publish-pkg-repo.sh's promote arm requires SOURCE_REPOSITORY, RELEASE_ID,
    RELEASE_TAG, DESTINATIONS, SOURCE_RUN_ID, STAGING_PREFIX, and PUBLISH_STAGE --
    but never ASSETS_DIR (issue #2389: the script's tagged-mode env guard used to
    require ASSETS_DIR unconditionally, which broke every promote since this job
    never exports it) nor ROUTE_MATRIX/BASE_URL (issue #2450 step 3: promote never
    ran the publisher or a renderer, so both were always vestigial there; rendering
    is now render-site's own job, downstream, with its own BASE_URL)."""
    job = _extract_job(_workflow("release-published.yml"), "promote-pkg-repo")
    for var in (
        "SOURCE_REPOSITORY",
        "RELEASE_ID",
        "RELEASE_TAG",
        "DESTINATIONS",
        "SOURCE_RUN_ID",
        "STAGING_PREFIX",
        "PUBLISH_STAGE",
    ):
        assert re.search(rf"^\s+{var}:", job, re.MULTILINE), f"promote-pkg-repo env missing {var!r}:\n{job}"
    assert not re.search(r"^\s+ASSETS_DIR:\s*", job, re.MULTILINE)
    assert not re.search(r"^\s+ROUTE_MATRIX:\s*", job, re.MULTILINE)
    assert not re.search(r"^\s+BASE_URL:\s*", job, re.MULTILINE)


def test_release_published_serialises_publishes() -> None:
    text = _workflow("release-published.yml")
    assert re.search(r"^concurrency:\n  group: \S+\n  cancel-in-progress: false\n", text, re.MULTILINE), text


def test_release_published_prepare_live_gate_fails_on_untestable_target() -> None:
    job = _extract_job(_workflow("release-published.yml"), "prepare-live-gate")
    assert "::error::prepare-live-gate produced an empty matrix" in job
    assert "::error::touched target(s) with no matching CI leg to live-install-test" in job
    assert "::error::touched target(s) outside resolve's destinations (state drift)" in job


def test_release_published_prepare_live_gate_uses_shared_matrix_builder() -> None:
    """The matrix step imports the SAME pure function tests/test_live_gate_matrix.py
    exercises directly -- never a re-implementation embedded in the YAML."""
    job = _extract_job(_workflow("release-published.yml"), "prepare-live-gate")
    assert "from scripts.live_gate_matrix import compute_live_gate_matrix" in job
    assert "TOUCHED: ${{ needs.publish-pkg-repo.outputs.touched }}" in job


def test_default_live_base_url_is_stable() -> None:
    from tests.smoke import test_repo_install as repo_install

    assert repo_install.DEFAULT_LIVE_BASE_URL == "https://pfblockerng.github.io/pkg/stable"
