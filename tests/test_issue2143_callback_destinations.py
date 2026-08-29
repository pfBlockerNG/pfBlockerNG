"""Issue #2143 callbacks derive the tuple from one exact published tag."""

from __future__ import annotations

from pathlib import Path

from tests._workflow_steps import extract_after, extract_between

ROOT = Path(__file__).resolve().parents[1]

PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")
MANUAL = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")
TAGGED_INGEST = (ROOT / ".github/workflows/pkg-tagged-ingest.yml").read_text(encoding="utf-8")
SMOKE_SINGLE = (ROOT / ".github/workflows/smoke-single.yml").read_text(encoding="utf-8")
NIGHTLY = (ROOT / ".github/workflows/nightly.yml").read_text(encoding="utf-8")


def test_published_callback_derives_and_forwards_the_fresh_tuple() -> None:
    assert "derive_destinations_from_git" in PUBLISHED
    assert "current_commit=sys.argv[3]" in PUBLISHED
    assert "+refs/heads/release/*:refs/remotes/origin/release/*" in PUBLISHED
    assert "destinations=${DESTINATIONS}" in PUBLISHED
    assert "destinations: ${{ needs.resolve.outputs.destinations }}" in PUBLISHED
    assert "gh release list" not in PUBLISHED


def test_manual_callback_validates_published_release_and_derives_tuple() -> None:
    assert "releases/${RELEASE_ID}" in MANUAL
    assert "jq -r '.draft'" in MANUAL
    assert "primary_channel_for_tag" in MANUAL
    assert "derive_destinations_from_git" in MANUAL
    assert "destinations: ${{ needs.resolve.outputs.destinations }}" in MANUAL
    assert "gh release list" not in MANUAL


def test_published_callback_uses_full_history_for_branch_ancestry() -> None:
    checkout = extract_between(PUBLISHED, "uses: actions/checkout@v6", "      - name: Classify")
    assert "fetch-depth: 0" in checkout


def test_tagged_callers_forward_live_smoke_secrets_through_both_reusable_hops() -> None:
    for workflow in (PUBLISHED, MANUAL):
        publish_job = extract_after(workflow, "  publish-pkg:")
        assert "secrets: inherit" in publish_job
        assert "PKG_GITHUB_APP_ID:" not in publish_job
        assert "PKG_GITHUB_APP_PRIVATE_KEY:" not in publish_job

    live_gate_job = extract_between(TAGGED_INGEST, "  validate-live-pages-install:", "\n  finalize-pkg:")
    assert "uses: ./.github/workflows/smoke-single.yml" in live_gate_job
    assert "secrets: inherit" in live_gate_job
    assert "SMOKE_SSH_PRIV_KEY" in SMOKE_SINGLE


def test_every_pkg_mutation_orchestrator_keeps_queued_runs() -> None:
    for workflow in (PUBLISHED, MANUAL, NIGHTLY):
        concurrency = extract_between(workflow, "concurrency:", "\njobs:")
        assert "group: pkg-repository-mutation" in concurrency
        assert "queue: max" in concurrency
        assert "cancel-in-progress: false" in concurrency


def test_tagged_intermediate_preserves_package_read_for_nested_smoke() -> None:
    permissions = extract_between(TAGGED_INGEST, "permissions:", "\njobs:")
    assert "contents: read" in permissions
    assert "packages: read" in permissions
    manual_permissions = extract_between(MANUAL, "permissions:", "\nconcurrency:")
    assert "packages: read" in manual_permissions


def test_live_pkg_publication_stays_disabled_until_owner_enables_it() -> None:
    gate = "if: vars.PKG_PUBLICATION_ENABLED == 'true'"
    for workflow, job_name in (
        (PUBLISHED, "publish-pkg"),
        (MANUAL, "publish-pkg"),
        (NIGHTLY, "publish-nightly-oci"),
    ):
        job = extract_after(workflow, f"  {job_name}:")
        assert gate in "\n".join(job.splitlines()[:5])
