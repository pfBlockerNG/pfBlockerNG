"""Issue #2143 callbacks derive the tuple from one exact published tag."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tests._workflow_steps import extract_after, extract_between

ROOT = Path(__file__).resolve().parents[1]

PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")
MANUAL = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")
TAGGED_INGEST = (ROOT / ".github/workflows/pkg-tagged-ingest.yml").read_text(encoding="utf-8")
SMOKE_SINGLE = (ROOT / ".github/workflows/smoke-single.yml").read_text(encoding="utf-8")
NIGHTLY = (ROOT / ".github/workflows/nightly.yml").read_text(encoding="utf-8")

APP_TOKEN_ACTION = "actions/create-github-app-token@v3"
APP_CLIENT_ID = "${{ secrets.PKG_GITHUB_APP_CLIENT_ID }}"
APP_PRIVATE_KEY = "${{ secrets.PKG_GITHUB_APP_PRIVATE_KEY }}"
APP_TOKEN_SCOPES = {
    "release-published.yml:sync-ports-fork:steps[0]": ("FreeBSD-ports", {"permission-contents": "write"}),
    "pkg-tagged-ingest.yml:stage-pkg:steps[1]": ("pkg", {"permission-actions": "write"}),
    "pkg-tagged-ingest.yml:finalize-pkg:steps[1]": ("pkg", {"permission-actions": "write"}),
    "nightly.yml:ingest-pkg:steps[1]": ("pkg", {"permission-actions": "write"}),
    "nightly.yml:cleanup-nightly-oci:steps[1]": ("pkg", {"permission-actions": "write"}),
}


def _app_token_steps() -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    workflows = ROOT / ".github/workflows"
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in document["jobs"].items():
            for step_index, step in enumerate(job.get("steps", [])):
                if step.get("uses") == APP_TOKEN_ACTION:
                    found.append((f"{path.name}:{job_name}:steps[{step_index}]", step))
    return found


def test_app_token_steps_use_client_id_and_preserve_private_key() -> None:
    steps = _app_token_steps()
    locations = [location for location, _step in steps]
    assert len(steps) == 5, f"expected exactly five {APP_TOKEN_ACTION} steps, got {locations}"
    assert set(locations) == set(APP_TOKEN_SCOPES), locations

    for location, step in steps:
        inputs = step["with"]
        assert inputs.get("client-id") == APP_CLIENT_ID, f"{location}: client-id must use the App client ID secret"
        assert "app-id" not in inputs, f"{location}: deprecated app-id input remains"
        assert inputs.get("private-key") == APP_PRIVATE_KEY, f"{location}: private-key changed"
        repository, permissions = APP_TOKEN_SCOPES[location]
        assert inputs.get("owner") == "pfBlockerNG", f"{location}: owner changed"
        assert inputs.get("repositories") == repository, f"{location}: repository scope changed"
        assert {name: value for name, value in inputs.items() if name.startswith("permission-")} == permissions, (
            f"{location}: permission scope changed"
        )

    tagged = yaml.safe_load(TAGGED_INGEST)
    secrets = tagged[True]["workflow_call"]["secrets"]
    assert secrets.get("PKG_GITHUB_APP_CLIENT_ID", {}).get("required") is True
    assert "PKG_GITHUB_APP_ID" not in secrets


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
    checkout = extract_between(PUBLISHED, "uses: actions/checkout@v7", "      - name: Classify")
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
