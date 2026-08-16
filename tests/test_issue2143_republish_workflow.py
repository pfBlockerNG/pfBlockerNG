"""Issue #2143 exact-identity republish callback reproduction."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _workflow_steps import extract_step

REPUBLISH = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")
PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")

# Per-workflow forwarded VALUE expressions for the pkg-catalogue-dispatch step's
# identity keys — release-published.yml resolves them from the `resolve` job's
# outputs, pkg-republish.yml from its own dispatch inputs plus the ambient
# repository. A key-name-only assertion would still pass if either were
# forwarded from the WRONG source. release-published.yml renamed its step
# "Stage the pkg catalogue" (issue #2389: gate-before-announce); pkg-republish.yml's
# is untouched and stays "Publish the pkg catalogue".
_STEP_NAMES = {
    PUBLISHED: "Stage the pkg catalogue",
    REPUBLISH: "Publish the pkg catalogue",
}
_IDENTITY_VALUES = {
    PUBLISHED: {
        "SOURCE_REPOSITORY": "${{ needs.resolve.outputs.source_repository }}",
        "RELEASE_ID": "${{ needs.resolve.outputs.release_id }}",
        "RELEASE_TAG": "${{ needs.resolve.outputs.release_tag }}",
    },
    REPUBLISH: {
        "SOURCE_REPOSITORY": "${{ github.repository }}",
        "RELEASE_ID": "${{ inputs.release_id }}",
        "RELEASE_TAG": "${{ inputs.release_tag }}",
    },
}
_SOURCE_RUN_ID_VALUE = "${{ github.run_id }}:${{ github.run_attempt }}"
# issue #2416 follow-up: pkg-republish.yml's own `refresh_landing` workflow_dispatch
# input (never `github.event.inputs.*`, which would read `${{ }}` context syntax
# from the wrong namespace under `workflow_dispatch` — `inputs.*` is the one that
# resolves) toggled to the '0'/'1' string publish-pkg-repo.sh's own
# PUBLISH_REFRESH_LANDING case-statement parses.
_PUBLISH_REFRESH_LANDING_VALUE = "${{ inputs.refresh_landing && '1' || '0' }}"


def test_manual_republish_requires_exact_release_identity() -> None:
    assert "release_id:" in REPUBLISH
    assert "release_tag:" in REPUBLISH
    assert "required: true" in REPUBLISH
    assert "source_repository:" not in REPUBLISH.split("on:", 1)[1].split("jobs:", 1)[0]
    assert "gh release list" not in REPUBLISH


def test_republish_and_published_callbacks_forward_exact_run_identity() -> None:
    # The retired `gh workflow run publish.yml -f <name>=<value>` dispatch was replaced
    # by an in-repo job that forwards the same identity via env vars on the
    # pkg-catalogue-dispatch step (see _STEP_NAMES).
    for workflow, expected in _IDENTITY_VALUES.items():
        step = extract_step(workflow, _STEP_NAMES[workflow])
        for key, value in expected.items():
            assert f"{key}: {value}" in step
        assert f"SOURCE_RUN_ID: {_SOURCE_RUN_ID_VALUE}" in step
        assert "gh release list" not in workflow


def test_republish_env_carries_refresh_landing_toggle_expression() -> None:
    # PUBLISHED (release-published.yml) never sets PUBLISH_REFRESH_LANDING — its
    # "Stage the pkg catalogue" step always runs PUBLISH_STAGE=stage, and the knob
    # is a usage error there (publish-pkg-repo.sh rejects PUBLISH_REFRESH_LANDING=1
    # unless PUBLISH_STAGE=direct) — only REPUBLISH carries the toggle.
    step = extract_step(REPUBLISH, _STEP_NAMES[REPUBLISH])
    assert f"PUBLISH_REFRESH_LANDING: {_PUBLISH_REFRESH_LANDING_VALUE}" in step


def test_manual_republish_rejects_release_selector_before_api(tmp_path: Path) -> None:
    marker = tmp_path / "gh-called"
    gh = tmp_path / "gh"
    gh.write_text(
        '#!/bin/sh\ntouch "$GH_CALLED"\nprintf \'%s\\n\' \'{"tag_name":"v4.0.0","draft":false}\'\n',
        encoding="utf-8",
    )
    gh.chmod(0o755)
    script = textwrap.dedent(REPUBLISH.split("        run: |\n", 1)[1].split("      - uses:", 1)[0])
    completed = subprocess.run(
        ["sh", "-c", script],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
            "GH_CALLED": str(marker),
            "RELEASE_ID": "tags/v4.0.0",
            "RELEASE_TAG": "v4.0.0",
            "REPOSITORY": "owner/repo",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert not marker.exists()
