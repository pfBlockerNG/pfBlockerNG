"""Issue #2143 exact-identity republish callback reproduction."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPUBLISH = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")
PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")


def test_manual_republish_requires_exact_release_identity() -> None:
    assert "release_id:" in REPUBLISH
    assert "release_tag:" in REPUBLISH
    assert "required: true" in REPUBLISH
    assert "source_repository:" not in REPUBLISH.split("on:", 1)[1].split("jobs:", 1)[0]
    assert "gh release list" not in REPUBLISH


def test_republish_and_published_callbacks_forward_exact_run_identity() -> None:
    # The retired `gh workflow run publish.yml -f <name>=<value>` dispatch was replaced
    # by an in-repo job (commit 07016c70) that forwards the same identity via env vars
    # on the "Publish the pkg catalogue" step.
    for workflow in (REPUBLISH, PUBLISHED):
        step = workflow.split("- name: Publish the pkg catalogue", 1)[1]
        assert "SOURCE_REPOSITORY:" in step
        assert "RELEASE_ID:" in step
        assert "RELEASE_TAG:" in step
        assert "SOURCE_RUN_ID:" in step
        assert "github.run_id" in step
        assert "github.run_attempt" in step
        assert "gh release list" not in workflow


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
