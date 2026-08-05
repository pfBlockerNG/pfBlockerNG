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
    for workflow in (REPUBLISH, PUBLISHED):
        assert "-f source_repository=" in workflow
        assert "-f release_id=" in workflow
        assert "-f release_tag=" in workflow
        assert "-f source_run_id=" in workflow
        assert "github.run_id" in workflow
        assert "github.run_attempt" in workflow
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
