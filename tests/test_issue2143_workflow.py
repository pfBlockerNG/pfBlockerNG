"""Issue #2143 release workflow handoff reproduction."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")
REPUBLISH = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")


def test_release_workflow_validates_the_exact_tag_before_building() -> None:
    assert "derive_destinations_from_git" in RELEASE
    assert "Validate immutable tag source" in RELEASE
    assert "destinations=${DESTINATIONS}" not in RELEASE
    assert "--build-record" in RELEASE
    assert '"destinations":' not in RELEASE


def test_published_callback_dispatches_exact_release_identity() -> None:
    assert "release_id" in PUBLISHED
    assert "release_tag" in PUBLISHED
    assert "source_repository" in PUBLISHED
    assert "uses: ./.github/workflows/pkg-tagged-ingest.yml" in PUBLISHED
    assert "release_id: ${{ needs.resolve.outputs.release_id }}" in PUBLISHED
    assert "destinations: ${{ needs.resolve.outputs.destinations }}" in PUBLISHED
    assert "gh release list" not in PUBLISHED


def _republish_validate_script() -> str:
    block = REPUBLISH.split("      - name: Resolve exact immutable Release", 1)[1]
    script = block.split("        run: |\n", 1)[1].split("\n          git fetch", 1)[0]
    return textwrap.dedent(script) + "\nexit 0\n"


def test_manual_republish_validates_decimal_release_identity(tmp_path: Path) -> None:
    script = _republish_validate_script()
    cases = (("v4.0.0", False, 0), ("v4.0.1", False, 1), ("v4.0.0", True, 1))
    for index, (tag, draft, expected_returncode) in enumerate(cases):
        bin_dir = tmp_path / f"case-{index}"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        payload = f'{{"tag_name":"v4.0.0","draft":{str(draft).lower()},"prerelease":false,"immutable":true}}'
        gh.write_text(
            f"#!/bin/sh\nprintf '%s\\n' '{payload}'\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)
        completed = subprocess.run(
            ["sh", "-c", script],
            cwd=ROOT,
            env=os.environ
            | {
                "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
                "RELEASE_ID": "12345",
                "RELEASE_TAG": tag,
                "SOURCE_REPOSITORY": "owner/repo",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == expected_returncode, completed.stdout + completed.stderr
