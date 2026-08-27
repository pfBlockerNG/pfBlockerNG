"""Issue #2143 release workflow handoff reproduction."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

from tests._workflow_steps import extract_after, extract_between

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
    block = extract_after(REPUBLISH, "      - name: Resolve exact immutable Release")
    script = extract_between(block, "        run: |\n", "\n          git fetch")
    return textwrap.dedent(script) + "\nexit 0\n"


def test_manual_republish_validates_decimal_release_identity(tmp_path: Path) -> None:
    script = _republish_validate_script()
    cases = (
        ("v4.0.0", False, True, 0),
        ("v4.0.1", False, True, 1),
        ("v4.0.0", True, True, 1),
        ("v4.0.0", False, False, 1),
    )
    for index, (tag, draft, immutable, expected_returncode) in enumerate(cases):
        bin_dir = tmp_path / f"case-{index}"
        bin_dir.mkdir()
        gh_log = tmp_path / f"case-{index}.log"
        gh = bin_dir / "gh"
        payload = (
            f'{{"tag_name":"v4.0.0","draft":{str(draft).lower()},'
            f'"prerelease":false,"immutable":{str(immutable).lower()}}}'
        )
        gh.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$*\" > '{gh_log}'\nprintf '%s\\n' '{payload}'\n",
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
        assert gh_log.read_text(encoding="utf-8").strip() == ("api repos/owner/repo/releases/12345")


def test_manual_republish_rejects_non_decimal_selector_before_api(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh_log = tmp_path / "gh.log"
    gh = bin_dir / "gh"
    gh.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{gh_log}'\nexit 99\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    completed = subprocess.run(
        ["sh", "-c", _republish_validate_script()],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "RELEASE_ID": "tags/v4.0.0",
            "RELEASE_TAG": "v4.0.0",
            "SOURCE_REPOSITORY": "owner/repo",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "release_id must be decimal" in completed.stdout + completed.stderr
    assert not gh_log.exists()
