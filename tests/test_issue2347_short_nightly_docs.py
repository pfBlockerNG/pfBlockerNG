"""Active Nightly documentation uses the seven-character SHA format."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FORMAT_SURFACES = (
    ".agents/context/release.md",
    ".agents/skills/release-with-changelog/SKILL.md",
    ".agents/skills/release/SKILL.md",
    "docs/build-pkg-portable.md",
    "docs/misc/release-channels.md",
    "scripts/README.md",
    "scripts/build-pkg-portable.py",
    "scripts/build-repo-portable.py",
    "scripts/release_version.py",
)


@pytest.mark.parametrize("relative_path", FORMAT_SURFACES)
def test_active_nightly_format_surfaces_use_short_source_sha(relative_path: str) -> None:
    text = (ROOT / relative_path).read_text(encoding="utf-8")

    assert "7-character source SHA" in text or "7-character-source-sha" in text
    assert "<full source SHA>" not in text
    assert "<full-source-sha>" not in text
