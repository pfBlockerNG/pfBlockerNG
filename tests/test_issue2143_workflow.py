"""Issue #2143 release workflow handoff reproduction."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")


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
    assert "-f release_id=" in PUBLISHED
    assert '-f destinations="$DESTINATIONS"' in PUBLISHED
    assert "gh release list" not in PUBLISHED
