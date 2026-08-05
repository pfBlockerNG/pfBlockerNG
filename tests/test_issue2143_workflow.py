"""Issue #2143 release workflow handoff reproduction."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")


def test_release_workflow_derives_and_passes_destinations_into_build_record() -> None:
    assert "derive_destinations_from_git" in RELEASE
    assert "destinations=${DESTINATIONS}" in RELEASE
    assert "--build-record" in RELEASE
    assert "DESTINATIONS" in RELEASE


def test_published_callback_dispatches_exact_release_identity() -> None:
    assert "release_id" in PUBLISHED
    assert "release_tag" in PUBLISHED
    assert "source_repository" in PUBLISHED
    assert "-f release_id=" in PUBLISHED
    assert "gh release list" not in PUBLISHED
