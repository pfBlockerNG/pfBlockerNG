"""Issue #2143 exact-identity republish callback reproduction."""

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
