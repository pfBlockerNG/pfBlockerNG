"""Issue #2143 callbacks derive the tuple from one exact published tag."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")
MANUAL = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")


def test_published_callback_derives_and_forwards_the_fresh_tuple() -> None:
    assert "derive_destinations_from_git" in PUBLISHED
    assert "current_commit=sys.argv[3]" in PUBLISHED
    assert "+refs/heads/release/*:refs/remotes/origin/release/*" in PUBLISHED
    assert "destinations=${DESTINATIONS}" in PUBLISHED
    assert '-f destinations="$DESTINATIONS"' in PUBLISHED
    assert "gh release list" not in PUBLISHED


def test_manual_callback_validates_published_release_and_derives_tuple() -> None:
    assert "releases/${RELEASE_ID}" in MANUAL
    assert "jq -r '.draft'" in MANUAL
    assert "primary_channel_for_tag" in MANUAL
    assert "derive_destinations_from_git" in MANUAL
    assert '-f destinations="$DESTINATIONS"' in MANUAL
    assert "gh release list" not in MANUAL


def test_published_callback_uses_full_history_for_branch_ancestry() -> None:
    checkout = PUBLISHED.split("uses: actions/checkout@v6", 1)[1].split("      - name: Classify", 1)[0]
    assert "fetch-depth: 0" in checkout
