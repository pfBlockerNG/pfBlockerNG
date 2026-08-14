"""Issue #2347: Nightly package versions use the short source SHA."""

from pathlib import Path

import pytest

from scripts import release_version as rv

ROOT = Path(__file__).resolve().parent.parent
NIGHTLY_WORKFLOW = ROOT / ".github" / "workflows" / "nightly.yml"
SMOKE_WORKFLOW = ROOT / ".github" / "workflows" / "smoke-single.yml"
SOURCE_SHA = "a" * 40
SHORT_SHA = SOURCE_SHA[:7]
VERSION = f"20260814153045.{SHORT_SHA}"


def test_nightly_version_uses_seven_character_source_sha() -> None:
    assert rv.validate_nightly_version(VERSION, source_sha=SOURCE_SHA) == VERSION
    with pytest.raises(ValueError):
        rv.validate_nightly_version(f"20260814153045.{SOURCE_SHA}", source_sha=SOURCE_SHA)


def test_nightly_workflow_shortens_only_the_package_version_sha() -> None:
    workflow = NIGHTLY_WORKFLOW.read_text(encoding="utf-8")

    assert 'SOURCE_SHORT_SHA="$(printf \'%.7s\' "$SOURCE_SHA")"' in workflow
    assert 'PKG_VERSION="${BUILD_TIMESTAMP}.${SOURCE_SHORT_SHA}"' in workflow
    assert "printf '%s\\n' \"$SOURCE_SHA\" > plan/source-sha" in workflow


def test_smoke_fixture_keeps_full_sha_annotation() -> None:
    workflow = SMOKE_WORKFLOW.read_text(encoding="utf-8")
    nightly = workflow.split("- name: Build a nightly .pkg", 1)[1].split("\n      # ADR-24", 1)[0]

    assert 'SOURCE_SHORT_SHA="$(printf \'%.7s\' "$SOURCE_SHA")"' in nightly
    assert 'NIGHTLY_VERSION="$(date -u +%Y%m%d%H%M%S).${SOURCE_SHORT_SHA}"' in nightly
    assert '--annotate   "commit=${SOURCE_SHA}"' in nightly
