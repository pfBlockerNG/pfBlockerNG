"""Issue #2245: every Nightly run builds a stateless timestamped snapshot."""

from pathlib import Path

import yaml

from scripts import release_version as rv

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "nightly.yml"
ACTIONLINT_CONFIG = ROOT / ".github" / "actionlint.yaml"
SOURCE_SHA = "a" * 40
VERSION = f"20260814153045.{SOURCE_SHA[:7]}"


def test_nightly_version_is_utc_seconds_plus_short_source_sha() -> None:
    assert rv.validate_nightly_version(VERSION, source_sha=SOURCE_SHA) == VERSION


def test_every_nightly_invocation_builds_without_durable_state() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert 'TOOLS_SHA="$(git -C "$TRUSTED_DIR" rev-parse HEAD)"' in workflow
    assert 'SOURCE_SHA="$(git -C "$SOURCE_DIR" rev-parse HEAD)"' in workflow
    assert 'BUILD_TIMESTAMP="$(date -u +%Y%m%d%H%M%S)"' in workflow
    assert 'SOURCE_SHORT_SHA="$(printf \'%.7s\' "$SOURCE_SHA")"' in workflow
    assert 'PKG_VERSION="${BUILD_TIMESTAMP}.${SOURCE_SHORT_SHA}"' in workflow
    assert "queue: max" in workflow
    assert "nightly-state" not in workflow
    assert 'nightly_provenance.py" allocate' not in workflow
    assert 'nightly_provenance.py" complete' not in workflow
    assert "needs.prepare.outputs.outcome" not in workflow


def test_actionlint_exception_is_narrowly_scoped_to_workflows_using_queue_max() -> None:
    queue_error = 'unexpected key "queue" for "concurrency" section'
    assert yaml.safe_load(ACTIONLINT_CONFIG.read_text(encoding="utf-8")) == {
        "paths": {
            ".github/workflows/nightly.yml": {"ignore": [queue_error]},
            ".github/workflows/pkg-render-site.yml": {"ignore": [queue_error]},
            ".github/workflows/release-published.yml": {"ignore": [queue_error]},
            ".github/workflows/pkg-republish.yml": {"ignore": [queue_error]},
            ".github/workflows/release.yml": {"ignore": [queue_error]},
            ".github/workflows/image-refresh.yml": {"ignore": [queue_error]},
            ".github/workflows/nightly-failure-alert.yml": {"ignore": [queue_error]},
        }
    }
