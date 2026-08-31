"""Issue #2145 contract for tagged release skills and notes prompt."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.release_version import (
    ReleaseTagCandidate,
    derive_destinations,
    parse_release_tag,
    primary_channel_for_tag,
    select_previous_release_tag,
)
from tests._workflow_steps import extract_after

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".agents/skills/release/SKILL.md"
CHANGELOG = ROOT / ".agents/skills/release-with-changelog/SKILL.md"
PROMPT = ROOT / "scripts/release-notes-prompt.txt"
WORKFLOW = ROOT / ".github/workflows/release.yml"

RETIRED_SHAPES = (
    ".testing.N",
    ".alpha.N",
    ".beta.N",
    ".rc.N",
    "snapshot.1",
    "snapshot.2",
    "stored follower-Edge",
    "Nightly follows devel",
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _candidate(
    tag: str,
    *,
    on_source_line: bool = True,
    ancestor_of_current: bool = True,
) -> ReleaseTagCandidate:
    primary = primary_channel_for_tag(tag)
    return ReleaseTagCandidate(
        tag=tag,
        info=parse_release_tag(tag, primary),
        primary=primary,
        on_source_line=on_source_line,
        ancestor_of_current=ancestor_of_current,
    )


def _release_branch(tag: str) -> str:
    major, minor = tag[1:].split(".", 2)[:2]
    return f"release/{major}.{minor}"


def test_tagged_release_skill_requires_exact_run_identity_and_one_draft() -> None:
    content = _text(RELEASE)
    required = (
        "explicit channel",
        "explicit release target",
        "admitted branch",
        "pinned source SHA",
        "workflow run",
        "primary kind",
        "destination tuple",
        "source branch",
        "one tag creates one draft",
        "exact source SHA",
        "exact asset",
        "dry_run=false",
        "do not create or push a tag by hand",
        "stop at the complete draft",
    )
    missing = [phrase for phrase in required if phrase not in content]
    assert not missing, f"{RELEASE}: missing exact-run release contract {missing}"


def test_changelog_skill_pins_family_scoped_bases_and_single_publication() -> None:
    content = _text(CHANGELOG)
    required = (
        "Stable: previous Stable in the same family",
        "first Stable in a family",
        "previous family's last Stable",
        "Testing: nearest preceding Stable or Testing-primary",
        "Edge: nearest preceding Stable or Edge-primary",
        "release line",
        "Stable primary keeps Stable notes",
        "Testing primary keeps Testing notes",
        "one Release",
        "running notes twice",
        "exact commit range",
        "fabricated issue or PR link",
        "withheld confirmation",
        "reread the draft",
        "stale draft",
        "missing asset",
        "empty range",
        "internal-only",
    )
    missing = [phrase for phrase in required if phrase not in content]
    assert not missing, f"{CHANGELOG}: missing changelog contract {missing}"


def test_changelog_skill_dispatches_and_watches_the_exact_downstream_run() -> None:
    """issue #3004: publication must deterministically start the downstream
    ingest -- GitHub suppresses the implicit release event for GITHUB_TOKEN
    actors, so the skill itself dispatches `release-published.yml` with the exact
    published Release identity, watches that exact run to completion, and reports
    both downstream outcomes."""
    content = _text(CHANGELOG)
    required = (
        "Dispatch `release-published.yml`",
        "`release_id`",
        "`release_tag`",
        "publish response",
        "never from a re-derivation",
        "default branch",
        "dispatch response",
        "exact downstream run ID",
        "attempt",
        "wait for every job",
        "Ports fork bump",
        "pfBlockerNG/pkg ingest",
        "before any redispatch",
        "never republish the same version",
    )
    missing = [phrase for phrase in required if phrase not in content]
    assert not missing, f"{CHANGELOG}: missing explicit downstream dispatch contract {missing}"


def test_release_skills_reject_nightly_and_retired_shapes() -> None:
    for path in (RELEASE, CHANGELOG):
        content = _text(path)
        assert "Nightly" in content and "explicit no-op" in content, path
        found = [shape for shape in RETIRED_SHAPES if shape in content]
        assert not found, f"{path}: retired release shapes remain {found}"


def test_notes_prompt_uses_current_grammar_and_context_only_links() -> None:
    content = _text(PROMPT)
    required = (
        "vX.Y.Z",
        "vX.Y.Z.aN",
        "vX.Y.Z.bN",
        "vX.Y.Z.rN",
        "commit subjects",
        "repository in the Context",
        "Final line",
        "## Features",
        "## Improvements",
        "## Bug Fixes",
        "Output EXACTLY",
    )
    missing = [phrase for phrase in required if phrase not in content]
    assert not missing, f"{PROMPT}: missing current notes prompt contract {missing}"

    found = [shape for shape in RETIRED_SHAPES if shape in content]
    assert not found, f"{PROMPT}: retired release shapes remain {found}"
    assert "4.0.0" not in content, "prompt must not carry a release-specific template"


@pytest.mark.parametrize(
    ("tag", "ordered_tags", "expected"),
    (
        ("v4.0.1", ("v4.0.0",), ("stable", "testing", "edge")),
        ("v4.0.1", ("v4.0.0", "v5.0.0.a1"), ("stable", "testing", "edge")),
        ("v4.0.1.a1", ("v4.0.0",), ("testing", "edge")),
        ("v4.0.1.a1", ("v4.0.0", "v5.0.0.a1"), ("testing", "edge")),
        ("v4.0.0.a1", (), ("edge",)),
    ),
)
def test_concrete_primary_routes_and_destination_fanout(
    tag: str,
    ordered_tags: tuple[str, ...],
    expected: tuple[str, ...],
) -> None:
    branches = {candidate: _release_branch(candidate) for candidate in ordered_tags}
    branch = _release_branch(tag)
    assert derive_destinations(tag, branch=branch, ordered_tags=ordered_tags, tag_branches=branches) == expected


def test_family_scoped_previous_bases_and_explicit_empty_range() -> None:
    assert (
        select_previous_release_tag(
            "v4.0.0.a1",
            "edge",
            (
                _candidate("v3.2.17", ancestor_of_current=True),
                _candidate("v3.2.19", ancestor_of_current=False),
            ),
        )
        == "v3.2.17"
    )

    assert (
        select_previous_release_tag(
            "v4.0.0",
            "stable",
            (
                _candidate("v3.2.18", ancestor_of_current=True),
                _candidate("v3.2.19", ancestor_of_current=False),
            ),
        )
        == "v3.2.18"
    )

    assert (
        select_previous_release_tag(
            "v4.0.1.a2",
            "testing",
            (
                _candidate("v4.0.0"),
                _candidate("v4.0.1.a1"),
                _candidate("v3.2.15", on_source_line=True, ancestor_of_current=False),
            ),
        )
        == "v4.0.1.a1"
    )

    assert (
        select_previous_release_tag(
            "v5.0.0.a1",
            "edge",
            (_candidate("v4.0.2", on_source_line=True, ancestor_of_current=False),),
        )
        is None
    )
    assert (
        select_previous_release_tag(
            "v4.0.1.a1",
            "testing",
            (_candidate("v3.2.15", on_source_line=False, ancestor_of_current=False),),
        )
        is None
    )


def test_workflow_propagates_trusted_release_contract_outputs() -> None:
    workflow = _text(WORKFLOW)
    required = (
        "dry_run=false",
        "primary_kind:",
        "destination_tuple:",
        "previous_tag:",
        "base_tag:",
        "commit_range:",
        "source_sha:",
        "source_branch:",
        "draft_url:",
        "assets:",
        "select_previous_release_tag",
        'line.startswith("pfBlockerNG-Release-Channel: ")',
        "empty range",
    )
    missing = [phrase for phrase in required if phrase not in workflow]
    assert not missing, f"{WORKFLOW}: missing executable release outputs {missing}"
    assert "Fallback: highest-version ANCESTOR tag of ANY channel" not in workflow
    assert "next-lower version tag overall" not in workflow
    assert "PREV: ${{ steps.prev_tag.outputs.previous_tag }}" in workflow


def test_draft_healthcheck_propagates_final_asset_handoff() -> None:
    workflow = extract_after(_text(WORKFLOW), "  draft-healthcheck:")
    for output in (
        "primary_kind:",
        "destination_tuple:",
        "previous_tag:",
        "base_tag:",
        "base_sha:",
        "commit_range:",
        "source_sha:",
        "source_branch:",
        "draft_url:",
        "assets:",
    ):
        assert output in workflow, f"draft-healthcheck missing {output}"
    assert 'OUTPUT_PATH="${GITHUB_OUTPUT:-/dev/null}"' in workflow
    assert 'echo "draft_url=${URL}" >> "$OUTPUT_PATH"' in workflow
    assert 'echo "assets=${ASSETS}" >> "$OUTPUT_PATH"' in workflow


def test_concrete_safety_fixtures_stop_before_publication() -> None:
    workflow = _text(WORKFLOW)
    changelog = _text(CHANGELOG)
    fixtures = {
        "stale_draft": ("IS_DRAFT=$(printf", "stale draft"),
        "missing_asset": ("missing release-row asset", "missing asset"),
        "fabricated_link": ("fabricated issue or PR link", "fabricated issue or PR link"),
        "withheld_confirmation": ("withheld confirmation", "withheld confirmation"),
    }
    assert fixtures["stale_draft"][0] in workflow
    for fixture_name, (needle, documented_failure) in fixtures.items():
        surface = workflow if fixture_name in {"stale_draft", "missing_asset"} else changelog
        assert needle in surface, f"{fixture_name}: missing executable/documented guard"
        assert documented_failure in changelog, f"{fixture_name}: missing stop condition"
    assert "stops without publication" in changelog


def test_empty_and_internal_ranges_are_not_written_as_user_notes() -> None:
    changelog = _text(CHANGELOG)
    ranges = {"empty": "", "internal-only": "deadbeef...tag"}
    assert ranges["empty"] == ""
    assert ranges["internal-only"].endswith("...tag")
    assert "empty/internal range used as non-empty" in changelog
    assert "Omit empty or internal-only sections from notes." in changelog


def test_nightly_path_performs_no_lookup_or_mutation() -> None:
    release = _text(RELEASE)
    changelog = _text(CHANGELOG)
    assert "before tag, Release, workflow-run, or range lookup" in release
    assert "Nightly performs no lookup and no mutation here." in release
    assert "before any lookup" in changelog
    assert "Nightly performs no lookup or mutation." in changelog
