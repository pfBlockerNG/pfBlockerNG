"""Issue #2145 contract for tagged release skills and notes prompt."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".agents/skills/release/SKILL.md"
CHANGELOG = ROOT / ".agents/skills/release-with-changelog/SKILL.md"
PROMPT = ROOT / "scripts/release-notes-prompt.txt"

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
        "one tag creates one draft",
        "exact source SHA",
        "exact asset",
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
        "same release line",
        "Stable primary keeps Stable notes",
        "Testing primary keeps Testing notes",
        "does not create a second Release",
        "does not run notes twice",
        "exact commit range",
        "fabricated issue or PR link",
        "withheld confirmation",
        "reread the draft",
    )
    missing = [phrase for phrase in required if phrase not in content]
    assert not missing, f"{CHANGELOG}: missing changelog contract {missing}"


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
