"""Additional per-surface checks for the post-green release contract."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = (
    ROOT / ".agents/skills/release/SKILL.md",
    ROOT / ".agents/skills/release-with-changelog/SKILL.md",
)
ACTIVE = (
    *SKILLS,
    ROOT / ".agents/context/release.md",
    ROOT / "docs/misc/release-channels.md",
    ROOT / "scripts/README.md",
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_each_release_skill_carries_the_minimum_procedure() -> None:
    required = (
        "channel is explicit",
        "configured",
        "vX.Y.Z.aN",
        "vX.Y.Z.bN",
        "vX.Y.Z.rN",
        "same Release and artifact bytes",
        "no second Release",
        "no rebuild",
        "Nightly",
        "untagged",
        "YYYYMMDD",
        "YYYYMMDD_1",
        "no-op",
    )
    for path in SKILLS:
        content = _text(path)
        missing = [phrase for phrase in required if phrase not in content]
        assert not missing, f"{path}: missing release procedure phrases {missing}"


def test_all_active_release_surfaces_reject_superseded_shapes() -> None:
    rejected = (
        "vX.Y.Z.edge.YYYYMMDD.N",
        "X.Y.Z.snapshot.1.YYYYMMDD.N",
        "X.Y.Z.snapshot.2.YYYYMMDD.N",
        "YYYYMMDD.HHMMSS",
        "Nightly version:X.Y.Z.nightly.YYYYMMDD.N",
        "target final version",
        "`main` only",
        "`devel` only",
    )
    for path in ACTIVE:
        content = _text(path)
        found = [phrase for phrase in rejected if phrase in content]
        assert not found, f"{path}: superseded release shapes remain {found}"


def test_scripts_readme_documents_shared_identity_and_provenance() -> None:
    content = _text(ROOT / "scripts/README.md")
    for phrase in (
        "pfSense-pkg-pfBlockerNG",
        "explicit/configured",
        "immutable",
        "FreeBSD-ports SHA",
        "matrix/dependency digest",
        "no routine version commit",
        "no target final",
        "no PORTEPOCH",
        "repo-qualified downgrade",
    ):
        assert phrase in content, f"scripts/README.md: missing {phrase!r}"


def test_channel_targets_are_explicit_and_nightly_is_not_branch_bound() -> None:
    for path in SKILLS + (ROOT / ".agents/context/release.md", ROOT / "docs/misc/release-channels.md"):
        content = _text(path)
        assert "pfBlockerNG-Release-Channel: <stable|testing|edge>" in content, path
        assert "pinned source SHA" in content, path
        assert "Nightly" in content and "devel` branch" not in content, path
        assert "Edge follows Testing only when no distinct target" in content, path
        assert "distinct-target Edge uses its configured target/line" in content, path


def test_scripts_readme_nightly_contract_is_branch_independent() -> None:
    content = _text(ROOT / "scripts/README.md")
    paragraph = content.split("## Release channel contract", 1)[1].split("## ", 1)[0]
    assert "Nightly is an independent untagged" in paragraph
    assert "pinned source SHA" in paragraph
    assert not any(branch in paragraph for branch in ("`devel`", "`main`", "release/X.Y"))
