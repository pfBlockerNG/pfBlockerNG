"""Additional per-surface checks for the contextual release contract."""

from __future__ import annotations

from pathlib import Path

from tests._workflow_steps import extract_between

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
        "`Z == 0` selects Edge",
        "`Z != 0` selects Testing",
        "Nightly",
        "untagged",
        "YYYYMMDDHHMMSS.<7-character source SHA>",
        "manual invocation builds",
        "No counter, deduplication",
        "state exists",
    )
    for path in SKILLS:
        content = _text(path)
        missing = [phrase for phrase in required if phrase not in content]
        assert not missing, f"{path}: missing release procedure phrases {missing}"


def test_release_skills_enforce_prerelease_patch_routing() -> None:
    for path in SKILLS:
        content = _text(path)
        assert "`Z == 0` selects Edge" in content, path
        assert "`Z != 0` selects Testing" in content, path
        assert "follower Edge" not in content, path


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
        "tag and trailer must agree",
        "immutable",
        "FreeBSD-ports SHA",
        "matrix/dependency digest",
        "no routine version commit",
        "no target final",
        "no PORTEPOCH",
        "repo-qualified downgrade",
    ):
        assert phrase in content, f"scripts/README.md: missing {phrase!r}"
    assert "`Z == 0`" in content
    assert "`Z != 0`" in content


def test_channel_targets_are_explicit_and_nightly_is_not_branch_bound() -> None:
    for path in SKILLS + (ROOT / ".agents/context/release.md", ROOT / "docs/misc/release-channels.md"):
        content = _text(path)
        assert "pfBlockerNG-Release-Channel: <stable|testing|edge>" in content, path
        assert "pinned source SHA" in content, path
        assert "Nightly" in content and "devel` branch" not in content, path
        assert "`Z == 0` selects Edge" in content, path
        assert "`Z != 0` selects Testing" in content, path


def test_scripts_readme_nightly_contract_is_branch_independent() -> None:
    content = _text(ROOT / "scripts/README.md")
    paragraph = extract_between(content, "## Release channel contract", "## ")
    assert "Nightly is an independent untagged" in paragraph
    assert "pinned source SHA" in paragraph
    assert not any(branch in paragraph for branch in ("`devel`", "`main`", "release/X.Y"))


def test_branch_independent_adr_contract_is_current() -> None:
    active = (
        ROOT / ".agents/skills/release/SKILL.md",
        ROOT / ".agents/skills/release-with-changelog/SKILL.md",
        ROOT / ".agents/context/release.md",
        ROOT / "docs/misc/release-channels.md",
    )
    for path in active:
        assert "Nightly follows devel" not in _text(path), path

    for name in ("ADR_09_Release_Version_Automation", "ADR_18_Nightly_Channel"):
        content = _text(ROOT / f"legacy/ADRs/{name}/ADR.md")
        assert "## Amendment — 2026-08-04" in content, name
        amendment = content.rsplit("## Amendment — 2026-08-04", 1)[-1]
        assert "pinned source SHA" in amendment, name
        assert "devel` snapshot" not in amendment, name

    for name in ("ADR_17_Pkg_Repository", "ADR_27_Release_Rollback_And_EOL_Routing"):
        content = _text(ROOT / f"legacy/ADRs/{name}/ADR.md")
        assert "## Amendment — 2026-08-04" in content, name
        amendment = content.rsplit("## Amendment — 2026-08-04", 1)[-1]
        assert "pinned pfBlockerNG SHA" in amendment, name
        assert "no branch inference" in amendment, name


def test_active_docs_describe_the_implemented_channel_trailer_and_order() -> None:
    docs = (
        ROOT / ".agents/context/release.md",
        ROOT / "docs/misc/release-channels.md",
    )
    for path in docs:
        content = _text(path)
        assert "tag trailer carries the channel" in content, path
        assert "Nightly < target final" not in content, path
        assert "f6db736b" not in content, path
        assert "remain current at the issue #2140 base revision" not in content, path


def test_published_workflow_has_no_retired_nightly_ports_bump_contract() -> None:
    content = _text(ROOT / ".github/workflows/release-published.yml")
    assert "`-nightly` port's PORTVERSION" not in content
    assert "the bump happens inside the release run" not in content
    assert "nightly still built from devel HEAD" not in content
    assert "from devel HEAD" not in _text(ROOT / ".github/workflows/smoke-single.yml")


def test_latest_adr09_amendment_matches_the_implemented_trailer_and_workflows() -> None:
    content = _text(ROOT / "legacy/ADRs/ADR_09_Release_Version_Automation/ADR.md")
    assert "## Amendment — 2026-08-04" in content
    amendment = content.rsplit("## Amendment — 2026-08-04", 1)[-1]
    assert "tag trailer carries only the channel" in amendment
    assert "workflow consumers are updated" in amendment
