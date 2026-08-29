"""Contract guard for the issue #2140 release authoring documentation."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE_DOCS = (
    ROOT / ".agents/skills/release/SKILL.md",
    ROOT / ".agents/skills/release-with-changelog/SKILL.md",
    ROOT / ".agents/context/release.md",
    ROOT / "docs/misc/release-channels.md",
)


def _active_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in ACTIVE_DOCS)


def test_active_release_docs_pin_issue_2140_contract() -> None:
    text = _active_text()
    required = (
        "Stable uses `vX.Y.Z` / `X.Y.Z`",
        "Testing uses `vX.Y.Z.aN`, `vX.Y.Z.bN`, or `vX.Y.Z.rN`",
        "`Z == 0` selects Edge",
        "`Z != 0` selects Testing",
        "immutable tag trailer",
        "Nightly is untagged",
        "no GitHub Release",
        "no release notes",
        "`YYYYMMDDHHMMSS.<7-character source SHA>`",
        "Every scheduled or manual invocation builds",
        "No counter, deduplication, or durable state exists",
        "source SHA",
        "FreeBSD-ports SHA",
        "matrix/dependency digest",
        "no routine version commit",
        "no target final",
        "no PORTEPOCH",
        "Timestamped Nightly versions intentionally outrank semantic releases",
        "repo-qualified downgrade",
    )
    missing = [phrase for phrase in required if phrase not in text]
    assert not missing, f"release contract missing from active docs: {missing}"


def test_active_release_docs_reject_superseded_normative_shapes() -> None:
    text = _active_text()
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
    found = [phrase for phrase in rejected if phrase in text]
    assert not found, f"superseded release contract remains active: {found}"
