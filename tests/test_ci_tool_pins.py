import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SHELLCHECK_PIN = "v0.11.0"
SHELLSPEC_PIN = "0.28.1"
KCOV_PIN = "a39874f938ce13f7a65f253120d1ec946b349ffe"  # the commit tag v43 pointed at


def _workflow() -> str:
    return (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")


def _dockerfile() -> str:
    return (ROOT / ".github/docker/ci-runner.Dockerfile").read_text(encoding="utf-8")


def _ci_requirements() -> str:
    return (ROOT / ".github/docker/ci-requirements.txt").read_text(encoding="utf-8")


def _docs_under(root: Path) -> list[Path]:
    """The Markdown files this checkout is answerable for.

    `.claude/worktrees/` is excluded by PATH, not by directory name: it holds per-task
    agent worktrees — gitignored, one whole repository checkout each — so a name-based
    skip would also drop a legitimate `worktrees/` directory elsewhere in the tree, while
    walking into them grades OTHER branches' documentation at commits this checkout has no
    say over. One worktree pinned before #2198 then reports an unpinned installer forever,
    and no edit here can make the suite green (#2353). CI never sees it: a fresh
    actions/checkout has no worktrees.
    """
    skip = {"node_modules", ".venv", "vendor", "plugins", ".git"}
    worktrees = root / ".claude" / "worktrees"
    return [path for path in root.rglob("*.md") if not skip & set(path.parts) and worktrees not in path.parents]


def test_the_gate_deciding_pins_live_in_the_image_and_nowhere_else() -> None:
    """The toolchain moved from per-job installs into ci-runner. These pins decide gate
    verdicts, so they need exactly ONE home: a workflow that re-installs a pinned tool
    would grade against a different build than the image everyone else runs."""
    workflow, dockerfile, requirements = _workflow(), _dockerfile(), _ci_requirements()

    assert f"SHELLCHECK_VERSION={SHELLCHECK_PIN}" in dockerfile
    assert f"SHELLSPEC_VERSION={SHELLSPEC_PIN}" in dockerfile
    assert f"KCOV_COMMIT={KCOV_PIN}" in dockerfile
    assert "ruff==" in requirements

    # and must NOT have been left behind in the workflow, where they would drift apart
    for stale in (
        "setup-python",
        "setup-php",
        "setup-node",
        "pip install ruff",
        "SHELLCHECK_VERSION",
        "SHELLSPEC_VERSION",
        "KCOV_COMMIT",
    ):
        assert stale not in workflow, (
            f"{stale!r} still in test.yml: the pin now lives in the image, and two homes drift"
        )


def _contributing() -> str:
    return (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")


def _job(workflow: str, name: str, next_name: str) -> str:
    return workflow.split(f"\n  {name}:\n", 1)[1].split(f"\n  {next_name}:\n", 1)[0]


def test_ci_shellcheck_pin_matches_the_documented_local_version() -> None:
    """CI and a clean local run must agree — 0.11.0 accepts constructs 0.9.0 rejects
    (`A && B || C` / SC2015, issue #2185), so a drift here reds CI after a green local run."""
    documented = re.findall(
        r"ShellCheck.{0,200}?\bv(\d+\.\d+\.\d+)\b",
        (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8"),
        re.DOTALL,
    )

    assert documented, "CONTRIBUTING.md must document the ShellCheck version contributors install locally"
    assert set(documented) == {SHELLCHECK_PIN.lstrip("v")}, (
        f"CONTRIBUTING.md documents ShellCheck {documented}, CI pins {SHELLCHECK_PIN}"
    )


def test_contributing_documents_the_shellspec_version_ci_pins() -> None:
    """A contributor whose local shellspec differs from the verified CI one gets a verdict
    CI will not reproduce, so the documented install names the pinned version (#2198)."""
    # Anchored on the install instruction itself. Scanning a window after any mention of
    # shellspec would take its version from whatever unrelated `X.Y.Z` a later doc edit
    # happens to put nearby — the file names shellspec ~20 times.
    documented = re.findall(r"Install shellspec\D{0,40}?\b(\d+\.\d+\.\d+)\b", _contributing())

    assert documented, "CONTRIBUTING.md must document the shellspec version contributors install locally"
    assert set(documented) == {SHELLSPEC_PIN}, (
        f"CONTRIBUTING.md documents shellspec {documented}, CI pins {SHELLSPEC_PIN}"
    )


def test_no_doc_offers_an_unpinned_shellspec_installer() -> None:
    """CONTRIBUTING.md's pinned instructions are only worth anything if they are the ones a
    contributor finds: tests/shell/README.md carried a second, unpinned install (`brew` +
    the upstream `curl | sh`) that CONTRIBUTING.md itself links to (#2198)."""
    offenders = sorted(
        str(path.relative_to(ROOT))
        for path in _docs_under(ROOT)
        if "git.io/shellspec" in path.read_text(encoding="utf-8")
    )

    assert offenders == [], (
        f"these docs still hand out an unpinned shellspec installer instead of pointing at"
        f" CONTRIBUTING.md's pinned instructions: {offenders}"
    )


def test_the_doc_scan_ignores_agent_worktrees(tmp_path: Path) -> None:
    """`.claude/worktrees/` holds per-task agent worktrees — gitignored, one whole
    repository checkout each. Walking into them grades OTHER branches' documentation, at
    commits this checkout has no say over, so a worktree pinned before #2198 reports an
    unpinned installer forever and the suite cannot be made green from here (#2353)."""
    (tmp_path / ".claude/worktrees/issue-1/docs").mkdir(parents=True)
    (tmp_path / ".claude/worktrees/issue-1/CONTRIBUTING.md").write_text("stale", encoding="utf-8")
    (tmp_path / ".claude/worktrees/issue-1/docs/deep.md").write_text("stale", encoding="utf-8")

    assert _docs_under(tmp_path) == []


def test_the_doc_scan_still_reaches_the_checkouts_own_docs(tmp_path: Path) -> None:
    """The exclusion has to be the worktree directory and nothing more: a scan that skipped
    `.claude/` wholesale, or simply returned nothing, would pass every assertion above while
    guarding nothing at all."""
    (tmp_path / "docs/misc").mkdir(parents=True)
    (tmp_path / ".claude").mkdir()
    (tmp_path / "vendor").mkdir()
    (tmp_path / "docs/misc/notes.md").write_text("kept", encoding="utf-8")
    (tmp_path / ".claude/rules.md").write_text("kept", encoding="utf-8")
    (tmp_path / "README.md").write_text("kept", encoding="utf-8")
    (tmp_path / "vendor/upstream.md").write_text("skipped — not ours to grade", encoding="utf-8")

    found = sorted(str(path.relative_to(tmp_path)) for path in _docs_under(tmp_path))

    assert found == [".claude/rules.md", "README.md", "docs/misc/notes.md"]
