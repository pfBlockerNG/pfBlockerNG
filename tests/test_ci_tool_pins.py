import re
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SHELLCHECK_PIN = "v0.11.0"
SHELLSPEC_PIN = "0.28.1"
KCOV_PIN = "a39874f938ce13f7a65f253120d1ec946b349ffe"  # the commit tag v43 pointed at


_WORKFLOWS = ROOT / ".github/workflows"

# A pinned tool version, upstream commit or release-asset checksum, as the workflows
# spell it: an env key whose value is a literal. `${{ ... }}` values are expressions
# resolved per run (a matrix leg, an input), not pins, so they are skipped.
_PIN_ENTRY = re.compile(r"^\s*([A-Z][A-Z0-9_]*(?:_VERSION|_COMMIT|_SHA256)):\s*(\S+)\s*$")


def _pin_index(sources: Iterable[tuple[str, str]]) -> dict[str, dict[str, list[str]]]:
    """{PIN: {value: [where:line, ...]}} over (name, text) pairs."""
    found: dict[str, dict[str, list[str]]] = {}
    for where, text in sources:
        for line_no, line in enumerate(text.splitlines(), 1):
            match = _PIN_ENTRY.match(line)
            if not match:
                continue
            name, value = match.group(1), match.group(2).strip("\"'")
            if value.startswith("${{"):
                continue
            found.setdefault(name, {}).setdefault(value, []).append(f"{where}:{line_no}")
    return found


def _pins() -> dict[str, dict[str, list[str]]]:
    paths = sorted([*_WORKFLOWS.glob("*.yml"), *_WORKFLOWS.glob("*.yaml")])
    return _pin_index((path.name, path.read_text(encoding="utf-8")) for path in paths)


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


def test_gate_deciding_pins_agree_wherever_they_appear() -> None:
    """A tool version decides gate verdicts, so every job that installs it must install
    the SAME build. The installs are per job again, and the same pin is spelled out in
    more than one job (ShellCheck twice in test.yml, shellspec in test.yml and
    build-pkg-linux.yml) — two spellings of one pin drift, and the jobs then grade
    against different binaries while both read as green (#2185)."""
    pins = _pins()

    # Floor: the three pins whose drift changes a verdict must actually be found. A
    # workflow that renames or restructures them would otherwise pass vacuously.
    for name, expected in (
        ("SHELLCHECK_VERSION", SHELLCHECK_PIN),
        ("SHELLSPEC_VERSION", SHELLSPEC_PIN),
        ("KCOV_COMMIT", KCOV_PIN),
    ):
        assert name in pins, f"no workflow pins {name} any more — the install moved; retarget this gate"
        assert set(pins[name]) == {expected}, (
            f"workflows pin {name} to {sorted(pins[name])}, this gate records {expected}"
        )

    split = {
        name: {value: sorted(where) for value, where in values.items()}
        for name, values in pins.items()
        if len(values) > 1
    }
    assert not split, (
        "these pins have more than one value across the workflows, so the jobs grade against different builds: "
        + repr(split)
    )


def test_pin_scanner_reports_a_planted_disagreement() -> None:
    """Vacuity guard for the scanner: two jobs pinning one tool differently are
    reported with both sites, a matching pair is not, and an expression value is
    never read as a pin (it resolves per run, so it has no fixed value to compare)."""
    index = _pin_index(
        [
            ("a.yml", "        env:\n          TOOL_VERSION: 1.0.0\n          KEPT_VERSION: 9\n"),
            ("b.yml", "        env:\n          TOOL_VERSION: 2.0.0\n          KEPT_VERSION: 9\n"),
            ("c.yml", "        env:\n          TOOL_VERSION: ${{ matrix.tool }}\n"),
        ]
    )
    assert index["TOOL_VERSION"] == {"1.0.0": ["a.yml:2"], "2.0.0": ["b.yml:2"]}
    assert index["KEPT_VERSION"] == {"9": ["a.yml:3", "b.yml:3"]}


def _contributing() -> str:
    return (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")


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
