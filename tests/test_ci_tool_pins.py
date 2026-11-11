import re
import tomllib
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SHELLCHECK_PIN = "v0.11.0"
SHELLSPEC_PIN = "0.28.1"
KCOV_PIN = "a39874f938ce13f7a65f253120d1ec946b349ffe"  # the commit tag v43 pointed at
GO_PIN = "1.27.0"  # the compiler that cross-builds the pfB-DNS payload (issue #3513)
UV_PIN = "0.12.6"  # the uv that syncs the locked dependency-package toolchain


_WORKFLOWS = ROOT / ".github/workflows"
_DOCKERFILE = ROOT / ".github/docker/Dockerfile"

# A pinned tool version, upstream commit or release-asset checksum: an env key in a workflow
# whose value is a literal, or an `ARG` in the CI image's Dockerfile (the single home of the
# tool pins). `${{ ... }}` values are expressions resolved per run (a matrix leg, an input),
# not pins, so they are skipped.
_PIN_NAME = r"[A-Z][A-Z0-9_]*(?:_VERSION|_COMMIT|_SHA256)"
_PIN_ENTRY = re.compile(rf"^\s*({_PIN_NAME}):\s*(\S+)\s*$")
_DOCKERFILE_ARG = re.compile(rf"^ARG\s+({_PIN_NAME})=(\S+)\s*$")


def _pin_index(sources: Iterable[tuple[str, str]]) -> dict[str, dict[str, list[str]]]:
    """{PIN: {value: [where:line, ...]}} over (name, text) pairs."""
    found: dict[str, dict[str, list[str]]] = {}
    for where, text in sources:
        for line_no, line in enumerate(text.splitlines(), 1):
            match = _PIN_ENTRY.match(line) or _DOCKERFILE_ARG.match(line)
            if not match:
                continue
            name, value = match.group(1), match.group(2).strip("\"'")
            if value.startswith("${{"):
                continue
            found.setdefault(name, {}).setdefault(value, []).append(f"{where}:{line_no}")
    return found


def _pins() -> dict[str, dict[str, list[str]]]:
    paths = sorted([*_WORKFLOWS.glob("*.yml"), *_WORKFLOWS.glob("*.yaml"), _DOCKERFILE])
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
    """A tool version decides gate verdicts, so every place that declares it must declare
    the SAME build. The pins live as ARGs in the CI image's Dockerfile; two spellings of one
    pin drift, and the jobs then grade against different binaries while both read as green
    (#2185)."""
    pins = _pins()

    # Floor: the pins whose drift changes a verdict or a shipped binary must actually be found,
    # in the Dockerfile and nowhere with another value. A restructured install would otherwise
    # pass vacuously.
    for name, expected in (
        ("SHELLCHECK_VERSION", SHELLCHECK_PIN),
        ("SHELLSPEC_VERSION", SHELLSPEC_PIN),
        ("KCOV_COMMIT", KCOV_PIN),
        ("GO_VERSION", GO_PIN),
        ("UV_VERSION", UV_PIN),
    ):
        assert name in pins, f"nothing pins {name} any more — the install moved; retarget this gate"
        assert set(pins[name]) == {expected}, f"{name} is pinned to {pins[name]}, this gate records {expected}"
        assert any(site.startswith("Dockerfile:") for site in pins[name][expected]), (
            f"the CI image's Dockerfile does not pin {name}: {pins[name]}"
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


def _declared_outside_the_dockerfile(index: dict[str, dict[str, list[str]]]) -> dict[str, list[str]]:
    """{PIN: [site, ...]}: every site beyond the Dockerfile that declares a pin the Dockerfile owns."""
    stray: dict[str, list[str]] = {}
    for name, values in index.items():
        sites = [site for where in values.values() for site in where]
        if any(site.startswith("Dockerfile:") for site in sites):
            others = [site for site in sites if not site.startswith("Dockerfile:")]
            if others:
                stray[name] = others
    return stray


def test_a_tool_pin_the_image_owns_is_declared_only_in_the_dockerfile() -> None:
    """The jobs run inside the image, so its Dockerfile ARG is the one version they use. A
    workflow that spells the same name again states a version nothing installs any more, and
    the two drift apart while both read as current."""
    pins = _pins()
    owned = {
        name for name, values in pins.items() if any(s.startswith("Dockerfile:") for v in values.values() for s in v)
    }
    # Floor: a scan that stopped reading the Dockerfile's ARGs would find nothing to compare.
    assert {"GO_VERSION", "NODE_VERSION", "ORAS_VERSION", "SHELLSPEC_VERSION", "KCOV_COMMIT"} <= owned
    assert _declared_outside_the_dockerfile(pins) == {}


def test_image_pin_scanner_reports_a_workflow_that_redeclares_a_dockerfile_pin() -> None:
    """Vacuity guard: a workflow env key named like a Dockerfile ARG is reported with its site; a pin
    only a workflow declares, and a Dockerfile-only pin, are not."""
    dockerfile = ("Dockerfile", "ARG TOOL_VERSION=1.0.0\nARG DEBIAN_FRONTEND=noninteractive\n")
    workflow = ("w.yml", '    env:\n      TOOL_VERSION: "1.0.0"\n      OTHER_VERSION: 2\n')
    assert _declared_outside_the_dockerfile(_pin_index([dockerfile, workflow])) == {"TOOL_VERSION": ["w.yml:2"]}
    assert _declared_outside_the_dockerfile(_pin_index([dockerfile])) == {}
    assert _declared_outside_the_dockerfile(_pin_index([workflow])) == {}


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


def test_the_baked_playwright_matches_the_locked_one() -> None:
    """The ui job's `playwright install chromium` finds the browser baked into ci-vm at
    PLAYWRIGHT_BROWSERS_PATH only while the locked playwright wants the same build. On a
    mismatch it downloads a browser on every run instead of failing, so the drift is silent."""
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked = [package["version"] for package in lock["package"] if package["name"] == "playwright"]
    baked = re.findall(r"^ARG\s+PLAYWRIGHT_VERSION=(\S+)\s*$", _DOCKERFILE.read_text(encoding="utf-8"), re.MULTILINE)

    assert len(locked) == 1, f"uv.lock must lock exactly one playwright, found {locked}"
    assert baked == locked, f"the Dockerfile bakes playwright {baked}, uv.lock locks {locked}"
