"""Issue #2212 — a path git C-quotes must still reach every changed-file gate.

`core.quotePath=false` stops git octal-escaping *high-bit* bytes, which is what
#2137 fixed. Git's C-style quoting of a literal ``"``, ``\\``, tab or newline is
unconditional and has no such switch, so a path in any of those classes still
arrives wrapped in double quotes:

    $ git -c core.quotePath=false diff --no-index --name-only a b
    "b/src/has\\ttab.inc"

Every gate that classifies a path by prefix or suffix then matches nothing, and
the change ships un-gated while the job reports a clean pass. Two transports
carry paths in this repo and each needs its own answer:

* ``--name-only`` lists — fixed with ``-z``, which emits raw NUL-separated
  paths and sidesteps quoting entirely.
* the ``+++ b/<path>`` header of a unified diff — ``-z`` does not apply, and no
  git option suppresses the quoting, so the header path is unquoted on read.

These tests pin the behaviour of one gate per transport, unit-test the shared
unquoting against every hostile class, and hold the whole consumer list to the
rule so a seventh site cannot be added quietly.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
PRE_COMMIT = ROOT / ".githooks" / "pre-commit"

# One representative of each class git quotes unconditionally, plus the non-ASCII
# case #2137 already fixed (it must not regress).
HOSTILE_BASENAMES = ['has"quote', "has\\backslash", "has\ttab", "café"]


def _load_git_paths() -> ModuleType:
    """Import ``scripts/git_paths.py`` by path.

    Imported lazily inside the tests that need it: at module scope a missing
    module would abort collection for the whole file, hiding the behavioural
    rows that are the actual reproduction.
    """
    spec = importlib.util.spec_from_file_location("git_paths", SCRIPTS / "git_paths.py")
    assert spec and spec.loader, "scripts/git_paths.py is missing"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _repo(tmp_path: Path) -> Path:
    """A scratch repo with one base commit, isolated from ambient git config.

    ``HOME`` is redirected so a developer's own ``~/.gitconfig`` cannot change
    what git emits and turn a real failure into a false pass.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    # `git init -b` needs git >= 2.28; this must work on older git too.
    _git("init", cwd=repo)
    _git("config", "user.email", "test@example.invalid", cwd=repo)
    _git("config", "user.name", "Test", cwd=repo)
    _git("config", "commit.gpgsign", "false", cwd=repo)
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git("add", "README.md", cwd=repo)
    _git("commit", "-m", "base", cwd=repo)
    return repo


def _commit_file(repo: Path, relpath: str, body: str) -> None:
    target = repo / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    _git("add", "--", relpath, cwd=repo)
    _git("commit", "-m", "add", cwd=repo)


# --------------------------------------------------------------------------
# Transport 1: the `+++ b/<path>` header of a unified diff.
# --------------------------------------------------------------------------

NARRATION = "# ADR-99 Phase 3: narration\nx = 1\n"


@pytest.mark.parametrize("basename", [*HOSTILE_BASENAMES, "plain"])
def test_the_narration_gate_sees_a_quoted_path(tmp_path: Path, basename: str) -> None:
    """A narration comment is caught whatever bytes its path carries.

    ``plain`` is the control: it was already caught before the fix, so a hostile
    row going green cannot be explained by the probe's shape.
    """
    repo = _repo(tmp_path)
    _commit_file(repo, f"scripts/{basename}.py", NARRATION)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "check_comment_narration.py"), "--diff", "HEAD~1"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (
        f"scripts/{basename}.py: ADR-phase narration passed the gate (rc={result.returncode}); stderr={result.stderr!r}"
    )


# --------------------------------------------------------------------------
# Transport 2: a --name-only changed-file list.
# --------------------------------------------------------------------------


def _compute_command() -> str:
    """The coverage-pairing job's own command, read from the YAML not retyped."""
    matches = [
        line.strip()
        for line in WORKFLOW.read_text(encoding="utf-8").splitlines()
        if "diff --name-only" in line and "changed.txt" in line
    ]
    assert len(matches) == 1, f"expected exactly one changed-file computation, got {matches}"
    return matches[0]


@pytest.mark.parametrize("basename", [*HOSTILE_BASENAMES, "plain"])
def test_an_unpaired_src_change_fails_the_coverage_gate(tmp_path: Path, basename: str) -> None:
    """A src/ change with no test fails the gate whatever bytes its path carries."""
    repo = _repo(tmp_path)
    base_sha = _git("rev-parse", "HEAD", cwd=repo).strip()
    _git("update-ref", "refs/remotes/origin/devel", base_sha, cwd=repo)
    _commit_file(repo, f"src/usr/local/pkg/pfblockerng/{basename}.inc", "x\n")

    subprocess.run(
        ["sh", "-euc", _compute_command()],
        cwd=repo,
        check=True,
        env={"PATH": "/usr/bin:/bin", "BASE": "devel", "HOME": str(repo)},
        capture_output=True,
    )
    changed = (repo / "changed.txt").read_bytes()
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "check_coverage_pairing.py")],
        input=changed,
        capture_output=True,
    )
    assert result.returncode == 1, (
        f"src/.../{basename}.inc: unpaired src change passed the coverage-pairing gate "
        f"(rc={result.returncode}); stdout={result.stdout!r}"
    )


# --------------------------------------------------------------------------
# The shared unquoting.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("quoted", "expected"),
    [
        ('"src/has\\"quote.inc"', 'src/has"quote.inc'),
        ('"src/has\\\\backslash.inc"', "src/has\\backslash.inc"),
        ('"src/has\\ttab.inc"', "src/has\ttab.inc"),
        ('"src/has\\nnewline.inc"', "src/has\nnewline.inc"),
        ('"src/caf\\303\\251.inc"', "src/café.inc"),
        # An unquoted path is returned untouched — backslashes in it are literal,
        # because git only escapes inside a quoted form.
        ("src/plain.inc", "src/plain.inc"),
        ("src/has\\backslash.inc", "src/has\\backslash.inc"),
    ],
)
def test_unquote_reverses_gits_c_quoting(quoted: str, expected: str) -> None:
    assert _load_git_paths().unquote(quoted) == expected


def test_name_only_z_returns_raw_paths(tmp_path: Path) -> None:
    """The NUL transport hands back the path itself, with no quoting to undo."""
    repo = _repo(tmp_path)
    base_sha = _git("rev-parse", "HEAD", cwd=repo).strip()
    for basename in HOSTILE_BASENAMES:
        _commit_file(repo, f"src/{basename}.inc", "x\n")

    paths = _load_git_paths().changed_paths(f"{base_sha}...HEAD", cwd=repo)
    assert sorted(paths) == sorted(f"src/{b}.inc" for b in HOSTILE_BASENAMES)
    assert not any(p.startswith('"') for p in paths), f"a path came back quoted: {paths}"


# --------------------------------------------------------------------------
# The rule, held over the whole consumer list.
# --------------------------------------------------------------------------


def test_every_name_only_consumer_uses_the_nul_transport() -> None:
    """A changed-file list is read NUL-separated, everywhere, with no exceptions.

    Pins the class rather than the four sites known today: a new consumer that
    reads a newline-separated list fails here instead of silently re-opening the
    hole.
    """
    offenders: list[str] = []
    for path in [WORKFLOW, PRE_COMMIT, SCRIPTS / "check_context_budget.py"]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "--name-only" not in line or line.lstrip().startswith("#"):
                continue
            if "-z" not in line.split("--name-only")[0] and "-z" not in line.split("--name-only")[1]:
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert not offenders, "changed-file lists read without -z:\n  " + "\n  ".join(offenders)


def test_every_unified_diff_parser_unquotes_its_header_path() -> None:
    """The three `+++ b/` parsers all route the header path through the helper."""
    missing = [
        name
        for name in (
            "check_comment_narration.py",
            "check_retired_tokens.py",
            "check_version_literals.py",
        )
        if "diff_header_name" not in (SCRIPTS / name).read_text(encoding="utf-8")
    ]
    assert not missing, f"unified-diff parsers not unquoting their header path: {missing}"
