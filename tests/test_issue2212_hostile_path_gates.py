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
import re
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
    repo.mkdir(parents=True)
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


def _executable_lines(path: Path) -> list[tuple[int, str]]:
    """Lines of ``path`` that are code, with comments and docstrings dropped.

    Prose mentioning a command must not be mistaken for one. Python docstrings
    are tracked with a triple-quote toggle rather than parsed: the scanners
    below only need to know whether a line is code, and a real parse cannot
    distinguish an invocation from a string constant anyway, since the flag
    itself is a string literal in the call.
    """
    lines: list[tuple[int, str]] = []
    fence: str | None = None
    # errors="replace": a binary under a scan root must not abort the sweep, and
    # a mangled byte cannot hide the ASCII flag being looked for.
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        stripped = line.strip()
        if path.suffix == ".py":
            for quote in ('"""', "'''"):
                if fence is None and stripped.startswith(quote):
                    # A one-line docstring opens and closes on the same line.
                    fence = None if stripped.endswith(quote) and len(stripped) > len(quote) else quote
                    break
                if fence == quote and quote in stripped:
                    fence = None
                    break
            else:
                if fence is not None:
                    continue
                lines.append((number, line))
                continue
            continue
        if stripped.startswith("#"):
            continue
        lines.append((number, line))
    return lines


def _scan_roots() -> list[Path]:
    """Every file that could invoke git, found by walking — never a fixed list.

    A hand-maintained tuple is what let the first pass at #2212 miss three
    sites: it can only catch a regression in a file someone already thought of.
    """
    roots = [ROOT / ".github", ROOT / ".githooks", ROOT / "scripts"]
    found: list[Path] = []
    for root in roots:
        found += [
            p
            for p in sorted(root.rglob("*"))
            # Compiled bytecode carries the source's strings and would report a
            # fixed site as still broken; it is a build artifact, not a site.
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        ]
    return found


def test_every_name_only_consumer_uses_the_nul_transport() -> None:
    """A changed-file list is read NUL-separated, everywhere, with no exceptions.

    Pins the class, not the sites known today: the tree is walked, so a NEW
    consumer that reads a newline-separated list fails here instead of quietly
    re-opening the hole.
    """
    offenders: list[str] = []
    for path in _scan_roots():
        for number, line in _executable_lines(path):
            if "--name-only" not in line:
                continue
            if "--no-index" in line:
                continue  # not a changed-file list; the helper's own example
            # A standalone -z token: quoted in a Python arg list, bare in shell.
            if re.search(r"(?<![\w-])-z(?![\w-])", line):
                continue
            offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert not offenders, "changed-file lists read without -z:\n  " + "\n  ".join(offenders)


def test_run_gates_refuses_a_hostile_path_instead_of_skipping_it(tmp_path: Path) -> None:
    """run-gates.sh fails loudly on a path it cannot gate, never silently.

    It is named authoritative by AGENTS.md alongside the hooks and CI, and it
    opts out of the NUL transport (piping through ``tr`` would hide git's exit
    status behind ``|| exit 2``). What replaces it must therefore be checked by
    running it: a quoted path has to reach the unsafe-filename guard and fail
    the run, and a non-ASCII path has to map to its gates as normal.
    """
    script = ROOT / "scripts" / "agent" / "run-gates.sh"

    hostile = _repo(tmp_path / "hostile")
    _git("branch", "devel", cwd=hostile)
    _commit_file(hostile, 'src/usr/local/www/has"quote.php', "<?php echo 1;\n")
    refused = subprocess.run(
        ["sh", str(script), "--worktree", str(hostile), "--diff", "devel", "--plan", "--allow-missing"],
        capture_output=True,
        text=True,
    )
    assert "unsafe filename in diff" in refused.stdout, (
        f"a quoted path produced no refusal; plan was {refused.stdout!r}"
    )

    # The non-ASCII class must not vanish either. Which way it resolves is
    # environment-dependent — run-gates' unsafe-filename filter is
    # `[^A-Za-z0-9._/-]`, and whether an accented byte trips it varies with the
    # locale and grep the run happens to use (it refuses on CI, gates here) — so
    # asserting one outcome would pin the environment, not the contract. What
    # #2212 is about is that neither outcome may be SILENCE.
    accented = _repo(tmp_path / "accented")
    _git("branch", "devel", cwd=accented)
    _commit_file(accented, "src/usr/local/www/café.php", "<?php echo 1;\n")
    planned = subprocess.run(
        ["sh", str(script), "--worktree", str(accented), "--diff", "devel", "--plan", "--allow-missing"],
        capture_output=True,
        text=True,
    )
    surfaced = "src/usr/local/www/café.php" in planned.stdout or "unsafe filename in diff" in planned.stdout
    assert surfaced, f"a non-ASCII path was silently skipped; plan was {planned.stdout!r}"

    # An ordinary path is the control: it must map to its gates, so a plan that
    # refuses or skips everything cannot make the two rows above pass.
    plain = _repo(tmp_path / "plain")
    _git("branch", "devel", cwd=plain)
    _commit_file(plain, "src/usr/local/www/plain.php", "<?php echo 1;\n")
    control = subprocess.run(
        ["sh", str(script), "--worktree", str(plain), "--diff", "devel", "--plan", "--allow-missing"],
        capture_output=True,
        text=True,
    )
    assert "php -l src/usr/local/www/plain.php" in control.stdout, (
        f"the ASCII control mapped to no gate; plan was {control.stdout!r}"
    )


def test_a_newline_in_a_path_cannot_forge_a_different_one(tmp_path: Path) -> None:
    """A path holding a newline must never be split into other paths.

    ``tr '\\0' '\\n'`` makes a newline inside a pathname indistinguishable from
    the record separator, so ``ignored\\nsrc/existing.php`` arrives as two
    records. The second names a real, UNCHANGED file: the gate then lints that
    file, passes, and never looks at the changed one. That is a manufactured
    green, strictly worse than the skip issue #2212 started from.
    """
    repo = _repo(tmp_path)
    (repo / "src").mkdir()
    (repo / "src" / "existing.php").write_text("<?php echo 1;\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "existing", cwd=repo)
    _git("branch", "devel", cwd=repo)

    forged = repo / "ignored\nsrc"
    forged.mkdir()
    (forged / "existing.php").write_text("<?php bad\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "forge", cwd=repo)

    result = subprocess.run(
        [
            "sh",
            str(ROOT / "scripts" / "agent" / "run-gates.sh"),
            "--worktree",
            str(repo),
            "--diff",
            "devel",
            "--plan",
            "--allow-missing",
        ],
        capture_output=True,
        text=True,
    )
    assert "php -l src/existing.php" not in result.stdout, (
        f"a newline path forged a gate for an unchanged file; plan was {result.stdout!r}"
    )


def test_run_gates_fails_closed_when_git_itself_fails(tmp_path: Path) -> None:
    """A git failure aborts the run; it never reports GATES: PASS on no files.

    The changed-file lists pipe git into ``tr``, and a shell pipeline reports
    TR's status — which is 0 on empty input — so a naive ``|| exit 2`` would
    check the wrong command and let a broken repository look clean. dash has no
    ``pipefail`` to lean on, so git's own status has to be taken separately.

    A corrupted index is the cheap reproduction: ``git diff --cached`` and
    ``git ls-files`` both need it and fail, while ``git diff <base>...HEAD``
    does not, so the run still has a plausible-looking file list to proceed on.
    """
    repo = _repo(tmp_path)
    _git("branch", "devel", cwd=repo)
    (repo / "extra.txt").write_text("y\n", encoding="utf-8")
    _git("add", "extra.txt", cwd=repo)
    (repo / ".git" / "index").write_bytes(b"garbage")

    result = subprocess.run(
        [
            "sh",
            str(ROOT / "scripts" / "agent" / "run-gates.sh"),
            "--worktree",
            str(repo),
            "--diff",
            "devel",
            "--allow-missing",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        f"a corrupted index produced a clean run (rc={result.returncode}); stdout={result.stdout!r}"
    )
    assert "GATES: PASS" not in result.stdout, f"a corrupted index reported success: {result.stdout!r}"


def test_every_unified_diff_parser_unquotes_its_header_path() -> None:
    """Anything parsing a `+++ b/` header routes it through the helper.

    Walked, not listed, for the same reason as the scanner above.
    """
    missing: list[str] = []
    for path in _scan_roots():
        if path.suffix != ".py" or path.name == "git_paths.py":
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        if '"+++ ' not in body and "'+++ " not in body:
            continue
        if "diff_header_name" not in body:
            missing.append(str(path.relative_to(ROOT)))
    assert not missing, f"unified-diff parsers not unquoting their header path: {missing}"
