"""Changed-file gates must classify a path git C-quotes, never skip it silently.

git wraps a path in double quotes and C-escapes it whenever the path holds a
double quote, a backslash or a control byte (tab, newline). That quoting is
unconditional: ``core.quotePath=false`` only stops HIGH-BIT bytes being escaped,
so the fix for the non-ASCII class left this one open (issue #2212). Every gate
covered here classifies a changed path by prefix or suffix, so a quoted path
matches no rule at all — its file skips the gate while the job still reports a
clean pass.

Each test drives the gate the way CI or the hook drives it, over a scratch
repository holding one hostile path, and asserts the gate SEES that file. The
``plain`` row is the control: it already passed before the fix, so a green
hostile row cannot be explained away by the probe shape.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

from tests._workflow_steps import extract_step
from tests.gitenv import scrubbed_git_env

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


car = _load("check_agent_roles")
ccb = _load("check_context_budget")

# One filename stem per escape class git applies, plus an ASCII control. The
# non-ASCII stem is the class the earlier fix closed — it must stay closed.
HOSTILE_STEMS = {
    "plain": "plain",
    "quote": 'has"quote',
    "backslash": "has\\backslash",
    "tab": "has\ttab",
    "newline": "has\nnewline",
    # A control byte outside git's named-escape set (\a\b\f\n\r\t\v) is escaped
    # in OCTAL, and that stays true under core.quotePath=false — this row is the
    # only one that reaches the octal decode path.
    "control-byte": "has\x01control",
    "non-ascii": "café",
}
QUOTED_CLASSES = [name for name in HOSTILE_STEMS if name != "plain"]


def _git(*args: str, cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="surrogateescape",
        env=scrubbed_git_env(drop_git_vars=True),
    )
    return proc.stdout


def _scratch_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    """A repo whose HEAD adds ``files`` on top of a base commit tagged ``devel``.

    ``refs/remotes/origin/devel`` is written directly rather than standing up a
    second repository to clone from — the gates only ever name it as a diff base.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", cwd=repo)
    _git("config", "user.email", "test@example.invalid", cwd=repo)
    _git("config", "user.name", "Test", cwd=repo)
    _git("config", "commit.gpgsign", "false", cwd=repo)

    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git("add", "README.md", cwd=repo)
    _git("commit", "-m", "base", cwd=repo)
    _git("update-ref", "refs/remotes/origin/devel", _git("rev-parse", "HEAD", cwd=repo).strip(), cwd=repo)
    _git("branch", "-f", "devel", "HEAD", cwd=repo)

    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "add the hostile path", cwd=repo)
    return repo


def _step_body(step_name: str) -> str:
    """The shell of a workflow step, read from the YAML rather than retyped.

    Retyping would let the workflow drift away from the test while both stayed
    green, so the ``run:`` block is extracted from the file CI executes.
    """
    body = extract_step(WORKFLOW.read_text(encoding="utf-8"), step_name)
    _, marker, script = body.partition("run: |\n")
    assert marker, f"step {step_name!r} has no run: block"
    return textwrap.dedent(script)


# ── coverage-pairing (the src<->tests gate) ──────────────────────────────────


def _compute_command() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    matches = [line.strip() for line in text.splitlines() if "diff --name-status" in line and "changed.txt" in line]
    assert len(matches) == 1, f"expected exactly one changed-file computation, got {matches}"
    return matches[0]


def _run_coverage_pairing(repo: Path) -> subprocess.CompletedProcess[bytes]:
    subprocess.run(
        ["sh", "-euc", _compute_command()],
        cwd=repo,
        check=True,
        env={"PATH": "/usr/bin:/bin", "BASE": "devel", "HOME": str(repo)},
        capture_output=True,
    )
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_coverage_pairing.py"), "--name-status-z"],
        input=(repo / "changed.txt").read_bytes(),
        capture_output=True,
    )


@pytest.mark.parametrize("klass", list(HOSTILE_STEMS))
def test_an_unpaired_src_change_fails_the_coverage_pairing_gate(tmp_path: Path, klass: str) -> None:
    """A src/ change shipping no test fails the gate whatever bytes its path carries."""
    rel = f"src/usr/local/pkg/pfblockerng/{HOSTILE_STEMS[klass]}.inc"
    result = _run_coverage_pairing(_scratch_repo(tmp_path, {rel: "x\n"}))
    expected_rc = 2 if klass == "newline" else 1
    assert result.returncode == expected_rc, (
        f"{klass}: unpaired {rel!r} passed the coverage-pairing gate (rc={result.returncode}); stdout={result.stdout!r}"
    )
    expected = b"cannot be represented in Markdown" if klass == "newline" else b"coverage pairing violated"
    assert expected.lower() in result.stdout.lower()


# ── bash-shebang gate (tracked-file listing) ─────────────────────────────────


@pytest.mark.parametrize("klass", list(HOSTILE_STEMS))
def test_a_bash_shebang_is_rejected_whatever_the_path(tmp_path: Path, klass: str) -> None:
    """The shebang gate reads every tracked file, including a C-quoted one."""
    rel = f"scripts/{HOSTILE_STEMS[klass]}.sh"
    repo = _scratch_repo(tmp_path, {rel: "#!/bin/bash\necho hi\n"})
    # bash -e is the shell GitHub gives a `run:` block with no `shell:` keyword;
    # running the step under anything else would not exercise its real wiring.
    result = subprocess.run(
        ["bash", "-e", "-c", _step_body("Forbid bash shebangs")],
        cwd=repo,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(repo)},
    )
    assert result.returncode == 1, (
        f"{klass}: bash shebang in {rel!r} passed the gate (rc={result.returncode}); stdout={result.stdout!r}"
    )


# ── diff-header parsers (+++ b/<path>) ───────────────────────────────────────


def _run_checker(script: str, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *args],
        cwd=repo,
        capture_output=True,
        encoding="utf-8",
        errors="surrogateescape",
        env=scrubbed_git_env(drop_git_vars=True),
    )


@pytest.mark.parametrize("klass", list(HOSTILE_STEMS))
def test_comment_narration_reads_a_hostile_path(tmp_path: Path, klass: str) -> None:
    """Process narration added to a C-quoted path is still a violation."""
    rel = f"scripts/{HOSTILE_STEMS[klass]}.py"
    repo = _scratch_repo(tmp_path, {rel: "# Phase 4: wire the thing\nx = 1\n"})
    result = _run_checker("check_comment_narration.py", repo, "--diff", "devel")
    assert result.returncode == 1, (
        f"{klass}: narration in {rel!r} passed the gate (rc={result.returncode}); stderr={result.stderr!r}"
    )
    assert "ADR phase narration" in result.stderr


@pytest.mark.parametrize("klass", list(HOSTILE_STEMS))
def test_version_literals_reads_a_hostile_path(tmp_path: Path, klass: str) -> None:
    """A hardcoded version literal added to a C-quoted path is still a violation."""
    rel = f"scripts/{HOSTILE_STEMS[klass]}.sh"
    repo = _scratch_repo(tmp_path, {rel: '#!/bin/sh\nabi="FreeBSD:14"\necho "$abi"\n'})
    result = _run_checker("check_version_literals.py", repo, "--diff", "devel")
    assert result.returncode == 1, (
        f"{klass}: version literal in {rel!r} passed the gate (rc={result.returncode}); stderr={result.stderr!r}"
    )
    # rc 1 alone would also cover an uncaught crash; the report line is what
    # proves the gate reached a verdict about this file.
    assert "Hardcoded pfSense/FreeBSD version literal" in result.stderr, result.stderr


@pytest.mark.parametrize("klass", list(HOSTILE_STEMS))
def test_guard_erosion_reads_a_hostile_path(tmp_path: Path, klass: str) -> None:
    """A test retired from a C-quoted path is still an unexcused retirement.

    This gate reads the REMOVED side of the diff, so the fixture adds the test in
    one commit and deletes it in the next and diffs against the first.
    """
    rel = f"tests/test_{HOSTILE_STEMS[klass]}.py"
    repo = _scratch_repo(tmp_path, {rel: "def test_reaps_the_orphan():\n    assert True\n"})
    (repo / rel).unlink()
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "retire the guard", cwd=repo)
    result = _run_checker("check_guard_erosion.py", repo, "--diff", "HEAD~1")
    assert result.returncode == 1, (
        f"{klass}: retiring the test in {rel!r} passed the gate (rc={result.returncode}); stderr={result.stderr!r}"
    )
    # rc 1 alone would also cover an uncaught crash; naming the retired test is
    # what proves the gate reached a verdict about this file.
    assert "test_reaps_the_orphan" in result.stderr, result.stderr


# ── --name-only listings ─────────────────────────────────────────────────────


@pytest.mark.parametrize("klass", QUOTED_CLASSES)
def test_agent_roles_changed_paths_are_real_paths(tmp_path: Path, klass: str) -> None:
    """A C-quoted role-surface path must still trigger role validation."""
    rel = f".agents/policy/{HOSTILE_STEMS[klass]}.md"
    repo = _scratch_repo(tmp_path, {rel: "text\n"})
    changed = car._changed_paths(repo, ["devel...HEAD"])
    assert rel in changed, f"{klass}: changed paths {changed} do not include {rel!r}"
    assert car.touches_role_surface(changed)


@pytest.mark.parametrize("klass", QUOTED_CLASSES)
def test_context_budget_does_not_skip_a_hostile_context_surface(
    tmp_path: Path, klass: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """A C-quoted policy file must not read as "no context surface in the diff".

    The skip short-circuits before any budget is measured, so a quoted path
    silently exempts the whole run rather than one file.
    """
    rel = f".agents/policy/{HOSTILE_STEMS[klass]}.md"
    repo = _scratch_repo(tmp_path, {rel: "text\n"})
    ccb.main(["--diff", "devel", "--root", str(repo)])
    assert "no context surface in the diff" not in capsys.readouterr().out, (
        f"{klass}: {rel!r} was classified as no context surface"
    )


def test_every_changed_file_gate_reads_a_nul_separated_listing() -> None:
    """The gates that transport a path list use -z, the only quote-proof form.

    Pins the cause, not just the symptom: a rewrite that drops -z and goes back
    to newline-separated output re-opens every row above at once.
    """
    assert re.search(r"\bgit\s+diff\s+--name-status\s+-z\b", _compute_command()), _compute_command()
    shebang = _step_body("Forbid bash shebangs")
    assert re.search(r"\bgit\s+ls-files\s+-z\b", shebang), shebang
