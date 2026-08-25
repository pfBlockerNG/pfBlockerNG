"""The coverage-pairing gate must see real paths, not git's quoted escapes.

``.github/workflows/test.yml``'s ``coverage-pairing`` job computes the PR's
changed-file list with NUL-delimited ``git diff --name-status`` records and
pipes it into ``scripts/check_coverage_pairing.py``, which classifies paths by
``str.startswith("src/")``. Under git's default ``core.quotePath=true`` a path
carrying any non-ASCII byte comes back wrapped in double quotes and
octal-escaped (``"src/.../caf\\303\\251.inc"``), so it starts with ``"`` and
matches no classifier at all: not src, not www, not docs, not a test. A
production file under ``src/`` then clears the gate with no paired test and no
``no-test-needed`` justification, and the job reports a clean pass rather than a
skip — the miss is silent (issue #2137).

These tests run the workflow's OWN command line, extracted from the YAML rather
than retyped, against a scratch repository holding one non-ASCII ``src/`` path.
The classifier is deliberately left strict: it is fed the real bytes, never
taught to unwrap a quoted form.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
CHECKER = ROOT / "scripts" / "check_coverage_pairing.py"

# The non-ASCII path from the issue's transcript. 'é' is two UTF-8 bytes, which is
# what git escapes as \303\251 when core.quotePath is left at its default.
NON_ASCII_SRC = "src/usr/local/pkg/pfblockerng/café.inc"
ASCII_SRC = "src/usr/local/pkg/pfblockerng/plain.inc"


def _compute_command() -> str:
    """Return the workflow's changed-file command, read from the YAML itself.

    Retyping the command here would let the workflow drift away from the test
    while both stayed green, so the line is extracted instead.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    matches = [line.strip() for line in text.splitlines() if "diff --name-status" in line and "changed.txt" in line]
    assert matches, "no changed-file computation found in test.yml"
    assert len(matches) == 1, f"expected exactly one changed-file computation, got {matches}"
    return matches[0]


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def _scratch_repo(tmp_path: Path, changed: str) -> Path:
    """A repo whose HEAD adds ``changed`` on top of ``origin/devel``."""
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
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    # The workflow diffs against origin/$BASE; create that ref directly rather
    # than standing up a second repository to clone from.
    _git("update-ref", "refs/remotes/origin/devel", base_sha, cwd=repo)

    target = repo / changed
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x\n", encoding="utf-8")
    _git("add", "--", changed, cwd=repo)
    _git("commit", "-m", "add a src file with no test", cwd=repo)
    return repo


def _run_gate(repo: Path) -> subprocess.CompletedProcess[bytes]:
    """Run the workflow's compute step, then the gate, exactly as CI chains them."""
    subprocess.run(
        ["sh", "-euc", _compute_command()],
        cwd=repo,
        check=True,
        env={"PATH": "/usr/bin:/bin", "BASE": "devel", "HOME": str(repo)},
        capture_output=True,
        text=True,
    )
    changed_txt = (repo / "changed.txt").read_bytes()
    return subprocess.run(
        [sys.executable, str(CHECKER), "--name-status-z"],
        input=changed_txt,
        capture_output=True,
    )


@pytest.mark.parametrize(
    ("changed", "label"),
    [(ASCII_SRC, "ascii control"), (NON_ASCII_SRC, "non-ascii path")],
)
def test_an_unpaired_src_change_fails_the_gate(tmp_path: Path, changed: str, label: str) -> None:
    """A src/ change with no test fails the gate whatever bytes its path carries.

    The ASCII row is the control: it already failed before the fix, so a green
    non-ASCII row cannot be explained by the probe shape.
    """
    result = _run_gate(_scratch_repo(tmp_path, changed))
    assert result.returncode == 1, (
        f"{label}: unpaired {changed} passed the coverage-pairing gate "
        f"(rc={result.returncode}); stdout={result.stdout!r}"
    )
    assert b"coverage pairing violated" in result.stdout.lower()


def test_the_changed_file_list_holds_the_real_path(tmp_path: Path) -> None:
    """The computed list carries the path itself, never git's quoted escape.

    Pins the cause rather than the symptom: the classifier is strict by design,
    so the wiring is what has to hand it real bytes.
    """
    repo = _scratch_repo(tmp_path, NON_ASCII_SRC)
    _run_gate(repo)
    fields = (repo / "changed.txt").read_bytes().split(b"\0")
    assert fields == [b"A", NON_ASCII_SRC.encode(), b""], f"unexpected name-status fields: {fields!r}"
    assert b"\\303" not in fields[1], "path is octal-escaped: the listing is not NUL-separated"


def test_the_workflow_emits_a_nul_separated_listing() -> None:
    """The fix lives on the command, so a rewrite that drops -z fails here.

    ``-z`` supersedes the original ``core.quotePath=false`` pin: that flag only
    stopped HIGH-BIT bytes being escaped, leaving a quote/backslash/control byte
    in a path quoted anyway (issue #2212).
    """
    command = _compute_command()
    assert re.search(r"\bgit\s+diff\s+--name-status\s+-z\b", command), (
        f"changed-file computation must emit NUL-separated status/path records: {command!r}"
    )
