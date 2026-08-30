"""issue #2938 -- a mutation row's label must be the mutation, not prose about it.

The defect these tests pin is not "the number is wrong". Every number #2920 shipped was a
real measurement; four of the six were attached to the wrong experiment. So the assertions
below are mostly about IDENTITY -- that the emitted row carries the patch that produced the
count -- and about the script refusing to emit at all when the tree it measured cannot be
named (dirty), or when the count could not mean what it says (red or empty baseline).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.agent import mutation_table as mt  # noqa: E402

JUNIT_PASS = """<?xml version="1.0"?>
<testsuites><testsuite name="s" tests="2">
  <testcase classname="T" name="alpha"/>
  <testcase classname="T" name="beta"/>
</testsuite></testsuites>
"""

JUNIT_ONE_FAILED = """<?xml version="1.0"?>
<testsuites><testsuite name="s" tests="2">
  <testcase classname="T" name="alpha"><failure message="boom">x</failure></testcase>
  <testcase classname="T" name="beta"/>
</testsuite></testsuites>
"""


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A git repo whose "suite" reports a failure iff GUARD is missing from guard.txt.

    That is the smallest thing that behaves like a real suite for this script's purposes:
    the verdict depends on the tree, so a patch can genuinely change it and the revert can
    genuinely be observed to have taken.
    """
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "guard.txt").write_text("GUARD\n", encoding="utf-8")
    (root / "suite.sh").write_text(
        "#!/bin/sh\nif grep -q GUARD guard.txt; then cat pass.xml > report.xml; else cat fail.xml > report.xml; fi\n",
        encoding="utf-8",
    )
    (root / "suite.sh").chmod(0o755)
    (root / "pass.xml").write_text(JUNIT_PASS, encoding="utf-8")
    (root / "fail.xml").write_text(JUNIT_ONE_FAILED, encoding="utf-8")
    (root / ".gitignore").write_text("report.xml\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


@pytest.fixture
def killing_patch(repo: Path) -> Path:
    """A patch that removes the guard, so the fixture suite reports a failure under it."""
    patch = repo.parent / "kill.patch"
    patch.write_text(
        "--- a/guard.txt\n+++ b/guard.txt\n@@ -1 +1 @@\n-GUARD\n+MUTATED\n",
        encoding="utf-8",
    )
    return patch


def _run(repo: Path, *patches: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "scripts" / "agent" / "mutation_table.py"),
            "--suite",
            "sh suite.sh",
            "--report",
            "report.xml",
            "--root",
            str(repo),
            *[str(p) for p in patches],
        ],
        capture_output=True,
        text=True,
        check=False,
    )


# --------------------------------------------------------------------------- #
# render_patch -- the label IS the patch
# --------------------------------------------------------------------------- #


def test_render_patch_keeps_the_changed_lines_and_the_path() -> None:
    """The row's label carries what changed and where, so it cannot name another run."""
    rendered = mt.render_patch(
        "diff --git a/x.php b/x.php\nindex 1..2 100644\n--- a/x.php\n+++ b/x.php\n"
        "@@ -1,3 +1,3 @@\n unchanged\n-if ($ok) {\n+if (FALSE) {\n more\n"
    )
    assert "`x.php`" in rendered, rendered
    assert "`-if ($ok) {`" in rendered, rendered
    assert "`+if (FALSE) {`" in rendered, rendered
    assert "unchanged" not in rendered, f"context bloats the label: {rendered}"
    assert "@@" not in rendered, f"hunk headers bloat the label: {rendered}"
    assert "index 1..2" not in rendered, f"preamble bloats the label: {rendered}"


def test_render_patch_rejects_a_patch_that_changes_nothing() -> None:
    """A label with no change in it would name a mutation that never happened."""
    with pytest.raises(ValueError, match="changes no lines"):
        mt.render_patch("--- a/x\n+++ b/x\n@@ -1 +1 @@\n context only\n")


def test_render_patch_says_so_when_it_truncates() -> None:
    """A truncated label must READ truncated, or it reads like a complete description."""
    body = "".join(f"+line {i}\n" for i in range(mt.MAX_PATCH_LINES + 5))
    rendered = mt.render_patch(f"--- a/x\n+++ b/x\n@@ -1 +1 @@\n{body}")
    assert "and 5 more changed lines" in rendered, rendered


# --------------------------------------------------------------------------- #
# parse_failures -- an unreadable result is never "killed nothing"
# --------------------------------------------------------------------------- #


def test_parse_failures_reports_failures_and_errors_but_not_passes(tmp_path: Path) -> None:
    report = tmp_path / "r.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="C" name="ok"/>'
        '<testcase classname="C" name="bad"><failure message="m"/></testcase>'
        '<testcase classname="C" name="err"><error message="m"/></testcase>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    assert mt.parse_failures(report) == ["C::bad", "C::err"]


@pytest.mark.parametrize(
    ("content", "expected"),
    [(None, "no JUnit report"), ("", "empty JUnit report"), ("<testsuite", "malformed JUnit report")],
)
def test_parse_failures_raises_rather_than_reporting_zero(tmp_path: Path, content: str | None, expected: str) -> None:
    """Missing, empty and truncated reports each raise -- none may read as a clean run."""
    report = tmp_path / "r.xml"
    if content is not None:
        report.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=expected):
        mt.parse_failures(report)


# --------------------------------------------------------------------------- #
# End to end -- the two halves come out of one command
# --------------------------------------------------------------------------- #


def test_the_row_carries_the_patch_and_the_tests_it_killed(repo: Path, killing_patch: Path) -> None:
    """Scenario: the whole point of the script.

    Given a green baseline and a patch that removes a guard the suite checks,
    When the table is generated,
    Then ONE row carries both the patch's own changed lines and the id of the test that
      failed under it -- so the label and the measurement cannot be separated, which is
      how #2920 shipped four numbers attached to the wrong experiment.
    """
    result = _run(repo, killing_patch)
    assert result.returncode == 0, result.stderr
    row = [ln for ln in result.stdout.splitlines() if ln.startswith("| `guard.txt`")]
    assert len(row) == 1, result.stdout
    assert "`-GUARD`" in row[0] and "`+MUTATED`" in row[0], row[0]
    assert "`T::alpha`" in row[0], row[0]
    assert "| 1 |" in row[0], row[0]


def test_the_table_names_the_commit_it_measured(repo: Path, killing_patch: Path) -> None:
    """A table pasted into a body must still say which tree it describes."""
    head = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    result = _run(repo, killing_patch)
    assert head in result.stdout.splitlines()[0], result.stdout


def test_a_mutation_that_kills_nothing_is_reported_as_a_finding(repo: Path) -> None:
    """An unexercised branch is the finding the table exists to surface, so it exits 1."""
    inert = repo.parent / "inert.patch"
    inert.write_text("--- a/guard.txt\n+++ b/guard.txt\n@@ -1 +1,2 @@\n GUARD\n+harmless\n", encoding="utf-8")
    result = _run(repo, inert)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "**0 — nothing**" in result.stdout, result.stdout
    assert "killed nothing" in result.stderr, result.stderr


def test_the_tree_is_clean_again_afterwards(repo: Path, killing_patch: Path) -> None:
    """A mutation left applied would silently measure every later row under it."""
    assert _run(repo, killing_patch).returncode == 0
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, check=True)
    assert status.stdout.strip() == "", status.stdout
    assert (repo / "guard.txt").read_text(encoding="utf-8") == "GUARD\n"


# --------------------------------------------------------------------------- #
# Refusals -- a table that is wrong is worse than no table
# --------------------------------------------------------------------------- #


def test_a_dirty_tree_is_refused(repo: Path, killing_patch: Path) -> None:
    """Defect #1 of the six: a figure true about what ran, false about what it names."""
    (repo / "guard.txt").write_text("GUARD\nuncommitted\n", encoding="utf-8")
    result = _run(repo, killing_patch)
    assert result.returncode == 2, result.stdout
    assert "working tree is dirty" in result.stderr, result.stderr


def test_a_red_baseline_is_refused(repo: Path, killing_patch: Path) -> None:
    """With a red baseline no row can tell a killed test from an already-dead one."""
    (repo / "guard.txt").write_text("REMOVED\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "break the baseline")
    result = _run(repo, killing_patch)
    assert result.returncode == 2, result.stdout
    assert "baseline is not green" in result.stderr, result.stderr
    assert "T::alpha" in result.stderr, "the refusal must name what was already failing"


def test_an_empty_baseline_is_refused(repo: Path, killing_patch: Path) -> None:
    """A suite command that selects nothing would make every mutation look survivable."""
    (repo / "pass.xml").write_text('<?xml version="1.0"?><testsuites></testsuites>', encoding="utf-8")
    _git(repo, "commit", "-qam", "select nothing")
    result = _run(repo, killing_patch)
    assert result.returncode == 2, result.stdout
    assert "ran no tests" in result.stderr, result.stderr


def test_a_patch_that_does_not_apply_is_refused(repo: Path) -> None:
    """Silently skipping it would leave a row describing a mutation that never happened."""
    bogus = repo.parent / "bogus.patch"
    bogus.write_text("--- a/guard.txt\n+++ b/guard.txt\n@@ -1 +1 @@\n-NOT THE CONTENT\n+x\n", encoding="utf-8")
    result = _run(repo, bogus)
    assert result.returncode == 2, result.stdout
    assert "does not apply" in result.stderr, result.stderr
