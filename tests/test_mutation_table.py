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

    The report is deliberately NOT gitignored. A real suite writes its JUnit inside the tree
    it grades -- PHPUnit's ``--log-junit`` resolves against its own cwd -- so the report is
    itself tree dirt, and a run that produced one is indistinguishable from a run that left
    a mutation applied unless the script excludes it. Ignoring it here would hide that from
    every test in this file, which is how the defect reached a first real run.
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


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "agent" / "mutation_table.py"


def _run(repo: Path, *patches: Path, suite: str = "sh suite.sh") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--suite",
            suite,
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
    assert "<code>x.php</code>" in rendered, rendered
    assert "<code>-if ($ok) {</code>" in rendered, rendered
    assert "<code>+if (FALSE) {</code>" in rendered, rendered
    assert "unchanged" not in rendered, f"context bloats the label: {rendered}"
    assert "@@" not in rendered, f"hunk headers bloat the label: {rendered}"
    assert "index 1..2" not in rendered, f"preamble bloats the label: {rendered}"


def test_render_patch_rejects_a_patch_that_changes_nothing() -> None:
    """A label with no change in it would name a mutation that never happened."""
    with pytest.raises(mt.Unproducible, match="changes no lines"):
        mt.render_patch("--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n context only\n")


def test_render_patch_reads_dashes_inside_a_hunk_as_content() -> None:
    """`-- a comment` is SQL, Lua and Haskell; `++i` is C. Neither is a file header.

    Reading them as headers dropped a real changed line out of the label and invented a path
    out of another, so the row described a patch that was never applied -- which is the whole
    defect this script exists to make impossible.
    """
    rendered = mt.render_patch(
        "--- a/q.sql\n+++ b/q.sql\n@@ -1,2 +1,2 @@\n--- old comment\n-SELECT 1;\n+++ i;\n+SELECT 2;\n"
    )
    assert "<code>--- old comment</code>" in rendered, rendered
    assert "<code>+++ i;</code>" in rendered, rendered
    assert rendered.count("<code>q.sql</code>") == 1, rendered
    assert "<code>i;</code>" not in rendered, f"a hunk line was mistaken for a path: {rendered}"


def test_render_patch_keeps_the_old_path_when_a_file_is_deleted() -> None:
    """A deletion names its file only on the `---` side, so dropping that loses WHERE."""
    rendered = mt.render_patch("--- a/gone.txt\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-bye\n")
    assert "<code>gone.txt</code>" in rendered, rendered
    assert "/dev/null" not in rendered, rendered


def test_a_cell_cannot_break_the_table_or_inject_markdown() -> None:
    """`|` splits a table cell even inside a code span, and a backtick closes one early.

    PHP is this tool's first subject and `||` is everywhere in it, so an unescaped label
    would shift the killed count into a different column of the very table the tool exists
    to make trustworthy -- and a backtick in a patch would let its content write markdown
    into a PR body.
    """
    rendered = mt.cell("-if ($a || $b) { `ls` }")
    assert "|" not in rendered, rendered
    assert "`" not in rendered, rendered
    assert "&#124;" in rendered and "<code>" in rendered, rendered


def test_render_patch_says_so_when_it_truncates() -> None:
    """A truncated label must READ truncated, or it reads like a complete description."""
    n = mt.MAX_PATCH_LINES + 5
    body = "".join(f"+line {i}\n" for i in range(n))
    rendered = mt.render_patch(f"--- a/x\n+++ b/x\n@@ -1,0 +1,{n} @@\n{body}")
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


def test_parse_failures_does_not_count_a_skipped_case(tmp_path: Path) -> None:
    """A skip proves nothing, so counting one as a kill would inflate a row with silence."""
    report = tmp_path / "r.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="C" name="skip"><skipped message="m"/></testcase>'
        '<testcase classname="C" name="bad"><failure message="m"/></testcase>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    assert mt.parse_failures(report) == ["C::bad"]


def test_parse_failures_survives_shellspecs_illegal_control_byte(tmp_path: Path) -> None:
    """shellspec's own writer emits a byte XML cannot represent, for this repo's fixtures.

    check_skip_allowlist.py scrubs it, and this file claims that file's convention. Refusing
    a report the sibling reads fine would make the claim wider than the parser.

    It must SUBSTITUTE, not delete, for the same reason the sibling does: deleting collapses
    `a\x01b` and `ab` into one id, and two genuinely different failing tests then arrive in
    the table indistinguishable from each other.
    """
    report = tmp_path / "r.xml"
    report.write_bytes(
        b"<testsuites><testsuite>"
        b'<testcase classname="C" name="wi\x01th"><failure/></testcase>'
        b'<testcase classname="C" name="with"><failure/></testcase>'
        b"</testsuite></testsuites>"
    )
    found = mt.parse_failures(report)
    assert found == ["C::wi?th", "C::with"], found
    assert len(set(found)) == 2, f"the scrub collapsed two distinct ids: {found}"


def test_a_newline_in_a_test_id_cannot_end_the_row(tmp_path: Path) -> None:
    """A JUnit writer keeps an intentional newline in an attribute as `&#10;`.

    A raw newline in an attribute is whitespace-normalised away, so `&#10;` is how a
    compliant writer preserves one -- and the parser hands it back as a real newline, which
    ends the markdown row outright. Same threat as the pipe and the backtick, different
    character.
    """
    report = tmp_path / "r.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="C" name="a&#10;b"><failure/></testcase></testsuite></testsuites>',
        encoding="utf-8",
    )
    (found,) = mt.parse_failures(report)
    assert "\n" in found, found
    rendered = mt.cell(found)
    assert "\n" not in rendered and "\r" not in rendered, repr(rendered)
    assert "&#10;" in rendered, rendered


@pytest.mark.parametrize(
    ("content", "expected"),
    [(None, "no JUnit report"), ("", "empty JUnit report"), ("<testsuite", "malformed JUnit report")],
)
def test_parse_failures_raises_rather_than_reporting_zero(tmp_path: Path, content: str | None, expected: str) -> None:
    """Missing, empty and truncated reports each raise -- none may read as a clean run."""
    report = tmp_path / "r.xml"
    if content is not None:
        report.write_text(content, encoding="utf-8")
    with pytest.raises(mt.Unproducible, match=expected):
        mt.parse_failures(report)


# --------------------------------------------------------------------------- #
# End to end -- the two halves come out of one command
# --------------------------------------------------------------------------- #


def test_the_row_carries_the_patch_and_the_tests_it_killed(repo: Path, killing_patch: Path) -> None:
    """Scenario: the whole point of the script.

    Given a green baseline and a patch that removes a guard the suite checks,
    When the table is generated,
    Then ONE row carries both the patch's own changed lines and the id of the test that
      failed under it, under a header naming the tree measured -- so the label and the
      measurement cannot be separated, which is how #2920 shipped four numbers attached to
      the wrong experiment.
    """
    head = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    result = _run(repo, killing_patch)
    assert result.returncode == 0, result.stderr
    # The table must name the tree it measured, or a block pasted into a PR body stops being
    # checkable the moment that tree moves on.
    assert head in result.stdout.splitlines()[0], result.stdout
    row = [ln for ln in result.stdout.splitlines() if ln.startswith("| <code>guard.txt</code>")]
    assert len(row) == 1, result.stdout
    assert "<code>-GUARD</code>" in row[0] and "<code>+MUTATED</code>" in row[0], row[0]
    assert "<code>T::alpha</code>" in row[0], row[0]
    assert "| 1 |" in row[0], row[0]


def test_a_mutation_that_kills_nothing_is_reported_as_a_finding(repo: Path) -> None:
    """An unexercised branch is the finding the table exists to surface, so it exits 1."""
    inert = repo.parent / "inert.patch"
    inert.write_text("--- a/guard.txt\n+++ b/guard.txt\n@@ -1 +1,2 @@\n GUARD\n+harmless\n", encoding="utf-8")
    result = _run(repo, inert)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "**0 — nothing**" in result.stdout, result.stdout
    assert "killed nothing" in result.stderr, result.stderr


def test_the_tree_is_clean_again_afterwards(repo: Path, killing_patch: Path) -> None:
    """A mutation left applied would silently measure every later row under it.

    The suite's own report is the one thing allowed to remain: it is output, not residue.
    Asserting that it is the ONLY entry pins both halves at once -- the revert took, and the
    report is not being counted as a mutation someone forgot to undo.
    """
    assert _run(repo, killing_patch).returncode == 0
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, check=True)
    assert status.stdout.split() == ["??", "report.xml"], status.stdout
    assert (repo / "guard.txt").read_text(encoding="utf-8") == "GUARD\n"


# --------------------------------------------------------------------------- #
# Refusals -- a table that is wrong is worse than no table
# --------------------------------------------------------------------------- #


def test_the_report_the_suite_writes_is_not_mistaken_for_dirt(repo: Path, killing_patch: Path) -> None:
    """Scenario: the suite writes its JUnit inside the tree it grades, which is the norm.

    Given a repo where the report is untracked and not ignored,

    When two patches are measured in turn,

    Then the SECOND one still runs -- before the report was excluded from the cleanliness
      check, the first row's report was read as residue from an unreverted mutation and the
      script aborted, reporting a revert failure that had not happened.

    Found by pointing the script at its first real subject, not by a test, because this
    file's fixture used to gitignore the report and so could never see it.
    """
    second = repo.parent / "second.patch"
    second.write_text("--- a/guard.txt\n+++ b/guard.txt\n@@ -1 +1 @@\n-GUARD\n+OTHER\n", encoding="utf-8")
    result = _run(repo, killing_patch, second)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = [ln for ln in result.stdout.splitlines() if ln.startswith("| <code>guard.txt</code>")]
    assert len(rows) == 2, f"the second row never ran:\n{result.stdout}\n{result.stderr}"
    assert "<code>+MUTATED</code>" in rows[0] and "<code>+OTHER</code>" in rows[1], rows


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


def test_a_revert_that_does_not_take_is_refused_and_does_not_look_like_a_finding(
    repo: Path,
) -> None:
    """The safety net's own red path, demonstrated rather than asserted into existence.

    The suite is made to append to the patched file, so `git apply -R` cannot reverse it. The
    run must exit 2 -- "no table" -- and never 1, which the contract reserves for "the table
    is fine and one mutation killed nothing". A caller reading 1 here would act on a table
    that was never printed, against a tree still carrying the mutation.
    """
    (repo / "suite.sh").write_text(
        "#!/bin/sh\n"
        "if grep -q GUARD guard.txt; then cat pass.xml > report.xml;\n"
        "else printf 'TRASH\\n' >> guard.txt; cat fail.xml > report.xml; fi\n",
        encoding="utf-8",
    )
    _git(repo, "commit", "-qam", "suite that dirties the tree")
    patch = repo.parent / "kill2.patch"
    patch.write_text("--- a/guard.txt\n+++ b/guard.txt\n@@ -1 +1 @@\n-GUARD\n+MUTATED\n", encoding="utf-8")
    result = _run(repo, patch)
    assert result.returncode == 2, f"rc={result.returncode}\n{result.stdout}\n{result.stderr}"
    assert "did not take" in result.stderr, result.stderr


def test_a_suite_that_cannot_run_is_refused_rather_than_reported_as_a_kill(repo: Path, killing_patch: Path) -> None:
    """A missing binary used to escape as a traceback on exit 1 -- the finding's own status."""
    result = _run(repo, killing_patch, suite="no-such-suite-binary-xyz")
    assert result.returncode == 2, f"rc={result.returncode}\n{result.stderr}"
    assert "cannot run" in result.stderr, result.stderr


def test_a_quoted_suite_argument_survives_parsing(repo: Path, killing_patch: Path) -> None:
    """A suite command routinely carries a quoted argument -- PHPUnit `--filter` patterns do.

    The suite here refuses to run unless it received EXACTLY ONE argument, so a naive
    `.split()` -- which turns `'one arg with spaces'` into four -- makes the baseline red and
    the run exit 2. Under `shlex` it is one argument, the baseline is green, and the mutation
    is measured normally.
    """
    (repo / "suite.sh").write_text(
        "#!/bin/sh\n"
        '[ "$#" -eq 1 ] || { cat fail.xml > report.xml; exit 0; }\n'
        "if grep -q GUARD guard.txt; then cat pass.xml > report.xml;\n"
        "else cat fail.xml > report.xml; fi\n",
        encoding="utf-8",
    )
    _git(repo, "commit", "-qam", "a suite that requires exactly one argument")
    result = _run(repo, killing_patch, suite="sh suite.sh 'one arg with spaces'")
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "<code>+MUTATED</code>" in result.stdout, result.stdout


def test_a_suite_that_outlasts_the_timeout_is_refused(repo: Path, killing_patch: Path) -> None:
    """No orphaned waits: a hanging suite must not hang the tool with a mutation applied."""
    (repo / "suite.sh").write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "a suite that hangs")
    result = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--suite",
            "sh suite.sh",
            "--report",
            "report.xml",
            "--root",
            str(repo),
            "--timeout",
            "1",
            str(killing_patch),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 2, f"rc={result.returncode}\n{result.stderr}"
    assert "outlasted --timeout" in result.stderr, result.stderr


def test_a_tracked_report_is_refused(repo: Path, killing_patch: Path) -> None:
    """The report is deleted before every run and hidden from every check, so tracking it
    would mean silently destroying a real file and still exiting 0."""
    (repo / "report.xml").write_text(JUNIT_PASS, encoding="utf-8")
    _git(repo, "add", "report.xml")
    _git(repo, "commit", "-qm", "track the report")
    result = _run(repo, killing_patch)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "is tracked by git" in result.stderr, result.stderr


def test_a_patch_that_does_not_apply_is_refused(repo: Path) -> None:
    """Silently skipping it would leave a row describing a mutation that never happened."""
    bogus = repo.parent / "bogus.patch"
    bogus.write_text("--- a/guard.txt\n+++ b/guard.txt\n@@ -1 +1 @@\n-NOT THE CONTENT\n+x\n", encoding="utf-8")
    result = _run(repo, bogus)
    assert result.returncode == 2, result.stdout
    assert "does not apply" in result.stderr, result.stderr
