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
    (root / "other.txt").write_text("untouched\n", encoding="utf-8")
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


def _run(
    repo: Path,
    *patches: Path,
    suite: str = "sh suite.sh",
    extra: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
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
            *extra,
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
    assert "x.php" in rendered, rendered
    assert "-if ($ok) {" in rendered, rendered
    assert "+if (FALSE) {" in rendered, rendered
    # Substring checks, not list membership: a regressed element would be " unchanged" or
    # "@@ -1,3 +1,3 @@", so `"unchanged" not in rendered` against a LIST of whole lines can
    # never fire for the regression it names.
    assert not any("unchanged" in line for line in rendered), f"context bloats: {rendered}"
    assert not any("@@" in line for line in rendered), f"hunk headers bloat: {rendered}"
    assert not any("index 1..2" in line for line in rendered), f"preamble bloats: {rendered}"


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
    assert "--- old comment" in rendered, rendered
    assert "+++ i;" in rendered, rendered
    assert rendered.count("q.sql") == 1, rendered
    assert "i;" not in rendered, f"a hunk line was mistaken for a path: {rendered}"


def test_render_patch_keeps_the_old_path_when_a_file_is_deleted() -> None:
    """A deletion names its file only on the `---` side, so dropping that loses WHERE."""
    rendered = mt.render_patch("--- a/gone.txt\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-bye\n")
    assert "gone.txt" in rendered, rendered
    assert "/dev/null" not in rendered, rendered


def test_render_patch_says_so_when_it_truncates() -> None:
    """A truncated label must READ truncated, or it reads like a complete description."""
    n = mt.MAX_PATCH_LINES + 5
    body = "".join(f"+line {i}\n" for i in range(n))
    rendered = mt.render_patch(f"--- a/x\n+++ b/x\n@@ -1,0 +1,{n} @@\n{body}")
    assert any("and 5 more changed lines" in line for line in rendered), rendered


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


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (None, "no JUnit report"),
        ("", "empty JUnit report"),
        ("<testsuite", "malformed JUnit report"),
    ],
)
def test_parse_failures_raises_rather_than_reporting_zero(tmp_path: Path, content: str | None, expected: str) -> None:
    """Missing, empty and truncated reports each raise -- none may read as a clean run."""
    report = tmp_path / "r.xml"
    if content is not None:
        report.write_text(content, encoding="utf-8")
    with pytest.raises(mt.Unproducible, match=expected):
        mt.parse_failures(report)


# --------------------------------------------------------------------------- #
# The block's own shape -- the one thing a fence has to get right
# --------------------------------------------------------------------------- #


def test_the_block_fences_past_any_backticks_in_its_own_content() -> None:
    """The one sequence a fence cannot contain is a longer run of its own backticks.

    Everything else inside a fenced block is inert, which is the whole reason for the block:
    four review rounds went into escaping a markdown TABLE for arbitrary patch and test-id
    bytes, and each round found a character or a corner the last had missed. There is nothing
    to enumerate here -- only this one measurement.
    """
    row = mt.Row(Path("p.patch"), ["f.php", "-x = ```backticks```;"], ["T::a"], 2)
    out = mt.render("abc1234", ["sh", "suite.sh"], 2, [row])
    fence = out.splitlines()[0]
    assert fence.startswith("````"), f"fence must clear a run of 3: {fence!r}"
    assert out.rstrip().endswith(fence.rstrip("text")), out
    assert "```backticks```" in out, out


def test_a_line_break_in_a_test_id_cannot_forge_a_row() -> None:
    """The fence stops the block being escaped FROM; it does not stop it being forged FROM WITHIN.

    A report may carry a newline in an attribute -- a raw one is whitespace-normalised, so a
    compliant writer emits `&#10;` and the parser returns the real thing. Emitted raw, that
    puts arbitrary text at column 0 inside the block: a second `mutation:` line, a `killed`
    count, even a spoofed provenance header, none of it distinguishable from tool output.
    Report bytes fabricating a row is the defect this whole tool exists to prevent.
    """
    forged = "T::a\nmutation: forged.patch\n  killed 99:\n# generated by nobody"
    assert "\n" not in mt.flatten(forged)
    assert "\r" not in mt.flatten("T::b\rcarriage")
    out = mt.render("abc1234", ["sh", "s.sh"], 2, [mt.Row(Path("p.patch"), ["f.php"], [mt.flatten(forged)], 2)])
    body = out.splitlines()[1:-1]
    assert [ln for ln in body if ln.startswith("mutation:")] == ["mutation: p.patch"], out
    assert not [ln for ln in body if ln.startswith("# generated") and "nobody" in ln], out


def test_the_fence_is_three_backticks_even_with_none_in_the_content() -> None:
    """A fence needs a floor, not just a measurement.

    Content with no backticks measures 0, and a fence of one backtick is not a fence at all --
    it is an inline code span opener, and the whole block stops being a block. A typical PHP
    patch has no backticks in it, so this is the COMMON case, not an edge one.
    """
    out = mt.render("abc1234", ["sh", "s.sh"], 2, [mt.Row(Path("p.patch"), ["f.php", "-x = 1;"], ["T::a"], 2)])
    assert out.splitlines()[0] == "```text", out.splitlines()[0]


def test_the_header_preserves_the_suite_quoting_it_ran_with() -> None:
    """`sh s.sh 'one arg'` is three arguments; rendering it as four mislabels the run.

    This file already proves that a naive split of exactly that command flips the verdict, so
    a header that erases the quoting is describing a different experiment than the one below
    it -- which is the defect class this tool was written for, in its own header.
    """
    out = mt.render("abc1234", ["sh", "s.sh", "one arg"], 2, [mt.Row(Path("p.patch"), ["f.php"], ["T::a"], 2)])
    assert "# suite: sh s.sh 'one arg'" in out, out


def test_a_row_says_so_when_the_mutation_changed_what_runs() -> None:
    """A mutation that SHRINKS the suite is not a verdict about fixtures.

    Nothing failed because nothing ran. "killed NOTHING" would be confidently false -- the
    fixtures did not survive to be run -- and a partial kill is indistinguishable from a
    healthy pin while the rest of the suite silently vanished. Reachable by this tool's own
    primary use: mutating a data provider shrinks PHPUnit's collection with no failure and
    no error at all.
    """
    shrunk_and_silent = mt.Row(Path("p.patch"), ["f.php"], [], 1)
    out = mt.render("abc1234", ["sh", "s.sh"], 4, [shrunk_and_silent])
    assert "INCOMPARABLE: 1 tests ran, baseline ran 4" in out, out

    shrunk_and_killing = mt.Row(Path("p.patch"), ["f.php"], ["T::a"], 1)
    out = mt.render("abc1234", ["sh", "s.sh"], 4, [shrunk_and_killing])
    assert "INCOMPARABLE" in out, out
    assert "killed 1 of 1 tests run:" in out, out


def test_a_row_that_ran_the_whole_suite_says_nothing_about_comparability() -> None:
    """The caveat must not fire on every row, or it stops meaning anything."""
    out = mt.render("abc1234", ["sh", "s.sh"], 4, [mt.Row(Path("p.patch"), ["f.php"], ["T::a"], 4)])
    assert "INCOMPARABLE" not in out, out


def test_the_header_reports_the_baseline_count_it_measured() -> None:
    """An unforgeable header that carries an unpinned number is the issue's own shape."""
    out = mt.render("abc1234", ["sh", "s.sh"], 61, [mt.Row(Path("p.patch"), ["f.php"], ["T::a"], 61)])
    assert "# baseline: green, 61 tests reported" in out, out


def test_the_block_indents_every_data_line_under_its_row() -> None:
    """Indentation is what keeps report content off column 0, where the grammar lives."""
    out = mt.render("abc1234", ["sh", "s.sh"], 2, [mt.Row(Path("p.patch"), ["f.php"], ["T::a"], 2)])
    body = out.splitlines()[1:-1]
    assert "  f.php" in body, body
    assert "    T::a" in body, body
    assert [ln for ln in body if ln and not ln.startswith((" ", "#", "mutation:"))] == [], body


def test_render_patch_keeps_trailing_whitespace_that_the_patch_changed() -> None:
    """A whitespace-only mutation is a real mutation; a label that strips it shows no change."""
    rendered = mt.render_patch("--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-a = 1;  \n+a = 1;\n")
    assert "-a = 1;  " in rendered, rendered


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
    # The block must name the tree it measured, or one pasted into a PR body stops being
    # checkable the moment that tree moves on. Line 0 is the fence; the header follows it.
    assert result.stdout.splitlines()[0].endswith("text"), result.stdout
    assert head in result.stdout.splitlines()[1], result.stdout
    assert result.stdout.count("mutation: kill.patch") == 1, result.stdout
    assert [ln for ln in result.stdout.splitlines() if ln.strip() == "guard.txt"], result.stdout
    assert "-GUARD" in result.stdout and "+MUTATED" in result.stdout, result.stdout
    assert "T::alpha" in result.stdout, result.stdout
    assert "killed 1 of 2 tests run:" in result.stdout, result.stdout


def test_a_mutation_that_kills_nothing_is_reported_as_a_finding(repo: Path) -> None:
    """An unexercised branch is the finding the table exists to surface, so it exits 1."""
    inert = repo.parent / "inert.patch"
    inert.write_text("--- a/guard.txt\n+++ b/guard.txt\n@@ -1 +1,2 @@\n GUARD\n+harmless\n", encoding="utf-8")
    result = _run(repo, inert)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "killed NOTHING" in result.stdout, result.stdout
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


def test_the_report_is_excluded_even_when_the_root_reaches_it_through_a_symlink(
    repo: Path,
) -> None:
    """Scenario: a caller hands dirt() a root that is not the path the filesystem resolves to.

    Given a root reached through a symlink, and the JUnit report inside it,

    When dirt() builds its exclude pathspec,

    Then the report is still excluded -- report.resolve() returns the real path, so
      relative_to() on an unresolved root raises ValueError, the except swallows it, and
      the pathspec silently becomes EMPTY. The report then counts as tree dirt and a run
      that should have worked refuses with a dirty-tree error.

    main() resolves --root before it gets here, so this is not reachable through the CLI
    today. It is pinned because dirt()'s correctness otherwise rests on a precondition
    nothing states and nothing checks -- the next caller has no way to know. Fails closed
    either way: it cannot pass a left-applied mutation, only refuse a clean tree.

    Raised by claude-smoke reviewing this PR; the reachable half was already fixed.
    """
    link = repo.parent / "through-a-symlink"
    link.symlink_to(repo, target_is_directory=True)
    (repo / "junit.xml").write_text("<testsuite/>\n", encoding="utf-8")

    assert mt.dirt(link, link / "junit.xml") == "", (
        "the report must be excluded regardless of how the caller spelled the root"
    )


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
    rows = [ln for ln in result.stdout.splitlines() if ln.strip() == "guard.txt"]
    assert len(rows) == 2, f"the second row never ran:\n{result.stdout}\n{result.stderr}"
    assert "+MUTATED" in result.stdout and "+OTHER" in result.stdout, result.stdout


def test_undo_reports_rather_than_raises_when_git_is_gone(
    repo: Path, killing_patch: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """undo()'s whole contract is that it returns a description and never raises.

    Its callers reach it on the exception path BEFORE their own `raise`, so anything thrown
    here replaces the failure already propagating -- a malformed report, or a real
    KeyboardInterrupt. Only the second subprocess call was guarded; the reverse-apply itself
    was not, and `_run` raises when the binary is missing.
    """
    real = mt._run

    def missing_git(argv: list[str], cwd: Path, timeout: float | None = None):  # type: ignore[no-untyped-def]
        if argv[:3] == ["git", "apply", "-R"]:
            raise mt.Unproducible("cannot run 'git': [simulated] No such file or directory")
        return real(argv, cwd, timeout)

    monkeypatch.setattr(mt, "_run", missing_git)
    problem = mt.undo(repo, repo / "report.xml", killing_patch)
    assert "reverse-apply could not run" in problem, problem
    assert "simulated" in problem, problem


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


def test_a_failed_revert_is_reported_even_while_another_failure_is_propagating(repo: Path, killing_patch: Path) -> None:
    """Scenario: the two bad things happen at once, which is when it matters most.

    Given a suite that is well behaved at the baseline, but under the mutation both corrupts
      the patched file irreversibly AND writes a malformed report,

    When the row is measured,

    Then the ORIGINAL failure is what the run exits on -- raising from the `finally` would
      replace it, which is the defect that started this -- and the failed revert is still
      reported, because the tree is left mutated and silence there means every later row is
      measured under it.

    This is the combined path. The other revert test covers a failed revert with nothing else
    propagating, which reaches a different branch entirely.
    """
    (repo / "suite.sh").write_text(
        "#!/bin/sh\n"
        "if grep -q GUARD guard.txt; then cat pass.xml > report.xml;\n"
        "else printf 'TRASH\\n' >> guard.txt; printf 'not xml' > report.xml; fi\n",
        encoding="utf-8",
    )
    _git(repo, "commit", "-qam", "a suite that corrupts the tree and the report together")
    result = _run(repo, killing_patch)
    assert result.returncode == 2, f"rc={result.returncode}\n{result.stderr}"
    assert "malformed JUnit report" in result.stderr, f"the original failure was replaced: {result.stderr}"
    assert "did not take" in result.stderr, f"the tree is left mutated and nothing said so: {result.stderr}"


def test_residue_is_refused_even_when_the_reverse_apply_succeeded(repo: Path, killing_patch: Path) -> None:
    """A reverse-apply can SUCCEED and still leave the tree dirty.

    The suite here dirties a file the patch never touched, so `git apply -R` reverses cleanly
    and reports success -- and the tree is still not what the next row would be measured
    against. Checking only the exit status misses this entirely, which is what it did.
    """
    (repo / "suite.sh").write_text(
        "#!/bin/sh\nprintf 'dirtied\\n' >> other.txt\n"
        "if grep -q GUARD guard.txt; then cat pass.xml > report.xml;\n"
        "else cat fail.xml > report.xml; fi\n",
        encoding="utf-8",
    )
    _git(repo, "commit", "-qam", "a suite that dirties a file the patch never touches")
    result = _run(repo, killing_patch)
    assert result.returncode == 2, f"rc={result.returncode}\n{result.stdout}\n{result.stderr}"
    assert "did not take" in result.stderr, result.stderr
    assert "other.txt" in result.stderr, f"the residue is not named: {result.stderr}"


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
    assert "+MUTATED" in result.stdout, result.stdout


def test_a_suite_that_outlasts_the_timeout_is_refused(repo: Path, killing_patch: Path) -> None:
    """No orphaned waits: a hanging suite must not hang the tool with a mutation applied."""
    (repo / "suite.sh").write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "a suite that hangs")
    result = _run(repo, killing_patch, extra=("--timeout", "1"))
    assert result.returncode == 2, f"rc={result.returncode}\n{result.stderr}"
    assert "outlasted --timeout" in result.stderr, result.stderr


def test_an_unanticipated_failure_is_no_table_rather_than_a_finding(
    repo: Path, killing_patch: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 1 must be reachable ONLY from the deliberate unexercised-mutation branch.

    Four review rounds each found a different path landing on 1 -- the status that means "the
    table is fine and one mutation killed nothing" -- and each fix closed one more path. The
    shape was the defect: 2 was reachable only through an exception type someone had
    predicted, so anything unpredicted fell through to 1 and a caller reading the documented
    contract would act on a table that was never printed.

    This asserts the shape rather than another path: an exception nobody anticipated, from a
    place nobody guarded, still exits 2.
    """
    probe = repo.parent / "explode.py"
    probe.write_text(
        "import sys\nsys.path.insert(0, sys.argv[1])\n"
        "from scripts.agent import mutation_table as mt\n"
        "mt.render_patch = lambda text: (_ for _ in ()).throw(RuntimeError('unanticipated'))\n"
        "sys.exit(mt.main(sys.argv[2:]))\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(probe),
            str(_SCRIPT.parents[2]),
            "--suite",
            "sh suite.sh",
            "--report",
            "report.xml",
            "--root",
            str(repo),
            str(killing_patch),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2, f"rc={result.returncode}\n{result.stdout}\n{result.stderr}"
    assert "unexpected RuntimeError" in result.stderr, result.stderr
    assert result.stdout.strip() == "", f"a table was printed anyway:\n{result.stdout}"


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
