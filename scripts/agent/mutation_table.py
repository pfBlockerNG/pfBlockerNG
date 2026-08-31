#!/usr/bin/env python3
"""Emit a mutation table whose label and measurement come out of one command (issue #2938).

PROBLEM
-------
A mutation probe is executed in one place and described in another. An agent runs a
mutation, reads the count, and later writes prose about it into a PR body. The
measurement and its label are produced by different acts, so nothing checks that the
label still matches the measurement.

Adversarial review does not catch this: #2920 ran seven rounds and shipped six wrong
numbers anyway. Every one described a real run. Four of the six were a number attached
to the wrong experiment -- the reviewer re-runs "the mutation the body names", gets a
different count, and reports a contradiction that is really a naming error. Both parties
measured correctly and disagreed anyway.

WHAT THIS DOES
--------------
Applies each patch, runs the suite, and prints the patch AND the tests it killed as one
row. The label is not a description of the mutation; it is the mutation. A stale figure
is impossible because the figure and its label are one string, and a mislabelled figure
is impossible because the label is the diff that was applied.

The header carries the commit the table describes, so a table pasted into a body still
says which tree it measured after that tree moves on.

WHY IT REFUSES A DIRTY TREE
---------------------------
A table measured against uncommitted work describes a state no commit contains, which is
defect #1 of the six: a figure that is true about the thing that was run and false about
the thing it names. The same reason drives the baseline check -- a mutation table over a
red baseline cannot distinguish "this mutation killed the test" from "it was already
dead", so a non-green baseline is fatal rather than a footnote.

FAILING-TEST IDS
----------------
``<classname>::<name>``, taken verbatim from the JUnit report's ``<testcase>``
attributes -- the same shape ``scripts/check_skip_allowlist.py`` uses, minus its suite
prefix, so an id here reads the same as an id there. Every suite this repo gates writes
that report -- pytest, PHPUnit, shellspec and the ``node --test`` legs -- which is why the
suite command is asked to produce one rather than having its human-readable output parsed
per runner. shellspec's own writer emits an XML-illegal control byte for this repo's
C-quoted-path fixtures, so the same scrub ``check_skip_allowlist.py`` applies is applied
here; without it a report that sibling reads fine would be refused as malformed.

EXIT STATUS
-----------
* ``0`` -- every patch applied, ran, and reverted; the table is on stdout.
* ``1`` -- a mutation killed nothing. That is the finding the table exists to surface
  (an unexercised branch), so it is reported in the table AND in the status.
* ``2`` -- the table could not be produced: dirty tree, red or empty baseline, a patch
  that does not apply, a missing or malformed report, a suite that will not run, a run that
  outlasts ``--timeout``, or a revert that did not take. A table that is wrong is worse than
  no table, so none of these fall through to 0, and none of them is allowed to land on 1 --
  a caller reading the contract would take that for "the table is fine, one branch is
  unexercised" and act on a table that does not exist.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

# Keep a rendered patch from swamping the row it labels. A mutation big enough to exceed
# this is one whose name was never going to be trustworthy anyway -- the row says so
# rather than quietly truncating to something that reads complete.
MAX_PATCH_LINES = 12

# shellspec 0.28.1 embeds a raw XML-1.0-illegal control byte verbatim when a spec
# description carries one (tests/shell/agent_run_gates_git_spec.sh uses a literal 0x01 by
# design). Such a byte has no legal XML representation, so a strict parse of shellspec's
# REAL report always raises. Same scrub, same reason, as scripts/check_skip_allowlist.py --
# claiming that file's convention while refusing a report it accepts would be a narrower
# parser wearing a wider claim. It SUBSTITUTES rather than deletes, for the same reason the
# sibling does: deleting collapses `a\x01b` and `ab` into one id, so two genuinely different
# failing tests become indistinguishable in the table.
_XML_ILLEGAL_CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class Unproducible(Exception):
    """The table cannot be produced. Always exit 2, never 1."""


@dataclass(frozen=True)
class Row:
    """One mutation and what it killed, as one value so they cannot drift apart."""

    patch: Path
    label: list[str]
    failures: list[str]


def _run(argv: list[str], cwd: Path, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    """Run $argv in $cwd. A missing binary or a run past $timeout is Unproducible, not a row."""
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False, timeout=timeout)
    except FileNotFoundError as exc:
        raise Unproducible(f"cannot run {argv[0]!r}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise Unproducible(f"{argv[0]!r} outlasted --timeout={timeout}s") from exc


def dirt(root: Path, report: Path) -> str:
    """``git status --porcelain`` for $root, minus the JUnit report the suite writes.

    The suite is normally told to write its report inside the tree it is run in, so the
    report is itself tree dirt -- and a run that produced one would then be indistinguishable
    from a run that left a mutation applied. Found by pointing this script at its first real
    subject: every row after the first was refused because PHPUnit had written `junit.xml`
    next to the code it graded.

    git does the excluding, via a pathspec. Parsing the porcelain here instead meant
    re-implementing its C-quoting, and a report whose name git quotes would have slipped the
    filter and been blamed on the revert.
    """
    try:
        spec = ["--", f":(exclude,literal){report.resolve().relative_to(root)}"]
    except ValueError:
        spec = []
    status = _run(["git", "status", "--porcelain", *spec], root)
    if status.returncode != 0:
        raise Unproducible(f"git status failed: {status.stderr.strip()}")
    return status.stdout.strip()


def _require_untracked_report(root: Path, report: Path) -> None:
    """Refuse a report path git tracks.

    dirt() filters that path out of every cleanliness check and measure() unlinks it before
    each run, so a TRACKED report would be deleted and its disappearance hidden -- the tool
    would quietly destroy a file and still exit 0.
    """
    try:
        rel = str(report.resolve().relative_to(root))
    except ValueError:
        return
    tracked = _run(["git", "ls-files", "--error-unmatch", "--", rel], root)
    if tracked.returncode == 0:
        raise Unproducible(
            f"{rel} is tracked by git; this script deletes the report before every run and "
            "excludes it from every cleanliness check, so it must not be a tracked file"
        )


_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def render_patch(text: str) -> list[str]:
    """The patch's own touched paths and changed lines, which is what labels the row.

    Context, hunk headers and the ``diff --git``/index preamble are dropped: they are
    the same for every mutation of one file and would bury the one or two lines that
    actually distinguish this row from its neighbours. The touched paths are kept, so a
    row still says WHERE as well as WHAT.

    A ``---``/``+++`` line is a file header only OUTSIDE a hunk. Inside one it is content:
    ``-- a comment`` is ordinary SQL, Lua and Haskell, and ``++i`` is ordinary C. Reading
    those as headers dropped a real changed line from the label and invented a path out of
    another -- a row that quietly described a different patch than the one applied, which is
    the exact defect this script exists to make impossible. So the hunk headers ARE parsed,
    for their line counts, even though they are not rendered.
    """
    paths: list[str] = []
    changes: list[str] = []
    old_left = new_left = 0
    for line in text.splitlines():
        if old_left <= 0 and new_left <= 0:
            hunk = _HUNK.match(line)
            if hunk is not None:
                old_left = int(hunk.group(1)) if hunk.group(1) is not None else 1
                new_left = int(hunk.group(2)) if hunk.group(2) is not None else 1
                continue
            if line.startswith(("--- ", "+++ ")):
                path = line[4:].split("\t")[0].strip()
                # A deletion names its file only on the `---` side, so both sides are read
                # and deduped; `/dev/null` is not a path.
                if path != "/dev/null":
                    path = path[2:] if path[:2] in ("a/", "b/") else path
                    if path not in paths:
                        paths.append(path)
                continue
            continue
        if line.startswith("\\"):
            continue
        if line.startswith("-"):
            old_left -= 1
        elif line.startswith("+"):
            new_left -= 1
        else:
            old_left -= 1
            new_left -= 1
            continue
        changes.append(line.rstrip())
    if not changes:
        raise Unproducible("patch changes no lines")
    if len(changes) > MAX_PATCH_LINES:
        kept = changes[:MAX_PATCH_LINES]
        kept.append(f"... and {len(changes) - MAX_PATCH_LINES} more changed lines")
        changes = kept
    return [*paths, *changes]


def parse_failures(report: Path) -> list[str]:
    """Every failing/erroring testcase id in a JUnit report, in document order.

    A report that is missing, empty or malformed raises: a run whose result could not be
    read must not be rendered as "killed nothing", which is the exact shape of a table
    that lies with a plausible number.
    """
    if not report.is_file():
        raise Unproducible(f"no JUnit report at {report}")
    raw = report.read_bytes()
    if not raw.strip():
        raise Unproducible(f"empty JUnit report at {report}")
    try:
        root = ET.fromstring(_XML_ILLEGAL_CONTROL.sub(b"?", raw))
    except ET.ParseError as exc:
        raise Unproducible(f"malformed JUnit report at {report}: {exc}") from exc
    failures: list[str] = []
    for case in root.iter("testcase"):
        if case.find("failure") is None and case.find("error") is None:
            continue
        classname = case.get("classname", "")
        name = case.get("name", "")
        failures.append(f"{classname}::{name}" if classname else name)
    return failures


def _require_clean(root: Path, report: Path) -> None:
    residue = dirt(root, report)
    if residue:
        raise Unproducible(
            "the working tree is dirty, so a table measured here would describe a state no commit contains:\n" + residue
        )


def _head(root: Path) -> str:
    rev = _run(["git", "rev-parse", "--short", "HEAD"], root)
    if rev.returncode != 0:
        raise Unproducible(f"git rev-parse failed: {rev.stderr.strip()}")
    return rev.stdout.strip()


def measure(root: Path, suite: list[str], report: Path, patch: Path | None, timeout: float | None) -> list[str]:
    """Run the suite once, optionally under a patch, and return the ids that failed.

    The patch is reverted in a ``finally`` and the revert is VERIFIED, because a mutation
    left applied would silently label every later row with the wrong tree.

    The revert runs in a ``finally``; the VERIFICATION runs after it, so it cannot replace a
    failure already on its way out. ``sys.exit`` here exited 1 -- the status reserved for "a
    mutation killed nothing" -- so a caller reading the documented contract would have taken
    a tree left dirty for a finished table, and raising from the ``finally`` hid the
    malformed report or the KeyboardInterrupt that caused the mess in the first place.
    """
    if patch is not None:
        applied = _run(["git", "apply", str(patch.resolve())], root)
        if applied.returncode != 0:
            raise Unproducible(f"{patch} does not apply: {applied.stderr.strip()}")
    try:
        report.unlink(missing_ok=True)
        run = _run(suite, root, timeout)
        if not report.is_file():
            raise Unproducible(
                f"the suite wrote no report at {report} (exit {run.returncode}): "
                f"{(run.stderr or run.stdout).strip()[-400:]}"
            )
        failures = parse_failures(report)
    except BaseException:
        # Something else is already on its way out. Undo the patch anyway, and REPORT rather
        # than raise -- raising here replaces the failure that caused the mess, which is the
        # defect this structure exists to prevent.
        if patch is not None:
            problem = undo(root, report, patch)
            if problem:
                print(f"mutation_table.py: WARNING: {problem}", file=sys.stderr)
        raise
    if patch is not None:
        problem = undo(root, report, patch)
        if problem:
            raise Unproducible(problem)
    return failures


def undo(root: Path, report: Path, patch: Path) -> str:
    """Reverse $patch; return what is still wrong afterwards, or '' when the tree is clean.

    RESIDUE, not just the exit status. A reverse-apply can SUCCEED and still leave the tree
    dirty, because the suite itself changed something -- and then the next row is measured
    under it. Checking only the return code missed exactly that.

    Returning the description rather than raising is what lets the two callers differ: on the
    clean path a problem here is fatal, and on the exception path it can only be reported,
    because raising would replace the exception already propagating. ``sys.exc_info()`` is not
    how to tell those apart -- inside a ``finally`` it reports the exception being HANDLED,
    which for one merely passing through is None, so a ``finally`` that consulted it stayed
    silent in precisely the case it was added for.

    NOTHING in here raises, which is the promise the docstring above makes and did not keep:
    both subprocess calls are guarded, not only the second. ``_run`` raises when the binary is
    missing, so an absent ``git`` at the reverse-apply threw straight through the caller's
    exception path and replaced whatever was already propagating.
    """
    try:
        reverted = _run(["git", "apply", "-R", str(patch.resolve())], root)
        reverse = f"git apply -R exit {reverted.returncode}: {reverted.stderr.strip()}"
        clean = reverted.returncode == 0
    except Unproducible as exc:
        # This call was the one thing in here that could still raise, which made the
        # docstring's promise false exactly when it mattered: on the exception path the
        # caller reaches undo() BEFORE its `raise`, so anything thrown here replaces the
        # failure already on its way out -- a malformed report, or a KeyboardInterrupt.
        reverse = f"the reverse-apply could not run: {exc}"
        clean = False
    try:
        residue = dirt(root, report)
    except Unproducible:  # pragma: no cover - git itself is unavailable
        residue = "(git status unavailable)"
    if clean and not residue:
        return ""
    return (
        f"reverting {patch} did not take, so every later row would be measured under it. "
        f"{reverse}\nremaining:\n{residue or '(none)'}"
    )


def render(head: str, suite: list[str], baseline: int, rows: list[Row]) -> str:
    """The result as DATA, inside one fenced block, for pasting into a body verbatim.

    Not a markdown table. Four review rounds went into escaping one for arbitrary patch and
    test-id bytes, and each round found a character or a corner the last had missed -- `|`,
    then a backtick, then `\r`/`\n`, then the discovery that an HTML ``<code>`` element is
    not a code span and suppresses no markdown at all, then an empty cell whose fence bled
    into its neighbour. Each fix was right about the case in front of it and wrong about its
    own edges, which is a sign the shape was wrong rather than the enumeration incomplete.

    Inside a fenced block nothing is parsed, so there is nothing to escape and no character
    to have missed. The one sequence a fence cannot contain is a longer run of its own
    backticks, and the fence is measured against the content for exactly that -- the same
    rule a code span uses, applied to the one place it still has to be.

    The cost is that a reader gets aligned text instead of a rendered table. The label and
    the measurement still arrive as one string, which is the property #2938 asks for; a
    table was never part of the requirement.
    """
    lines = [
        f"# generated by scripts/agent/mutation_table.py against {head}",
        f"# suite: {' '.join(suite)}",
        f"# baseline: green, {baseline} tests reported",
    ]
    for row in rows:
        lines.append("")
        lines.append(f"mutation: {row.patch.name}")
        lines.extend(f"  {line}" for line in row.label)
        if row.failures:
            lines.append(f"  killed {len(row.failures)}:")
            lines.extend(f"    {f}" for f in row.failures)
        else:
            lines.append("  killed NOTHING -- this code has no failing fixture")
    body = "\n".join(lines)
    fence = "`" * max(3, longest_backtick_run(body) + 1)
    return f"{fence}text\n{body}\n{fence}"


def longest_backtick_run(text: str) -> int:
    """The longest run of backticks in $text, so a fence can be built that clears it."""
    return max((len(m) for m in re.findall(r"`+", text)), default=0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", required=True, help="suite command, run from --root")
    parser.add_argument("--report", required=True, type=Path, help="JUnit path the suite writes")
    parser.add_argument("--root", default=Path.cwd(), type=Path, help="worktree to mutate")
    parser.add_argument("--timeout", type=float, default=1800.0, help="hard cap per suite run, seconds")
    parser.add_argument("patches", nargs="+", type=Path, help="unified diffs, one per row")
    args = parser.parse_args(argv)

    root: Path = args.root.resolve()
    report: Path = args.report if args.report.is_absolute() else root / args.report
    # shlex, not split(): a suite command routinely carries a quoted argument -- PHPUnit
    # --filter patterns do -- and a naive split turns one into several, after which the
    # failure the operator sees is "no JUnit report" rather than "your quoting was dropped".
    suite = shlex.split(args.suite)

    try:
        if not suite:
            raise Unproducible("--suite is empty")
        _require_untracked_report(root, report)
        _require_clean(root, report)
        head = _head(root)
        baseline_failures = measure(root, suite, report, None, args.timeout)
        if baseline_failures:
            raise Unproducible(
                "the baseline is not green, so no row could tell a killed test from an "
                "already-dead one:\n  " + "\n  ".join(baseline_failures)
            )
        baseline_count = len(list(ET.fromstring(report.read_bytes()).iter("testcase")))
        if baseline_count == 0:
            raise Unproducible("the baseline ran no tests; the suite command selects nothing")
        rows = []
        for patch in args.patches:
            try:
                text = patch.read_text(encoding="utf-8")
            except OSError as exc:
                raise Unproducible(f"cannot read {patch}: {exc}") from exc
            rows.append(Row(patch, render_patch(text), measure(root, suite, report, patch, args.timeout)))
    except Unproducible as exc:
        print(f"mutation_table.py: {exc}", file=sys.stderr)
        return 2

    print(render(head, suite, baseline_count, rows))
    unexercised = [r.patch for r in rows if not r.failures]
    if unexercised:
        print(
            "mutation_table.py: these mutations killed nothing, so the code they change has "
            "no failing fixture: " + ", ".join(str(p) for p in unexercised),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
