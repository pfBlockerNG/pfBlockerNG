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
prefix, so an id here reads the same as an id there. Both PHPUnit (``--log-junit``) and
pytest (``--junitxml``) write this report, which is why the suite command is asked to
produce one rather than having its human-readable output parsed per runner.

EXIT STATUS
-----------
* ``0`` -- every patch applied, ran, and reverted; the table is on stdout.
* ``1`` -- a mutation killed nothing. That is the finding the table exists to surface
  (an unexercised branch), so it is reported in the table AND in the status.
* ``2`` -- the table could not be produced: dirty tree, red or empty baseline, a patch
  that does not apply, a missing or malformed report, or a revert that did not take. A
  table that is wrong is worse than no table, so none of these fall through to 0.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

# Keep a rendered patch from swamping the row it labels. A mutation big enough to exceed
# this is one whose name was never going to be trustworthy anyway -- the row says so
# rather than quietly truncating to something that reads complete.
MAX_PATCH_LINES = 12


@dataclass(frozen=True)
class Row:
    """One mutation and what it killed, as one value so they cannot drift apart."""

    patch: Path
    label: str
    failures: list[str]


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)


def dirt(root: Path, report: Path) -> str:
    """``git status --porcelain`` for $root, minus the JUnit report the suite writes.

    The suite is normally told to write its report inside the tree it is run in, so the
    report is itself tree dirt -- and a run that produced one would then be indistinguishable
    from a run that left a mutation applied. Found by pointing this script at its first real
    subject: every row after the first was refused because PHPUnit had written `junit.xml`
    next to the code it graded.
    """
    status = _run(["git", "status", "--porcelain"], root)
    if status.returncode != 0:
        raise ValueError(f"git status failed: {status.stderr.strip()}")
    try:
        ignore = str(report.resolve().relative_to(root))
    except ValueError:
        ignore = ""
    kept = [ln for ln in status.stdout.splitlines() if ln.strip() and ln[3:].strip('"') != ignore]
    return "\n".join(kept)


def render_patch(text: str) -> str:
    """The patch's own changed lines, which is what labels the row.

    Context, hunk headers and the ``diff --git``/index preamble are dropped: they are
    the same for every mutation of one file and would bury the one or two lines that
    actually distinguish this row from its neighbours. The touched paths are kept, so a
    row still says WHERE as well as WHAT.
    """
    paths: list[str] = []
    changes: list[str] = []
    for line in text.splitlines():
        if line.startswith("+++ ") and not line.startswith("+++ /dev/null"):
            path = line[4:].strip()
            path = path[2:] if path.startswith("b/") else path
            if path not in paths:
                paths.append(path)
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            changes.append(line.rstrip())
    if not changes:
        raise ValueError("patch changes no lines")
    if len(changes) > MAX_PATCH_LINES:
        kept = changes[:MAX_PATCH_LINES]
        kept.append(f"... and {len(changes) - MAX_PATCH_LINES} more changed lines")
        changes = kept
    return "<br>".join(f"`{line}`" for line in [*paths, *changes])


def parse_failures(report: Path) -> list[str]:
    """Every failing/erroring testcase id in a JUnit report, in document order.

    A report that is missing, empty or malformed raises: a run whose result could not be
    read must not be rendered as "killed nothing", which is the exact shape of a table
    that lies with a plausible number.
    """
    if not report.is_file():
        raise ValueError(f"no JUnit report at {report}")
    raw = report.read_bytes()
    if not raw.strip():
        raise ValueError(f"empty JUnit report at {report}")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"malformed JUnit report at {report}: {exc}") from exc
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
        raise ValueError(
            "the working tree is dirty, so a table measured here would describe a state no commit contains:\n" + residue
        )


def _head(root: Path) -> str:
    rev = _run(["git", "rev-parse", "--short", "HEAD"], root)
    if rev.returncode != 0:
        raise ValueError(f"git rev-parse failed: {rev.stderr.strip()}")
    return rev.stdout.strip()


def measure(root: Path, suite: list[str], report: Path, patch: Path | None) -> list[str]:
    """Run the suite once, optionally under a patch, and return the ids that failed.

    The patch is reverted in a ``finally`` and the revert is VERIFIED, because a mutation
    left applied would silently label every later row with the wrong tree.
    """
    if patch is not None:
        applied = _run(["git", "apply", str(patch.resolve())], root)
        if applied.returncode != 0:
            raise ValueError(f"{patch} does not apply: {applied.stderr.strip()}")
    try:
        report.unlink(missing_ok=True)
        _run(suite, root)
        return parse_failures(report)
    finally:
        if patch is not None:
            _run(["git", "apply", "-R", str(patch.resolve())], root)
            residue = dirt(root, report)
            if residue:
                sys.exit(
                    f"mutation_table.py: reverting {patch} left the tree dirty; every later "
                    f"row would be measured under it:\n{residue}"
                )


def render(head: str, suite: list[str], baseline: int, rows: list[Row]) -> str:
    """The table, in the form that goes into a PR body verbatim."""
    out = [
        f"<!-- generated by scripts/agent/mutation_table.py against {head} -->",
        f"Suite `{' '.join(suite)}` at `{head}`, baseline green ({baseline} tests reported).",
        "",
        "| mutation (the patch that was applied) | killed | failing tests |",
        "| --- | --- | --- |",
    ]
    for row in rows:
        killed = str(len(row.failures)) if row.failures else "**0 — nothing**"
        tests = "<br>".join(f"`{f}`" for f in row.failures) or "_no test failed_"
        out.append(f"| {row.label} | {killed} | {tests} |")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", required=True, help="suite command, run from --root")
    parser.add_argument("--report", required=True, type=Path, help="JUnit path the suite writes")
    parser.add_argument("--root", default=Path.cwd(), type=Path, help="worktree to mutate")
    parser.add_argument("patches", nargs="+", type=Path, help="unified diffs, one per row")
    args = parser.parse_args(argv)

    root: Path = args.root.resolve()
    report: Path = args.report if args.report.is_absolute() else root / args.report
    suite = args.suite.split()

    try:
        _require_clean(root, report)
        head = _head(root)
        baseline_failures = measure(root, suite, report, None)
        if baseline_failures:
            raise ValueError(
                "the baseline is not green, so no row could tell a killed test from an "
                "already-dead one:\n  " + "\n  ".join(baseline_failures)
            )
        baseline_count = len(list(ET.fromstring(report.read_bytes()).iter("testcase")))
        if baseline_count == 0:
            raise ValueError("the baseline ran no tests; the suite command selects nothing")
        rows = [
            Row(patch, render_patch(patch.read_text(encoding="utf-8")), measure(root, suite, report, patch))
            for patch in args.patches
        ]
    except ValueError as exc:
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
