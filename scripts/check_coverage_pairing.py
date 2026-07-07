#!/usr/bin/env python3
"""Gate a PR's diff for src<->tests and www<->UI-test coverage pairing.

PROBLEM
-------
CLAUDE.md's test-coverage mandate (#2: "every change ships WITH its tests"; #4:
"front-end changes REQUIRE front-end tests") is currently enforced only by human/
review discipline. This script is the mechanical backstop, wired as a PR-only CI
job in ``.github/workflows/test.yml`` (see the ``coverage-pairing`` job) — never
in ``.githooks/pre-commit``, because pre-commit only ever sees ONE commit's
staged files, not the whole PR's diff against its base; the pairing question
("did this PR's *src* change ship *any* test?") is only answerable with the full
PR diff, which is what the CI job computes via ``git diff --name-only
origin/<base>...HEAD`` and pipes into this script over stdin.

THE TWO RULES
-------------
1. Any changed ``src/**`` path (rule: "src<->tests") requires at least one
   changed ``tests/**`` path somewhere in the diff.
2. Any changed ``src/usr/local/www/**`` path (rule: "www<->ui") additionally
   requires at least one changed ``tests/smoke/ui/**`` path (Tier-A UI
   coverage, CLAUDE.md test mandate #4) — a non-UI test under ``tests/`` alone
   does NOT satisfy this second, stricter rule.

DOCS ARE NEUTRAL
----------------
A changed path whose basename ends in ``.md`` (any case) OR that starts with
``docs/`` never counts toward EITHER side of either rule — it neither trips a
requirement (a docs-only diff must not fire) nor satisfies one (a `.md` explaining
a change is not a test). This is checked first, so a `.md` file physically living
under ``src/`` is still neutral, not "src code with no test".

ESCAPE HATCH
------------
The CI job downgrades a violation to a warning (exit 0, printed to
``$GITHUB_STEP_SUMMARY``) instead of failing the PR when the PR carries the
``no-test-needed`` label — the ``--warn-only`` CLI flag mirrors that from this
script's side; the label itself is applied by a human, not this script.

This is dev/CI-only tooling under ``scripts/`` (mirrors ``check_url_encoding.py``
/ ``check_appliance_python.py``): it reasons over path STRINGS only, never reads
file contents, and is intentionally NOT part of ``.githooks/pre-commit``.
"""

from __future__ import annotations

import sys

_FIX_HINT = "add the paired test, or apply the `no-test-needed` label if none is warranted"


def _is_docs(path: str) -> bool:
    """True if ``path`` is documentation and therefore neutral to both rules."""
    return path.lower().endswith(".md") or path == "docs" or path.startswith("docs/")


def _is_src(path: str) -> bool:
    """True if ``path`` is production ``src/**`` code (docs under src excluded)."""
    return not _is_docs(path) and (path == "src" or path.startswith("src/"))


def _is_www(path: str) -> bool:
    """True if ``path`` is ``src/usr/local/www/**`` (not e.g. ``www-legacy/``)."""
    return not _is_docs(path) and path.startswith("src/usr/local/www/")


def _is_test(path: str) -> bool:
    """True if ``path`` is under ``tests/**`` (a sibling ``othertests/`` is not)."""
    return path == "tests" or path.startswith("tests/")


def _is_ui_test(path: str) -> bool:
    """True if ``path`` is under ``tests/smoke/ui/**`` (Tier-A UI coverage)."""
    return path == "tests/smoke/ui" or path.startswith("tests/smoke/ui/")


def evaluate(changed: list[str]) -> list[str]:
    """Classify ``changed`` paths and return human-readable violation messages.

    An empty return means the diff passes both pairing rules. Both rules are
    independent and can both fire (up to 2 messages).
    """
    has_src = any(_is_src(p) for p in changed)
    has_www = any(_is_www(p) for p in changed)
    has_test = any(_is_test(p) for p in changed)
    has_ui_test = any(_is_ui_test(p) for p in changed)

    violations: list[str] = []
    if has_src and not has_test:
        violations.append(
            "src<->tests coverage pairing violated: this PR changes `src/**` but ships no "
            "`tests/**` change (CLAUDE.md test mandate #2: 'every change ships WITH its "
            f"tests'). {_FIX_HINT}."
        )
    if has_www and not has_ui_test:
        violations.append(
            "www<->ui-tests coverage pairing violated: this PR changes `src/usr/local/www/**` "
            "but ships no `tests/smoke/ui/**` change (Tier-A `ui_render` coverage, CLAUDE.md "
            f"test mandate #4: front-end changes require front-end tests). {_FIX_HINT}."
        )
    return violations


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Positional args are changed paths (used by tests); with none, changed paths
    are read newline-separated from stdin — how the CI job pipes
    ``git diff --name-only`` output in. Both entry points are normalized the
    same way (surrounding whitespace stripped, blank entries dropped), so a
    padded positional arg and a trailing-newline stdin line classify identically.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    warn_only = "--warn-only" in args
    paths = [a for a in args if a != "--warn-only"]

    if not paths:
        paths = list(sys.stdin)
    paths = [p.strip() for p in paths if p.strip()]

    violations = evaluate(paths)

    if not violations:
        print("Coverage pairing OK: no src<->tests or www<->ui-tests violation.")
        return 0

    if warn_only:
        print("WARNING (no-test-needed label): coverage pairing would otherwise FAIL this PR:")
    else:
        print("Coverage pairing FAILED:")
    for msg in violations:
        print(f"  - {msg}")

    if warn_only:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
