# Retired tests — the tombstone ledger

A test that asserts a named invariant is the only mechanical memory of it.
Retiring or renaming one therefore needs either a successor assertion or an
entry here, and `scripts/check_guard_erosion.py` blocks a retirement that has
neither (pre-commit and CI, judging only the diff).

Prefer the successor: add the assertion that takes the invariant over and mark
it `successor: <retired name>` on a line of the new test. This ledger is for the
other case — the invariant itself is gone, or it is deliberately no longer
guarded, and that decision is what needs recording.

One row per retired test. The name is the declaration's own name: a Python
`def test_*`, a PHPUnit `function test*`, or a shellspec `It`/`Example`
description. The reason says why nothing replaced it, and names the commit or
issue that removed the subject where one exists.

| Date | Retired test | Reason |
| --- | --- | --- |
| 2026-08-18 | `test_container_jobs_pass_init` | Container jobs were deleted along with the `ci-runner` images (issue #2513, commit `20d65c05d`), so the invariant it pinned — every workflow container job passes `--init` — has no subject left to guard. Retiring it uncovered the guard-erosion gap this ledger closes (issue #2396, issue #2414). |
