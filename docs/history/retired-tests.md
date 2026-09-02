# Retired tests — the tombstone ledger

`scripts/check_guard_erosion.py` blocks retiring a test that has neither a
successor nor an entry here; the rule lives in `.agents/policy/testing.md`.

Prefer the successor: add the assertion that takes the invariant over and
comment it `successor: <retired name>`. This ledger is for the other case — the
invariant itself is gone, or is deliberately no longer guarded, and that
decision is what needs recording. Stage the row in the same commit as the
deletion; the pre-commit run judges one commit's index.

One row per retired test, named as its declaration was: a Python `def test_*`,
a PHPUnit `function test*`, a shellspec `It`/`Example` description, or a
`node --test` `test`/`it` description.

| Date | Retired test | Reason |
| --- | --- | --- |
| 2026-08-18 | `test_container_jobs_pass_init` | Container jobs were deleted along with the `ci-runner` images (issue #2513, commit `20d65c05d`), so the invariant it pinned — every workflow container job passes `--init` — has no subject left to guard. Retiring it uncovered the guard-erosion gap this ledger closes (issue #2396, issue #2414). |
