---
name: delegate
description: >
  Run ONE ad-hoc coding task through the full CLAUDE.md delegation contract —
  the same brief → Sonnet 5 implementer → mechanical gate discipline /adr-phase
  and /gh-issue enforce, for work that belongs to neither. Args: <task
  description> [--base <branch>]. Use when the user says "delegate this", "have
  sonnet build X", "do this via the contract", or invokes /delegate. Not for
  ADR phases (/adr-phase) or issue fixes (/gh-issue --fix) — route those to
  their skills.
---

You orchestrate one ad-hoc delegated task under **CLAUDE.md "The delegation contract"**. The
contract is the law here; this skill only sequences it. Ad-hoc work is exactly where the
contract used to be skipped — that is why this skill exists.

Args: `{{ args }}`

## Step 0 — Route and size

- `git fetch origin`; base = `--base` if given, else `devel`. Ground all reading on the
  fresh `origin/<base>`.
- If the task belongs to a GitHub issue or an ADR, stop and route to `/gh-issue N --fix` or
  `/adr-phase N` instead.
- If the task is **small and doable in one step** (CLAUDE.md: the higher model implements
  those directly — docs/config/skills always), do it yourself in a worktree with the same
  verification discipline, and say so. Delegation is for non-trivial `src/`/`tests/`/CI work.

## Step 1 — Investigate, then write THE BRIEF

Read the actual code first (Working principles — never brief from memory). Then produce the
brief with **all seven mandatory sections** from CLAUDE.md "THE BRIEF":

1. Objective. 2. Required reading (`file:line`). 3. **Coverage matrix** — enumerate sibling
axes/callers/branches **from grep or the version-matrix file**, each row → test or explicit
deferral; "all X" without the list is invalid. 4. **Hostile-input rows** for any
parser/regex/guard work. 5. Constraints + do-NOT-touch + the never-weaken rule. 6.
Verification — the canonical gates + per-item acceptance checks ("WHEN `<command>` THEN
`<observable>`"). 7. The ESCALATE contract.

Also in the brief: worktree-only work, the fixed HANDOFF fields (CLAUDE.md "THE HANDOFF"),
and commit style.

A weak brief is YOUR bug. If a load-bearing fact is unverified, probe it now or mark it
ASSUMED with a verification step in the brief.

## Step 2 — Worktree and branch

`git worktree add -b <branch> .claude/worktrees/<name> origin/<base>`. Branch: reuse the
work-item convention when one applies; otherwise `task/{slug}` with the CLAUDE.md "Branch
naming" sanitiser. All work happens in the worktree; never the main checkout.

## Step 3 — Spawn the implementer

One Agent: `subagent_type: general-purpose`, **`model: sonnet`**, **effort `xhigh`** stated
explicitly. The brief is Step 1's text, self-contained — no carry-over from this
conversation. The implementer works with Read/Edit/Write/Bash and may spawn subagents for a
subtask that genuinely splits (CLAUDE.md "Plan with a higher model" — nested work is verified
by the spawner and its defects are the spawner's at the gate); it runs the gates, does not
proceed red, self-reviews the diff against the objective, commits (`<scope>: <imperative
summary>`), and returns the handoff with every fixed field.

## Step 4 — THE GATE (mechanical — CLAUDE.md "THE GATE", all items)

Terse prose, full checks; a skipped item is recorded SKIPPED with the reason:

1. Handoff carries every fixed field — missing/empty field rejects it.
2. Re-run the canonical gates yourself: `scripts/agent/run-gates.sh --worktree <path> --diff <base>`
   (plus any cross-language consumers the runner cannot infer).
3. Re-execute the red proof yourself for behaviour changes
   (`sh scripts/agent/verify-red-proof.sh --worktree <path> --test-cmd '<test>' --src ...
   --hash <test>=<red-hash>` — revert → named test FAILS;
   `git -C <path> checkout HEAD -- .` → PASSES). Record both results; verify the freeze
   (`git hash-object` of the committed reproduction test == the handoff's red-time hash).
4. Read the FULL diff (`git show`, never `--stat` alone); tick every plan item and matrix
   row.
5. Test honesty: vacuity check on negative assertions; no impossible monkeypatched faults;
   `www/` touched ⇒ Tier-A coverage present.
6. Conventions: sibling-named symbols; stale comments/docs reconciled.
7. Emit the gate record as a fixed-field block in your report.

Gate fails or handoff BLOCKED → HALT, report, keep the worktree for follow-up. One retry with
a corrected brief is fine; more means the plan is wrong — stop and rethink.

## Step 5 — Land and report

- Code (`src/`/`tests/`/CI) → rebase onto fresh `origin/<base>`, push, PR, **`/pr-merge-flow`**.
- Dev-only classes (docs/CLAUDE.md/ADR text/skills) → rebase + push directly to `devel`.
- Report: brief summary, handoff verdict, the gate record, landing outcome, worktree cleanup.
