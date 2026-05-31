---
name: adr-phase
description: >
  Implement an ADR (Architecture Decision Record) — a single phase, or the whole
  ADR end-to-end with the `all` selector. Args:
  <ADR-number> <phase-number | all> [--base <branch>]. Every phase is reviewed
  against its objectives before its handoff is written. Work happens on a clean
  branch cut from the base; each committed phase (code + RESULTS handoff) is a
  transaction, so the run is **resumable** — on restart it resets to the last
  completed phase and continues. When the ADR is complete it offers a PR (default)
  or a rebase onto the base. Use when the user says "implement phase N of ADR-M",
  "run adr phase", "implement all of ADR-N", "finish ADR-N", or invokes
  /adr-phase.
---

You implement ADR phases in this repository — either **one phase** or, with the
`all` selector, **every remaining phase in order**. Work happens **inline in this
session** on a **clean branch cut from the base branch** (never committing in
place on the base), one commit per phase. Each completed phase — its code change
**plus** its `RESULTS/{NN}_Results.txt` handoff, committed — is a **transaction**;
that is what makes the run resumable. **Every** phase is reviewed against its own
objectives (Step 6.4) before its handoff is written.

**Equivalence invariant (load-bearing).** `/adr-phase {NN} all` must produce
**exactly** the same end state — same `adr/{NN}` branch, same per-phase commits in
the same order, same landing — as running the phases one at a time
(`/adr-phase {NN} 1`, `… 2`, … through the last) and choosing the same landing at
the end. Keep every step path-independent: nothing may behave differently merely
because it ran under `all` versus a single invocation. `all` is just a loop over
the single-phase procedure.

## Step 1 — Parse args

Args string: `{{ args }}`

- **Token 1 — ADR number** (required). Bare digits: "1", "01".
- **Token 2 — phase selector** (optional):
  - a **number** → run that single phase.
  - the word **`all`** → run every remaining phase, in order.
  - **omitted** → the first phase with a prompt but no committed handoff.
- **`--base <branch>`** (optional) → use `<branch>` as the base `adr/{NN}` is cut
  from (and the eventual PR/rebase target). If omitted, resolve it in
  Step 3.

## Step 2 — Locate the ADR and list phases

ADR dirs live under `.ADRs/` as `ADR_{NN}_{Name}/` (zero-padded `NN`). Find the
match; if none, stop and tell the user. The **phase prompts** are the
`{NN}_*.txt` files, sorted numerically — their count is the total phase count.

## Step 3 — Get onto the ADR branch `adr/{NN}` (always)

The working branch is always **`adr/{NN}`** (NN = the ADR number) — never commit
onto the base directly. Set it up idempotently:

- **If you are already on `adr/{NN}`** → just resume on it; do **not** create
  another branch, do not re-cut from base.
- **Else if `adr/{NN}` already exists** → `git checkout adr/{NN}`.
- **Else create it from the base** → resolve the **base** (next bullet), require a
  clean tree, `git fetch origin <base>`, then `git checkout -b adr/{NN}
  origin/<base>`.

**Base branch** (needed to cut `adr/{NN}` when it doesn't exist, and as Step 7's
PR/rebase target): `--base` if given; else if exactly one branch contains this
ADR's prompt files use it (`git for-each-ref` + `git ls-tree -r`); else the current
branch if it is a base (`devel`/`main`/release); else default **`devel`**. Ask only
if genuinely unclear. The rule is deterministic, so `all` and one-at-a-time resolve
the same base.

`adr/{NN}` is the **working branch** for the rest of the run. Commits stay
**local** until the ADR is complete (Step 7) — do not push mid-run, so a reset
(Step 4) never needs a force-push.

## Step 4 — Reconcile / resume (commits as transactions)

Bring the working branch to a clean transaction boundary so an interrupted run
resumes correctly:

1. **Completion state.** A phase `M` is **complete** iff `RESULTS/{MM}_Results.txt`
   is **committed** (tracked, unmodified) at HEAD — judged from committed state,
   not the working tree. Let `L` = highest **contiguous** complete phase from 1
   (0 if none).
2. **Detect interrupted state above `L`:** a dirty working tree, and/or commits
   above phase `L`'s handoff commit that do not correspond to a complete phase
   (e.g. a phase `L+1` that committed code but no handoff).
3. **If interrupted, reset to the last completed phase:** target = the commit that
   recorded `RESULTS/{LL}_Results.txt` (or, if `L = 0`, the fork point
   `git merge-base adr/{NN} origin/<base>`). **Safety gate:** review what would be
   discarded (`git log <target>..HEAD --oneline`, `git status`); proceed with
   `git reset --hard <target>` **only** if every discarded commit and uncommitted
   change is recognizably ADR-`NN` phase work (commit tag `(ADR-NN P…)` and/or
   touches only this ADR's files + its phase's code). If anything **unrelated**
   would be lost, **STOP and ask**.
4. **Confirm the baseline is green:** run `python -m pytest` and `ruff check .`
   once. If red, **STOP and report** — a "completed" phase is broken and needs a
   human.
5. Resume point = phase `L+1`.

## Step 5 — Decide which phase(s) to run

- **`all`:** phases `L+1 … total`, in order.
- **explicit phase `P`:** `P ≤ L` → already done (report; offer to redo = reset to
  `P-1` then re-run `P`, only on confirmation); `P = L+1` → run it; `P > L+1` →
  prerequisites missing, **stop** and say so.
- **omitted:** run just phase `L+1`.

If the resume point is past the last phase, the ADR is already fully implemented
— skip to Step 7.

## Step 6 — Run each selected phase

For every phase `M` to run (in `all` mode this is the loop body), in order:

1. **Read** the phase prompt `{ADR_DIR}/{MM}_*.txt`.
2. **Required reading**, in order — including the prior phase's
   `RESULTS/{M-1}_Results.txt` handoff (if that gate is in the prompt and it is
   missing, STOP and report). Then work the ACTION PLAN under its CONSTRAINTS; make
   the edits directly.
3. **Verify (gates).** Run what the prompt lists and what `CLAUDE.md` requires —
   `python -m pytest`, `ruff check .`, `ruff format .`, plus `php -l` / ShellCheck
   for any PHP/shell touched. All must pass.
4. **Review the phase against its objectives — ALWAYS, before the handoff.** This
   is the trust gate; run it for single phases and `all` alike. Read the actual
   `git diff` (do not trust your own narration) and confirm:
   - **Gates green** — pytest / ruff / `php -l` / ShellCheck all clean.
   - **Test coverage created** — the phase added the test cases it should: the new
     or preserved behaviour, plus edge cases, are actually pinned by tests (golden/
     oracle/property tests where the prompt calls for them). A behaviour-preserving
     phase must have tests holding the behaviour; a phase that adds logic must test
     the new paths. "Existing tests still pass" is **not** sufficient.
   - **Objectives met** — every item the phase's ACTION PLAN + EXPECTED RESULT (and
     the relevant `ADR.md` section) promised is actually implemented, not partial.
   - **Contract intact** — the ADR's "semantics that MUST be preserved" still hold.
   - **Scope clean** — no scope creep, nothing bled in from later phases, no
     unrelated edits.

   If any check fails, **fix it within this phase's scope**, then **re-run the
   gates (6.3) and re-review (6.4)**. Only once the review passes do you proceed —
   so the handoff describes the corrected, final state.
5. **Write the handoff** `RESULTS/{MM}_Results.txt` (plain text, per the prompt's
   HANDOFF section): state after this phase, decisions/values chosen, watch-outs,
   verification numbers, go-ahead. It must reflect the post-review reality.
6. **Commit** a single commit using the message from the prompt's COMMIT block,
   including both the code change and the handoff. This closes the transaction for
   phase `M`. **Do not push yet** (Step 7).

**Loop safety:** never run more iterations than there are phases; never re-run a
completed phase except via the explicit `P ≤ L` redo path.

## Step 7 — When the ADR is complete: PR or rebase onto base

Reach this step when the ADR is now **fully implemented** — the phase just
finished (a single run, or the last `all` iteration) was the final phase, or
Step 5 found nothing left to do. This is **identical whether you got here via
`all` or via the single-phase run that completed the last phase** (the
equivalence invariant). For an intermediate single-phase run that did **not**
complete the ADR, stop after Step 6 and report progress — commits stay local on
`adr/{NN}` for the next run; do not land.

When complete, **ask the user** (via AskUserQuestion) how to land it — confirm the
base branch first if it is at all unclear:

- **Create a PR** *(default — and the expected choice for `… all`)*: push the
  branch (`git push -u origin adr/{NN}`) and open one MR/PR against the base —
  `gh pr list --head adr/{NN} --base <base>` then, if none,
  `gh pr create --base <base> --head adr/{NN} --title "ADR-NN: <ADR title>"
  --body-file <tmpfile>` (always `--body-file`, never inline `--body`; seed the
  body from `ADR.md`).
- **Rebase onto the base and push:** `git fetch origin <base>`,
  `git rebase origin/<base>` on `adr/{NN}`, then land the phase commits on top of
  the base (fast-forward the base to the rebased tip and push the base). Use this
  only when the user wants the commits directly on the base with no PR; if the
  rebase hits conflicts, stop and surface them rather than forcing.

## Step 8 — Report back

Summarize:
- The working (feature) branch and the base; whether the run **resumed** (and from
  which phase).
- Per phase run: which ADR/phase, gate results, the **review verdict** (6.4),
  commit hash, and handoff path.
- If the ADR completed: which landing option was chosen and the **PR URL** (or the
  base branch the commits were rebased onto).
- The ADR's Definition of Done from `ADR.md` §7 — especially the **manual smoke /
  live-box checks the maintainer must run** (most ADRs here cannot reach
  **Accepted** from CI alone — no live Unbound); Status stays "Implemented (pending
  smoke test)" until those pass.
- Any blockers or deviations.
