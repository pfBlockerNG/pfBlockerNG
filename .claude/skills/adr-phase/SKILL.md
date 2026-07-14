---
name: adr-phase
description: >
  Implement an ADR (Architecture Decision Record) — a single phase, or the whole
  ADR end-to-end with the `all` selector. Args:
  <ADR-number> <phase-number | all> [--base <branch>]. Runs in a dedicated
  per-ADR git worktree (your main checkout stays free); each phase is executed by
  a fresh sub-agent with a clean context — briefed with the phase prompt,
  CLAUDE.md, and the prior phase's handoff, working in the full worktree. Commits
  AND pushes branch `adr/{NN}-{slug}` after every phase
  (crash-safe), so the run is resumable — on restart it resets to the last
  completed phase and continues. When the ADR is complete it offers a PR (default)
  or a rebase onto the base. Use when the user says "implement phase N of ADR-M",
  "run adr phase", "implement all of ADR-N", "finish ADR-N", or invokes
  /adr-phase.
---

You **orchestrate** the implementation of an ADR. The actual phase work runs in a
**dedicated git worktree (one per ADR)** so the user can keep working in the main
checkout, and **each phase is delegated to a fresh sub-agent with a clean
context** — its brief is that phase's prompt, `CLAUDE.md`, and the previous
phase's handoff, with **no carry-over from this conversation**. The agent
naturally has the **entire worktree** (the full codebase) to read and edit as the
prompt directs; what's kept minimal is the *starting context*, not file access.
The handoff document (`RESULTS/{NN}_Results.txt`) is the **interface between phase
sessions**.

Branch is always **`adr/{NN}-{slug}`**, where `{slug}` is the sanitised ADR-title
slug from CLAUDE.md "Branch naming (ADRs and issues)" — lowercase, emoji/non-ASCII
stripped, `[a-z0-9-]` only, ≤30 chars; source is the ADR `{Name}` (the `ADR.md` H1
if you prefer the prose title). The slug is **deterministic** from the ADR, so every
invocation recomputes the **same** branch name (which is what lets phases reuse it).
After **every** phase the branch is **committed and pushed**, so progress survives a
crash/offline machine. Each completed phase — code change **plus** its handoff,
committed and pushed — is a **transaction**, and that is what makes the run resumable.

**Equivalence invariant (load-bearing).** `/adr-phase {NN} all` must produce
**exactly** the same end state — same worktree, same `adr/{NN}-{slug}` branch, same
per-phase commits in order, same landing — as running the phases one at a time
(`/adr-phase {NN} 1`, `… 2`, …) and choosing the same landing at the end. `all`
is just a loop over the single-phase procedure; nothing may differ because it ran
under `all` versus a single invocation. There is **one worktree per ADR**, reused
across phases whether you call each phase yourself or `all` loops them.

## Step 0 — Sync to the latest remote base FIRST (before parsing or planning)

`git fetch origin` before anything else, **every invocation** — base all work on the
just-fetched `origin/<base>` (default `origin/devel`), never a stale local branch or an
earlier in-session snapshot (CLAUDE.md "Rebase onto the latest base"; the remote advances
out of band). Governs Step 3: cut a fresh `adr/{NN}-{slug}` from `origin/<base>`; when
**reusing/resuming** an existing branch, rebase it onto the freshly-fetched base
(`git -C <path> rebase origin/<base>`; `--force-with-lease` to push) **before** running any
phase.

## Step 1 — Parse args

Args string: `{{ args }}`

- **Token 1 — ADR number** (required). Bare digits: "1", "01".
- **Token 2 — phase selector** (optional): a **number** → that single phase;
  **`all`** → every remaining phase in order; **omitted** → the first phase with a
  prompt but no committed handoff.
- **`--base <branch>`** (optional) → base that `adr/{NN}-{slug}` is cut from and the
  eventual PR/rebase target. If omitted, resolve in Step 3.

## Step 2 — Locate the ADR and list phases

ADR dirs live under `.ADRs/` as `ADR_{NN}_{Name}/` (zero-padded `NN`). Find the
match; if none, stop. The **phase prompts** are the `{NN}_*.txt` files, sorted
numerically — their count is the total phase count.

## Step 3 — Set up the per-ADR worktree on `adr/{NN}-{slug}`

All phase work happens in a dedicated worktree checked out to `adr/{NN}-{slug}`; the main
checkout is never edited by phases. Set it up idempotently:

- **Managed-remote sessions (check FIRST).** Per CLAUDE.md "Managed-remote sessions" (full
  text in workflow-reference, including the `ADR-RESUME:` sentinel + prior-work discovery +
  fast-forward resume mechanics): the canonical `adr/{NN}-{slug}` when the push policy
  allows it — resume is then native. A hard-pinned `claude/*` branch replaces it only when
  minted for THIS item — one branch per work item; reusing a stale-named pinned branch
  requires flagging the name/item mismatch to the user first.
- **Resolve the branch name first.** Compute `{slug}` from the ADR title per CLAUDE.md
  "Branch naming (ADRs and issues)" → the target branch `adr/{NN}-{slug}`. This is
  deterministic, so it matches whatever a prior phase already created.
- **Base branch** (needed only to create `adr/{NN}-{slug}`, and as Step 7's target):
  `--base` if given; else if exactly one branch contains this ADR's prompt files
  use it (`git for-each-ref` + `git ls-tree -r`); else the current branch if it is
  a base (`devel`/`main`/release); else default **`devel`**. Ask only if genuinely
  unclear. Deterministic, so `all` and one-at-a-time resolve the same base.
- **Worktree path:** a fixed, gitignored per-ADR path, e.g.
  `.claude/worktrees/adr-{NN}` (the harness already uses `.claude/worktrees/`; if
  that area is not ignored, use a path outside the main checkout to avoid polluting
  `git status`).
- **Create or reuse** (check `git worktree list` first; match this ADR's branch by the
  `adr/{NN}-*` prefix — and the legacy bare `adr/{NN}` — so a branch cut before the
  slug scheme is still picked up rather than duplicated):
  - An existing worktree for this ADR's branch: reuse per CLAUDE.md "Worktrees" — only one
    you created earlier in THIS run; foreign uncommitted changes ⇒ fall through to a fresh
    `-{epoch}`-suffixed worktree.
  - Else if the branch exists → `git worktree add <path> <branch>`.
  - **On either reuse path, rebase the branch onto the freshly-fetched `origin/<base>` (Step 0)
    before running any phase** (`git -C <path> rebase origin/<base>`; `--force-with-lease` to
    push) — a branch cut earlier in (or before) this session must pick up commits the base
    gained since, or its phases run against an already-fixed base.
  - Else (cutting `adr/{NN}-{slug}` fresh): `git fetch origin <base>`, then **check the
    base for unpushed work** — `git rev-list --count origin/<base>..<base>`. **If
    the local base branch has commits not on the remote, WARN the user and ask
    whether to push them first** before the ADR branch is cut — cutting from
    `origin/<base>` would otherwise omit them. Only after that resolve:
    `sh scripts/agent/work-branch.sh adr {NN} "<ADR Name>" --worktree --base origin/<base>`
    (implements the CLAUDE.md sanitiser + collision suffix; push first if the user
    agreed; if they decline, state explicitly that those local-only base commits
    are excluded from `adr/{NN}-{slug}`).

  This warning fires only when **creating** the worktree/branch; reusing an
  existing `adr/{NN}-{slug}` skips it.
  - **Collision:** if `adr/{NN}-{slug}` is already taken by an **unrelated** branch
    (not this ADR's — e.g. a different title reused the same `{NN}`), append
    `-{epoch}` (epoch seconds) per CLAUDE.md's rule and use that name consistently
    for the rest of the run.

From here, every git/file operation for this ADR uses `<path>` (e.g.
`git -C <path> …`, and absolute paths under `<path>` for edits). Do **not** touch
the main checkout.

## Step 4 — Reconcile / resume (in the worktree)

Bring `adr/{NN}-{slug}` to a clean transaction boundary:

1. `git -C <path> fetch origin` and fast-forward `adr/{NN}-{slug}` to `origin/adr/{NN}-{slug}` if
   behind (a prior run on another machine).
2. **Completion state.** Phase `M` is **complete** iff `RESULTS/{MM}_Results.txt`
   is **committed** at HEAD. `L` = highest **contiguous** complete phase from 1
   (0 if none).
3. **Reset interrupted work above `L`** (a dirty tree, or a commit for phase `L+1`
   without its handoff): target = the commit recording `RESULTS/{LL}_Results.txt`
   (or `git -C <path> merge-base adr/{NN}-{slug} origin/<base>` if `L = 0`). **Safety
   gate:** only `git -C <path> reset --hard <target>` if everything discarded is
   recognizably ADR-`NN` phase work; else **STOP and ask**. This is safe against
   force-pushes because only completed phases are ever pushed — interrupted work is
   never on the remote.
4. **Confirm baseline green:** run the **canonical gates** (CLAUDE.md "Canonical gates" table)
   for the ADR's languages in `<path>`. If red, **STOP and report** — a completed phase is
   broken.
5. Resume point = phase `L+1`.

## Step 5 — Decide which phase(s) to run

- **`all`:** phases `L+1 … total`, in order.
- **explicit `P`:** `P ≤ L` → done (offer to redo = reset to `P-1` then re-run
  `P`, only on confirmation; note this rewrites already-pushed history and needs a
  force-push); `P = L+1` → run it; `P > L+1` → prerequisites missing, **stop**.
- **omitted:** run just phase `L+1`.

If the resume point is past the last phase, the ADR is already implemented — skip
to Step 7.

## Step 6 — Run each phase via the `phase-step` workflow, then validate and gate

For every phase `M` to run (the loop body in `all`):

**Default route — the `phase-step` workflow (hand-spawning the stages while it is
available requires a recorded reason in your report — PR #937 bypassed it silently and
produced no fixed-field gate record, #943).** Run the whole phase as ONE call, passing
**pointers, not a composed brief** (issue #1089 — the brief is written by the workflow's
fresh higher-model Brief stage, so your own context stays flat across a long `all` run):
`Workflow({name: 'phase-step', args: {worktree: '<path>', briefSpec: {adrDir: '<ADR_DIR
relative to the worktree>', phase: M, notes: '<session constraints the disk cannot show —
base override, user instructions; omit if none>'}, ponytailLevel: <active level or
null>}})` — pass no extra parameter: the call is already asynchronous, and
`run_in_background` is not a Workflow parameter (it fails validation). It is harness-tracked —
end the turn and answer its completion notification; never arm a sleep/poll to await it.
The Brief stage reads `ADR.md`, the phase prompt, and the prior `RESULTS/`
records + carry_forward chain just-in-time, runs the enumeration greps itself, and
evaluates the previous phase's landed diff against the ADR's invariants (the broadened
drift check); the workflow pipes the schema-forced brief through the Sonnet implementer
and a fresh Sonnet verifier (never the brief author's model) and returns `{briefRecord, handoff, gateRecord}` — all
schema-forced (field contracts in `.claude/workflows/phase-step.js`).

Your duties on return:

1. **Transaction**: `RESULTS/{MM}_Results.txt` committed and **pushed**
   (`git -C <path> log`/`status`, remote ref updated) — the crash-safe boundary.
2. **Validate the briefRecord non-vacuously**: re-run at least one cited coverage-matrix
   `source` and confirm it yields the row; judge any `drift_flags`.
3. **Validate the handoff + gateRecord** per workflow-reference "Validating workflow
   records" (fields non-empty, evidence executed + pasted, spot-read the load-bearing diff
   hunks — never a third run of the gates or red proof the verifier just executed). Reject
   a record with any failed or missing item.
4. **Write the gate record** `RESULTS/{MM}_Gate.txt` from the gateRecord (fixed fields:
   commands + results, red/green re-execution evidence, per-item diff verdicts, matrix
   confirmation, SKIPPED list) and commit + push it as its own small commit
   (`docs: ADR-NN phase M gate record`). On resume, a phase with a Results file but no
   Gate record gets its gate run retroactively before the next phase starts.
5. Keep ALL judgment: HALT/continue/redo and the Step 7 landing.

The legacy `brief:` argument (you compose the brief yourself) remains supported but is not
the default for ADR phases. **Workflow tool unavailable** → play the Brief, Implement, and
Verify stages from `.claude/workflows/phase-step.js` yourself with plain Agents (its
prompts + schemas ARE the contract; Brief and Verify on the higher model, implementer
`model: sonnet`, effort `xhigh` stated explicitly on every spawn), then run the duties
above — the contract is identical; the workflow only packages it.

A BLOCKED briefRecord or handoff, a FAIL gate record, or any missing fixed field →
**HALT and report**; do not start `M+1`. (You verify the transaction and the content against
the plan; you do not re-implement it.) When a phase's executed reality contradicts the ADR's
own text (a falsified claim, an overturned decision — the ESCALATE contract's trigger), the
gate also reconciles the ADR: correct the text now, or post-merge via a §8 "Post-merge
amendments" entry (workflow-reference "ADR amendments after merge"), before any later phase
plans against the stale claim.

**Loop safety:** never run more iterations than there are phases; never re-run a
completed phase except via the explicit redo path.

## Step 7 — When the ADR is complete: PR or rebase onto base

Reach this when the ADR is now **fully implemented** — the phase just finished (a
single run, or the last `all` iteration) was the final phase, or Step 5 found
nothing left. Identical whether reached via `all` or the single-phase run that
completed the last phase. For an intermediate single-phase run that did **not**
complete the ADR, stop after Step 6 and report — the branch is already pushed.

The branch `adr/{NN}-{slug}` is already on the remote (pushed each phase). **Ask the
user** (AskUserQuestion) how to land it — confirm the base if unclear:

- **Create a PR** *(default; expected for `… all`)*: `gh pr list --head adr/{NN}-{slug}
  --base <base>`; if none, `gh pr create --base <base> --head adr/{NN}-{slug}
  --title "ADR-NN: <ADR title>" --body-file <tmpfile>` (always `--body-file`; seed
  from `ADR.md`).
- **Rebase the branch onto base and push the branch (no merge):** `git -C <path>
  fetch origin <base>`, `git -C <path> rebase origin/<base>`, then push the rebased
  **`adr/{NN}-{slug}`** branch — `git -C <path> push --force-with-lease`. This updates
  the agent's own branch only; it **never** pushes to `<base>`. Leaves a clean, current
  branch ready to land (via `/pr-merge-flow` or the user's merge). On conflicts, stop
  and surface them — never force blindly.

After landing, offer to remove the worktree (`git worktree remove <path>`) once the
PR is merged / commits have landed; otherwise leave it for follow-up.

## Step 8 — Report back

Summarize:

- The worktree path and branch `adr/{NN}-{slug}`; that the main checkout was untouched;
  whether the run **resumed** (and from which phase).
- Per phase: which ADR/phase, the sub-agent's gate results and **review verdict**,
  your orchestrator-gate result, commit hash, and confirmation it was pushed.
- If the ADR completed: the landing choice and the **PR URL** (or the base the
  commits were rebased onto), and the worktree-cleanup status.
- The ADR's Definition of Done from `ADR.md` §7 against CLAUDE.md "ADR acceptance": the ADR
  flips to **Accepted** on green automated coverage alone (smoke/UI on the CE+Plus fan-out) —
  report which §7 items the automated runs prove, and list any **documented out-of-CI
  limitation** (HA/CARP, real HAProxy reload, load profiles, true visual correctness) left for
  the maintainer. Status stays "Implemented (pending smoke test)" only until the fan-out is
  green, not pending a manual sign-off.
- Any blockers or deviations.

**Trigger sweep (mandatory).** The task just reached a terminal state: run the
cancel-on-resolution sweep — CLAUDE.md "No orphaned waits" / workflow-reference "Bounded
waits" §3 (kill every trigger class, then `TaskList` once for stale waits you own) — and
report it in one line (what was stopped / "nothing pending").
