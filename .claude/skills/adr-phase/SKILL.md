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

Before anything else — **every invocation, including when you already implemented another ADR or
issue earlier in this session** — `git fetch origin` and base all work on the just-fetched
`origin/<base>` (default `origin/devel`). The remote advances out of band (parallel agents land
commits), so re-fetch and re-base each time; never plan or branch off a stale local `devel` or an
in-session snapshot left over from a previous item. A stale base re-runs bugs the base has already
fixed and sends you chasing a phantom regression (CLAUDE.md "Rebase onto the latest base BEFORE
opening a PR"). This governs Step 3: cut a fresh `adr/{NN}-{slug}` from `origin/<base>`, and when
**reusing/resuming** an existing branch, rebase it onto the freshly-fetched `origin/<base>`
(`git -C <path> rebase origin/<base>`; `--force-with-lease` to push) **before** running any phase.

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

- **Managed-remote sessions (check FIRST).** Per CLAUDE.md "Managed-remote sessions: branch
  policy + cross-session resume": if the environment permits pushing to the canonical
  `adr/{NN}-{slug}` branch (the **preferred** config), use it as normal — resume is native, no
  special-casing. Only if push is **hard-pinned** to a minted `claude/<slug>-<rand>` branch does
  the pinned branch replace `adr/{NN}-{slug}`: then work in the primary checkout (not a separate
  worktree), `git fetch origin` and **discover** any prior branch carrying this ADR's
  `RESULTS/{NN}_*` handoffs + an `ADR-RESUME:` sentinel; if exactly one unambiguous candidate
  exists, **fast-forward its commits onto the current pinned branch** and continue at its
  `next-phase` (no prompt). Ask only on genuine ambiguity. Record/carry the `ADR-RESUME` sentinel
  in the handoff. **But if the pinned branch was minted/named for a different item** (its name
  references another ADR/issue, e.g. `claude/gh-issue-7-…` while you start ADR-12), do **not**
  overload it: cut a **new** branch named for **this** ADR and push there if the policy allows;
  only when pushes are hard-pinned to that one stale branch may you reuse it, and then **flag the
  name/item mismatch to the user first** (CLAUDE.md "One branch per work item").
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
  - If a worktree for this ADR's branch already exists → reuse it.
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
    `git worktree add <path> -b adr/{NN}-{slug} origin/<base>` (push first if the user
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
4. **Confirm baseline green:** run `python -m pytest` and `ruff check .` in
   `<path>`. If red, **STOP and report** — a completed phase is broken.
5. Resume point = phase `L+1`.

## Step 5 — Decide which phase(s) to run

- **`all`:** phases `L+1 … total`, in order.
- **explicit `P`:** `P ≤ L` → done (offer to redo = reset to `P-1` then re-run
  `P`, only on confirmation; note this rewrites already-pushed history and needs a
  force-push); `P = L+1` → run it; `P > L+1` → prerequisites missing, **stop**.
- **omitted:** run just phase `L+1`.

If the resume point is past the last phase, the ADR is already implemented — skip
to Step 7.

## Step 6 — Run each phase in a fresh sub-agent, then gate

For every phase `M` to run (the loop body in `all`):

**6a. Delegate to a clean sub-agent.** Spawn an Agent (`subagent_type:
general-purpose`, **`model: sonnet`**) — **without** `isolation: "worktree"`, since
the worktree already exists. Per CLAUDE.md "Plan with a higher model, implement with
Sonnet", **you are the higher-model planner/gater and the implementer runs on Sonnet**;
your brief must be self-contained, accurate, and well-referenced (the cheaper implementer
is only safe because you gate every step). Give it a **self-contained** brief — no
carry-over from this conversation, though it has the full worktree (the whole codebase) to
read and edit:

- The **full text** of the phase prompt `{ADR_DIR}/{MM}_*.txt`.
- "Work **entirely inside** the worktree at `<path>` — all edits and all git
  commands there (`git -C <path> …`). Do not touch the main checkout."
- "Follow the prompt exactly. Do its REQUIRED READING, including `CLAUDE.md` and
  the prior handoff `RESULTS/{M-1}_Results.txt` (if that gate is in the prompt and
  the file is missing, STOP and report). Implement the ACTION PLAN under its
  CONSTRAINTS."
- "Run the verification gates (`python -m pytest`, `ruff check .`,
  `ruff format .`, plus `php -l` / ShellCheck for any PHP/shell). Do not proceed
  red."
- "**Review your own work against the phase objectives BEFORE writing the
  handoff:** read your actual `git diff`; confirm the phase added the test cases it
  should (new/preserved behaviour + edge cases, not just 'existing tests pass'),
  every ACTION-PLAN / EXPECTED-RESULT objective is met, the ADR's preserved-
  semantics contract holds, and scope is clean. Fix and re-verify if anything is
  off."
- "Then write `RESULTS/{MM}_Results.txt`, make a **single commit** (code + handoff)
  with the COMMIT-block message, and **push**: `git -C <path> push -u origin
  adr/{NN}-{slug}`."
- "Report back: gate results, commit hash, push status, handoff path, and any
  deviation or STOP."

**6b. Orchestrator gate (independent; keep it light to stay context-lean).** When
the agent returns, in `<path>`: confirm `RESULTS/{MM}_Results.txt` is **committed
and pushed** (`git -C <path> log`, `git -C <path> status`, remote ref updated),
re-run `python -m pytest` + `ruff check .` once to independently confirm green, and
sanity-check the phase's EXPECTED RESULT against `git -C <path> show --stat`. If the
agent reported a STOP/failure, the handoff is missing, or a gate fails → **HALT and
report**; do not start `M+1`. (You verify the transaction; you do not re-implement
it.)

**Loop safety:** never run more iterations than there are phases; never re-run a
completed phase except via the explicit redo path.

## Step 7 — When the ADR is complete: PR or rebase onto base

Reach this when the ADR is now **fully implemented** — the phase just finished (a
single run, or the last `all` iteration) was the final phase, or Step 5 found
nothing left. Identical whether reached via `all` or the single-phase run that
completed the last phase. For an intermediate single-phase run that did **not**
complete the ADR, stop after Step 6b and report — the branch is already pushed.

The branch `adr/{NN}-{slug}` is already on the remote (pushed each phase). **Ask the
user** (AskUserQuestion) how to land it — confirm the base if unclear:

- **Create a PR** *(default; expected for `… all`)*: `gh pr list --head adr/{NN}-{slug}
  --base <base>`; if none, `gh pr create --base <base> --head adr/{NN}-{slug}
  --title "ADR-NN: <ADR title>" --body-file <tmpfile>` (always `--body-file`; seed
  from `ADR.md`).
- **Rebase onto base and push:** `git -C <path> fetch origin <base>`,
  `git -C <path> rebase origin/<base>`, then land the commits on top of the base
  (fast-forward base to the rebased tip and push). On conflicts, stop and surface
  them — never force blindly.

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
- The ADR's Definition of Done from `ADR.md` §7 — especially the **manual smoke /
  live-box checks the maintainer must run** (no live Unbound in CI); Status stays
  "Implemented (pending smoke test)" until those pass.
- Any blockers or deviations.
