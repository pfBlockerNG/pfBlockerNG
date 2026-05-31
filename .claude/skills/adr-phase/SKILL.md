---
name: adr-phase
description: >
  Implement an ADR (Architecture Decision Record) — a single phase, or the whole
  ADR end-to-end with the `all` selector. Args:
  <ADR-number> <phase-number | all> [--base <branch>]. Runs in a dedicated
  per-ADR git worktree (your main checkout stays free); each phase is executed by
  a fresh sub-agent with a clean context — briefed with the phase prompt,
  CLAUDE.md, and the prior phase's handoff, working in the full worktree. Commits
  AND pushes branch `adr/NN` after every phase
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

Branch is always **`adr/{NN}`**. After **every** phase the branch is **committed
and pushed**, so progress survives a crash/offline machine. Each completed phase —
code change **plus** its handoff, committed and pushed — is a **transaction**, and
that is what makes the run resumable.

**Equivalence invariant (load-bearing).** `/adr-phase {NN} all` must produce
**exactly** the same end state — same worktree, same `adr/{NN}` branch, same
per-phase commits in order, same landing — as running the phases one at a time
(`/adr-phase {NN} 1`, `… 2`, …) and choosing the same landing at the end. `all`
is just a loop over the single-phase procedure; nothing may differ because it ran
under `all` versus a single invocation. There is **one worktree per ADR**, reused
across phases whether you call each phase yourself or `all` loops them.

## Step 1 — Parse args

Args string: `{{ args }}`

- **Token 1 — ADR number** (required). Bare digits: "1", "01".
- **Token 2 — phase selector** (optional): a **number** → that single phase;
  **`all`** → every remaining phase in order; **omitted** → the first phase with a
  prompt but no committed handoff.
- **`--base <branch>`** (optional) → base that `adr/{NN}` is cut from and the
  eventual PR/rebase target. If omitted, resolve in Step 3.

## Step 2 — Locate the ADR and list phases

ADR dirs live under `.ADRs/` as `ADR_{NN}_{Name}/` (zero-padded `NN`). Find the
match; if none, stop. The **phase prompts** are the `{NN}_*.txt` files, sorted
numerically — their count is the total phase count.

## Step 3 — Set up the per-ADR worktree on `adr/{NN}`

All phase work happens in a dedicated worktree checked out to `adr/{NN}`; the main
checkout is never edited by phases. Set it up idempotently:

- **Base branch** (needed only to create `adr/{NN}`, and as Step 7's target):
  `--base` if given; else if exactly one branch contains this ADR's prompt files
  use it (`git for-each-ref` + `git ls-tree -r`); else the current branch if it is
  a base (`devel`/`main`/release); else default **`devel`**. Ask only if genuinely
  unclear. Deterministic, so `all` and one-at-a-time resolve the same base.
- **Worktree path:** a fixed, gitignored per-ADR path, e.g.
  `.claude/worktrees/adr-{NN}` (the harness already uses `.claude/worktrees/`; if
  that area is not ignored, use a path outside the main checkout to avoid polluting
  `git status`).
- **Create or reuse** (check `git worktree list` first):
  - If a worktree for `adr/{NN}` already exists → reuse it.
  - Else if branch `adr/{NN}` exists → `git worktree add <path> adr/{NN}`.
  - Else (cutting `adr/{NN}` fresh): `git fetch origin <base>`, then **check the
    base for unpushed work** — `git rev-list --count origin/<base>..<base>`. **If
    the local base branch has commits not on the remote, WARN the user and ask
    whether to push them first** before the ADR branch is cut — cutting from
    `origin/<base>` would otherwise omit them. Only after that resolve:
    `git worktree add <path> -b adr/{NN} origin/<base>` (push first if the user
    agreed; if they decline, state explicitly that those local-only base commits
    are excluded from `adr/{NN}`).

  This warning fires only when **creating** the worktree/branch; reusing an
  existing `adr/{NN}` skips it.

From here, every git/file operation for this ADR uses `<path>` (e.g.
`git -C <path> …`, and absolute paths under `<path>` for edits). Do **not** touch
the main checkout.

## Step 4 — Reconcile / resume (in the worktree)

Bring `adr/{NN}` to a clean transaction boundary:

1. `git -C <path> fetch origin` and fast-forward `adr/{NN}` to `origin/adr/{NN}` if
   behind (a prior run on another machine).
2. **Completion state.** Phase `M` is **complete** iff `RESULTS/{MM}_Results.txt`
   is **committed** at HEAD. `L` = highest **contiguous** complete phase from 1
   (0 if none).
3. **Reset interrupted work above `L`** (a dirty tree, or a commit for phase `L+1`
   without its handoff): target = the commit recording `RESULTS/{LL}_Results.txt`
   (or `git -C <path> merge-base adr/{NN} origin/<base>` if `L = 0`). **Safety
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
general-purpose`) — **without** `isolation: "worktree"`, since the worktree
already exists. Give it a **self-contained** brief — no carry-over from this
conversation, though it has the full worktree (the whole codebase) to read and
edit:
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
  adr/{NN}`."
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

The branch `adr/{NN}` is already on the remote (pushed each phase). **Ask the
user** (AskUserQuestion) how to land it — confirm the base if unclear:
- **Create a PR** *(default; expected for `… all`)*: `gh pr list --head adr/{NN}
  --base <base>`; if none, `gh pr create --base <base> --head adr/{NN}
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
- The worktree path and branch `adr/{NN}`; that the main checkout was untouched;
  whether the run **resumed** (and from which phase).
- Per phase: which ADR/phase, the sub-agent's gate results and **review verdict**,
  your orchestrator-gate result, commit hash, and confirmation it was pushed.
- If the ADR completed: the landing choice and the **PR URL** (or the base the
  commits were rebased onto), and the worktree-cleanup status.
- The ADR's Definition of Done from `ADR.md` §7 — especially the **manual smoke /
  live-box checks the maintainer must run** (no live Unbound in CI); Status stays
  "Implemented (pending smoke test)" until those pass.
- Any blockers or deviations.
