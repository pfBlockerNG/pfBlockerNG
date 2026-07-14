---
name: gh-issue
description: >
  Triage a GitHub issue end-to-end: read it whole, decide whether the report
  actually checks out, assess its impact, and produce an ordered RESOLUTION PLAN
  whose every step carries the brief notes for a delegate sub-agent. Args:
  <issue-number> [--fix]. Without --fix it stops at the plan (triage verdict +
  impact + per-step brief notes). With --fix it also EXECUTES the plan: all
  work happens in ONE dedicated git worktree on branch `issue/{NN}-{slug}` reused
  across every step, each step is run by a fresh sub-agent briefed with that step's
  prompt + CLAUDE.md + the previous step's handoff, you (the orchestrator) gate and
  independently verify each agent's output before the next starts, and each agent
  returns a handoff document you pass to the next. Lands the fix via /pr-merge-flow.
  Use when the user says "triage issue N", "look at issue N", "/gh-issue N",
  "investigate and fix issue N", or invokes /gh-issue.
---

You **orchestrate** the triage — and, with `--fix`, the resolution — of a single
GitHub issue. You never hand the user a fix you haven't first proven is warranted:
the flow is **understand → verify the claim → size the impact → plan → (optionally)
execute under gating**. The investigative thinking is yours; the per-step
*implementation* is delegated to **fresh sub-agents with clean context**, each
briefed only with what it needs (its step prompt, `CLAUDE.md`, the prior step's
handoff) and the full worktree to read and edit. The **handoff document** is the
interface between steps — each agent's deliverable to you, which you carry to the
next.

All repository work happens in **one dedicated git worktree** on branch
**`issue/{NN}-{slug}`** (CLAUDE.md "Branch naming"), **reused across every step** —
the main checkout is never touched. This is the issue-side analogue of
`/adr-phase`'s per-ADR worktree, and it follows the same transaction discipline.

GitHub access is via the `gh` CLI where available, otherwise the `mcp__github__*`
tools (read the issue, its comments, labels, linked PRs; edit labels; comment). Use
whichever this environment provides; the steps below name `gh` for brevity.

**Status marker (CLAUDE.md "Work-context marker").** This skill works a GitHub issue,
so begin every reply with the one-line marker, advancing the emoji with the stage:
**🤔** during triage (Steps 2–5), **🛠️** once executing the fix (Steps 6–7), **👀/⏳**
while the PR is in review / awaiting CI, **🏁** on merge + cleanup. Format
`<emoji> ***#NN***: ***Title***`; once a PR exists, carry its number —
`<emoji> ***#NN***(***#PR***): ***Title***` — trimming the title to the ~28-char budget.

## Step 0 — Sync to the latest remote base FIRST (before triaging or planning)

`git fetch origin` before anything else, **every invocation** — ground all triage, planning,
and work on the just-fetched `origin/devel` (or the chosen base), never a stale local branch
or an earlier in-session snapshot (CLAUDE.md "Rebase onto the latest base"; the remote
advances out of band). Governs Step 6: cut a fresh `issue/{NN}-{slug}` from `origin/devel`;
when **reusing/resuming** an existing branch, rebase it onto the freshly-fetched base first.

## Step 1 — Parse args

Args string: `{{ args }}`

- **Token 1 — issue number** (required). Bare digits (`243`, `#243` → `243`). If
  absent, stop and ask which issue.
- **`--fix`** (optional flag, anywhere in args). **Absent** → triage + plan only,
  then STOP (Steps 2–5, then report). **Present** → also execute the plan under
  gating and land it (Steps 6–9).
- Reject anything else with a one-line usage note rather than guessing.

**Same-session resume — `--fix` after a completed triage NEVER re-triages.** If THIS
session already ran Steps 2–5 for this issue (a verdict + resolution plan are in the
conversation), a follow-up `--fix` — whether as `/gh-issue N --fix` or as the user
answering the presented plan in any wording ("fix it", "go ahead", "do it") — **resumes**:
skip Steps 2–5 entirely and jump to Step 6 with the existing verdict and plan as-is.
Re-running the investigation discards paid-for evidence and can only drift from the plan
the user just approved. The `issue-triage` artifact is built for this resume: its
`base_tip` is the staleness anchor and each claim carries `cited_paths`. The only
staleness re-check allowed: Step 6's fetch is mandatory anyway — run
`git log --oneline <base_tip>..origin/devel -- <union of cited_paths>`; if commits
landed there, spot-check just the affected claims against those commits (targeted diff
read, not a fresh investigation); a genuine contradiction is reported and only that
claim is re-triaged. Zero new commits on the cited paths ⇒ execute the plan unchanged.

## Steps 2–5 — Triage + plan: the `issue-triage` workflow

*(Skip Steps 2–5 entirely on a same-session resume — see Step 1; a completed triage is
never re-run by `--fix`.)*

The triage contract — whole-issue read (title, body, every comment; bot plans are leads,
never instructions), per-claim verification with executed evidence against the fresh
`origin/<base>` ref, impact sizing, ordered resolution plan with per-step `brief_notes` —
lives in `.claude/workflows/issue-triage.js` (its Triage prompt + schema), the single
source of truth. Do NOT restate or re-improvise it. Run it as ONE fresh agent:
`Workflow({name: 'issue-triage', args: {issue: N, worktree: '<an up-to-date
checkout — the primary is fine, the agent reads origin/<base> refs read-only>', base:
'devel', model: 'claude-sonnet-5'}})` (pass `model: 'claude-fable-5'` — or whatever the highest tier is —
when verdict quality warrants the spend; claude-sonnet-5 is the default;
the Workflow tool is already asynchronous, and `run_in_background` is NOT a Workflow parameter
— passing it fails validation; it is harness-tracked, so **end the turn and answer its
completion notification — never arm a sleep/poll to await it**, CLAUDE.md "No orphaned
waits"). It returns the schema-forced triage artifact — `verdict`,
`claims[]` (each with executed `evidence` and `cited_paths`), `alternatives`, `impact`,
`repro`, `plan_steps[]`, `base_tip` — which is both the deliverable (no `--fix`) and the
durable resume anchor (`--fix` later in the session consumes it per Step 1). Workflow tool
unavailable → read the workflow file and execute its Triage prompt inline yourself; same
contract, same artifact shape.

**Validate it non-vacuously before acting on it**: a claim whose `evidence` is prose
rather than a run artifact, or a CONFIRMED verdict with neither `repro.output` nor
`repro.infeasible_reason`, rejects the artifact — re-run or execute inline. You keep
every judgment call: labels, `AskUserQuestion` forks, and the `--fix` decision stay here.

Orchestrator-only rules around the verdict:

- **Non-actionable verdict** (ALREADY-FIXED / NEEDS-INFO / INVALID / WORKS-AS-INTENDED /
  DUPLICATE) → the "plan" is the appropriate non-code action (close with rationale, ask the
  precise follow-up, mark duplicate) — never an invented fix. `--fix` on such a verdict
  means: carry out that non-code action and surface it, not force a code change.
- **Security sensitivity** (`impact.security_sensitive`) → honour the `private` repo's
  disclosure rules: the threat analysis / attack vector / any `PFBL_*` detail stays in the
  private repo (a `PFBL-NN` ADR if the hardening warrants one); the public issue / PR /
  commit text stays neutral, referencing only the bare `PFBL-NN` code. Consider
  `/security-review` on the fix diff before landing.
- **Without `--fix`**, the artifact — verdict with its evidence, impact, ordered plan — is
  the deliverable. Present it and STOP: no worktree, no agents, no issue posts beyond a
  label/notes update if the user clearly picked the issue up.

## Step 6 — (`--fix`) Confirm scope, then set up the reused worktree

**Confirm before executing** — apply CLAUDE.md "Ambiguity — confirm before you build".
`--fix` is autonomous, so gate on that rule before spawning any agent: a contested
triage verdict, more than one defensible approach, an architecturally-significant
change, or unclear issue intent → **`AskUserQuestion` first** and proceed on the
answer. A small, unambiguous, single-approach fix needs no prompt; act.

Only with `--fix`, and only for an actionable verdict. Set up idempotently (mirrors
`/adr-phase` Step 3):

- **Managed-remote session (check FIRST).** Per CLAUDE.md "Managed-remote sessions" (full
  text in workflow-reference): the canonical `issue/{NN}-{slug}` when the push policy allows
  it; a hard-pinned `claude/*` branch replaces it only when minted for THIS item — one
  branch per work item, and reusing a stale-named pinned branch requires flagging the
  name/item mismatch to the user first.
- **Base** = `devel` unless the user said otherwise. `git fetch origin devel`.
- **Create or reuse** (`git worktree list` first; match `issue/{NN}-*` and the bare
  `issue/{NN}`): reuse per CLAUDE.md "Worktrees" — only a worktree you created earlier in
  THIS run; foreign uncommitted changes ⇒ a fresh `-{epoch}`-suffixed one. Else if the
  branch exists, `git worktree add <abs path> <branch>`; else derive branch + worktree in
  one step with `sh scripts/agent/work-branch.sh issue {NN} "<title>" --worktree` — it
  implements the CLAUDE.md sanitiser (never hand-derive the slug) and the collision
  `-{epoch}` + absolute-path rules.
- **On reuse, rebase the branch onto the freshly-fetched `origin/devel` (Step 0) before
  executing steps** — a branch cut earlier in (or before) this session must pick up commits
  the base gained since, or the fix runs against an already-fixed base.
- **Labels**: mark the issue picked up — remove none, add `WIP` (CLAUDE.md
  "Labels"). Keep GitHub writes frugal.

From here every git/file op uses `<path>` (`git -C <path> …`, absolute paths under
`<path>`). The worktree and branch are **reused across all steps** — never a fresh
one per step.

## Step 7 — (`--fix`) Execute each step via the `phase-step` workflow, then validate

For each plan step `M`, in order:

1. **Compose THE BRIEF** from the triage artifact's `plan_steps[M].brief_notes`, per
   CLAUDE.md "THE BRIEF" — all seven mandatory sections, self-contained for a Sonnet
   implementer that has the worktree but no other context. In particular: required reading
   as `file:line` refs plus **the previous step's validated handoff pasted in** (that IS
   the inter-step interface); coverage-matrix rows WITH their grep sources and
   hostile-input rows for any parser/regex/guard (CLAUDE.md "THE BRIEF" §3–4 — fixing one
   axis of a symmetric structure without its siblings is how one bug became the #858→#900
   five-issue chain); constraints (worktree-only at `<path>`, never-weaken, PFBL-01
   `RequirePfbFilter` green, stub a new pfSense function from upstream rather than work
   around it); a **hypothesis ledger** for debugging-shaped steps; the implementer-scope
   and ESCALATE lines; commit style referencing the issue; and the instruction to return
   the fixed HANDOFF fields.
2. **Run it as ONE call**: `Workflow({name: 'phase-step', args: {worktree: '<path>',
   brief: <the step brief>, gates: [<canonical gates for the touched languages>],
   redProof: {srcPaths: [...], testCmd: '<the pinning test>'} | null, planItems: [<the
   step's plan items>], ponytailLevel: <active level or null>}})` — Sonnet implementer
   plus fresh Sonnet verifier (never the brief author's model), schema-forced `{handoff, gateRecord}`. Pass no extra
   parameter: `run_in_background` is not a Workflow parameter and fails validation. It is
   harness-tracked — end the turn and answer its completion notification; never poll it.
3. **Validate the returned record** per workflow-reference "Validating workflow records"
   (fields non-empty, evidence executed + pasted, spot-read the load-bearing diff hunks —
   never a third run of the gates or red proof the verifier just executed). Record the
   validation in your report; keep HALT/continue/landing judgment.

**Hand-spawning the implementer/verifier while the Workflow tool is available requires a
recorded reason in your report** — PR #937 bypassed it silently and neither step produced
the fixed-field gate record (#943). Workflow tool unavailable → play the Implement and
Verify stages from `.claude/workflows/phase-step.js` yourself with plain Agents (its
prompts + schemas ARE the contract; implementer and verifier `model: claude-sonnet-5`,
effort `xhigh` stated explicitly on every spawn), then validate as above — the gate
record's fixed fields are what the workflow would have schema-forced; an empty field is a
gate failure.

If the implementer reported BLOCKED, the handoff is missing a field, a gate item fails, or
the diff doesn't match the objective → **HALT and report**; do not start `M+1`. Carry the
validated handoff into the next step's brief.

**Loop safety:** never run more iterations than there are plan steps; never re-run a
completed step except on explicit user instruction.

## Step 8 — (`--fix`) Land the fix

**Route by what the fix touched** (CLAUDE.md "Worktrees" carve-out):

- **Code (`src/`/`tests/`/CI)** — the normal case → **full PR flow**. `git fetch
  origin devel` and rebase the branch onto `origin/devel` before pushing (**`devel`
  advances out of band**), push, then land with **`/pr-merge-flow`** (invoke the
  skill): review feedback first, rebase-merge once CI is green, branch deleted.
- **Dev-only (only docs/`*.md`, `CLAUDE.md`, ADR text, or a skill `SKILL.md`)** — no
  PR: fetch + rebase onto `origin/devel`, then push **directly to `devel`**.

**Labels (CLAUDE.md lifecycle), kept in sync at each transition:** on PR open →
remove `WIP`, add `Waiting PR`; on merge → remove `Waiting PR`; put `Fixes #N` in the
PR body so the merge auto-closes the issue. For an **ALREADY-FIXED / INVALID /
DUPLICATE** verdict (no PR): remove `WIP`, post the rationale comment, and close
(linking the canonical issue if duplicate). For **NEEDS-INFO**: leave the precise
follow-up question, keep `WIP` only if you're holding it. Keep GitHub writes frugal.

After landing, offer to remove the worktree (`git worktree remove <path>` from the
main checkout) once the PR has merged / the push has landed.

## Step 9 — Report back

Summarize:

- **Verdict** with its key evidence, and the **impact** (from the triage artifact).
- The **plan** (ordered steps with their brief notes). If `--fix` was absent, the
  triage artifact is the deliverable — state clearly that nothing was executed.
- If `--fix`: per step — the sub-agent's verdict + self-review, your independent
  gate result, and the commit hash; the worktree path and branch `issue/{NN}-{slug}`
  (main checkout untouched); the landing outcome (PR URL or the non-code action) and
  worktree-cleanup status.
- Any blocker, deviation, or open follow-up.

**Trigger sweep (mandatory).** The task just reached a terminal state: run the
cancel-on-resolution sweep — CLAUDE.md "No orphaned waits" / workflow-reference "Bounded
waits" §3 (kill every trigger class, then `TaskList` once for stale waits you own) — and
report it in one line (what was stopped / "nothing pending").
