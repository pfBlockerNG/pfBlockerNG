# Fresh-session ticket workflow — the contract

- **Scope:** vendor-neutral protocol, map issue to merged PR (wayfinder map
  [#1383](https://github.com/pfBlockerNG/pfBlockerNG/issues/1383), resolved by ticket
  [#1385](https://github.com/pfBlockerNG/pfBlockerNG/issues/1385)).
- **Load-when:** coordinate, claim, execute, review, or continue GitHub ticket under
  fresh-session workflow.
- **Owner:** repo owner. **Last-verified:** 2026-07-16.

## Principles (fixed by the map)

- GitHub Issues and PRs = durable execution state. Session transcripts disposable.
- One bounded ticket per fresh top-level session (wayfinder research fan-out excepted).
- No worker inherits parent transcript. Workers get task packet.
- Explorer, implementer, reviewer run fresh bounded contexts. Reviewer independent and
  read-only.
- Mechanical gates and CI mandatory. Extra verification risk-triggered.
- Compaction near = checkpoint and terminate. Correctness-critical work never continues
  through compaction.
- No committed plan or handoff ledger duplicates GitHub state.

## Artifacts and schemas

### Map

Issue labelled `wayfinder:map` and typed `Task`, sections **Destination**, **Notes**,
**Decisions so far**, **Not yet specified** (the fog), **Out of scope**. Tickets = native
sub-issues. Body edited in place as current truth. Each resolved ticket appends one
pointer line to Decisions so far.

### Spec

Repo-committed doc: feature/system specs in `docs/specs/<slug>.md`; agent-protocol policy
in `.agents/policy/`. Required sections: **Goal**, **Fixed constraints**, **Decisions**,
**Acceptance criteria**, **Out of scope**, **Open forks** (each an issue link, or "none").
Spec with open forks not implementable — forks are tickets.

### Task packet

Issue body IS packet. Issue carries native type defined by `issues.md` plus optional
optional additive labels when they add info beyond that type. Fresh session must execute from
packet plus linked references alone. Required fields:

- **Objective** — the one outcome.
- **Required reading** — `file:line` and doc pointers (bootstrap routing rows), never
  pasted bodies.
- **Constraints** — do-not-touch list. Packet never weakens policy mandate.
- **Verification** — canonical gates plus per-item acceptance checks, each
  "WHEN `<command/input>` THEN `<observable>`".
- **Escalation** — falsified premise or mechanism packet never named = STOP: checkpoint
  and route `needs-info`/`ready-for-human`. Never silently patch plan.

Conditional fields, mandatory when applicable:

- **Coverage matrix** — sibling axes enumerated from source (grep/matrix output, never
  memory) whenever change touches anything with siblings.
- **Hostile-input rows** — any new or changed parser, regex, or input guard.
- **Risk triggers** — when present, name extra verification they require (see Model
  escalation and risk triggers).

### Claim

Assignee on issue, set **before any work**. Open + unassigned = unclaimed. Frontier =
open + unblocked + unclaimed. One claimed ticket maps to one live session. Release claim
by posting checkpoint and unassigning. Default staleness rule: claim with no pushed commit
or comment for 24 h may be taken over after posting takeover comment.

### Checkpoint

Structured comment posted whenever session stops short of done (compaction near, blocker,
needs-info, session end). All fields mandatory:

- **State** — branch, pushed commit SHA(s), what is complete.
- **Verified** — executed commands + output tails backing every done claim.
- **Next** — ordered remaining steps.
- **Open** — blockers, unanswered forks, ASSUMED facts.
- **Continue-with** — exact reading a continuation session needs (this ticket, this
  checkpoint, listed refs — nothing else).

Push before checkpointing (unpushed work = lost work), update state markers, unassign,
terminate.

### Evidence

Claim without run artifact = ASSUMED. Every load-bearing claim in ticket, checkpoint, or
PR carries executed command + output tail. Red→green proofs executed and pasted per repo
test policy — never reasoned through.

### Review

Every code PR gets independent adversarial review in fresh read-only context using
client's native reviewer surface, plus mechanical gates and CI. Reviewer never edits.
Findings return as PR review comments. Loop limits below. Landing mechanics — review
sources, reviewer contract, CI waits, squash-merge — specified in [`landing.md`](landing.md).
  CodeRabbit is not automatic — it is asked for once, when the PR is ready to merge
  ([`coderabbit.md`](coderabbit.md)).

### Continuation

Fresh session re-claims ticket, reads packet + latest checkpoint + its Continue-with refs
— never a transcript — and resumes from **Next**.

## Dependency and sub-issue semantics

- Parent/child: native GitHub sub-issues (map→tickets; oversized ticket→subtasks).
- Ordering: native blocked-by relations. Ticket unblocked when every blocker closed.
- Workers take frontier tickets only. Re-read frontier state immediately before claiming
  (assignee write = atomic claim).

## Ticket states and transition ownership

| State | Marker | Set by |
| ----- | ------ | ------ |
| intake | `needs-triage` label | opener/automation |
| under-specified | `needs-info` label | triager or worker |
| ready | `ready-for-agent` / `ready-for-human` label | triager |
| claimed/active | assignee | worker |
| waiting on PR | open PR with a `Fixes #N` closing reference | worker |
| blocked | open blocked-by relation | whoever discovers the dependency |
| done | closed + resolution comment | worker after gates pass / merger |
| cancelled | closed + comment stating why and what is NOT done | human (or worker on explicit human instruction) |

Native signals replaced `WIP`/`Waiting PR` labels
([#1388](https://github.com/pfBlockerNG/pfBlockerNG/issues/1388), adopted 2026-07-17;
scheme in `.agents/policy/issues.md` "Issue state (lifecycle)"). Old issues keep legacy
labels — no bulk migration. Clear one when a transition you perform would have cleared it.

Worker may move its claimed ticket between agent states. Never cancels without human.
Never overrides human-set `needs-info`/`ready-for-human` routing.

## Model escalation and risk triggers

- Tiers from `.agents/model-tiers.conf` (top/mid/small). Default: top/mid plans, gates,
  reviews; small implements bounded steps.
- Mid-ticket escalation to higher tier needs documented evidence **in the ticket**: failed
  executed attempt, falsified packet premise, or cross-cutting design surfaced mid-step.
  "Feels hard" not evidence.
- Separate verifier or reproducer session risk-triggered, never default. Triggers:
  new/changed parser, guard, or security surface; privilege or config-schema change;
  live-appliance behaviour; data-loss path; recurring reviewer-confirmed defect class.
  Packet names trigger. Absent one, gates + review suffice.

## Retry and fix-loop limits (defaults, amendable by pilot evidence)

- Implementer: max 2 executed attempts per step. Second failure checkpoints and escalates,
  citing both runs.
- Review fix loop: continues only while latest round has blocking finding. All-nitpick or
  clean round closes it. Hard cap 3 fix rounds, then checkpoint + `ready-for-human`.
- CI: same failure cause twice after fix attempt = stop, checkpoint, route
  `ready-for-human` or tracking issue. Never open-ended CI round-trips.

## What lives where

| Home | Content |
| ---- | ------- |
| Issue body | the task packet / current truth — edited in place |
| Issue comments | append-only events: checkpoints, evidence, resolution, cancellation |
| Branch | code, named `issue/{NN}-{slug}` (`scripts/agent/work-branch.sh`) |
| Pull request | the change + evidence summary, linked to its ticket; review lives here |
| Repo documents | durable norms: specs, policy, context docs |
| Nowhere | committed plan/handoff ledgers; transcript dumps |

## needs-info, ready-for-human, blocked, cancellation

- **needs-info:** post precise questions as checkpoint, apply label, unassign, terminate.
  Answers route ticket back to ready.
- **ready-for-human:** same shape, for decisions only human may make (owner forks,
  security judgment).
- **blocked:** wire blocked-by relation, checkpoint, release claim. Never poll another
  ticket from worker session.
- **cancelled:** close with comment stating why and what is NOT done. Sweep labels. Close
  any open PR.

## Parallel work

- Across tickets: allowed — claim discipline, one worktree/branch per ticket, never touch
  another claim's branch or PR.
- Same ticket: never two sessions. Sub-agents inside the one session fine: fresh bounded
  contexts with packet-scoped briefs.

## Vendor mapping

Behavioral equivalence, not surface parity. Each client uses its native orchestration
(Claude workflows/subagents, Codex roles) provided packet, claim, checkpoint, evidence,
review, and continuation land exactly as specified here. Role families and conditional
parity check are [#1387](https://github.com/pfBlockerNG/pfBlockerNG/issues/1387)'s ticket.

## Acceptance

Fresh Claude or Codex session can take one frontier ticket, load only bootstrap routing
rows plus packet's Required reading, complete or checkpoint it, and different fresh session
can continue from checkpoint alone. Map's pilots validate this contract before any
superseded flow retires.
