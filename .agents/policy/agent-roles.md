# Agent role families — shared contract

- **Scope:** vendor-neutral agent role families for Claude, Codex, Copilot: what each role
  for, what it read and mutate, what it return, which model tier serve it
  (issue [#1387](https://github.com/pfBlockerNG/pfBlockerNG/issues/1387); companion to
  fresh-session ticket workflow in [`workflow.md`](workflow.md)).
- **Load-when:** defining or routing agent role; changing `.codex/agents/`, `.github/agents/`,
  `.agents/model-tiers.conf`, or this registry.
- **Owner:** repo owner. **Last-verified:** 2026-08-20.

## Goal

One semantic contract per role family, mapped explicit onto each vendor's native
definitions, so every client stay behaviorally aligned without identical files, models,
tools, or wording. Context-window pollution = enemy: role load its purpose-built
context slice (contract section plus packet's Required reading), never whole
policy corpus.

## Fixed constraints

- Tier vocabulary = **top / mid / small** from
  [`.agents/model-tiers.conf`](../model-tiers.conf). Contract name tiers, never
  vendor model ids; tier select model, procedures set effort independent.
- Expensive tiers need evidence (see Tier economics).
- Delegation contract (`.agents/policy/delegation.md`: brief → handoff → gate) and task-packet /
  checkpoint schemas ([`workflow.md`](workflow.md)) bind every role unchanged; role
  contract may narrow them, never weaken.
- `scripts/check_agent_roles.py` validate registry below against each vendor's
  definitions if and only if either side change (pre-commit + CI). Check semantic
  fields — tier vocabulary, mutation boundaries, binding targets, model-tier pins, Codex
  review-effort pins — never textual identity, so vendor-native wording stay free.

## Tier economics (Sol/Luna discipline, every vendor)

- **small** = default executor tier: implementation, verification, review, triage,
  publishing, coordination all start small.
- **top** need named routing trigger: planning/gating substantial work; whole-PR
  review of large/complex PR (>300 lines, >6 files, or `src/`
  parsing/guard/scheduling behaviour); verdict-quality triage of complex issue.
  Mid-task escalation also need documented evidence **in ticket** —
  failed executed attempt, falsified packet premise, or cross-cutting design surfaced
  mid-step; "feels hard" not evidence ([`workflow.md`](workflow.md) "Model escalation
  and risk triggers").
- **mid** = fallback tier: substitute unavailable top, for planning and review
  alike, and review alone in that case — never default route (2026-08-01: former
  small+mid dual pass retired).

## Role registry (machine-readable)

`scripts/check_agent_roles.py` parse this table. Column vocabularies: **Tiers** —
`top`/`mid`/`small`, primary (default) tier first, `+`-separated; **Mutation** —
`read-only`/`workspace-write`; **Independent** — `yes`/`no`; **bindings** —
comma-separated `kind:name` (Claude kinds: `agent` = `.claude/agents/<name>.md`,
`skill` = `.agents/skills/<name>/`, `policy` = `.agents/policy/<name>`,
`session` = top-level session itself or fresh native sub-agent it spawn with
role's contract; Codex kinds: `agent` = `.codex/agents/<name>.toml`, plus
`skill`/`policy`/`session` as for Claude; Copilot kinds: `agent` =
`.github/agents/<name>.agent.md`, plus `skill`/`policy`/`session` as for Claude).

<!-- role-registry:begin -->

| Role | Tiers | Mutation | Independent | Claude bindings | Codex bindings | Copilot bindings |
| ---- | ----- | -------- | ----------- | --------------- | -------------- | ---------------- |
| explorer | small+top | read-only | no | session | agent:analyst, agent:analyst-top | agent:analyst, agent:analyst-top |
| planner | top+mid | read-only | no | session | agent:planner | agent:planner |
| implementer | small | workspace-write | no | session | agent:implementer | agent:implementer |
| verifier | small | read-only | yes | agent:adversarial-reviewer | agent:adversarial-reviewer | agent:adversarial-reviewer |
| reviewer | small+top+mid | read-only | yes | agent:adversarial-reviewer, agent:adversarial-reviewer-top, agent:adversarial-reviewer-mid | agent:adversarial-reviewer, agent:adversarial-reviewer-top, agent:adversarial-reviewer-mid | agent:adversarial-reviewer, agent:adversarial-reviewer-top, agent:adversarial-reviewer-mid |
| publisher | small | workspace-write | no | policy:landing.md | policy:landing.md | policy:landing.md |
| coordinator | small | workspace-write | no | policy:workflow.md | policy:workflow.md | policy:workflow.md |

<!-- role-registry:end -->

## Role contracts

### explorer

- **Purpose & routing:** read-only investigation with cited evidence — locate code,
  gather facts, triage issue, run ADR investigation fan-out. Route here when
  outcome = report, never edit.
- **Inputs & task packet:** scoped question or issue, worktree path, output
  schema; Required reading as `file:line`/doc pointers, never pasted bodies.
- **Outputs & evidence:** requested schema, every load-bearing fact tagged
  verified (command + output) or ASSUMED; never different planning artifact.
- **Permissions & mutation:** read-only. May run read-only commands (grep, `git log`,
  `gh` reads); never edit, commit, push, or change labels.
- **Context & skills:** packet plus its named refs; code-search tooling. Not full
  policy corpus. Floor: `issues.md` when triaging; `pfsense-live.md` for live repro;
  routing row of suspect subsystem.
- **Stop & escalation:** packet premise contradicted by source ⇒ STOP, return
  structured blocker; under-specified scope ⇒ route `needs-info`.
- **Independence:** not required — serve its caller.
- **Tier intent:** small by default; top for verdict-quality triage of complex issue
  or evidence-heavy cross-cutting investigation. Never mid.

### planner

- **Purpose & routing:** decompose substantial work into bounded steps, author
  brief/task packet (coverage matrix and hostile-input rows enumerated from source),
  gate every delegated step mechanically. Route: substantial multi-step
  `src/`/`tests/`/CI work, ADR design, ambiguity forks.
- **Inputs & task packet:** work item (issue, ADR, map ticket), live tree,
  policy annexes item touch.
- **Outputs & evidence:** brief (mandatory sections per delegation contract),
  per-step gate record, HALT/continue decisions — each check executed
  command with pasted output.
- **Permissions & mutation:** read-only as role: briefs and gates, not edits.
  Session hosting it may switch roles in place — implementer for small direct fix or
  docs/config/skills work (CLAUDE.md carve-out), publisher/coordinator for landing and
  bookkeeping — but planner never grade its own implementation work.
- **Context & skills:** bootstrap (AGENTS.md) and its routed annexes, prior handoffs;
  fresh-session workflow ([`workflow.md`](workflow.md)). Floor:
  [`delegation.md`](delegation.md) always; `issues.md` on issue work, `landing.md` when
  landing, `coderabbit.md` on any PR or Fair Usage notice, `waits.md` when wait armed.
- **Stop & escalation:** genuine user fork ⇒ ask user; falsified premise ⇒ stop
  and re-plan, loud. Never silent patch plan.
- **Independence:** not independent of work item, but producer≠gater: per-step
  verifier and PR reviewer always different agents.
- **Tier intent:** top — every downstream artifact lean on brief, and brief bugs
  demonstrably ship defects; mid as documented sole fallback when top
  unavailable.

### implementer

- **Purpose & routing:** execute exactly one approved brief/packet in assigned
  worktree. Two weights, one contract: **full** (default) and **light** —
  behaviour-preserving mechanical step pinned by earlier gate-passed oracle, run
  without planning/reconcile wrapper (this = issue's "quick implementer";
  same permissions and evidence schema, smaller scope).
- **Inputs & task packet:** THE BRIEF (mandatory sections) plus prior step's
  handoff. Trust brief — no re-investigating its evidence.
- **Outputs & evidence:** THE HANDOFF, fixed fields: verdict, what changed, gate
  commands + output tails, red→green proof (executed, test-first, frozen), coverage
  matrix ticks, deviations, carry-forward.
- **Permissions & mutation:** workspace-write inside its worktree; commits as directed.
  Never push protected branches, never merge, never edit brief or policy.
- **Context & skills:** brief, its named refs, code it edit, language
  annex for touched file types — nothing broader. Floor: `coding.md`, `testing.md`,
  `lang-*.md` per touched file type; domain rows per routing table.
- **Stop & escalation:** ESCALATE contract — contradicted premise or mechanism
  brief never named ⇒ BLOCKED (or DONE-WITH-DEVIATION), never plain DONE; at most
  2 executed attempts per step, then checkpoint and escalate citing both runs.
- **Independence:** none; accountability stay with spawner. May re-delegate
  genuine split, never whole brief.
- **Tier intent:** small, always. Higher tier mid-step need documented evidence
  in ticket.

### verifier

- **Purpose & routing:** independently re-derive one completed step: re-run gates,
  re-execute red→green proof, read full diff against every plan item and
  coverage row, audit test honesty and conventions. Route: after every delegated step,
  before next start.
- **Inputs & task packet:** brief, handoff, diff, canonical gate
  commands.
- **Outputs & evidence:** gate-record fields — commands + results, red/green
  evidence, per-item diff verdicts, matrix confirmation, explicit SKIPPED list.
- **Permissions & mutation:** read-only on sources; may execute gates and tests
  ephemerally. Never patch finding — defects route back to planner.
- **Context & skills:** brief + handoff + diff and canonical gate table;
  deliberately not implementer's transcript. Floor: `testing.md`, `landing.md`;
  touched `lang-*.md` and domain rows of diff.
- **Stop & escalation:** any defect or unnamed mechanism in diff ⇒ reject step;
  check it cannot run recorded SKIPPED with reason, never silent dropped.
- **Independence:** required — never agent (or model) that authored brief or
  diff.
- **Tier intent:** small, always (owner directive 2026-07-14): different model read
  with different blind spots, and step gate need no top tier.

### reviewer

- **Purpose & routing:** four parallel leg reviewers (contract · correctness+hostile
  · test honesty · over-engineering) over whole PR diff; re-review legs focus on
  changes since their own leg's recorded head SHA. Route: every code PR and fix round.
- **Inputs & task packet:** PR number, leg, its latest audit comment (head SHA =
  focus base), worktree, intent/acceptance spec.
- **Outputs & evidence:** schema-forced findings — severity, location, evidence,
  reproduction — as review output; never edited tree.
- **Permissions & mutation:** read-only; may run discriminating probes and hostile
  inputs. Never edit, commit, or downgrade pre-existing defect — those route
  to tracked follow-up.
- **Context & skills:** full diff + surrounding code; policy annexes diff
  touch. Floor: `testing.md`, `landing.md`; touched `lang-*.md` and diff's
  domain rows.
- **Stop & escalation:** fix→re-review loop continue only while latest
  round has blocking finding; hard cap 3 rounds, then human decide.
- **Independence:** required — fresh context, never author of change.
- **Tier intent:** per leg — correctness+hostile top (mid iff top unavailable),
  contract mid, test honesty small, over-engineering top (mid iff top
  unavailable); re-reviews all small.

### publisher

- **Purpose & routing:** commit-and-publish operator — mechanical landing:
  rebase onto live base, clean diff, push, open PR, keep labels in sync,
  run bounded CI/review waits, merge only on instruction. Route: after gates and
  review, when remaining work = procedure, not judgment.
- **Inputs & task packet:** branch, work item, landing instruction
  (which flow, which labels, merge or stop-before-merge).
- **Outputs & evidence:** PR URL, label transitions, merge/CI state — each
  claim with its executed command + output tail.
- **Permissions & mutation:** git/gh writes only — branch pushes, PR metadata, labels.
  No new source changes beyond rebase conflict resolution; never force-push over
  another session's PR; every wait bounded and swept.
- **Context & skills:** [`landing.md`](landing.md) and branch/release policy — not
  implementation history. Floor: [`landing.md`](landing.md); `context/release.md` for
  release, `git.md` for tag/push mechanics.
- **Stop & escalation:** same CI failure cause twice after fix attempt ⇒ stop and
  checkpoint; blocking review finding route back to planner, never silent
  self-fix.
- **Independence:** not required.
- **Tier intent:** small — procedure execution; never burn top tier on waits.

### coordinator

- **Purpose & routing:** low-cost ticket coordinator — shepherd ticket
  lifecycle: pick frontier tickets, claim before work, keep state labels honest, post
  checkpoints, route `needs-info`/`ready-for-human`, dispatch workers with task
  packets. Route: fresh-session ticket workflow sessions and label hygiene.
- **Inputs & task packet:** map/ticket state on GitHub — durable execution
  state; never parent transcript.
- **Outputs & evidence:** claims, structured checkpoints (all fields mandatory), label
  transitions, dispatched packets.
- **Permissions & mutation:** GitHub metadata writes (labels, assignees, comments,
  sub-issue/blocked-by relations). No source edits; never cancel ticket without
  human; never override human-set routing.
- **Context & skills:** [`workflow.md`](workflow.md) plus bootstrap routing rows —
  deliberately minimal. Floor: [`workflow.md`](workflow.md); `issues.md`.
- **Stop & escalation:** approaching compaction ⇒ checkpoint, unassign, terminate;
  correctness-critical work never continue through compaction.
- **Independence:** not required.
- **Tier intent:** small — routing and bookkeeping. Escalation happen by dispatching
  planner, not by upgrading coordinator.

## Vendor mappings

Behavioral equivalence, not surface parity: each client keep its native orchestration
as long as role's semantic fields land as specified. Tier→model resolution always
go through [`model-tiers.conf`](../model-tiers.conf).

### Claude

Reviewer and verifier roles define `.claude/agents/<role>.md` files with model and
`effort: medium` pinned in front matter, mirroring Codex and Copilot: **verifier**
runs `adversarial-reviewer.md` at small tier; **reviewer** implements
[`landing.md`](landing.md) contract using `adversarial-reviewer.md` (small default),
`adversarial-reviewer-top.md` (top tier for large/complex PR), and
`adversarial-reviewer-mid.md` (mid tier when top unavailable). **explorer** takes
packet-scoped brief (small default, top for verdict quality; `Explore` type for
ad-hoc read-only fan-out); **implementer** executes THE BRIEF in assigned worktree
at small tier. **planner**, **publisher**, **coordinator** = session itself
(small-tier delegate may publish), following [`delegation.md`](delegation.md),
[`landing.md`](landing.md), [`workflow.md`](workflow.md).

### Codex

One TOML file per role at `.codex/agents/<role>.toml` — registry's Codex column name
each binding, `model` carry tier and `sandbox_mode` mutation boundary. `reviewer`
use `-top` file for large or complex PR and `-mid` as top-unavailable substitute.
`publisher` and `coordinator` stay session, following [`landing.md`](landing.md) and
[`workflow.md`](workflow.md).

### Copilot

Same roles and tiers as Codex, one file per role at `.github/agents/<role>.agent.md`
(launched from `/agents`): `model` carry tier, mutation boundary ride
`<!-- mutation: read-only|workspace-write -->` marker in body, Copilot having no
`sandbox_mode` of its own.

## Decisions

Deviations from issue #1387's starting six, with rationale:

- **quick implementer merged into implementer** as `light` weight: identical
  permissions, evidence schema, escalation contract; differ only in scope cap
  and skipped wrapping stages. Repo already model this as routing parameter
  (`WEIGHT: light` phases), and Codex define one implementer role.
- **planner added**: de-facto top-tier role every vendor already define
  (`.codex/agents/planner.toml`; Claude session + Reconcile stage). Expensive
  tier need explicit contract precisely because expensive.
- **code reviewer split into verifier + reviewer**: different outputs (gate record vs
  findings schema) and different tier routing (verifier pinned small by owner
  directive; reviewer escalate to top for large/complex PRs). Both stay
  independent and read-only; Codex serve both from `adversarial-reviewer` family.
- **code explorer kept** (named `explorer`), covering evidence gathering, triage,
  investigation fan-outs — Codex `analyst` family.
- **publisher and coordinator kept**, bound to policy documents rather than
  dedicated vendor agent: both = procedure-driven small-tier roles session
  fill by loading one document, and neither vendor need separate agent definition
  for them.
- **Shell discovery guard stays.** `scripts/agent/check-agent-config-parity.sh`
  keep skill/workflow adapter parity, `model-tiers.conf` syntax, and its fast
  pre-commit Codex role→tier pins; `scripts/check_agent_roles.py` own
  registry-driven cross-vendor role semantics. Overlapping pins fail loud on
  divergence — folding them deliberately deferred until registry bedded in.

## Acceptance criteria

- Every registry role has contract section carrying all eight semantic fields, and
  explicit Claude, Codex, Copilot bindings that resolve to real files (or `session`).
- `scripts/check_agent_roles.py --all` pass on tree; fail loud when
  vendor definition drift from registry (retiered model pin, sandbox/mutation
  mismatch, orphaned vendor role, missing contract field) while tolerating any
  vendor-native wording difference.
- Check run if and only if role surface change: self-scoped `--staged` in
  pre-commit and `--diff <base>` in CI.

## Out of scope

- Per-role context-slice documents (splitting CLAUDE.md into role-specific required
  reading) — tracked by wayfinder map
  [#1383](https://github.com/pfBlockerNG/pfBlockerNG/issues/1383).
- Effort-level policy: tiers select models; procedures own their effort settings.
- Skill/workflow adapter parity and symlink integrity — already owned by
  `scripts/agent/check-agent-config-parity.sh`.

## Open forks

- None.
