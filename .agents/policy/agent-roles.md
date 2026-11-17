# Agent role families — shared contract

- **Scope:** vendor-neutral agent role families for Claude, Codex, Copilot: what each role
  for, what it read and mutate, what it return
  (issue [#1387](https://github.com/pfBlockerNG/pfBlockerNG/issues/1387); companion to
  fresh-session ticket workflow in [`workflow.md`](workflow.md)).
- **Load-when:** defining or routing agent role; changing `.claude/agents/`, `.codex/agents/`,
  `.github/agents/`, or this registry.
- **Owner:** repo owner. **Last-verified:** 2026-11-17.

## Goal

One semantic contract per role family, mapped explicit onto each vendor's native
definitions, so every client stay behaviorally aligned without identical files, tools,
or wording. Context-window pollution = enemy: role load its purpose-built context slice,
never whole policy corpus.

## Fixed constraints

- Task-packet / checkpoint schemas ([`workflow.md`](workflow.md)) bind every role
  unchanged; role contract may narrow them, never weaken.
- `scripts/check_agent_roles.py` validate registry below against each vendor's
  definitions if and only if either side change (pre-commit + CI). Check semantic
  fields — mutation boundaries, binding targets, contract-section completeness — never
  textual identity, so vendor-native wording stay free.

## Role registry (machine-readable)

`scripts/check_agent_roles.py` parse this table. Column vocabularies: **Mutation** —
`read-only`/`workspace-write`; **Independent** — `yes`/`no`; **bindings** —
comma-separated `kind:name` (Claude kinds: `agent` = `.claude/agents/<name>.md`,
`skill` = `.agents/skills/<name>/`, `policy` = `.agents/policy/<name>`,
`session` = top-level session itself or fresh native sub-agent it spawn with
role's contract; Codex kinds: `agent` = `.codex/agents/<name>.toml`, plus
`skill`/`policy`/`session` as for Claude; Copilot kinds: `agent` =
`.github/agents/<name>.agent.md`, plus `skill`/`policy`/`session` as for Claude).

<!-- role-registry:begin -->

| Role | Mutation | Independent | Claude bindings | Codex bindings | Copilot bindings |
| ---- | -------- | ----------- | --------------- | -------------- | ---------------- |
| explorer | read-only | no | session | agent:analyst | agent:analyst |
| planner | read-only | no | session | agent:planner | agent:planner |
| implementer | workspace-write | no | session | agent:implementer | agent:implementer |
| reviewer | read-only | yes | agent:adversarial-reviewer | agent:adversarial-reviewer | agent:adversarial-reviewer |
| publisher | workspace-write | no | policy:landing.md | policy:landing.md | policy:landing.md |
| coordinator | workspace-write | no | policy:workflow.md | policy:workflow.md | policy:workflow.md |

<!-- role-registry:end -->

## Role contracts

### explorer

- **Purpose & routing:** read-only investigation with cited evidence — locate code,
  gather facts, triage issue, run investigation fan-out. Route here when outcome =
  report, never edit.
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

### planner

- **Purpose & routing:** decompose substantial work into bounded steps with
  coverage matrix and hostile-input rows enumerated from source. Route: substantial
  multi-step `src/`/`tests/`/CI work, ADR design, ambiguity forks.
- **Inputs & task packet:** work item (issue, ADR, map ticket), live tree,
  policy annexes item touch.
- **Outputs & evidence:** plan with runnable acceptance checks, each premise backed
  by executed command with pasted output.
- **Permissions & mutation:** read-only as role: plans, not edits. Session hosting it
  may switch roles in place.
- **Context & skills:** bootstrap (AGENTS.md) and its routed annexes; fresh-session
  workflow ([`workflow.md`](workflow.md)). Floor: `issues.md` on issue work,
  `landing.md` when landing, `review-bots.md` on any PR or Fair Usage notice,
  `waits.md` when wait armed.
- **Stop & escalation:** genuine user fork ⇒ ask user; falsified premise ⇒ stop
  and re-plan, loud. Never silent patch plan.
- **Independence:** not independent of work item; never reviews its own work.

### implementer

- **Purpose & routing:** execute one approved plan or packet in assigned worktree.
- **Inputs & task packet:** plan or task packet plus its named refs.
- **Outputs & evidence:** what changed, gate commands + output tails, red→green
  proof (executed, test-first, frozen), deviations.
- **Permissions & mutation:** workspace-write inside its worktree; commits as directed.
  Never push protected branches, never merge, never edit policy.
- **Context & skills:** plan, its named refs, code it edit, language annex for
  touched file types — nothing broader. Floor: `coding.md`, `testing.md`, `lang-*.md`
  per touched file type; domain rows per routing table.
- **Stop & escalation:** contradicted premise or mechanism plan never named ⇒
  stop and report it, never plain done; at most 2 executed attempts per step, then
  checkpoint and escalate citing both runs.
- **Independence:** none; accountability stay with caller.

### reviewer

- **Purpose & routing:** one independent adversarial reviewer covering all four
  [`landing.md`](landing.md) lenses (contract · correctness+hostile · test honesty ·
  over-engineering) over whole change set, once before its PR opens — not per change
  or commit. Route: every code change set before PR.
- **Inputs & task packet:** branch or diff, intent/acceptance spec, worktree.
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
  checkpoint; blocking review finding never silent self-fixed.
- **Independence:** not required.

### coordinator

- **Purpose & routing:** ticket coordinator — shepherd ticket lifecycle: pick frontier
  tickets, claim before work, keep state labels honest, post checkpoints, route
  `needs-info`/`ready-for-human`. Route: fresh-session ticket workflow sessions and
  label hygiene.
- **Inputs & task packet:** map/ticket state on GitHub — durable execution
  state; never parent transcript.
- **Outputs & evidence:** claims, structured checkpoints (all fields mandatory), label
  transitions.
- **Permissions & mutation:** GitHub metadata writes (labels, assignees, comments,
  sub-issue/blocked-by relations). No source edits; never cancel ticket without
  human; never override human-set routing.
- **Context & skills:** [`workflow.md`](workflow.md) plus bootstrap routing rows —
  deliberately minimal. Floor: [`workflow.md`](workflow.md); `issues.md`.
- **Stop & escalation:** approaching compaction ⇒ checkpoint, unassign, terminate;
  correctness-critical work never continue through compaction.
- **Independence:** not required.

## Vendor mappings

Behavioral equivalence, not surface parity: each client keep its native orchestration
as long as role's semantic fields land as specified.

### Claude

**reviewer** runs `.claude/agents/adversarial-reviewer.md`, implementing
[`landing.md`](landing.md) contract. **explorer**, **planner**, **implementer**,
**publisher**, **coordinator** = session itself or a native sub-agent it chooses
(`Explore` type for ad-hoc read-only fan-out), following
[`landing.md`](landing.md), [`workflow.md`](workflow.md).

### Codex

One TOML file per role at `.codex/agents/<role>.toml` — registry's Codex column name
each binding, `sandbox_mode` carry mutation boundary. `publisher` and `coordinator`
stay session, following [`landing.md`](landing.md) and [`workflow.md`](workflow.md).

### Copilot

Same roles as Codex, one file per role at `.github/agents/<role>.agent.md`
(launched from `/agents`): mutation boundary ride
`<!-- mutation: read-only|workspace-write -->` marker in body, Copilot having no
`sandbox_mode` of its own.

## Decisions

Deviations from issue #1387's starting six, with rationale:

- **quick implementer merged into implementer**: identical permissions and escalation
  contract; differ only in scope.
- **planner added**: role every vendor already define (`.codex/agents/planner.toml`).
- **code reviewer = one adversarial reviewer** covering every lens; every vendor
  serve it from `adversarial-reviewer`.
- **code explorer kept** (named `explorer`), covering evidence gathering, triage,
  investigation fan-outs — Codex/Copilot `analyst`.
- **publisher and coordinator kept**, bound to policy documents rather than
  dedicated vendor agent: both = procedure-driven roles session fill by loading one
  document, and no vendor need separate agent definition for them.
- **No model choice or delegation mechanics here** (owner, 2026-11-17, issue
  [#4043](https://github.com/pfBlockerNG/pfBlockerNG/issues/4043)): skills cover them.
- **Shell discovery guard stays.** `scripts/agent/check-agent-config-parity.sh`
  keep skill/workflow adapter parity; `scripts/check_agent_roles.py` own
  registry-driven cross-vendor role semantics.

## Acceptance criteria

- Every registry role has contract section carrying all seven semantic fields, and
  explicit Claude, Codex, Copilot bindings that resolve to real files (or `session`).
- `scripts/check_agent_roles.py --all` pass on tree; fail loud when
  vendor definition drift from registry (sandbox/mutation mismatch, missing or orphaned
  vendor role, missing contract field) while tolerating any vendor-native wording
  difference.
- Check run if and only if role surface change: self-scoped `--staged` in
  pre-commit and `--diff <base>` in CI.

## Out of scope

- Per-role context-slice documents (splitting the bootstrap into role-specific required
  reading) — tracked by wayfinder map
  [#1383](https://github.com/pfBlockerNG/pfBlockerNG/issues/1383).
- Skill/workflow adapter parity and symlink integrity — already owned by
  `scripts/agent/check-agent-config-parity.sh`.

## Open forks

- None.
