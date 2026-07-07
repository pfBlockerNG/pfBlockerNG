# AI usage lessons — the 2026-07 workflow audit

What we learned making cheaper models (Opus 4.8 planning, Sonnet 5 implementing) produce
work that survives a stronger model's review — and what we built from it. Context: a
one-day post-hoc audit found **ten reproducible defects (issues #900–#909)** in work that
had passed every prose gate, adversarial review, and CI. Every rule below is pinned to a
shipped defect or a session-transcript observation, not theory.

## The failure taxonomy (what cheap-model work actually gets wrong)

1. **Self-consistent wrong mental model** — code and test encode the same wrong assumption,
   so the suite is green (#900: a dead recovery branch pinned by a test that monkeypatched a
   fault production cannot produce).
2. **Unverified environmental claims written into artifacts** — comments, workflows, docs
   (#902: `GITHUB_TOKEN`-created PRs trigger no CI; a false "pipefail" comment shipped from
   memory; ADR-59's wrong `domain_col` values for feeds nobody had fetched).
3. **Input-class subset** on parsers/regexes/guards (#903 IDN labels, #904 punycode TLDs,
   #907 tabs, #908 parens-in-strings, #920 case-folding).
4. **Sibling-axis subset** — fixing one axis of a symmetric structure (#858→#900 five-fix
   chain; PR #881's missed port axis; #901's CE/Plus mixing). Includes the audit's own
   orchestrator: a negative status grep (`-v implemented`) ate ADR-52's "Not yet
   implemented" and dropped it from a sweep.
5. **House-pattern violations** — prose conventions dropped under context pressure (#905).
6. **Self-exemption** — an agent deviating from a MUST rule with fabricated authorization
   ("per session config", transcript-verified).

## The principles that answer it

- **Required fields beat virtues.** Cheap models reliably fill required fields and reliably
  drop optional exhortations. Every check became a named field in an artifact (brief /
  handoff / gate record); an empty field is a visible failure, a skipped check says SKIPPED.
- **The producer never grades its own work.** Verification is a fresh agent that
  *re-derives*: re-runs gates, re-executes the red proof, reads the full diff item-by-item.
  Reading a handoff is not verification. This caught the strongest model in the loop (the
  ADR-52 miss), not just the cheapest.
- **Execution-grounded everything.** A claim without a run artifact is ASSUMED. Reviews must
  probe ("Empirically verified: …"), red→green is executed with output pasted — never
  "reasoned through" — and environmental facts are probed before being written down.
- **Enumerate from the source, never from memory.** The planner generates coverage matrices
  and hostile-input rows from grep / the version matrix / the structure's own definition.
  Implementers execute enumerated lists well and under-generate them reliably. Corollary:
  prefer positive filters (`Status: Proposed`) over negative ones (`-v implemented`).
- **The determinism ladder: script > workflow > skill prose.** Push each step to the lowest
  layer that can hold it. Scripts for exact answers (checkers, polls). Workflows for fixed
  shapes needing agents (fan-outs, per-item validation, implementer→verifier pairs) with
  schema-forced returns. Skill prose only for judgment and user interaction (verdicts,
  HALT/resume, landing). Each demotion removes a place a tired model can improvise.
- **Context engineering.** Law front-loaded (CLAUDE.md trimmed 1320→724, mechanically
  enforced rules collapsed to one line naming their enforcer); detail just-in-time
  (`workflow-reference.md` annex — still policy, read on contact); discipline re-injected
  per prompt by a `UserPromptSubmit` hook (rules stated once in a long file do not survive
  context pressure — hooks do).
- **Reality outranks the brief.** Every phase prompt carries the override line (prior
  RESULTS + live tree win on any conflict) and the ESCALATE contract (a falsified premise
  stops the step; it is never silently patched). Planner briefs contain errors in every
  era — the durable defence is an implementer instructed to disprove the brief.

## What was built (and where it lives)

| Piece | Where |
| ----- | ----- |
| The delegation contract (BRIEF / HANDOFF / GATE fields, canonical gate table, evidence rules, hypothesis-ledger debugging) | `CLAUDE.md` "The delegation contract" |
| Mechanical orchestrator gates (re-executed red proof, full-diff tick-off, vacuity checks, committed gate records) | `/adr-phase` 6b, `/gh-issue` 7b |
| Spec floor: phase prompts must carry the contract blocks | `scripts/check_phase_prompts.py` (pre-commit + CI), `/spec-lint`, `/adr-create` |
| Ad-hoc work under the contract; hypothesis-ledger debugging | `/delegate`, `/debug` |
| Deterministic multi-agent shapes | `.claude/workflows/`: `review-fanout` (3-lens PR review + execution-grounded verify), `phase-step` (implementer→verifier pair), `triage-findings` (per-finding validation pipeline), `adr-investigate` (evidence-tagged investigation fan-out) |
| Drift control | `SessionStart` + per-prompt `UserPromptSubmit` capsule hooks; `permissions.deny` for `git stash` |
| Review-source policy | Copilot requested + waited (bounded); CodeRabbit 5-minute rule on rate limits (its notice states the resume time); Snyk advisory — only a terminal `failure` where it actually ran gates anything |
| Prompt retrofits | All Proposed-ADR prompts (25/32/33/34/52/54/55) carry the contract blocks; the checker gates every Proposed ADR incl. future prompts of 51/56/57 |

Open follow-ups: #921 (src↔tests CI pairing gate), #922 (version-literal checker), #923
(PreToolUse bash guard), #925 (Stop-hook done-claim validator — spec + canary rollout), plus
mutation spot-checks as an optional gate step.

## Skills vs workflows — the working rules

- Skills calling skills is fine at **depth ≤ 2** when the callee is a genuine reusable
  contract (`pr-merge-flow → pr-comments/pr-merge`). Costs: each hop loads a full SKILL.md,
  and inter-skill state travels as prose. Never chain for code-reuse aesthetics.
- Skills call **workflows by name** for any fixed multi-agent shape — strictly better than
  describing the shape in prose and letting each session improvise it.
- Workflows cannot pause for user input: anything with an `AskUserQuestion` fork stays in
  the skill. Self-exiting background `bash` loops remain right for pure waits (no agents
  needed).
- Keep an **inline fallback** in the skill for environments without the Workflow tool; the
  workflow packages the contract, it must never be the only statement of it.

## Verification economics (why this is worth the tokens)

Generation is cheap and confident; verification is where cheap models earn trust. The
measured pattern: an execution-grounded Sonnet verifier at high effort finds real, reproducible
defects that the same model as a read-only reviewer misses — including defects planted by a
stronger model. Budget accordingly: spend planner tokens on the brief (enumeration, hostile
inputs) and on independent verification, not on longer implementation prompts. A review that
did not execute anything is an opinion; treat quota-limited bots as absent reviewers, never as
clean passes; and re-review fix commits — review fixes are new, unreviewed code and a known
defect entry path.
