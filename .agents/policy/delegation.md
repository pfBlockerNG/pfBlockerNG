# Delegation — tiers, brief/handoff/gate, canonical gates

Scope: delegate any step to sub-agent, validate what come back. Load when:
planning, spawning, or gating delegated work (ticket packets and ad-hoc alike).

## Plan top-tier, implement small-tier

Provider-neutral procedures name three capability tiers — **top / mid / small**
(disjoint from effort-level words, so "high" always mean effort value). Machine-readable
mapping: `.agents/model-tiers.conf`. **Top tier** = `claude-fable-5-1` in Claude,
`gpt-5.6-sol` in Codex; **mid tier** = `claude-opus-5` and `gpt-5.6-terra`; **small tier**
= `claude-sonnet-5` and `gpt-5.6-luna`. Tier pick model, not effort knob: workflows still
set required effort independently. Role families on these tiers (explorer, planner,
implementer, verifier, reviewer, publisher, coordinator) specified with vendor bindings in
[`agent-roles.md`](agent-roles.md); `scripts/check_agent_roles.py` keep every vendor
definition aligned when either side change.

Substantial coding work **planned and gated by top tier** (fall back to mid when top
unavailable) and **implemented by small-tier** sub-agents: planner split task into steps,
small-tier implementer execute each, **independent small-tier verifier gate every step**
(never brief author's model), planner validate returned records before next — that per-step
gating is what make cheaper implementer safe. Ticket execution follow fresh-session workflow
([`workflow.md`](workflow.md)); ad-hoc coding follow same shape. The **work agent** may
implement a small one-step fix **directly**, including **docs / config / settings /
skills**. Named GitHub issues still spawn. Delegation for non-trivial, multi-step
`src/`/`tests/`/CI work.
**Review-fix rounds are canonical direct case** (owner, 2026-08-08): small fix the
**work agent** understands — or reviewer's proposed solution it agree with — applied by
that session itself, tests included, never spawned onward. **Ticket pickup is
orchestrator per workflow.md**: the top-level session named the issue spawns a work
agent; it does not implement the ticket. The work agent still does small one-step
fixes directly (handful of lines in one production file + couple tests + doc
files). Hard constraint on ALL direct work: session context usage ≤ 50% — past 50%
session MUST delegate. Owner override: "implement here" / "no spawn".

- **Per-step verifier always small tier** (owner directive 2026-07-14) — never top-tier model
  that authored brief; different model read with different blind spots. Top model's
  cross-referencing reserved for correctness+hostile review leg ([`landing.md`](landing.md)).

- **Implementer may re-delegate when subtask genuinely split** (parallel siblings, verifier
  per finding) — platform enforce own nesting-depth cap. **Accountability never split**:
  spawning agent verify nested work itself before it enter its handoff, every handoff/gate
  field stay spawner's to fill, nested delegate's defect is spawner's defect at gate above.
  Delegating whole brief downward unexamined still a defect — split work, not responsibility.
- **Planner's brief to small-tier implementer follow delegation contract below** — vague or
  wrong brief is planner bug, and shipped defects trace directly to brief bugs.
- **New implementation-plan ADRs stop now** (wayfinder map #1383): big work charted as map of
  tickets with committed specs ([`workflow.md`](workflow.md)); unimplemented ADRs migrate to
  specs and tickets (#1389); implemented ADRs stay immutable historical records. Retired
  ADR-phase orchestration (`/adr-phase`, `phase-step`) live on only in those records.
- **Small tier follow every directive of canonical policy (AGENTS.md + its routed files).**
  Implementer cheaper, not exempt.
- **Agent and reasoning lever selection:** coordinator selects agent, model, and
  reasoning lever (effort, thinking budget, deliberation depth) in active
  harness per role, not a rigid matrix:
  - **Implementers:** Maximize deliberation depth (`xhigh`, max budget) to meet
    invariants and coverage.
  - **Reviewers:** Match deliberation and capability to lens demands:
    *correctness + hostile inputs* needs deep reasoning against logic, races, and
    security boundaries; *test honesty* requires critical behavioral evaluation (contract
    defense, vacuity checks, fault realism, and executed scratch mutations as probes,
    not mere framework output); *over-engineering (Ponytail)* needs simplicity and
    taste; *contract conformance* needs structured spec checks.
  - **Independence & auditability:** Review legs need fresh, independent context
    (never self-grading). Audit comments record invocation parameters (harness,
    model, reasoning lever, or `n/a`).

## The delegation contract (brief → handoff → gate)

**Review legs are spawned by the seat landing the PR** (owner, 2026-08-31):
independence comes from the reviewer's fresh context, not from a different box or
seat — never route the four legs to another seat, and spawning them needs no ask
beyond the assignment.

Three fixed artifacts govern **every** delegated step — ticket packets under
[`workflow.md`](workflow.md) and ad-hoc delegation alike. Design principle: **cheap models
reliably fill required fields and reliably drop optional virtues**, so every check is named
field in artifact, and **empty or missing field is gate failure** — never judgment call.
Contract exist because prose-only gates demonstrably failed: one-day post-hoc audit
(issues #900–#909) found ten reproducible defects in work that passed every prose gate and
review.

### THE BRIEF (planner → implementer) — mandatory sections

1. **Objective** — one outcome, tied to work item.
2. **Required reading** — `file:line` refs (identifiers, not pasted bodies — implementer read
   just-in-time in own fresh context); prior step's handoff.
3. **Coverage matrix** — when change touch anything with siblings (v4/v6, address/port,
   CE/Plus versions, parse modes, providers, every caller of touched symbol, every branch of
   touched conditional): planner enumerate ALL rows **from source** — grep output, the
   version-matrix file, structure's own definition — **never from memory**. Each row map to
   test or explicit justified deferral. Brief saying "all X" without enumerated list is
   invalid; planner generating enumeration is the point (implementers execute enumerated lists
   well and under-generate them reliably: #858→#900 five-fix chain, #901, #904, PR #881's
   missed port axis). Tool whose scope span file types (checker/parser over scan roots) get
   mandatory axis "per in-scope file type × its comment/quote syntax", enumerated from roots'
   actual extensions (`git ls-files <roots>`) — PR #937 shipped PHP false-positive class
   because only languages author thought of got rows (#941).
4. **Hostile-input rows** — for any new/changed parser, regex, or input guard planner supply
   adversarial input set with expected outcomes: punycode/IDN labels, empty input,
   header/no-header, quotes + shell/regex metacharacters, tabs and consecutive spaces,
   oversized values, wrong encoding (#903, #904, #907, #908, #920 all misses of exactly these).
5. **Constraints** — do-NOT-touch list, plus **never-weaken rule**: brief may never weaken
   canonical-policy mandate. In particular, red→green is **test-first** (testing.md principle
   #1): reproduction test authored and executed RED before any production edit, frozen
   byte-identical, re-run GREEN unchanged after — **executed runs with output pasted**, never
   "reasoned through" or "verified by reading". Comments follow "Comments — constraint, not
   narration" (Code standards): gate-facing justification go in handoff, never code.
6. **Verification** — canonical gates (table below) plus per-item acceptance checks, each
   runnable command with expected observable (shape "WHEN `<command/input>` THEN
   `<observable>`"), mapping 1:1 to tests the step ships.
7. **ESCALATE contract** — if any factual claim in brief/ADR contradicted by code or live
   probe, **STOP and return structured blocker**; never silently patch plan, never proceed on
   premise you just falsified. Reality outrank brief, loudly. Environmental claim brief tag
   ASSUMED (or embed with no evidence) get probed before anything built on it — same STOP rule
   if probe refute it. Same rule when fix require **inventing mechanism brief never named**
   (exemption layer, state machine, heuristic): escalate, or at minimum return
   DONE-WITH-DEVIATION — never plain DONE. PR #937's only blocking bug lived in improvised
   exemption layer that had no hostile-input rows because nobody planned for it to exist (#943).
8. **Implementer scope — trust brief, don't re-investigate it.** Brief embed its evidence
   (facts carry their run artifacts), so implementer's reading scope is brief + its named
   refs + code it edits: no re-fetching issue/ADR, no re-running brief's enumeration greps, no
   re-deriving its matrix — independent verifier and PR review carry the skepticism,
   duplicating them in implementer is pure step-budget burn. ESCALATE (item 7) is reactive:
   *encountered* contradiction trigger it; proactively auditing brief does not.

### THE HANDOFF (implementer → planner) — fixed fields, missing field = gate reject

- **Verdict**: DONE / DONE-WITH-DEVIATION / BLOCKED.
- **What changed**: files + one-line why each; commit hash.
- **Gates**: exact commands run + pasted output tails (pass/fail counts) — never bare claims.
- **Red→green proof** (behaviour-changing steps): reproduction test's FAILING output —
  executed BEFORE any production edit — AND its PASSING output after, both pasted from
  executed runs, plus test file's `git hash-object` at red time (must equal committed file —
  Test coverage #1's freeze).
- **Coverage matrix**: every brief row ticked with its test, or its stated deferral.
- **Deviations / judgment calls** (or "none"); **carry-forward** for next step.

### THE GATE (planner, after every step) — mechanical, evidenced, artifact-producing

Producer never grade own work; gate **re-derives**, never merely re-reads. Every item below
mandatory; skipped item recorded as SKIPPED with reason, so unrun check visible instead of
silent. **Terse prose, full checks** — brevity apply to gate report's wording, never to which
checks run.

1. **Re-run canonical gates yourself** — `scripts/agent/run-gates.sh --diff <base>`
   (table below; "touched" computed from diff's file types **plus cross-language consumers** —
   suite that parses artifact the diff changes run regardless of its language).
2. **Re-execute red proof yourself** for behaviour changes — never accept handoff's claim.
   Revert production paths to pre-fix commit (tests stay), require pinning test to FAIL,
   restore, require PASS, enforce freeze (`git hash-object` of each committed reproduction
   test equal handoff's red-time hash — test edited between red and green, or with no red-time
   hash, prove nothing). Pre-fix commit is `HEAD~1` only when step landed exactly one commit;
   follow-up doc/ADR reconciliation or review fix move it. Record the runs.
3. **Read full diff** (`git show` — never `--stat` alone) and tick **every** ACTION-PLAN item
   and **every** coverage-matrix row against what diff actually does. `--stat` cannot see
   hardcoded value, stubbed branch, or silently dropped plan item. Mechanism in diff the brief
   never named = STOP: planner write hostile-input rows for it and their tests land before
   PASS (PR #937's F1, #943).
4. **Test honesty**: no weakened/removed assertions; every "does NOT contain X" assertion has
   X-shaped fixture that could make it fail (vacuity check); no red-run manufactured by
   monkeypatching fault production cannot produce (#900's phantom `OSError`); real failure
   modes exercised through production surface (on-disk corrupt file, not injected exception).
5. **Conventions**: each new public symbol listed beside 3 sibling symbols proving name match
   house pattern (#905); comments/docs mentioning touched symbols reconciled with new reality
   (stale-comment defects recur); any comment/doc claim naming **sibling file or house
   convention** verified by grep — in-repo claims are cheapest probes there are (PR #937
   shipped fabricated "mirrors the URL-encoding checker" lineage, #941); added comments respect
   comment budget ("Comments — constraint, not narration").
6. **Write gate record** — fixed-field block (or per-phase file where skill say so): commands +
   results, red/green evidence, per-item diff verdicts, matrix confirmation, SKIPPED list.
   This artifact is what make skipped check auditable.

### Canonical gates (single source of truth — briefs and gates reference THIS table)

Mechanical runner: `scripts/agent/run-gates.sh [--diff <base>]` (`--plan` to preview) —
change table and runner together.

| Touched | Gates (all must pass) |
| ------- | --------------------- |
| Any diff (always-on) | `sh scripts/agent/check-graph-fresh.sh` — rebuilds `graphify-out/graph.json` (`PYTHONHASHSEED=0`, resolved Graphify launcher) and FAILS when the committed file differs: the commit that moves code moves the graph. Missing Graphify ⇒ FAIL, never SKIP. Fix: `PYTHONHASHSEED=0 graphify update .` + commit |
| Python (`*.py`) | `python3 -m pytest` · `ruff check .` · `ruff format --check .` · `mypy tests/` |
| PHP (`*.php`/`*.inc`) | `php -l` per touched file · `vendor/bin/phpunit` · `composer phpstan` · `composer phpcs -- --standard=phpcs.xml.dist src/` |
| Shell (`*.sh`) | `sh -n` · `shellcheck` (only `src/`, `scripts/`, `.claude/hooks/` — the scope `.githooks/pre-commit` + CI use; `tests/` shellspec specs trip SC2034 false-positives) · `shellspec --shell "$(command -v dash)"` (where specs exist; dash = strict-POSIX ash sibling of FreeBSD sh — bash-as-sh masks appliance divergences. Dash missing ⇒ this hand-run substitution goes empty and shellspec silently auto-detects, while the runner's own `$(command -v dash \|\| command -v sh)` falls back to `sh` — either way, INSTALL dash (`brew`/`apt install dash`) instead of dropping the pin; plain `shellspec` is a last resort and says so in the handoff) |
| Markdown (`*.md`) | `npx markdownlint-cli2` |
| `tests/skip-allowlist.txt` | `python3 -m pytest` — the skip-set checker and its red canary ride the pytest gate, which also carries the two tests that parse the real file (issue #3166) |
| `www/` | Reachable UI coverage exists for the change per test mandate #4 |

## Validating workflow records

What calling session do with fixed-field records delegated implementer/verifier return
(handoff + gate record above). **Validate, don't re-derive**: independent verifier just
re-ran gates, re-executed red proof, read full diff, with pasted evidence — that mandatory
independent gate always execute; calling session skip only redundant third derivation on top
of it.

- Every fixed field non-empty and internally consistent — missing/empty field reject record,
  never judgment call.
- Every evidence entry is executed command + pasted output, not prose.
- Spot-read load-bearing diff hunks the verdicts rest on.
- Do NOT re-run gates, re-execute red proof, or re-read whole diff verifier just processed.
- Reject record with any failed or missing item; rejection mean HALT (or one corrected
  re-run) — never patch record yourself.

## Agent-ops scripts (`scripts/agent/`)

Mechanical procedures the skills used to restate in prose live once, tested, in
`scripts/agent/`: `wait-reviewer.sh` (reviewer-wait state machine), `wait-checks.sh`
(CI wait), `run-gates.sh` (canonical-gates runner), `work-branch.sh` (branch sanitiser +
worktree cutter). Shared contract in `scripts/agent/agent_env.sh`; behaviour pinned by
`tests/shell/agent_*_spec.sh`.

- **Portability contract.** All network access ride `gh`/`git` CLIs — managed cloud
  environments route git/ssh/https through localhost proxy that only those CLIs inherit;
  never call raw endpoints. `gh` absent → script exit **3** with `GH-UNAVAILABLE` message:
  agent fall back to `mcp__github__*` tools with wakeup-paced checks (waits.md rule #4) — MCP
  tools are harness tools, unreachable from inside shell, so fallback cannot live in script.
  Any other missing tool → exit **4** (`TOOL-MISSING`). Exit **2** = usage/precondition,
  **1** = check itself failed, **0** = verdict reached.
- **Agent-maintained.** These scripts encode environment mechanics that drift. When
  environment change break one, agent fix script **in same session** and land it via normal
  flow (scripts are code-bearing: worktree + PR) — never work around it silently in transcript.
- **Hook-context safety.** Git-touching scripts (and any spec whose fixtures run git) scrub
  hook-exported `GIT_DIR`/`GIT_INDEX_FILE`/… via `scripts/lib/git-env-scrub.sh` (ADR-47) —
  inherited hook env otherwise aim fixture git ops at live repository.
- **Gate re-runs vs pre-commit hook (recorded-skip carve-out).** THE GATE item 1's
  `run-gates.sh` re-run may be recorded as SKIPPED for gate the pre-commit hook **provably
  just executed identically**: gater watched that gate's `[pre-commit]` step line pass on
  exact commits being gated, same session, no `--no-verify`. Two hook properties keep this
  narrow: hook **skips missing tools instead of failing** (green commit is not proof gate ran
  — only its step line is), and its shellspec run is **impacted-scoped**, not full suite, so
  it never satisfy canonical full-suite shellspec gate. In practice carve-out cover whole-tree
  `markdownlint`, per-file `sh -n`/`shellcheck`/`php -l` lint gates, and phpstan/phpcs
  analyses (hook run both, memory-capped, off same configs); unit suites (`pytest`,
  `phpunit`) and full shellspec run exist only in `run-gates.sh` and never satisfied by
  pre-commit.
