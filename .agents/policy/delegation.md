# Delegation — tiers, brief/handoff/gate, canonical gates

Scope: delegating any step to a sub-agent, and validating what comes back. Load when:
planning, spawning, or gating delegated work (ticket packets and ad-hoc alike).

## Plan top-tier, implement small-tier

Provider-neutral procedures name three capability tiers — **top / mid / small**
(deliberately disjoint from the effort-level words, so "high" always means an
effort value). The machine-readable mapping is `.agents/model-tiers.conf`: the
**top tier** means `claude-fable-5` in Claude and `gpt-5.6-sol` in Codex; the
**mid tier** means `claude-opus-4-8` and `gpt-5.6-terra`; the **small tier**
means `claude-sonnet-5` and `gpt-5.6-luna`. A tier selects the model, not
the effort knob: workflows still set their required effort independently.
The role families built on these tiers (explorer, planner, implementer,
verifier, reviewer, publisher, coordinator) are specified with their vendor
bindings in [`agent-roles.md`](agent-roles.md);
`scripts/check_agent_roles.py` keeps both vendors' definitions aligned
whenever either side changes.

Substantial coding work is **planned and gated by the top tier** (falling back
to mid when top is unavailable) and **implemented by small-tier** sub-agents:
the planner splits the task into steps, a small-tier
implementer executes each, an **independent small-tier verifier gates every step** (never
the brief author's model), and the planner validates the returned records before the next
— that per-step gating is what makes a cheaper implementer safe. Ticket execution follows
the fresh-session workflow ([`workflow.md`](workflow.md)); for ad-hoc coding, follow the
same shape. The higher
model may implement a fix **directly** when it is relatively small and doable in one step —
and always handles **docs / config / settings / skills** directly. Delegation is for
non-trivial, multi-step `src/`/`tests/`/CI work.

- **The per-step verifier is always small tier** (owner directive 2026-07-14) — never the
  top-tier model that authored the brief; a different model reads with different blind
  spots, and the step gate doesn't need the top tier. The top
  model's cross-referencing is reserved for the **whole-PR review** (the adversarial
  reviewer on a large/complex PR, [`landing.md`](landing.md)), where it sees every
  step's diff at once.

- **An implementer may re-delegate when a subtask genuinely splits** (parallel siblings, a
  verifier per finding) — the platform enforces its own nesting-depth cap, so we add no depth
  rule of our own. **Accountability never splits**: the spawning agent verifies nested work
  itself before it enters its handoff, every handoff/gate field stays the spawner's to fill,
  and a nested delegate's defect is the spawner's defect at the gate above. Delegating the
  whole brief downward unexamined is still a defect — split work, not responsibility.
- **The planner's brief to the small-tier implementer follows the delegation contract below** — a vague or wrong
  brief is a planner bug, and a handful of real shipped defects trace directly to brief bugs
  (a half-enumerated axis, a vacuous test spec, an unverified "fact" stated as truth).
- **New implementation-plan ADRs stop now** (wayfinder map #1383): big work is charted as a
  map of tickets with committed specs ([`workflow.md`](workflow.md)); unimplemented ADRs
  migrate to specs and tickets (#1389); implemented ADRs remain immutable historical
  records. The retired ADR-phase orchestration (`/adr-phase`, `phase-step`) lives on only
  in those historical records.
- **Mode propagation to delegates is mechanical** — the `SubagentStart` hook
  (`.claude/settings.json`) injects the ponytail + caveman capsule into every spawned
  sub-agent; the capsule itself carries the rules (reviewer carve-out; "terse prose,
  verbatim evidence"). Briefs add a mode line only for a non-default level (e.g. `ultra`).
- **The small tier follows every directive of the canonical policy (AGENTS.md + its routed files).** The implementer is cheaper, not exempt.
- **Run at effort xhigh or better** — the session default in `.claude/settings.json`
  (`effortLevel: xhigh`), and stated explicitly in every spawn (never rely on inheritance).

## The delegation contract (brief → handoff → gate)

Three fixed artifacts govern **every** delegated step — ticket packets under
[`workflow.md`](workflow.md) and ad-hoc delegation alike. The design principle: **cheap models reliably fill
required fields and reliably drop optional virtues**, so every check is a named field in an
artifact, and **an empty or missing field is a gate failure** — never a judgment call. This
contract exists because prose-only gates demonstrably failed: a one-day post-hoc audit
(issues #900–#909) found ten reproducible defects in work that had passed every prose gate
and review.

### THE BRIEF (planner → implementer) — mandatory sections

1. **Objective** — the one outcome, tied to the work item.
2. **Required reading** — `file:line` refs (identifiers, not pasted bodies — the implementer
   reads just-in-time in its own fresh context); the prior step's handoff.
3. **Coverage matrix** — when the change touches anything with siblings (v4/v6, address/port,
   CE/Plus versions, parse modes, providers, every caller of a touched symbol, every branch of
   a touched conditional): the planner enumerates ALL rows **from the source** — grep output,
   the version-matrix file, the structure's own definition — **never from memory**. Each row
   maps to a test or an explicit justified deferral. A brief saying "all X" without the
   enumerated list is invalid; the planner generating the enumeration is the point
   (implementers execute enumerated lists well and under-generate them reliably: the
   #858→#900 five-fix chain, #901, #904, PR #881's missed port axis). A tool whose scope
   spans file types (a checker/parser over scan roots) gets a mandatory axis "per in-scope
   file type × its comment/quote syntax", enumerated from the roots' actual extensions
   (`git ls-files <roots>`) — PR #937 shipped a PHP false-positive class because only the
   languages the author thought of got rows (#941).
4. **Hostile-input rows** — for any new/changed parser, regex, or input guard the planner
   supplies the adversarial input set with expected outcomes: punycode/IDN labels, empty
   input, header/no-header, quotes + shell/regex metacharacters, tabs and consecutive spaces,
   oversized values, wrong encoding (#903, #904, #907, #908, #920 were all misses of exactly
   these).
5. **Constraints** — the do-NOT-touch list, plus the **never-weaken rule**: a brief may never
   weaken a canonical-policy mandate. In particular, red→green is **test-first** (testing.md principle #1):
   the reproduction test authored and executed RED before any production edit, frozen
   byte-identical, re-run GREEN unchanged after — **executed runs with output pasted**, never
   "reasoned through" or "verified by reading". Comments follow "Comments —
   constraint, not narration" (Code standards): gate-facing justification goes in the
   handoff, never the code.
6. **Verification** — the canonical gates (table below) plus per-item acceptance checks, each
   a runnable command with its expected observable (the shape "WHEN `<command/input>` THEN
   `<observable>`"), mapping 1:1 to the tests the step ships.
7. **ESCALATE contract** — if any factual claim in the brief/ADR is contradicted by the code
   or a live probe, **STOP and return a structured blocker**; never silently patch the plan,
   never proceed on a premise you have just falsified. Reality outranks the brief, loudly.
   An environmental claim the brief tags ASSUMED (or embeds with no evidence) is probed
   before anything is built on it — same STOP rule if the probe refutes it. Same rule when
   the fix requires **inventing a mechanism the brief never named** (an exemption layer, a
   state machine, a heuristic): escalate, or at minimum return DONE-WITH-DEVIATION — never
   plain DONE. PR #937's only blocking bug lived in an improvised exemption layer that had
   no hostile-input rows because nobody had planned for it to exist (#943).
8. **Implementer scope — trust the brief, don't re-investigate it.** The brief embeds its
   evidence (facts carry their run artifacts), so the implementer's reading scope is the
   brief + its named refs + the code it edits: no re-fetching the issue/ADR, no re-running
   the brief's enumeration greps, no re-deriving its matrix — the independent verifier and
   the PR review carry the skepticism, and duplicating them in the implementer is pure
   step-budget burn. ESCALATE (item 7) is reactive: an *encountered* contradiction
   triggers it; proactively auditing the brief does not.

### THE HANDOFF (implementer → planner) — fixed fields, missing field = gate reject

- **Verdict**: DONE / DONE-WITH-DEVIATION / BLOCKED.
- **What changed**: files + a one-line why each; the commit hash.
- **Gates**: the exact commands run + pasted output tails (pass/fail counts) — never bare
  claims.
- **Red→green proof** (behaviour-changing steps): the reproduction test's FAILING output —
  executed BEFORE any production edit — AND its PASSING output after, both pasted from
  executed runs, plus the test file's `git hash-object` at red time (must equal the committed
  file — Test coverage #1's freeze).
- **Coverage matrix**: every brief row ticked with its test, or its stated deferral.
- **Deviations / judgment calls** (or "none"); **carry-forward** for the next step.

### THE GATE (planner, after every step) — mechanical, evidenced, artifact-producing

The producer never grades its own work; the gate **re-derives**, it never merely re-reads.
Every item below is mandatory; a skipped item is recorded as SKIPPED with the reason, so an
unrun check is visible instead of silent. **Terse prose, full checks** — brevity applies to
the gate report's wording, never to which checks run.

1. **Re-run the canonical gates yourself** — `scripts/agent/run-gates.sh --diff <base>`
   (table below; "touched" is computed from the diff's
   file types **plus cross-language consumers** — a suite that parses an artifact the diff
   changes runs regardless of its language).
2. **Re-execute the red proof yourself** for behaviour changes — never accept the handoff's
   claim. Run `scripts/agent/verify-red-proof.sh --worktree <path> --test-cmd '<cmd>'
   --src <path>... --hash <test>=<red-time-sha>... [--base-ref <pre-fix-commit>]` — it
   reverts the src paths to `--base-ref` (default `HEAD~1`; tests stay), requires the test
   to FAIL, restores, requires PASS, and enforces the freeze (`git hash-object` of each
   committed reproduction test equals the handoff's red-time hash — a test edited between
   red and green, or with no red-time hash, proves nothing). A step that lands more than
   one commit (a follow-up doc/ADR reconciliation, a review fix) passes the true pre-fix
   commit explicitly via `--base-ref` — `HEAD~1` then names the wrong baseline. Record its
   verdict lines.
3. **Read the full diff** (`git show` — never `--stat` alone) and tick **every** ACTION-PLAN
   item and **every** coverage-matrix row against what the diff actually does. `--stat` cannot
   see a hardcoded value, a stubbed branch, or a silently dropped plan item. A mechanism in
   the diff the brief never named = STOP: the planner writes hostile-input rows for it and
   their tests land before PASS (PR #937's F1, #943).
4. **Test honesty**: no weakened/removed assertions; every "does NOT contain X" assertion has
   an X-shaped fixture that could make it fail (vacuity check); no red-run manufactured by
   monkeypatching a fault production cannot produce (#900's phantom `OSError`); real failure
   modes exercised through the production surface (an on-disk corrupt file, not an injected
   exception).
5. **Conventions**: each new public symbol listed beside 3 sibling symbols proving the name
   matches the house pattern (#905); comments/docs mentioning touched symbols reconciled with
   the new reality (stale-comment defects recur); any comment/doc claim naming a **sibling
   file or house convention** verified by grep — in-repo claims are the cheapest probes there
   are (PR #937 shipped a fabricated "mirrors the URL-encoding checker" lineage, #941);
   added comments respect the comment budget ("Comments — constraint, not narration").
6. **Write the gate record** — a fixed-field block (or per-phase file where the skill says
   so): commands + results, red/green evidence, per-item diff verdicts, matrix confirmation,
   the SKIPPED list. This artifact is what makes a skipped check auditable.

### Canonical gates (single source of truth — briefs and gates reference THIS table)

Mechanical runner: `scripts/agent/run-gates.sh [--diff <base>]` (`--plan` to preview) —
change the table and the runner together.

| Touched | Gates (all must pass) |
| ------- | --------------------- |
| Python (`*.py`) | `python3 -m pytest` · `ruff check .` · `ruff format --check .` · `mypy tests/` |
| PHP (`*.php`/`*.inc`) | `php -l` per touched file · `vendor/bin/phpunit` · `composer phpstan` · `composer phpcs -- --standard=phpcs.xml.dist src/` |
| Shell (`*.sh`) | `sh -n` · `shellcheck` (only `src/`, `scripts/`, `.claude/hooks/` — the scope `.githooks/pre-commit` + CI use; `tests/` shellspec specs trip SC2034 false-positives) · `shellspec --shell "$(command -v dash)"` (where specs exist; dash = strict-POSIX ash sibling of FreeBSD sh — bash-as-sh masks appliance divergences. Dash missing ⇒ this hand-run substitution goes empty and shellspec silently auto-detects, while the runner's own `$(command -v dash \|\| command -v sh)` falls back to `sh` — either way, INSTALL dash (`brew`/`apt install dash`) instead of dropping the pin; plain `shellspec` is a last resort and says so in the handoff) |
| Markdown (`*.md`) | `npx markdownlint-cli2` |
| `www/` | Tier-A `ui_render` coverage exists for the change (test mandate #4) |

## Validating workflow records

What the calling session does with the fixed-field records a delegated implementer/verifier
returns (the handoff + gate record above).
**Validate, don't re-derive**: the independent
verifier just re-ran the gates, re-executed the red proof, and read the full diff, with
pasted evidence — that mandatory independent gate always executes; the calling session
skips only a redundant third derivation on top of it.

- Every fixed field non-empty and internally consistent — a missing/empty field rejects
  the record, never a judgment call.
- Every evidence entry is an executed command + pasted output, not prose.
- Spot-read the load-bearing diff hunks the verdicts rest on.
- Do NOT re-run the gates, re-execute the red proof, or re-read the whole diff the
  verifier just processed.
- Reject a record with any failed or missing item; rejection means HALT (or one corrected
  re-run) — never patch the record yourself.

## Agent-ops scripts (`scripts/agent/`)

The mechanical procedures the skills used to restate in prose live once, tested, in
`scripts/agent/`: `wait-reviewer.sh` (reviewer-wait state machine), `wait-checks.sh`
(CI wait), `verify-red-proof.sh` (red→green re-execution + freeze hash),
`run-gates.sh` (canonical-gates runner), `work-branch.sh` (branch sanitiser +
worktree cutter). Shared contract in `scripts/agent/agent_env.sh`; behaviour pinned
by `tests/shell/agent_*_spec.sh`.

- **Portability contract.** All network access rides the `gh`/`git` CLIs — managed
  cloud environments route git/ssh/https through a localhost proxy that only those
  CLIs inherit; never call raw endpoints. `gh` absent → the script exits **3** with a
  `GH-UNAVAILABLE` message: the agent falls back to `mcp__github__*` tools with
  wakeup-paced checks (waits.md rule #4) — MCP tools are harness
  tools, unreachable from inside a shell, so the fallback cannot live in the script.
  Any other missing tool → exit **4** (`TOOL-MISSING`). Exit **2** = usage/precondition,
  **1** = the check itself failed, **0** = verdict reached.
- **Agent-maintained.** These scripts encode environment mechanics that drift. When an
  environment change breaks one, the agent fixes the script **in the same session** and
  lands it via the normal flow (scripts are code-bearing: worktree + PR) — never works
  around it silently in a transcript.
- **Hook-context safety.** Git-touching scripts (and any spec whose fixtures run git)
  scrub the hook-exported `GIT_DIR`/`GIT_INDEX_FILE`/… via
  `scripts/lib/git-env-scrub.sh` (ADR-47) — inherited hook env otherwise aims fixture
  git ops at the live repository.
- **Gate re-runs vs the pre-commit hook (recorded-skip carve-out).** THE GATE item 1's
  `run-gates.sh` re-run may be recorded as SKIPPED for a gate the pre-commit hook
  **provably just executed identically**: the gater watched that gate's `[pre-commit]`
  step line pass on the exact commits being gated, same session, no `--no-verify`. Two
  hook properties keep this narrow: the hook **skips missing tools instead of failing**
  (a green commit is not proof a gate ran — only its step line is), and its shellspec
  run is **impacted-scoped**, not the full suite, so it never satisfies the canonical
  full-suite shellspec gate. In practice the carve-out covers whole-tree
  `markdownlint`, the per-file `sh -n`/`shellcheck`/`php -l` lint gates, and the
  phpstan/phpcs analyses (the hook runs both, memory-capped, off the same configs);
  the unit suites (`pytest`, `phpunit`) and the full shellspec run exist only in
  `run-gates.sh` and are never satisfied by pre-commit.
