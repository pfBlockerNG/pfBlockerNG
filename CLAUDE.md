# Shared agent policy — pfBlockerNG

`CLAUDE.md` is the historical discovery filename and the canonical policy source
for every supported agent client. Claude Code reads it directly; Codex reads it
through [`AGENTS.md`](AGENTS.md), whose only job is translating runtime surfaces.
Shared behavior belongs here or in the referenced annexes, never in a duplicated
vendor summary.

## Scope — the pfBlockerNG-org default

These rules, **plus** the active client's project + user settings and lifecycle hooks,
are the **default way of working for every repository in the `pfBlockerNG` GitHub
organization** — not only `pfBlockerNG/pfBlockerNG`. A repo-local canonical-policy rule
wins for that repo, and only there.

**Carries over (how we work):** communication, Working principles, the delegation contract,
worktrees + the rebase-only landing flow (`.agents/policy/landing.md`), branch naming, the test-coverage
mandate, linting discipline, GitHub-issue handling + labels, commit style. **Does not carry
over (this package's mechanics):** the DNSBL/ABP pipeline, smoke/UI suites, the pkg repo,
ports/release plumbing, and the language/runtime specifics tied to this package. When in
doubt: a rule about *mechanics* is local; a rule about *how we work* is org-wide.

Displaced detail (still policy, read when the task touches it): the
[`.agents/policy/`](.agents/policy/) and [`.agents/context/`](.agents/context/) files and the
`docs/misc/` annexes each compressed section points at.

---

## Working principles — don't guess

The top rule: **never assume — read the source of truth, investigate the live state, and
confirm a genuine fork before building.** A clean grep of one file is not proof; a plausible
memory is not a fact.

### Ambiguity — confirm before you build

**Pick the obvious option and proceed when there is one; pause and ask (`AskUserQuestion`)
when the choice is genuinely the user's to make**: unclear requirement/intent, more than one
defensible approach diverging in ways the user would care about, or an architecturally
significant change (the DNSBL/ABP pipeline, the manifest boundary, the zero-downtime
swap/watcher, a `config.xml` schema/migration, a privilege/security surface, public
behaviour). Don't guess through that fork — but don't ask what the code, the request, or a
sensible default already answers. Applies to autonomous flows too.

### Investigate, don't assume — read sources, not proxies (the live system)

Verify against the source of truth and the effective live state; never infer presence/absence
from one generated artifact. The per-service gotchas (chroots, `include:` chains,
CLI-effective state, `config.xml` vs generated files — each cost a real misdiagnosis):
[`.agents/context/pfsense-live.md`](.agents/context/pfsense-live.md).

### Resolve pfSense-provided PHP functions from upstream

A missing/ambiguous pfSense-provided PHP function is resolved from the real source at every
supported ref, resolved by release date; **prefer stubbing the real function over an
exception/workaround.** Full ladder + ref-resolution recipe:
[`.agents/context/lang-php.md`](.agents/context/lang-php.md).

### Evidence rules (planner and implementer alike)

- **A claim without a run artifact is ASSUMED.** Every load-bearing fact in an ADR, brief, or
  triage verdict carries the command + output (or a doc citation fetched this session) that
  proved it. Facts marked ASSUMED must be verified before any step relies on them.
- **Environmental/platform claims written INTO artifacts** (code comments, workflows, docs —
  default shells, token semantics, external-service behaviour, third-party feed formats) must
  be probed or doc-verified **in-session, before being written**. A plausible memory is not a
  fact (a false "pipefail" comment shipped from memory; #902 shipped a CI contract that
  `GITHUB_TOKEN` event suppression made unfulfillable; ADR-59 shipped wrong `domain_col`
  values for feeds nobody had fetched). **Briefs are artifacts too**: an environmental claim
  a brief embeds in its build instructions (YAML, comments, commands) carries its probe
  evidence inline or is tagged ASSUMED — PR #933's pipefail no-op gate was seeded by the
  planner's own brief and caught only at the independent gate (#935).
- **No self-exemption.** Deviating from any MUST rule requires quoting the authorizing user
  message verbatim in the report. "Per session config" or "acceptable here" without a citation
  is fabricated authorization — a real observed failure, not a hypothetical.
- **Debugging = hypothesis ledger.** Before any fix edit: list ≥2 candidate hypotheses, the
  discriminating probe for each (what output confirms/refutes), run the probe, record the
  actual output. Only a CONFIRMED hypothesis gets a fix; the ledger rides the handoff so the
  gate can audit the causal chain instead of trusting the patch.

### Plan top-tier, implement small-tier

Three capability tiers — **top / mid / small** (deliberately disjoint from the effort-level
words, so "high" always means an effort value; machine-readable mapping in
`.agents/model-tiers.conf`, role families in
[`.agents/policy/agent-roles.md`](.agents/policy/agent-roles.md)). Substantial coding work is
planned and gated by the top tier and implemented by small-tier sub-agents, with an
independent small-tier verifier gating every step; the top tier implements small one-step
fixes — and docs / config / settings / skills — directly. Ticket execution follows the
fresh-session workflow ([`.agents/policy/workflow.md`](.agents/policy/workflow.md)). **New
implementation-plan ADRs stop now** (wayfinder map #1383); implemented ADRs remain immutable
historical records. Full tier, effort, and mode-propagation rules:
[`.agents/policy/delegation.md`](.agents/policy/delegation.md).

### The delegation contract (brief → handoff → gate)

Three fixed artifacts govern **every** delegated step; every check is a named field in an
artifact, and **an empty or missing field is a gate failure** — never a judgment call. The
brief's mandatory sections (coverage matrix enumerated from source, hostile-input rows, the
ESCALATE contract), the handoff's fixed fields (executed gates + red→green proof pasted),
the gate's mechanical re-derivation, and the **canonical gates table** (single source of
truth; `scripts/agent/run-gates.sh`):
[`.agents/policy/delegation.md`](.agents/policy/delegation.md).

---

## Test coverage (mandatory)

Tests are how a change proves itself. **Five non-negotiable principles govern every change —
unit, integration, E2E, smoke, or UI. Each is a hard gate: a change that violates any one is
NOT done, no matter what the line-coverage number says.**

1. **A test is EVIDENCE the change works — for a behaviour change it MUST fail before and pass
   after, and the proof is TEST-FIRST.** Author the reproduction test(s) **before touching
   production code**, at full suite quality (every standard here applies — they ship in the
   suite and double as the defect's in-suite reproduction), and execute them on the untouched
   code: they **FAIL for the exact reason the change addresses**. From that red run the tests
   are **frozen** — byte-identical until green (a temporary skip/disable while developing is
   fine, but the committed file matches the red-run content exactly; record `git hash-object`
   of each test file at red time). After the change the SAME tests, **zero edits**, **PASS** —
   one green run proving both that the tests test the condition and that the fix works. Only
   then write the further tests the change needs. A test written after the fix, or edited
   between red and green, is evidence of nothing — same for a test already green before the
   change. **Two exceptions:** behaviour-**PRESERVING** work (refactors, ADR prep phases) pins
   the *existing* behaviour as an oracle and stays green across the change — still mandatory;
   and **brand-new code with no pre-existing behaviour to be wrong** needs no red run against
   the void — the only possible red there is a missing symbol/file, an *existence* test,
   itself coverage theater. Its tests still ship with it asserting real behaviour, and any
   change it makes to EXISTING observable behaviour still gets its red-first proof.
2. **Every change ships WITH its tests.** "The existing suite still passes" is **not**
   coverage of a new change.
3. **NEVER coverage theater.** A test must *validate* the code, not merely *execute* it — it
   carries an assertion that would **fail on a regression**. Green at 100% line coverage with
   no failable assertion is **rejected**.
4. **Front-end changes REQUIRE front-end tests.** A change touching `www/` must carry UI tests
   (ADR-14). **Tier A (`ui_render`) is always required.** **Tier B (`ui_e2e`/`ui_browser`) is
   REQUIRED IFF the change is observable *only* in Tier B** — which explicitly includes a
   **new page**, a **multi-step flow** (anything spanning more than one request/interaction),
   and **visual/structural** changes (element positioning/addition/removal, layout). When in
   doubt, add Tier B.
5. **Tests express the change's INTENT — they are documentation, not just coverage.** Name and
   comments state the intended outcome being pinned, never the mechanics of how it is coded.

The five above are the law; how to satisfy them (branch coverage, before-state assertions,
self-encapsulation, BDD structure, expected-vs-actual output, the red canary):
[`.agents/policy/testing.md`](.agents/policy/testing.md).

### ADR acceptance — automated tests, not a manual sign-off

Legacy ADR corpus only — acceptance and post-merge amendment rules:
[`.agents/policy/legacy-adr-flow.md`](.agents/policy/legacy-adr-flow.md).

---

## Communication

**Mandatory at every session start (enforced by the `SessionStart` hook):** activate **both**
modes — ponytail at `full` (`/ponytail:ponytail` plugin form or `/ponytail` vendored form,
whichever exists; laziest working solution) and `/caveman` (terse, full technical accuracy). Ponytail governs what you build; caveman how you talk. A
per-prompt `UserPromptSubmit` hook re-injects the discipline capsule; the hooks are the
mechanism, this line is the rule.

Two style exceptions — still concise, but normal professional grammar: **external /
public-facing text** (issue/PR comments, PR bodies, commit messages) and **documentation**
(Markdown, code comments, docblocks, ADR text).

### Work-context marker

While actively working **an ADR, a GitHub issue, or a PR**, begin every reply with a one-line
status marker (plain markdown, no ANSI escapes), format
`<emoji> ***ID***(***#PR***): ***Title***` — ids/title ***bold+italic***, separators plain,
~28-char budget including the `(#PR)` group (trim the title with `…`). IDs: `ADR-NN` / `#NN`;
a PR belonging to an item appends `(#PR)`. Omit the marker on plain conversational turns.

| Emoji | State |
| ----- | ----- |
| 📝 | creating/authoring an ADR |
| 🏗️ | implementing an ADR |
| 🤔 | investigating a GitHub issue |
| 🛠️ | implementing/fixing a GitHub issue |
| 👀 | a PR is awaiting review |
| ⏳ | a PR is awaiting CI |
| 🏁 | a PR is merged — cleaning up |

Examples: `🛠️ ***#43***(***#56***): ***TLD-Allow KeyError on…***` ·
`🏗️ ***ADR-10***(***#56***): ***ABP precedence rework***`

---

## Code standards

### Naming, comments, conventions, linting

Follow the file's established naming pattern; comments state constraints, not narration
(default budget ≤3 lines; enforced diff-scoped by `scripts/check_comment_narration.py`); the
ADR-28 code-quality conventions and the full linter/checker inventory:
[`.agents/policy/coding.md`](.agents/policy/coding.md).

### Languages

Per-language rules load with the touched language: [`lang-php.md`](.agents/context/lang-php.md),
[`lang-python.md`](.agents/context/lang-python.md),
[`lang-shell.md`](.agents/context/lang-shell.md). Hard invariants that bear repeating: **no
Python interpreter ON the appliance** (PHP or POSIX sh; `pfb_unbound.py` is the sole
exception; enforced by `scripts/check_appliance_python.py`) and **POSIX sh only** for shell
(strict ash/dash semantics, not merely bashism-free).

### External processes — launching and waiting

Before code that runs `timeout(1)`, `mwexec_bg()`, a spawned daemon, or a live-tail/poll
loop, read [`docs/misc/external-process-waits.md`](docs/misc/external-process-waits.md)
(FreeBSD `timeout` is a process reaper by default; `mwexec_bg()` returns no PID; a daemon
inheriting the capture pipe blocks `exec()`).

### Config gateway — PfbConfig (ADR-29)

`PfbConfig` (`pfblockerng_extra.inc`) is the single access point for every registered
`installedpackages/pfblockerng*` scalar field — never direct `config_*_path` on a registered
key (sniff-enforced). Contract, storage adapter rule, and per-field inventory:
[`docs/misc/config-gateway.md`](docs/misc/config-gateway.md) — read it before adding a
field.

---

## Worktrees (mandatory for AI agents)

**Every AI agent MUST do all repository work in its own dedicated git worktree** — never the
primary checkout, never shared with another agent (concurrent agents race on the filesystem,
index, `HEAD`, refs). Cut it with `scripts/agent/work-branch.sh <issue|adr> <NN> [title...]
--worktree`; session layouts: [`.agents/policy/sessions.md`](.agents/policy/sessions.md).
**Dev-only classes need no PR** (ADR text, skills, agent workflows/configuration, and
documentation-only changes): still a worktree, but commit/push **directly to `devel`**
(fetch + rebase first); anything touching `src/`, `tests/`, or CI uses the full worktree +
rebase-only-PR flow. Mechanics, branch/worktree reuse rules, and gotchas:
[`.agents/policy/git.md`](.agents/policy/git.md).

## Git hooks

Activate once: `sh scripts/setup-hooks.sh` (idempotent; an agent runs it at session start if
`git config core.hooksPath` is not `.githooks`). `pre-commit` lints staged file types;
`prepare-commit-msg` aborts agent commits in the primary checkout and appends the owner's
`Co-authored-by:` trailer; `pre-push` enforces the tag scheme + the fetched-history rule.
The `--no-verify` bypass is for humans, not agents. Detail:
[`.agents/policy/git.md`](.agents/policy/git.md).

---

## Running tests

`python3 -m pytest` (after ANY change to `pfb_unbound.py` or `tests/`); `composer install`
once, then `vendor/bin/phpunit`. Environment gotchas that read as fake baseline failures
(zstd encoder, root-skips, pre-existing reds → tracking issue) and the PHPUnit shim/doubles
bootstrap: [`.agents/policy/testing.md`](.agents/policy/testing.md).

## Architecture pointers

Read [`docs/misc/architecture-notes.md`](docs/misc/architecture-notes.md) before touching
these (full designs in each `.ADRs/ADR_NN_*/`):

- **DNSBL/ABP pipeline** (ADR-06/07/10/12): preprocessing→Python, ABP support, zero-downtime
  swap/watcher, update hooks — read before touching `pfb_unbound.py`, the manifest boundary,
  the swap/watcher, or the hooks.
- **Feed change detection (ADR-42):** content-addressed, not mtime-based — tagged `xxh128`
  sidecars + a real conditional GET. Read "Change detection / content hashing" before
  touching `pfb_update_check`, `pfb_download`, or any change-detection site.
- **IP alias-table reloads (ADR-40):** a table reloads iff its **final membership set**
  changed (`pfb_alias_set_different()` vs the `/var/db/aliastables` mirror);
  `pfb_alias_delta_mode` (`auto`/`delta`/`replace`; upgrades grandfather-seeded to
  `replace`) and `pfb_alias_delta_batch` control the apply path.
- **Scheduling & trigger API (ADR-43):** `sync_package_pfblockerng()` takes
  `{scope, force, trigger}`; the legacy verbs are deprecated thin adapters; scheduling is one
  cron tick + the due-ledger (`pfb_due_ledger.json`; absent ⇒ due-now-jittered, past ⇒ due,
  corrupt ⇒ fail-safe due); knobs `pfb_tick_interval` (15) and `pfb_quiet_hours` ('').
- **Aggregated "Uber" aliases (ADR-11):** opt-in Native `pfB_<Type>_Aggregated_v{4,6}` built
  in-pass, mtime-gated, by `pfblockerng.sh aggregate`; membership pinned in
  `tests/php/AggregateMemberListTest.php`.

---

## Smoke tests (ADR-04 — live pfSense VM) — READ BEFORE TOUCHING `tests/smoke/`

`tests/smoke/` installs the branch `.pkg` on a REAL pfSense CE VM and asserts pfBlockerNG
end-to-end. It **always runs locally first** via `scripts/local-smoke.sh` + the owner's
`PFB_BOXES` pool — never claim it "needs CI" or "cannot run on this host". Every non-obvious
truth (on-box probing, `helpers.unique_domain()`, block shapes, tcsh, the enable chain, UI
tiers, selective dispatch, fixtures):
[`.agents/context/smoke.md`](.agents/context/smoke.md).

---

## Branches and releases

`main` = Stable, `devel` = Development. Tag scheme (single source of truth
`scripts/release-version.sh`): pre-releases cut from `devel` only, stable from `main` only.
Channels table, release-notes pipeline, and the self-hosted pkg repository (ADR-17/20 — the
catalog is keyed by *varver*, never `${ABI}`):
[`.agents/context/release.md`](.agents/context/release.md).

**Merge PRs by rebase only** — `gh pr merge <N> --rebase`; never a merge commit, never
squash. History stays strictly linear (`main` always an ancestor of `devel`).

**Default landing flow** after completing any issue or code change: review feedback first,
then merge, per [`.agents/policy/landing.md`](.agents/policy/landing.md) — the single
source for the landing mechanics AND the adversarial reviewer contract (an independent
review in a fresh read-only context runs on EVERY PR; effort floors, model-by-size rules,
delta-scoped convergent re-reviews, CodeRabbit/Snyk handling all live there, not here).
Only the dev-only no-PR classes are exempt.

**Applying review findings follows the coverage-matrix discipline** — re-enumerate a
finding's class from the source, tree-wide; a retired token gets a zero-hit tree grep; a
downgraded-but-real finding still lands as a tracking issue before the merge
([`.agents/policy/landing.md`](.agents/policy/landing.md)). **Accepted/Implemented ADR
bodies, phase documents, and Results artifacts are immutable**: a later fix appends a dated
amendment, never a rewrite
([`.agents/policy/legacy-adr-flow.md`](.agents/policy/legacy-adr-flow.md)).

**Rebase onto the latest base before every push, PR, or CI/smoke dispatch**, and **clean
the diff before you push/PR**: [`.agents/policy/git.md`](.agents/policy/git.md) "Rebase and
diff hygiene".

### Branch naming (ADRs and issues)

**ADR** `adr/{NN}-{slug}`, **issue** `issue/{NN}-{slug}`. **Never hand-derive the slug**:
`scripts/agent/work-branch.sh <issue|adr> <NN> [title...]` implements the mandatory
sanitiser (`--worktree` also cuts the worktree at an absolute path). Sanitiser spec +
collision rule: [`.agents/policy/git.md`](.agents/policy/git.md).

#### Managed-remote sessions: branch policy + cross-session resume

One branch per work item, always. Preferred config permits the canonical
`adr/{NN}-{slug}`/`issue/{NN}-{slug}` branches; a hard-pinned `claude/*` branch replaces the
convention with `*-RESUME:` sentinels + prior-work discovery. Full policy:
[`.agents/policy/sessions.md`](.agents/policy/sessions.md).

---

## GitHub issues

**Read the whole issue before working it** — title, body, AND every comment
(`gh issue view <N> --comments`); later comments routinely revise/narrow/downgrade/invalidate
the original (issue #25). Never act on the opening text alone. Branch: `issue/{NN}-{slug}`.

The scanner/audit finding gate (actionability, HARDENING-ONLY), the TypeError-class tracker
(#1143), and the issue-state lifecycle (native signals, #1388 — assignee, `Fixes #N`,
dependencies, `needs-info`): [`.agents/policy/issues.md`](.agents/policy/issues.md).

---

## Commit style

`<scope>: <imperative summary>` (follow the existing log — e.g. `ci: simplify pytest
invocation`). No trailing period; body optional for non-obvious changes. Attribution
(Verified badge, author/committer/signing shapes, coauthor trailers):
[`.agents/policy/git.md`](.agents/policy/git.md).

---

## No orphaned waits — every trigger dies with its task

Harness-tracked work (a `Workflow`, an `Agent`, a background Bash task) re-invokes you on
completion — arm nothing for it. Every untracked wait is self-terminating by construction
(hard cap + deadline inside the loop), follows the ≈2 h heartbeat ladder, and dies with its
task via the cancel-on-resolution sweep; no `gh` ⇒ wakeup-paced MCP checks. Full rules +
ladder: [`.agents/policy/waits.md`](.agents/policy/waits.md).

---

## Repository structure

```text
pfBlockerNG/
├── src/                   # Production code — mirrors the pfSense filesystem; releases ship ONLY src/
│   └── usr/local/
│       ├── pkg/pfblockerng/   # pfblockerng.inc/.sh, pfb_unbound.py, list_scripts/, installers
│       ├── share/             # info.xml
│       └── www/               # Web UI (PHP pages, JS, widgets, wizards)
├── tests/                 # pytest suite; tests/php/ (PHPUnit); tests/smoke/ (+ ui/); tests/phpcs/
├── docs/misc/             # Dev-only notes: architecture-notes, runbooks; docs/history/ = incident index
├── scripts/               # Dev tooling: deploy.sh, setup-hooks.sh, policy checkers, stub generator
├── stubs/                 # pfsense/ (PHPStan/IDE) + python/ (unboundmodule) — not shipped
└── pyproject.toml, phpunit.xml, phpcs.xml.dist, composer.json, .editorconfig, …
```

## Updating documentation

**Documentation-only changes skip CI** (`paths-ignore` on `**/*.md` + `docs/`) but still lint
pre-commit and still use a worktree + the normal landing flow. Update `README.md` when
workflow steps, min supported CE, or dev tooling change. **Stubs (`stubs/pfsense/`):**
regenerate on a min-CE bump (`scripts/update-pfsense-stubs.py`);
`globals.php`/`logging.php`/`supplemental.php` are always hand-maintained; prefer a real stub
over a `phpstan-baseline.neon` suppression. **Bumping the minimum pfSense version** is a
multi-step runbook: [`docs/misc/version-bump-runbook.md`](docs/misc/version-bump-runbook.md).

<!-- rtk-instructions v2 -->
## RTK (Rust Token Killer) - Token-Optimized Commands

### Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:

```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

### RTK Commands by Workflow

#### Build & Compile (80-90% savings)

```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

#### Test (60-99% savings)

```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

#### Git (59-80% savings)

```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

#### GitHub (26-87% savings)

```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

#### JavaScript/TypeScript Tooling (70-90% savings)

```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

#### Files & Search (60-75% savings)

```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

#### Analysis & Debug (70-90% savings)

```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

#### Infrastructure (85% savings)

```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

#### Network (65-70% savings)

```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

#### Meta Commands

```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

### Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->
