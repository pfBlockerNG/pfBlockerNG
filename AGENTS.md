# pfBlockerNG — agent bootstrap (canonical)

This file = **canonical, vendor-neutral agent policy bootstrap**. Claude Code load it
through `CLAUDE.md` (`@AGENTS.md` import), Codex and Grok native, Copilot via
`.github/copilot-instructions.md`. Detailed policy live in `.agents/policy/`, domain
context in `.agents/context/` and `docs/misc/` — load per routing table below, never
all at once. Shared behavior change land there, never in vendor copy.

## Scope — the pfBlockerNG-org default

These rules, plus active client settings and lifecycle hooks, = default way of
working for **every repository in the `pfBlockerNG` GitHub organization**; repo-local
canonical-policy rule win for that repo only. *How we work* (principles, delegation,
worktrees, landing, tests, issues, commits) carry over; *this package mechanics*
(DNSBL pipeline, smoke suites, pkg repo, language specifics) do not.

## Working principles — don't guess

- **Never assume** — read source of truth, investigate live state, confirm
  genuine fork before build. Clean grep of one file not proof; plausible memory not
  fact.
- **Ambiguity:** pick obvious option and proceed when one exist; `AskUserQuestion`
  only when choice genuinely user's (unclear intent, diverging defensible
  approaches, architecturally significant change). Apply to autonomous flows too.
- **Evidence:** claim without run artifact = ASSUMED; environmental claims written into
  artifacts probed in-session first; no self-exemption from MUST rule without quoting
  authorizing user message; debugging list ≥2 hypotheses + discriminating probe
  before any fix edit (incident index: `docs/history/incidents.md`).

## Never-list (hard invariants)

- All repository work happen in dedicated git worktree — cut via
  `scripts/agent/work-branch.sh <issue|adr> <NN> [title...] --worktree`; never hand-derive
  branch slug.
- Dev-only classes (ADR text, skills, agent workflows/config, documentation-only) commit
  direct to `devel` after fetch + rebase, still from worktree; anything touching
  `src/`, `tests/`, or CI take full rebase-only-PR flow with independent review.
- Merge PRs by squash only (a server-side rebase lands PR commits unsigned);
  history stay strictly linear; rebase onto latest base
  before every push, PR, or CI/smoke dispatch; clean diff before push.
- Push every green, final commit to its remote branch immediately; work never stay only on
  local branch. Dev-only commits push to `devel`; code branches push to own remote
  branch.
- Landing change ≠ committing it: mean commit, push, open non-draft PR, address
  every review round, and squash-merge it (dev-only classes land at push to `devel`).
  Report work landed only after that complete; otherwise report real state.
- Behaviour change need test-first red→green proof: reproduction test executed RED
  before any production edit, frozen byte-identical, re-run GREEN unchanged — executed
  runs, never reasoned through.
- Every change ship WITH its tests; no coverage theater (every test carry assertion
  that fail on regression); `www/` change carry reachable UI coverage required by
  `.agents/policy/testing.md`.
- No direct Python interpreter invocation ON appliance. Consumers invoke
  `/usr/local/pkg/pfblockerng/pfb_python.sh`; that wrapper alone derive exact versioned
  path from installed package dependency. `pfb_python_interpreter()` delegate to wrapper
  for compatibility and test probes. Otherwise use PHP or POSIX sh. Shell = POSIX sh
  under strict ash/dash semantics.
- Every registered config field go through `PfbConfig` — never direct `config_*_path`.
- No orphaned waits: harness-tracked work get no timer; every untracked wait has hard
  cap + deadline and die with its task.
- `--no-verify` for humans, not agents. Never weaken canonical mandate without quoted
  user authorization.
- Accepted/Implemented ADR bodies and artifacts immutable — corrections append dated
  amendments.
- Read whole GitHub issue (title, body, every comment) before working it.

Enforcement mechanical where possible: `.githooks/` pre-commit/prepare-commit-msg/
pre-push, CI, and `scripts/agent/run-gates.sh` authoritative; lifecycle hooks carry
client mechanics.

## Repository intelligence routing

At session start read `.agents/context/repository-intelligence.md`: it owns
`scripts/agent/ensure-codegraph.sh`, `codegraph_explore`, `codegraph serve --mcp`,
Serena, and Graphify, and it carries the hard invariants for the per-worktree
`.codegraph/` index, Serena's active project root, and the tracked root graph.

## Routing table — read on trigger, not up front

| Task touches | Read first |
| ------------ | ---------- |
| delegating any step; validating a handoff | `.agents/policy/delegation.md` |
| a ticket / fresh-session execution | `.agents/policy/workflow.md` (roles: `agent-roles.md`) |
| waiting on anything external | `.agents/policy/waits.md` |
| committing, branching, worktrees, attribution | `.agents/policy/git.md` |
| session layouts, managed-remote, resume | `.agents/policy/sessions.md` |
| landing a PR, review findings | `.agents/policy/landing.md` |
| a PR review bot / Fair Usage quota notice | `.agents/policy/coderabbit.md` |
| a GitHub issue (triage gates, lifecycle) | `.agents/policy/issues.md` |
| writing/changing tests; running suites | `.agents/policy/testing.md` |
| writing code (any language) | `.agents/policy/coding.md` + `.agents/context/lang-<php\|python\|shell>.md` per touched language |
| a live pfSense box / generated artifacts | `.agents/context/pfsense-live.md` |
| `tests/smoke/**` | `.agents/context/smoke.md` |
| release, tags, pkg repo | `.agents/context/release.md` |
| legacy ADR corpus (acceptance, amendments) | `.agents/policy/legacy-adr-flow.md` |
| config fields / `PfbConfig` | `docs/misc/config-gateway.md` |
| process spawn / `timeout(1)` / daemon waits | `docs/misc/external-process-waits.md` |
| `pfb_unbound.py`, manifest, swap/watcher | `docs/misc/architecture-notes.md` "DNSBL/ABP pipeline" |
| `pfb_update_check` / `pfb_download` | architecture-notes "Change detection / content hashing" (ADR-42) |
| IP alias tables / reload path | architecture-notes ADR-40; scheduling/cron → ADR-43; Uber aliases → ADR-11 |
| `www/` UI | architecture-notes "Web UI test tiers" + `lang-php.md`; Alerts/Reports pages → `docs/misc/alerts-reports-pipeline.md` |
| PSL / TLD Allow / HSTS / TOP1M refresh | `docs/misc/<public-suffix-list\|tld-lists\|hsts-preload-list\|top1m-providers>.md` |
| docs-only change; min-CE version bump | `git.md` dev-only classes; `docs/misc/version-bump-runbook.md` (stubs: `scripts/update-pfsense-stubs.py`) |

Delegation shape: substantial coding work planned/gated by **top tier**, implemented
by **small-tier** sub-agents, every step gated by independent small-tier verifier via
brief → handoff → gate contract; top tier handle small one-step fixes and
docs/config/settings/skills direct. Tiers top/mid/small map to models in
`.agents/model-tiers.conf` (disjoint from effort words — "high" always effort value).
New implementation-plan ADRs stopped (wayfinder map #1383).

Test law (five principles, full text in `testing.md`): red-before/green-after test-first
proof · every change ships with its tests · no coverage theater · front-end changes need
front-end tests · tests document intent.

## Repository structure

```text
pfBlockerNG/
├── src/                   # Production code — mirrors the pfSense filesystem; releases ship ONLY src/
│   └── usr/local/
│       ├── pkg/pfblockerng/   # pfblockerng.inc/.sh, pfb_unbound.py, list_scripts/, installers
│       ├── share/             # info.xml
│       └── www/               # Web UI (PHP pages, JS, widgets, wizards)
├── tests/                 # pytest; php/ (PHPUnit); smoke/ (+ui/); phpcs/; shell/; js/
├── legacy/               # Historical records excluded from active checks
│   ├── ADRs/             # Historical ADR corpus (plans = wayfinder maps)
│   ├── ADR_RESULTS/      # Root-level legacy ADR gate/handoff artifacts
│   ├── archive/          # Completed one-shot tooling
│   └── benchmarks/       # Frozen benchmark harnesses
├── .agents/               # policy/ + context/ + repo-owned skills/ + model-tiers.conf
├── docs/misc/             # Dev-only notes: architecture-notes, runbooks; docs/history/ = incidents
├── scripts/               # Dev tooling: deploy.sh, setup-hooks.sh, policy checkers, agent/ ops
└── stubs/                 # pfsense/ (PHPStan/IDE) + python/ (unboundmodule) — not shipped
```

`main` = Stable, `devel` = Development; tag scheme via `scripts/release-version.sh`
(pre-releases from `devel`, stable from `main`).

## Communication

Two style exceptions get normal professional grammar: external/public-facing
text (issues, PR bodies, commits) and documentation. Commits:
`<scope>: <imperative summary>`. While working ADR/issue/PR, prefix replies with
one-line status marker `<emoji> ***ID***(***#PR***): ***Title***` (~28 chars; 📝 authoring ·
🏗️ implementing ADR · 🤔 investigating · 🛠️ fixing · 👀 awaiting review · ⏳ awaiting CI ·
🏁 merged/cleanup); omit on plain conversational turns.

## Vendor adapters

Vendor-specific surfaces live in each vendor's own adapter, never in this neutral file.
Read the named adapter at session start:

- **Claude Code** → `CLAUDE.md` (`@AGENTS.md` import; hooks `.claude/settings.json`,
  skills `.claude/skills/` → `.agents/skills/`, marker `CLAUDECODE=1`).
- **Codex** → `.agents/context/codex-adapter.md` (native bootstrap; noun table,
  subagents, attribution, resume, hook/marker).
- **OMP** → `.agents/context/omp-adapter.md`.
- **GitHub Copilot** → `.github/copilot-instructions.md` plus
  `.agents/context/copilot-adapter.md` (custom agents `.github/agents/`, attribution).
- **Grok** → `GROK.md` plus `.agents/context/grok-adapter.md` (native bootstrap;
  markers `GROK_SESSION_ID` / `GROK_AGENT`).
