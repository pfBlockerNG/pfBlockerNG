# pfBlockerNG — agent bootstrap (canonical)

This file is the **canonical, vendor-neutral agent policy bootstrap**. Claude Code loads it
through the thin [`CLAUDE.md`](CLAUDE.md) adapter (`@AGENTS.md` import); Codex reads it
natively. Detailed policy lives in [`.agents/policy/`](.agents/policy/), domain context in
[`.agents/context/`](.agents/context/) and `docs/misc/` — loaded per the routing table
below, never all at once. Shared behavior changes land there, never in a vendor copy.

## Scope — the pfBlockerNG-org default

These rules, plus the active client's settings and lifecycle hooks, are the default way of
working for **every repository in the `pfBlockerNG` GitHub organization**; a repo-local
canonical-policy rule wins for that repo only. *How we work* (principles, delegation,
worktrees, landing, tests, issues, commits) carries over; *this package's mechanics*
(DNSBL pipeline, smoke suites, pkg repo, language specifics) do not.

## Working principles — don't guess

- **Never assume** — read the source of truth, investigate the live state, and confirm a
  genuine fork before building. A clean grep of one file is not proof; a plausible memory is
  not a fact.
- **Ambiguity:** pick the obvious option and proceed when there is one; `AskUserQuestion`
  only when the choice is genuinely the user's (unclear intent, diverging defensible
  approaches, architecturally significant change). Applies to autonomous flows too.
- **Evidence:** a claim without a run artifact is ASSUMED; environmental claims written into
  artifacts are probed in-session first; no self-exemption from a MUST rule without quoting
  the authorizing user message; debugging lists ≥2 hypotheses + a discriminating probe
  before any fix edit (incident index: `docs/history/incidents.md`).

## Never-list (hard invariants)

- All repository work happens in a dedicated git worktree — cut via
  `scripts/agent/work-branch.sh <issue|adr> <NN> [title...] --worktree`; never hand-derive
  the branch slug.
- Dev-only classes (ADR text, skills, agent workflows/config, documentation-only) commit
  directly to `devel` after fetch + rebase, still from a worktree; anything touching
  `src/`, `tests/`, or CI takes the full rebase-only-PR flow with independent review.
- Merge PRs by rebase only; history stays strictly linear; rebase onto the latest base
  before every push, PR, or CI/smoke dispatch; clean the diff before you push.
- A behaviour change needs its test-first red→green proof: reproduction test executed RED
  before any production edit, frozen byte-identical, re-run GREEN unchanged — executed
  runs, never reasoned through.
- Every change ships WITH its tests; no coverage theater (every test carries an assertion
  that fails on regression); a `www/` change carries Tier-A `ui_render` coverage.
- No Python interpreter ON the appliance (PHP or POSIX sh; `pfb_unbound.py` is the sole
  exception); shell is POSIX sh under strict ash/dash semantics.
- Every registered config field goes through `PfbConfig` — never direct `config_*_path`.
- No orphaned waits: harness-tracked work gets no timer; every untracked wait has a hard
  cap + deadline and dies with its task.
- `--no-verify` is for humans, not agents. Never weaken a canonical mandate without quoted
  user authorization.
- Accepted/Implemented ADR bodies and artifacts are immutable — corrections append dated
  amendments.
- Read the whole GitHub issue (title, body, every comment) before working it.

Enforcement is mechanical where possible: `.githooks/` pre-commit/prepare-commit-msg/
pre-push, CI, and `scripts/agent/run-gates.sh` are authoritative; lifecycle hooks carry the
communication-mode capsules.

## Routing table — read on trigger, not up front

| Task touches | Read first |
| ------------ | ---------- |
| delegating any step; validating a handoff | `.agents/policy/delegation.md` |
| a ticket / fresh-session execution | `.agents/policy/workflow.md` (roles: `agent-roles.md`) |
| waiting on anything external | `.agents/policy/waits.md` |
| committing, branching, worktrees, attribution | `.agents/policy/git.md` |
| session layouts, managed-remote, resume | `.agents/policy/sessions.md` |
| landing a PR, review findings | `.agents/policy/landing.md` |
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

Delegation shape: substantial coding work is planned/gated by the **top tier**, implemented
by **small-tier** sub-agents, every step gated by an independent small-tier verifier via the
brief → handoff → gate contract; the top tier handles small one-step fixes and
docs/config/settings/skills directly. Tiers top/mid/small map to models in
`.agents/model-tiers.conf` (disjoint from effort words — "high" is always an effort value).
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
├── tests/                 # pytest suite; tests/php/ (PHPUnit); tests/smoke/ (+ ui/); tests/phpcs/
├── .agents/               # policy/ + context/ + skills/ (canonical) + model-tiers.conf
├── docs/misc/             # Dev-only notes: architecture-notes, runbooks; docs/history/ = incidents
├── scripts/               # Dev tooling: deploy.sh, setup-hooks.sh, policy checkers, agent/ ops
└── stubs/                 # pfsense/ (PHPStan/IDE) + python/ (unboundmodule) — not shipped
```

`main` = Stable, `devel` = Development; tag scheme via `scripts/release-version.sh`
(pre-releases from `devel`, stable from `main`).

## Communication

Session-start hooks activate ponytail (build lazy) + caveman (talk terse); the capsules are
the mechanism. Two style exceptions get normal professional grammar: external/public-facing
text (issues, PR bodies, commits) and documentation. Commits:
`<scope>: <imperative summary>`. While working an ADR/issue/PR, prefix replies with the
one-line status marker `<emoji> ***ID***(***#PR***): ***Title***` (~28 chars; 📝 authoring ·
🏗️ implementing ADR · 🤔 investigating · 🛠️ fixing · 👀 awaiting review · ⏳ awaiting CI ·
🏁 merged/cleanup); omit on plain conversational turns.

## Vendor adapters

**Claude Code:** [`CLAUDE.md`](CLAUDE.md) (imports this file; Claude-only surfaces: hooks in
`.claude/settings.json`, skills at `.claude/skills/` symlinked from `.agents/skills/`,
git-hook marker `CLAUDECODE=1`).

**Codex** translates canonical nouns mechanically:

| Canonical / Claude surface | Codex surface |
| --- | --- |
| `/name` or `.claude/skills/name` | `$name` from `.agents/skills/name` (same source). |
| `Agent` / planner / implementer / verifier | Codex subagent per `.codex/agents/*.toml`; roles + tier bindings in `.agents/policy/agent-roles.md` (checked by `scripts/check_agent_roles.py`). |
| `AskUserQuestion` | The current Codex user-input surface. |
| Background Bash `run_in_background: true` | One harness-tracked background command; never shell `&`. |
| Claude `Co-authored-by` attribution | Never credit Claude for Codex work; no verified Codex coauthor identity — keep the human's signed identity and disclose Codex authorship in the PR audit/footer. |
| Claude public-comment footer | `🤖 Generated by OpenAI Codex and posted on behalf of @<login>.` Never identify Codex output as Claude. |
| Claude-only status/token/UI hooks | No equivalent unless `.codex/hooks.json` maps one. |

Codex specifics: reviews use `adversarial-reviewer`(-`top`/-`mid`) per
`.agents/policy/landing.md`; `work-branch.sh --worktree` resolves the primary checkout from
a Codex session worktree; the Codex `SessionStart` hook runs the branch-freshness check; in
Codex desktop, sandboxed `gh auth status` failure is not conclusive — retry via the approved
elevated path; `.codex/config.toml`/`hooks.json`/agents load only after trust; the shared
git-hook marker is `CODEX_THREAD_ID`; resume via `codex resume` (`--last`,
`<session-id-or-name>`).

@RTK.md

Respond terse like smart caveman. All technical substance stay. Only fluff die. Drop
articles/filler/pleasantries/hedging; fragments OK; technical terms exact; code unchanged.
Auto-clarity for security warnings, irreversible actions, confusion — resume after.
Code/commits/PRs written normal. Stop: "stop caveman" / "normal mode".
