# Research: vendor-neutral agent source architecture (#1384)

Ticket: [#1384](https://github.com/pfBlockerNG/pfBlockerNG/issues/1384), map
[#1383](https://github.com/pfBlockerNG/pfBlockerNG/issues/1383). Research only —
no migration is implemented here.

Question: how should shared policy, skills, roles, MCP configuration, hooks, and
client discovery entrypoints be stored so Claude Code and Codex are equally
capable and neither vendor tree is the semantic source of truth?

Every claim below is cited to an official doc URL, a repo `file:line`, or an
executed command; unverifiable claims are tagged **ASSUMED**.

## 1. Official discovery behavior (primary sources)

### Claude Code

Fetched this session from `code.claude.com/docs` (2026-07-16):

- **Skills** load from `~/.claude/skills/<name>/SKILL.md` (personal),
  `.claude/skills/<name>/SKILL.md` (project), and plugin `skills/` dirs.
  Claude Code skills "follow the [Agent Skills](https://agentskills.io) open
  standard". Source: <https://code.claude.com/docs/en/skills>.
- **Symlinked skills are officially supported**: "A `<skill-name>` entry in the
  enterprise, personal, or project locations can be a symlink to a directory
  elsewhere on disk. Claude Code follows the symlink and reads `SKILL.md` from
  the target directory, and if the same target is reachable from more than one
  location, Claude Code loads the skill once." Source:
  <https://code.claude.com/docs/en/skills> ("Where skills live").
- **Context cost**: skill *descriptions* load at session start; the SKILL.md
  body "loads only when it's used". Source: <https://code.claude.com/docs/en/skills>.
- **Policy**: Claude Code reads `CLAUDE.md`, **not** `AGENTS.md` — but the docs
  give the exact neutral pattern: "If your repository already uses `AGENTS.md`
  for other coding agents, create a `CLAUDE.md` that imports it so both tools
  read the same instructions without duplicating them" — a stub `CLAUDE.md`
  containing `@AGENTS.md` plus optional Claude-specific sections, or a plain
  symlink `ln -s AGENTS.md CLAUDE.md`. Imports load in full at launch, max
  depth 4. Source: <https://code.claude.com/docs/en/memory> ("AGENTS.md",
  "Import additional files").
- **Hooks** are wired in `settings.json` (`hooks` key, events such as
  `SessionStart`/`PreToolUse`/`SubagentStart`) and are enforced configuration,
  unlike CLAUDE.md prose. Source: <https://code.claude.com/docs/en/memory>
  (hooks vs CLAUDE.md table) and the live wiring in `.claude/settings.json`.
- **Project MCP** comes from `.mcp.json` at the repo root (live:
  `.mcp.json:1-11`, honored via `"enableAllProjectMcpServers": true` in
  `.claude/settings.json`).

### Codex

Fetched this session from `developers.openai.com/codex` (2026-07-16):

- **Skills**: Codex natively discovers repo skills from **`.agents/skills/`**
  (cwd, parents up to repo root), then `$HOME/.agents/skills`, then
  `/etc/codex/skills` and built-ins. Format: `SKILL.md` with `name` +
  `description` frontmatter; optional `agents/openai.yaml` for UI metadata and
  invocation policy. Startup context: "only skill names, descriptions, and file
  paths load into context, limited to at most 2% of the model's context window,
  or 8,000 characters"; the full SKILL.md loads on selection. Source:
  <https://developers.openai.com/codex/skills>.
- **Project config**: "Codex walks from the project root to your current
  working directory and loads every `.codex/config.toml` it finds"; project
  `.codex/` layers (config, hooks, rules) load **only when the project is
  trusted**. Some keys (`model_provider`, `openai_base_url`, `profile`, …)
  cannot be set at project level. Source:
  <https://developers.openai.com/codex/config-advanced>.
- **Policy**: Codex reads `AGENTS.md` by walking up from cwd to the project
  root (`.git` marker by default); the amount injected on the first turn is
  bounded by `project_doc_max_bytes`. Sources:
  <https://developers.openai.com/codex/config-advanced>,
  <https://developers.openai.com/codex/config-reference>.
- **Hooks**: loaded from `~/.codex/hooks.json`, `~/.codex/config.toml`,
  `<repo>/.codex/hooks.json`, or `<repo>/.codex/config.toml`; command hooks
  supported (`PreToolUse`, `SessionStart`, …); project hooks require trust.
  Source: <https://developers.openai.com/codex/config-advanced>.
- **Roles**: custom subagents are `.codex/agents/*.toml` plus `[agents]` in
  `config.toml`. Source: <https://developers.openai.com/codex/config-advanced>
  (Subagents reference); live: `.codex/agents/` (7 role TOMLs).

## 2. Empirical probes

- **Symlinks in git (macOS worktree, this session)**:
  `git ls-files -s .claude/skills` → 32 entries with mode `120000` (committed
  symlinks) alongside 60 regular files; `readlink .claude/skills/grilling` →
  `../../.agents/skills/grilling` (relative, worktree-safe). `.agents/` itself
  holds 120 regular files, no symlinks — it is the canonical copy.
- **Claude discovery of symlinked skills (live evidence)**: this very session's
  skill listing includes `grilling`, `tdd`, `research`, `code-review`,
  `codebase-design`, `qa`, `prototype`, … — all of which are `120000` symlinks
  into `.agents/skills/`. Claude Code demonstrably discovers and can invoke
  skills through committed relative symlinks.
- **Codex discovery of `.agents/skills/`**: doc-verified (above) but **not
  probed in a live Codex session from here** — tagged ASSUMED-live in §7.
- **Context cost**: `wc -c CLAUDE.md AGENTS.md` → **68,630 B** vs **4,585 B**.
  Claude auto-injects the 68 KB policy in full each session; Codex injects the
  4.6 KB adapter and reads `CLAUDE.md` by tool call when directed. This
  asymmetry is load-bearing for the policy recommendation (§4, §5).
- **Parity guard already exists and is wired**:
  `scripts/agent/check-agent-config-parity.sh` verifies (a) every symlinked
  `.claude/skills/<name>` resolves onto canonical `.agents/skills/<name>`
  (filesystem identity is the parity guarantee), (b) every non-symlinked Claude
  skill/workflow has a `.agents/skills/<name>/SKILL.md` adapter with a textual
  back-reference and matching `name:`, and (c) inverse drift — a stale Codex
  adapter with no canonical source — fails. Run by `.githooks/pre-commit:67-74`
  path-scoped to agent-config changes; inventory pinned by
  `tests/shell/agent_config_parity_spec.sh` in CI.

## 3. Inventory of current surfaces

| Surface | Where it lives today | Classification |
| --- | --- | --- |
| Shared policy body | `CLAUDE.md` (repo root, 68.6 KB) | Vendor-named canonical (content already provider-neutral: tiers, "active client" wording) |
| Codex policy entrypoint | `AGENTS.md` (4.6 KB adapter, mechanical noun mapping) | Adapter |
| Neutral skills (32) | `.agents/skills/<name>/` canonical; `.claude/skills/<name>` committed relative symlink; optional `agents/openai.yaml` | Already-neutral (in-flight migration, HEAD `64cf3769`) |
| Claude-native skills (~26: `adr-*`, `gh-issue`, `pr-merge*`, `delegate`, `spec-lint`, `release*`, `wizard`, `writing-*`, …) | `.claude/skills/<name>/` real dirs | Claude-only; workflow-coupled ones have `.agents/skills/<name>/SKILL.md` Codex adapters (parity-checked) |
| Workflows (6 `.js` programs) | `.claude/workflows/*.js` | Claude-only by design; `.agents/skills/<name>` adapters define the Codex orchestration replacement (`AGENTS.md` mapping table) |
| Roles | `.codex/agents/*.toml` (planner, implementer, analyst[-top], adversarial-reviewer[-mid/-top]) | Codex-only; Claude's equivalents are inline prompts inside `.claude/workflows/*.js` — no `.claude/agents/` exists |
| Model tiers | `.agents/model-tiers.conf` | Already-neutral (single source; both adapters read it) |
| MCP | `.mcp.json` (Claude) + `[mcp_servers.token-savior-recall]` in `.codex/config.toml` (Codex); both exec the shared `scripts/mcp-token-savior.sh` | Duplicated thin manifests over a neutral core script |
| Hooks — semantic | `.claude/hooks/session-branch-sync.sh` (branch freshness/merge-base), `scripts/claude-bash-guard.sh`, `scripts/check_retired_tokens.py` | **Shared semantics living in/wired from the Claude tree**; `.codex/hooks.json` reaches INTO `.claude/hooks/session-branch-sync.sh` with a SHA-256 integrity pin |
| Hooks — vendor UI | statusline, rtk, caveman-stats, vendored-plugin activation (`.claude/hooks/*`, `.claude/settings.json`) | Claude-only, legitimately |
| Hook wiring | `.claude/settings.json` `hooks` vs `.codex/hooks.json` | Vendor-owned by necessity (different event/config schemas) |
| Parity guard | `scripts/agent/check-agent-config-parity.sh` + pre-commit + shellspec | Already-neutral |
| Shared agent tooling | `scripts/agent/*` (work-branch, run-gates, verify-red-proof, waits) | Already-neutral |

**Ticket-premise check**: the premise largely holds, with one correction worth
stating loudly — the repo is **already most of the way to candidate 1** for
skills (canonical `.agents/skills/` + symlinked Claude discovery), and
`.agents/skills/` turns out to be **Codex's native discovery path**, not merely
a neutral convention. The genuinely non-neutral remainders are: (a) the policy
body under the vendor filename `CLAUDE.md`, and (b) shared hook semantics under
`.claude/hooks/` that Codex must reach into cross-tree.

## 4. Candidate evaluation

### C1 — neutral canonical files with symlinked discovery paths

**Best fit for skills; already proven in-tree.** `.agents/skills/` is
simultaneously the neutral canonical home *and* Codex's native discovery path
(zero adapter needed on the Codex side); Claude discovers it through committed
relative symlinks, which its docs explicitly bless. Context cost is identical
to native placement on both clients (metadata at startup, body on invocation —
both docs cited in §1). Failure mode: a dangling symlink — caught mechanically
by the existing parity guard at pre-commit and CI. Platform risk: symlinks are
first-class in git on macOS/Linux (probed: 32 committed `120000` entries
resolve in this macOS worktree); Windows would need Developer Mode — not a
supported dev platform here (`darwin` local, `ubuntu` CI). Not applicable to
policy (Claude does not follow a `CLAUDE.md` symlink chain for *content*
composition as well as `@import` does) or to hooks/MCP/roles (different file
*formats* per vendor, so a symlink cannot bridge them).

### C2 — neutral canonical files with generated adapters

Rejected as a default. Generation adds a build step and its own staleness
class: the generated artifact drifts from the generator input whenever someone
edits the output directly or forgets to regenerate — exactly the failure the
ticket asks about, and strictly worse than the current model where the
committed artifact IS the source and a mechanical guard checks resolution.
At this repo's scale (≈7 roles, 1 MCP server, ≈6 semantic hooks), hand-kept
thin manifests + the parity guard are cheaper than a generator plus the tests
the generator itself would need. Revisit only if manifest count grows an order
of magnitude.

### C3 — repository-local neutral plugin/package with client manifests

Rejected. On the Claude side a skills-dir plugin (`.claude-plugin/plugin.json`)
requires the workspace-trust dialog, and its `hooks/`, `.mcp.json`, and
`agents/` changes need `/reload-plugins` — the skills doc says live change
detection covers `SKILL.md` text only (<https://code.claude.com/docs/en/skills>).
Codex has no plugin runtime at all, so the "package" collapses back to plain
directories for one of the two clients anyway. Highest bootstrap cost, worst
update ergonomics, no capability gain over C1.

### C4 — shared Agent Skills + generated vendor-native roles/hooks/MCP/policy

Half adopted, half rejected. The "shared Agent Skills" half is C1 (both
clients implement the agentskills.io standard — cited §1) and is the
recommendation. The "generated everything else" half inherits C2's staleness
failure mode and is rejected for the same reasons.

### C5 — justified hybrid

**The recommendation** — see §5. Per surface: C1 for skills; the doc-blessed
`@AGENTS.md` import inversion for policy; neutral *scripts* + vendor-native
*wiring* for hooks and MCP; neutral role *contracts* + vendor-native role
*manifests*; Claude-native workflows grandfathered under the ticket's explicit
behavioral-equivalence carve-out (and slated for retirement by map #1383's
strangler cutover regardless).

## 5. Recommendation — per-surface ownership table

| Surface | Canonical (semantic) home | Claude entrypoint | Codex entrypoint | Parity mechanism |
| --- | --- | --- | --- | --- |
| Policy body | **`AGENTS.md`** (repo root — the cross-vendor standard filename Codex reads natively) | `CLAUDE.md` stub: `@AGENTS.md` import + Claude-runtime mapping section | native (first-turn injection, `project_doc_max_bytes`-bounded) | both entrypoints are ≤1-page adapters; guard checks the import line exists |
| Skills (neutral) | `.agents/skills/<name>/` (SKILL.md + optional `agents/openai.yaml`) | committed relative symlink `.claude/skills/<name>` | native discovery of `.agents/skills/` | existing parity guard (symlink-resolution check) |
| Skills (Claude-workflow-coupled) | `.claude/skills/<name>/` (Claude-native, per ticket carve-out) | native | `.agents/skills/<name>/SKILL.md` adapter naming the same contract | existing parity guard (back-reference check) |
| Workflows | `.claude/workflows/*.js` (Claude-native; retired later by #1383 cutover) | native `Workflow` tool | `.agents/skills/<name>` orchestration adapter | existing parity guard |
| Roles | **new** `.agents/roles/<name>.md` — neutral contract: purpose, inputs, outputs, permissions, evidence, routing (the alignment axes #1383 already fixed) | workflow prompts / future `.claude/agents/*` reference the contract file | `.codex/agents/<name>.toml` references the contract file; models from `.agents/model-tiers.conf` | extend parity guard: every vendor role manifest names an existing contract; every contract has ≥1 manifest per vendor (or a recorded N/A) |
| Model tiers | `.agents/model-tiers.conf` (unchanged) | consumed via policy | consumed via `AGENTS.md` mapping + guard | existing guard already validates Codex role models against it |
| MCP | `scripts/mcp-token-savior.sh` (launcher = the semantics; unchanged) | `.mcp.json` thin manifest | `[mcp_servers.*]` in `.codex/config.toml` thin manifest | extend parity guard: same server-name set on both sides, both exec the shared launcher |
| Hooks (shared semantics) | **move scripts to `.agents/hooks/`** (session-branch-sync.sh today; candidates: bash-guard, retired-tokens invocations stay in `scripts/`) | `.claude/settings.json` event wiring | `.codex/hooks.json` event wiring (+ its SHA integrity pin, path updated) | extend parity guard: each shared hook script is referenced by both wirings (or carries a recorded vendor-only exemption) |
| Hooks (vendor UI/UX) | vendor tree, declared vendor-only (statusline, rtk, caveman/ponytail activation) | native | none (per `AGENTS.md`: "No behavioral equivalent unless `.codex/hooks.json` explicitly maps one") | exemption list in the guard |
| Discovery entrypoints | vendor-owned *by definition*, thin-only rule: `CLAUDE.md` stub, `AGENTS.md` header, `.claude/skills` symlinks, `.codex/*` | — | — | guard + review rule: no semantic content in an entrypoint file |

Equal capability: both clients end up reading the same policy body natively
(injection vs `@import`), the same skill sources natively (`.agents/skills/`
directly vs via symlink), the same hook scripts, the same MCP launcher, the
same tier table, and role manifests pinned to one contract file. No surface's
semantics live only in the other vendor's tree.

## 6. Migration sequence (each step independently landable + revertable)

1. **Extend the parity guard first** (`check-agent-config-parity.sh` + its
   shellspec spec): add the MCP server-set check, the shared-hook
   both-wirings check, and the role-contract check (initially against the
   existing `.codex/agents/*.toml` with a temporary allowlist). Guard precedes
   movement so every later step is mechanically checked, red-path demonstrated
   per CLAUDE.md's newly-wired-gate rule.
2. **Hooks**: `git mv .claude/hooks/session-branch-sync.sh .agents/hooks/`;
   update `.claude/settings.json`, `.codex/hooks.json` (path + refreshed SHA
   pin), and any docs. Smallest, lowest-risk semantic de-vendoring step.
3. **Finish the skills migration**: remaining neutral skills →
   `.agents/skills/` + symlink (the pattern HEAD `64cf3769` already applies);
   Claude-workflow-coupled skills stay put pending the #1383 cutover.
4. **Roles**: author `.agents/roles/*.md` contracts extracted from the
   existing `.codex/agents/*.toml` + workflow prompts; point both sides at
   them; flip the guard's role check from allowlist to enforcing.
5. **Policy inversion** — *sequenced after (or together with) the map's
   policy-slimming work, not before*: move the slim hot-policy body into
   `AGENTS.md`; `CLAUDE.md` becomes `@AGENTS.md` + the Claude runtime-mapping
   section (mirror of today's Codex section, which moves into `AGENTS.md`'s
   tail or a per-vendor annex); set `project_doc_max_bytes` in
   `.codex/config.toml` if the slim body still exceeds the default cap.
   Rationale for the ordering: today's 68.6 KB body under `AGENTS.md` would
   collide with Codex's first-turn byte cap (§7 A1), whereas the current
   CLAUDE.md-canonical + AGENTS.md-adapter arrangement is behaviorally
   equivalent in the interim (Codex is *directed* to read the policy, at
   tool-call cost).
6. **MCP**: no file moves (launcher already neutral); the step-1 guard check
   simply starts enforcing manifest-set equality.

All steps are dev-only classes (skills/agent-config/docs) per CLAUDE.md —
worktree + direct-to-devel, no PR required — except any step that touches
`scripts/` guard code with tests, which takes the full PR flow.

## 7. Rollback path

Every step is a rename/symlink/pointer flip with no generated or runtime
state: `git revert` of the step's commit fully restores the prior arrangement,
and the parity guard passes on both sides of each flip (it accepts both the
symlink form and the adapter-back-reference form during migration — probed:
`check-agent-config-parity.sh:64-83` handles exactly this "or vice versa
mid-migration" case). Specifically: hooks rollback = revert the `git mv` +
SHA-pin bump; skills rollback = revert restores the real directory (git
materializes it from the same blobs); policy rollback = revert swaps the
canonical/stub roles back — both clients keep reading policy throughout, since
each intermediate state leaves a valid entrypoint pair. No step deletes
information available only in the moved location.

## 8. Rejected alternatives (summary)

- **Generated adapters as the default (C2/C4-second-half)** — adds a
  build/staleness failure class the ticket explicitly worries about; hand-thin
  manifests + a mechanical guard dominate at this surface count (§4).
- **Repo-local plugin/package (C3)** — trust-dialog + `/reload-plugins`
  friction on Claude, no plugin runtime on Codex, highest bootstrap cost (§4).
- **Symlinking `CLAUDE.md → AGENTS.md`** — doc-supported but strictly worse
  than the `@AGENTS.md` stub: the stub carries the Claude-specific runtime
  mapping that a symlink cannot (§1, memory doc).
- **Immediate policy inversion (before slimming)** — 68.6 KB body vs Codex's
  first-turn byte cap; deferred behind the map's hot-policy-slimming step (§6.5).
- **Duplicating skill bodies per vendor** — the pre-migration state; two
  drifting copies, already being retired by the in-flight `.agents/skills/`
  move; nothing supports resurrecting it.

## 9. ASSUMED facts needing a second-client or human probe

- **A1 (ASSUMED)**: Codex's `project_doc_max_bytes` default is 32 KiB and *is*
  overridable in a project-scoped `.codex/config.toml` (it is absent from the
  documented cannot-override list, but the exact default and project-level
  override were not confirmed from the config reference this session). Probe:
  read `project_doc_max_bytes` in
  <https://developers.openai.com/codex/config-reference> from a Codex session,
  or empirically feed an oversized AGENTS.md and observe truncation.
- **A2 (ASSUMED-live)**: Codex discovery of this repo's `.agents/skills/` is
  doc-verified but was not exercised in a live Codex session from here; the
  repo's `AGENTS.md` and parity guard already presuppose it works. Probe: run
  `codex` in the repo and confirm the skill selector lists the 32 migrated
  skills.
- **A3 (ASSUMED)**: Codex follows a *symlink* inside `.agents/skills/` (not
  needed by this design — Codex reads the canonical copies directly — recorded
  only in case a future surface wants the mirror-image link direction).
- **A4 (ASSUMED)**: Codex project-scoped `config.toml` may define
  `mcp_servers` — the advanced-config doc excerpt did not state it explicitly,
  but the repo's own trusted `.codex/config.toml:11-15` has shipped one since
  the Codex enablement work. Probe: confirm token-savior-recall appears in a
  live Codex session's MCP tool list.
