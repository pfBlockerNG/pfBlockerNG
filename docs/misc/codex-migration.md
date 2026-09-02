# Codex client — repository integration notes

Scope: Codex integration surfaces (`.codex/`, skill/role parity, hook trust,
activation). Load when: working from Codex client or changing vendor adapter
config. Note grew from 2026-07 Claude Code → Codex migration
(#1348); migration done — since Stage-2 inversion (#1437)
`AGENTS.md` is canonical vendor-neutral bootstrap, and since #1431
fresh-session policy replaced workflow-era orchestration.

## Source-of-truth layout

| Concern | Canonical source | Claude discovery/runtime | Codex discovery/runtime |
| --- | --- | --- | --- |
| Repository policy | `AGENTS.md` + `.agents/policy/` + `.agents/context/` | `CLAUDE.md` is the thin `@AGENTS.md` adapter | Loads `AGENTS.md` natively |
| Task procedures (skills) | `.agents/skills/*/SKILL.md` | `.claude/skills/*` symlinks onto the canonical dirs | Direct discovery (`$name`) |
| Specialist roles | `.agents/policy/agent-roles.md` + `.agents/model-tiers.conf` | Claude agents (`claude-fable-5-1` / `claude-opus-4-8` / `claude-sonnet-5`) | Role TOMLs in `.codex/agents/` (`gpt-5.6-sol` / `-terra` / `-luna`) |
| Lifecycle enforcement | Shared `.githooks/` + repository scripts | `.claude/settings.json` | `.codex/hooks.json` + `.codex/config.toml` |

`AGENTS.md` stays vendor-neutral: its "Vendor adapters" section is short pointer
to each vendor's own adapter — `CLAUDE.md` for Claude, `.agents/context/codex-adapter.md`
for Codex (canonical-noun → Codex translation table plus Codex specifics). Detailed
procedure lives once, in routed policy/context files, because summaries drift.

## Automatic parity enforcement

Run `sh scripts/agent/check-agent-config-parity.sh`. Pre-commit hook runs it
whenever either vendor's agent config staged (including deletions);
ShellSpec suite checks real repository inventory in CI.

For symlinked skill — normal state — filesystem identity is parity
guarantee: `.claude/skills/<name>` must resolve to canonical
`.agents/skills/<name>`. Textual-adapter branch (same-name `SKILL.md`
whose `../../../` reference must resolve to its exact source) exists only for
mid-migration non-symlink entry. Checker also rejects stale entry whose
counterpart was deleted or renamed, and validates shared
`.agents/model-tiers.conf` tier mapping.

Only sync boundary: editing canonical policy or skill
body needs no adapter change; adding or renaming skill needs only the
symlink; provider-specific runtime change stays in that provider's adapter.

## Active Codex equivalents

| Claude Code surface | Codex equivalent | Notes |
| --- | --- | --- |
| `CLAUDE.md` adapter | native `AGENTS.md` + `.agents/context/codex-adapter.md` | Same canonical bootstrap; Codex's vendor adapter is `.agents/context/codex-adapter.md`, mirroring `CLAUDE.md`. |
| `.claude/skills/*` symlinks | `.agents/skills/*` | One shared detailed procedure per skill. |
| `.claude/workflows/*.js` | *(retired 2026-07-17, #1431)* | Superseded by the fresh-session policy: `.agents/policy/workflow.md` + `landing.md`; every client uses fresh native sub-agents. |
| Top / mid / small model tier | GPT-5.6-Sol / GPT-5.6-Terra / GPT-5.6-Luna | `.agents/model-tiers.conf` is the shared mapping; reasoning effort remains independent. |
| Planner/implementer/analyst/verifier | `planner`, `implementer`, small/top `analyst`, and `adversarial-reviewer` plus top/mid reviewer variants | Project-scoped custom agents pin the corresponding Codex model tier without changing the canonical output contract. |
| `PreToolUse` Git policy | `.codex/hooks.json` | Reuses the raw-payload-compatible shared guard for Codex `Bash` hook events; coverage remains subject to the client emitting that event for unified shell execution. |
| Session activation | `.codex/hooks.json` | Runs branch synchronization on startup/resume/clear/compact. |

Shared Git hooks recognize both `CLAUDECODE=1` and Codex's
`CODEX_THREAD_ID`. Primary-checkout commits and unfetched-history rewrites
blocked for either agent runtime.

Codex command-hook commands pin SHA-256 of every repository script
they execute. Changing target script therefore changes trusted hook
definition; unreviewed branch cannot keep already-trusted command string
while replacing its implementation. Cross-agent config tests prevent
legitimate edits from leaving stale pins.

## Worktrees, shallow history, and resume

Both clients follow canonical one-agent/one-worktree rule
(`.agents/policy/git.md`; session layouts in `.agents/policy/sessions.md`);
create work-item worktree through `scripts/agent/work-branch.sh --worktree`,
which resolves primary checkout through `--git-common-dir` and does not nest
worktrees inside session tree.

Shared session hook unshallows once when depth-limited fetch moved
`origin/devel` past visible boundary, requires visible merge base, and
otherwise leaves branch untouched with recovery message; never rebases
dirty tree. Codex conversation persistence separate from Git state — leave
worktree coherent (preferably committed) before closing CLI, then
`codex resume`, `codex resume --last`, or `codex resume <session-id-or-name>`.

## Intentionally provider-specific

- **Status line:** Codex has no equivalent to Claude Code's command status-line
  config. UI-only, does not affect repository behavior.
- **Automatic environment installation:** Codex does not copy Claude's startup
  package install. Provision dependencies deliberately and diagnose
  failure against the base.
- **`pyright-lsp` plugin:** Codex does not use Claude plugin protocol.
  Repository Python gates stay authoritative.
- **Provider model identifiers:** procedures use top / mid / small tiers;
  `.agents/model-tiers.conf` maps them explicitly instead of treating one
  provider's model alias as portable.

## Activation and verification

1. Open repository with trusted Codex client and restart/reopen session.
2. Inspect and trust project hooks with `/hooks`; changed command hooks skipped
   until their new definitions reviewed.
3. Use `/skills` to verify `.agents/skills` entries discovered.
4. Use `/agent` or delegation request to select project roles.
5. Run `sh scripts/agent/check-agent-config-parity.sh` for explicit inventory
   audit; routine commits run it automatically when relevant config changes.

Keep personal model, provider, auth, notification, connector, and
memory preferences in `~/.codex/config.toml`. Repository config holds only
portable team behavior.
