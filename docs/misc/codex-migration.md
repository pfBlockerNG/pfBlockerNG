# Codex client — repository integration notes

Scope: Codex-side integration surfaces (`.codex/`, skill/role parity, hook trust,
activation). Load when: working from the Codex client or changing vendor adapter
configuration. This note grew out of the 2026-07 Claude Code → Codex migration
(#1348); the migration itself is complete — since the Stage-2 inversion (#1437)
`AGENTS.md` is the canonical vendor-neutral bootstrap, and since #1431 the
fresh-session policy replaced the workflow-era orchestration.

## Source-of-truth layout

| Concern | Canonical source | Claude discovery/runtime | Codex discovery/runtime |
| --- | --- | --- | --- |
| Repository policy | `AGENTS.md` + `.agents/policy/` + `.agents/context/` | `CLAUDE.md` is the thin `@AGENTS.md` adapter | Loads `AGENTS.md` natively |
| Task procedures (skills) | `.agents/skills/*/SKILL.md` | `.claude/skills/*` symlinks onto the canonical dirs | Direct discovery (`$name`) |
| Specialist roles | `.agents/policy/agent-roles.md` + `.agents/model-tiers.conf` | Claude agents (`claude-fable-5` / `claude-opus-4-8` / `claude-sonnet-5`) | Role TOMLs in `.codex/agents/` (`gpt-5.6-sol` / `-terra` / `-luna`) |
| Lifecycle enforcement | Shared `.githooks/` + repository scripts | `.claude/settings.json` | `.codex/hooks.json` + `.codex/config.toml` |

`AGENTS.md` stays vendor-neutral: its "Vendor adapters" section is a short pointer
to each vendor's own adapter — `CLAUDE.md` for Claude, `.agents/context/codex-adapter.md`
for Codex (the canonical-noun → Codex translation table plus Codex specifics). Detailed
procedure still lives once, in the routed policy/context files, because summaries drift.

## Automatic parity enforcement

Run `sh scripts/agent/check-agent-config-parity.sh`. The pre-commit hook runs it
whenever either vendor's agent configuration is staged (including deletions);
the ShellSpec suite checks the real repository inventory in CI.

For a symlinked skill — the normal state — filesystem identity is the parity
guarantee: `.claude/skills/<name>` must resolve to canonical
`.agents/skills/<name>`. The textual-adapter branch (a same-name `SKILL.md`
whose `../../../` reference must resolve to its exact source) exists only for a
mid-migration non-symlink entry. The checker also rejects a stale entry whose
counterpart was deleted or renamed, and validates the shared
`.agents/model-tiers.conf` tier mapping.

This is the only synchronization boundary: editing canonical policy or a skill
body requires no adapter change; adding or renaming a skill requires only the
symlink; a provider-specific runtime change stays in that provider's adapter.

## Active Codex equivalents

| Claude Code surface | Codex equivalent | Notes |
| --- | --- | --- |
| `CLAUDE.md` adapter | native `AGENTS.md` + `.agents/context/codex-adapter.md` | Same canonical bootstrap; Codex's vendor adapter is `.agents/context/codex-adapter.md`, mirroring `CLAUDE.md`. |
| `.claude/skills/*` symlinks | `.agents/skills/*` | One shared detailed procedure per skill. |
| `.claude/workflows/*.js` | *(retired 2026-07-17, #1431)* | Superseded by the fresh-session policy: `.agents/policy/workflow.md` + `landing.md`; every client uses fresh native sub-agents. |
| Top / mid / small model tier | GPT-5.6-Sol / GPT-5.6-Terra / GPT-5.6-Luna | `.agents/model-tiers.conf` is the shared mapping; reasoning effort remains independent. |
| Planner/implementer/analyst/verifier | `planner`, `implementer`, small/top `analyst`, and `adversarial-reviewer` plus top/mid reviewer variants | Project-scoped custom agents pin the corresponding Codex model tier without changing the canonical output contract. |
| `PreToolUse` Git policy | `.codex/hooks.json` | Reuses the raw-payload-compatible shared guard for Codex `Bash` hook events; coverage remains subject to the client emitting that event for unified shell execution. |
| `PreToolUse` retired-token notice | `.codex/hooks.json` | Reuses `check_retired_tokens.py --claude-hook` for the same supported `Bash` event surface. |
| Session and delegate activation | `.codex/hooks.json` | Runs branch synchronization and injects ponytail + caveman plus the Token Savior recall preference on startup/resume/clear/compact and every sub-agent start. |
| Token Savior MCP and capture hook | `.codex/config.toml` plus `.codex/hooks.json` | Uses the same pinned upstream Token Savior launcher and capture wrapper as Claude, with the client label set to `codex`; Bash compaction and rewriting retain upstream's opt-in defaults. |
| Ponytail and Caveman | Plugin + repository hooks | Ponytail ships as the local Codex plugin; repository hooks guarantee both modes for root sessions and sub-agents. |

The shared Git hooks recognize both `CLAUDECODE=1` and Codex's
`CODEX_THREAD_ID`. Primary-checkout commits and unfetched-history rewrites are
therefore blocked for either agent runtime.

Codex command-hook and MCP commands pin the SHA-256 of every repository script
they execute. Changing a target script therefore also changes the trusted hook
definition; an unreviewed branch cannot keep an already-trusted command string
while replacing its implementation. The ShellSpec configuration check prevents
legitimate edits from leaving stale pins.

## Worktrees, shallow history, and resume

Both clients follow the canonical one-agent/one-worktree rule
(`.agents/policy/git.md`; session layouts in `.agents/policy/sessions.md`);
create the work-item worktree through `scripts/agent/work-branch.sh --worktree`,
which resolves the primary checkout through `--git-common-dir` and does not nest
worktrees inside a session tree.

The shared session hook unshallows once when a depth-limited fetch has moved
`origin/devel` past the visible boundary, requires a visible merge base, and
otherwise leaves the branch untouched with a recovery message; it never rebases
a dirty tree. Codex conversation persistence is separate from Git state — leave
the worktree coherent (preferably committed) before closing the CLI, then
`codex resume`, `codex resume --last`, or `codex resume <session-id-or-name>`.

## Intentionally provider-specific

- **Status line:** Codex has no equivalent to Claude Code's command status-line
  configuration. It is UI-only and does not affect repository behavior.
- **Automatic environment installation:** Codex does not copy Claude's startup
  package installation. Provision dependencies deliberately and diagnose a
  failure against the base.
- **`pyright-lsp` plugin:** Codex does not use the Claude plugin protocol. The
  repository Python gates remain authoritative.
- **Remote-control URL cloning:** `$new-terminal` can start another CLI session,
  but Codex has no equivalent for Claude's bridge URL.
- **Provider model identifiers:** procedures use top / mid / small tiers;
  `.agents/model-tiers.conf` maps them explicitly instead of treating one
  provider's model alias as portable.

## Activation and verification

1. Open the repository with a trusted Codex client and restart/reopen the session.
2. Inspect and trust project hooks with `/hooks`; changed command hooks are skipped
   until their new definitions are reviewed.
3. Use `/skills` to verify the `.agents/skills` entries are discovered.
4. Use `/mcp` to verify `token-savior-recall` is running. Its shared launcher
   installs the repository-pinned upstream release into the per-user cache on first start.
5. Use `/agent` or a delegation request to select project roles.
6. Run `sh scripts/agent/check-agent-config-parity.sh` for an explicit inventory
   audit; routine commits run it automatically when relevant configuration changes.

Keep personal model, provider, authentication, notification, connector, and
memory preferences in `~/.codex/config.toml`. Repository config contains only
portable team behavior.
