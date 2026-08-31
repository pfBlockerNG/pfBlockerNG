# Codex adapter — pfBlockerNG

Scope: Codex surfaces + canonical-noun → Codex translation. Canonical policy = `AGENTS.md` + routed `.agents/policy/` / `.agents/context/` files; adapter only maps them onto Codex mechanics.
Load when: every Codex session, at start (AGENTS.md Vendor-adapters pointer send you here).
Claude sessions never read this file.

Codex translate canonical nouns mechanically:

| Canonical / Claude surface | Codex surface |
| --- | --- |
| `/name` or `.claude/skills/name` | `$name` from `.agents/skills/name` (same source). |
| `Agent` / planner / implementer / verifier | Codex subagent per `.codex/agents/*.toml`; roles + tier bindings in `.agents/policy/agent-roles.md` (checked by `scripts/check_agent_roles.py`). |
| `AskUserQuestion` | Current Codex user-input surface. |
| Background Bash `run_in_background: true` | One harness-tracked background command; never shell `&`. |
| Commit and public attribution | None. Commits use the configured user identity; public bodies contain no agent/model/client footer. |
| Claude-only status/token/UI hooks | No equivalent unless `.codex/hooks.json` map one. |

Repository-intelligence routing is canonical in `AGENTS.md`; Codex maps its exact
language-semantic/LSP surface there to Serena.

Skills with `policy.allow_implicit_invocation: false` may be absent from startup metadata but stay explicitly invokable. Never report explicitly named `$name` unavailable from startup metadata alone; first resolve `.agents/skills/<name>/SKILL.md`.

Codex specifics: reviews use `adversarial-reviewer`(-`top`/-`mid`) per `.agents/policy/landing.md`; `work-branch.sh --worktree` resolve primary checkout from Codex session worktree; Codex `SessionStart` hook run branch-freshness check; in Codex desktop, sandboxed `gh auth status` failure not conclusive — retry via approved elevated path; `.codex/config.toml`/`hooks.json`/agents load only after trust; shared git-hook marker is `CODEX_THREAD_ID`; resume via `codex resume` (`--last`, `<session-id-or-name>`).
