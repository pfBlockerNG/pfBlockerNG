# Grok adapter — pfBlockerNG

Scope: Grok-specific surfaces plus canonical-noun to Grok translation.
Canonical policy = `AGENTS.md` + routed `.agents/policy/` / `.agents/context/` files;
this adapter only map them onto Grok mechanics.
Load when: every Grok session, at start (`AGENTS.md` Vendor-adapters pointer and
`.grok/rules/harness.md` send you here). Claude, Codex, and Copilot sessions never
read this file.

Grok translate canonical nouns mechanically:

| Canonical / Claude surface | Grok surface |
| --- | --- |
| `/name` or `.claude/skills/name` | `/name` from `.agents/skills/name` (same source — Grok scan `.agents/skills/`, `.claude/skills/`, `.grok/skills/`, dedupe by skill name). |
| `Agent` / planner / implementer / verifier | Grok `spawn_subagent` (`general-purpose`, `explore`, `plan` — the three built-in types on 1.0.4, 2026-08-15). No in-repo `.grok/agents/` tree; roles + tier bindings in `.agents/policy/agent-roles.md` stay Claude/Codex/Copilot. Independent landing review still required — spawn a fresh `general-purpose` reviewer. |
| `AskUserQuestion` | Ask in conversation; use Grok's structured question tool when available. |
| Background `run_in_background: true` | Harness-tracked background command; never shell `&`. |
| Commit and public attribution | None. Commits use the configured user identity; public bodies contain no agent/model/client footer. |
| Claude-only status/token/UI hooks | No equivalent. Mode capsules ride `GROK.md` and `.grok/rules/harness.md`. |

Grok specifics:

- **Client detection is two environment variables.** Grok CLI export `GROK_AGENT=1`
  and `GROK_SESSION_ID=<id>` into every shell it spawn — inherited by nested shells,
  visible to git hooks (probed on 1.0.4, 2026-08-15: `env | grep ^GROK_` inside
  nested `sh`/`bash` from a live session; `grok --version` → `grok 1.0.4
  (d846eb93d9) [stable]`). `.githooks/prepare-commit-msg` and `.githooks/pre-push`
  read those exactly as they read `CLAUDECODE`, `CODEX_THREAD_ID`, and
  `COPILOT_CLI`. Nothing installed outside repo, no process tree inspected.
- **Attribution:** none. Commit identity and public-body content follow
  [`git.md`](../policy/git.md) and [`landing.md`](../policy/landing.md).
- **No session hooks are wired.** Grok auto-load `AGENTS.md` plus `.grok/rules/*.md`
  (`<dir>/.grok/rules/` "Always scanned" — Grok 1.0.4 user-guide
  `12-project-rules.md`). `GROK.md` is the thin adapter (Claude's `CLAUDE.md`
  twin); `.grok/rules/harness.md` injects the pointer so the adapter cannot be
  skipped. Skills already discovered from `.agents/skills/` — do not copy them
  under `.grok/skills/`.
- **Reviews** use an independent spawned reviewer per `.agents/policy/landing.md`.
- `work-branch.sh --worktree` resolve primary checkout from session worktree exactly
  as for other clients.
- **Smoke-1 bus (`pfb-msg`).** Session-length watch is the Grok **monitor** tool with
  `persistent: true` (`pfb-msg serve $PFB_AGENT`). Each stdout line is a turn. Do
  **not** arm it as background bash: that notifies only on process **exit**, and
  `serve` never exits on a message (probed 2026-08-27: unread piled for hours while
  the SSH serve stayed alive; the 10 h harness cap then killed it and that exit
  finally woke the session). One-shot form is `pfb-msg watch`.
  **Worktree-scope hole (same day, second stall):** `.grok/rules/` is loaded from
  *cwd's* checkout. A detached/stale session tree does not contain `bus.md`, and
  auto-compact does not re-fire SessionStart — so a docs-only rule in the repo is
  not enough. Install `sh .grok/hooks/install-home` so `~/.grok/rules/bus.md`
  and `~/.grok/hooks/bus.json` load on every Grok session on the box. PreToolUse
  denies bash-`serve`; Stop blocks on missing monitor, bash-`serve`, or unread
  peek. Owner off-switch: `~/.grok/pfb-msg-off`. Do not long-block the turn on
  CI while the bus is live. See [`.grok/rules/bus.md`](../../.grok/rules/bus.md).
