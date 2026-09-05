# Copilot adapter — pfBlockerNG

Scope: Copilot-specific surfaces plus canonical-noun to Copilot translation.
Canonical policy = `AGENTS.md` + routed `.agents/policy/` / `.agents/context/` files;
this adapter only map them onto Copilot mechanics.
Load when: every Copilot session, at start (`.github/copilot-instructions.md` send you
here). Claude and Codex sessions never read this file.

Copilot translate canonical nouns mechanically:

| Canonical / Claude surface | Copilot surface |
| --- | --- |
| `/name` or `.claude/skills/name` | `/name` from `.agents/skills/name` (same source — Copilot scan `.github/skills/`, `.agents/skills/`, `.claude/skills/`, dedupe by skill name). |
| `Agent` / planner / implementer / verifier | Copilot custom agent per `.github/agents/*.agent.md`, launch with `/agents`; roles + tier bindings in `.agents/policy/agent-roles.md` (checked by `scripts/check_agent_roles.py`). Mutation boundary ride `<!-- mutation: ... -->` marker in body: CLI 1.0.78 log `unknown field ignored` for any front-matter key outside its schema. |
| `AskUserQuestion` | Ask in conversation; Copilot have no structured question tool. |
| Background `run_in_background: true` | No harness-tracked background task exist — run wait in foreground with hard cap, or hand wait to user. Never shell `&`. |
| Commit and public attribution | None. Commits use the configured user identity; public bodies contain no agent/model/client footer. |
| Claude-only status/token/UI hooks | No equivalent unless `.github/hooks/pfblockerng.json` map one. |

Copilot specifics:

- **Client detection is one environment variable.** Copilot CLI export `COPILOT_CLI=1`
  into every shell it spawn — inherited by nested shells, visible to git hooks (probed on
  1.0.78, 2026-08-06, by dumping environment inside real session); cloud agent set
  `COPILOT_AGENT_PROMPT`. `.githooks/prepare-commit-msg` and `.githooks/pre-push` read those
  exactly as they read `CLAUDECODE` and `CODEX_THREAD_ID`. Nothing installed outside
  repo, no process tree inspected.
- **Attribution:** none. Commit identity and public-body content follow
  [`git.md`](../policy/git.md) and [`landing.md`](../policy/landing.md).
- **No session hooks are wired.** Copilot documented repo-level `.github/hooks/*.json` did
  not fire on CLI 1.0.78 (probed 2026-08-05 with `copilot -p`; identical user-level file
  did), and mode capsules ride `.github/copilot-instructions.md`, which load reliably.
  If later CLI honour repo hooks, that where capsule hook go.
- **Reviews** use `adversarial-reviewer`(-`top`/-`mid`) from `.github/agents/` per
  `.agents/policy/landing.md`.
- `work-branch.sh --worktree` resolve primary checkout from session worktree exactly
  as for other clients.
