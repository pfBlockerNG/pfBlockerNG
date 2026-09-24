# Claude Code adapter — pfBlockerNG

Scope: Claude Code surfaces + canonical-noun translation. Canonical policy = `AGENTS.md` +
routed `.agents/policy/` / `.agents/context/` files; adapter only maps them onto Claude Code
mechanics. Load when: every Claude Code session, at start (AGENTS.md Vendor-adapters pointer
send you here).

Claude Code reads `AGENTS.md` natively — no import shim.

Claude-only surfaces:

- Hooks live in `.claude/settings.json` (branch freshness, discipline, guards); skills at
  `.claude/skills/` symlink onto canonical `.agents/skills/`.
- Shared git hooks recognise Claude via `CLAUDECODE=1`. Claude adds no commit or public-body
  attribution; configured user identity remains authoritative.
- Claude sessions may start inside harness session worktree (`.claude/worktrees/…`) — see
  `.agents/policy/sessions.md`.
- Soft routing backstops live in `.claude/rules/*.md` (`paths:` frontmatter, Read-tool-triggered;
  shell reads bypass them — they carry pointers, never MUST invariants; bootstrap routing table
  stay authoritative).
- Harness may inject standing "do not call the AgentTool unless the user requested it" session
  directive. **Repository-documented procedure that unambiguously REQUIRES sub-agent is itself
  that request** (owner directive 2026-07-31): run procedure as written, never degraded to solo
  approximation (subject to procedure own exemptions, e.g. landing.md ≤50%-context small-change
  self-review). Canonical case — `.agents/policy/landing.md` independent adversarial reviewer,
  which every PR gets; review orchestrator perform on itself not independent, so skipping spawn
  voids gate rather than playing safe. Covers only spawns procedure NAMES; where one merely
  *permits* delegation, standing directive holds and you ask first.
