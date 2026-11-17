# Claude Code adapter — pfBlockerNG

Scope: Claude Code surfaces + canonical-noun translation. Canonical policy = `AGENTS.md` +
routed `.agents/policy/` / `.agents/context/` files; adapter only maps them onto Claude Code
mechanics. Load when: every Claude Code session, at start (AGENTS.md Vendor-adapters pointer
send you here). Non-Claude sessions never read this file.

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
