---
name: git-guardrails-claude-code
description: "Set up Claude Code hooks to block dangerous git commands (push, reset --hard, clean, branch -D, etc.) before they execute. Use when user wants to prevent destructive git operations, add git safety hooks, or block git push/reset in Claude Code."
---

# Codex adapter

Read and follow `../../../.claude/skills/git-guardrails-claude-code/SKILL.md` as the complete
procedure. Translate Claude-specific tool names and sub-agent calls to Codex
surfaces through `AGENTS.md`. Preserve upstream requirements unless repository
policy is stricter; `CLAUDE.md` and `AGENTS.md` win on conflict.
