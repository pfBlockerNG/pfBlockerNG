---
name: code-review
description: "Review the changes since a fixed point (commit, branch, tag, or merge-base) along two axes — Standards (does the code follow this repo's documented coding standards?) and Spec (does the code match what the originating issue/PRD asked for?). Runs both reviews in parallel sub-agents and reports them side by side. Use when the user wants to review a branch, a PR, work-in-progress changes, or asks to \"review since X\"."
---

# Codex adapter

Read and follow `../../../.claude/skills/code-review/SKILL.md` as the complete
procedure. Translate Claude-specific tool names and sub-agent calls to Codex
surfaces through `AGENTS.md`. Preserve upstream requirements unless repository
policy is stricter; `CLAUDE.md` and `AGENTS.md` win on conflict.
