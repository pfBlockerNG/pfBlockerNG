---
name: gh-issue
description: Triage a pfBlockerNG GitHub issue, and optionally fix it through isolated, independently gated steps. Use for "triage issue N", "look at issue N", or "fix issue N".
---

# Triage or fix an issue

Read `../../../.claude/skills/gh-issue/SKILL.md` for the detailed policy. Use
`$issue-triage` for the evidence-backed verdict and `$phase-step` for a `--fix`
execution path. Substitute Codex subagents for Claude `Workflow`/Agent calls and
apply canonical `CLAUDE.md` rules through the `AGENTS.md` runtime mapping;
preserve the worktree, labels, handoff, and review requirements.
