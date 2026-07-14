---
name: pr-merge
description: Rebase, verify CI for, and merge a pfBlockerNG pull request using the repository's rebase-only policy. Use for "merge this PR", "land PR N", or "rebase and merge".
---

# Merge a PR

Follow `../../../.claude/skills/pr-merge/SKILL.md` and the canonical `CLAUDE.md` policy;
use `AGENTS.md` only for Codex runtime translation. Work in a dedicated current
worktree; reject drafts, conflicts, and red required checks. Rebase onto the live
base, push only with `--force-with-lease`, merge via `gh pr merge --rebase`, and
perform the bounded-wait cancellation sweep.
