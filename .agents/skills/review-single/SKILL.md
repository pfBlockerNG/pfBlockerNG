---
name: review-single
description: Perform one independent, adversarial, evidence-backed review of a pfBlockerNG pull request. Use for the standard PR review pass or a focused final-diff audit.
---

# Review one PR

Read and execute the canonical workflow at
`../../../.claude/workflows/review-single.js`, translating only its runtime
surface: spawn exactly one Codex subagent with the matching
`../../../.codex/agents/adversarial-reviewer*.toml` role and preserve the
canonical prompt, review profile, schema, diff boundary, and verification rules.
Use low reasoning by default and for every delta review, high reasoning for a
large/complex whole-PR review, and medium reasoning only as the second half of
the documented high-tier fallback. `../../model-tiers.conf` resolves those tiers
to `claude-sonnet-5` / `claude-fable-5` / `claude-opus-4-8` for Claude and
`gpt-5.6-luna` / `gpt-5.6-sol` / `gpt-5.6-terra` for Codex. Return only
evidence-backed findings plus the per-file verdict.
