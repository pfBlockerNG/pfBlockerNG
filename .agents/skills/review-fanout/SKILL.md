---
name: review-fanout
description: Perform an explicit-user-requested multi-agent adversarial review of a pfBlockerNG pull request. Do not use for the normal one-reviewer merge flow.
---

# Fan out a review

Read and execute the canonical workflow at
`../../../.claude/workflows/review-fanout.js`, translating its Claude agents to
low-reasoning Codex subagents with the
`../../../.codex/agents/adversarial-reviewer.toml` role and the tier mapping in
`../../model-tiers.conf`. Use only when the user
explicitly requests fan-out. Preserve the canonical lenses, prompts, schemas,
diff boundary, finding verification, and normal `$review-single` default.
