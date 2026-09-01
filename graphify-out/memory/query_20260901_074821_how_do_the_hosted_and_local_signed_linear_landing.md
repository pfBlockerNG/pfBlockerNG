---
type: "query"
date: "2026-09-01T07:48:21.922831+00:00"
question: "How do the hosted and local signed linear landing paths pin the reviewed PR head, run exact-head CI, and prevent a head race before push or terminal sync?"
contributor: "graphify"
outcome: "dead_end"
correction: "Exact reads of .agents/policy/landing.md and local://issue-2996-final-correctness.md supplied the answer."
---

# Q: How do the hosted and local signed linear landing paths pin the reviewed PR head, run exact-head CI, and prevent a head race before push or terminal sync?

## Answer

The graph located the focused landing-policy test but did not expose the missing reviewed-SHA binding; exact policy reads and the Grok correctness report identified both races.

## Outcome

- Signal: dead_end
- Correction: Exact reads of .agents/policy/landing.md and local://issue-2996-final-correctness.md supplied the answer.