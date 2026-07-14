---
name: phase-step
description: Execute one pfBlockerNG ADR phase or issue-plan step through a fresh brief, focused implementation, and independent evidence gate. Use from ADR, issue, or delegated-work flows.
---

# Run one gated implementation step

Read `../../../.claude/workflows/phase-step.js` for the repository's complete brief,
handoff, red-proof, and gate schemas. Replace its unavailable Claude `agent()`
workflow with three Codex subagents: `planner` writes the brief when needed,
`implementer` makes one focused commit in the assigned worktree, and
`adversarial-reviewer` re-derives the gate. The parent validates every required
record field and decides whether to continue or halt.
