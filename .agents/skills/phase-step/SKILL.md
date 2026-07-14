---
name: phase-step
description: Execute one pfBlockerNG ADR phase or issue-plan step through a fresh reconcile/planning pass, focused implementation, and independent evidence gate. Use from ADR, issue, or delegated-work flows.
---

# Run one gated implementation step

Read `../../../.claude/workflows/phase-step.js` for the repository's complete
reconcile, handoff, red-proof, and gate schemas. Replace its unavailable Claude
`agent()` workflow with three Codex subagents: `planner` reconciles the phase
prompt against the live tree and derives the enumerations when needed,
`implementer` makes one focused commit in the assigned worktree, and
`adversarial-reviewer` re-derives the gate. The parent validates every required
record field and decides whether to continue or halt.
