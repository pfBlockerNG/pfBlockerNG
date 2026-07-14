---
name: adr-phase
description: Implement one phase or all phases of a pfBlockerNG ADR in an isolated worktree with evidence-backed gates. Use for "implement phase N of ADR-M" or "run ADR phase".
---

# Implement an ADR phase

Read `../../../.claude/skills/adr-phase/SKILL.md` for the full repository procedure. Work
only in a freshly based ADR worktree. For each phase, run `$phase-step` rather
than the Claude `Workflow` API: a `planner` creates the brief, an `implementer`
acts on it, and an `adversarial-reviewer` independently gates it. The parent owns
record validation, commits, push, and the halt/continue decision.
