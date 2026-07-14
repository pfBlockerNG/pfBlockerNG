---
name: adr-all
description: Implement an entire pfBlockerNG ADR end-to-end. Use for "implement all of ADR-N", "run the whole ADR", or "finish ADR-N".
---

# Implement all of an ADR

Run `$adr-phase` with the ADR number and `all`. Read
`../../../.claude/skills/adr-all/SKILL.md` for the repository's detailed, maintained
procedure. Replace its Claude-only `Workflow` invocation with the native
`$phase-step` skill and Codex subagents.
