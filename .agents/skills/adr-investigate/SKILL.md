---
name: adr-investigate
description: Gather evidence for a multi-component pfBlockerNG ADR without designing or implementing it. Use from ADR creation when independent codebase investigation is needed.
---

# Investigate ADR areas

Read `../../../.claude/workflows/adr-investigate.js` as the maintained area-report schema
and prompt contract. Spawn one read-only, low-reasoning `analyst` subagent per
independent area. Each report labels every fact `verified` with command/file-line
evidence or `assumed`; the caller owns synthesis and must resolve assumptions
before a phase depends on them.
