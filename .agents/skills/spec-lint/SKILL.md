---
name: spec-lint
description: Lint pfBlockerNG ADR phase prompts for the mandatory delegation-contract fields. Use for "lint ADR prompts", "spec-lint ADR N", or "check phase prompts".
---

# Lint ADR prompts

Follow `../../../.claude/skills/spec-lint/SKILL.md`; its `CLAUDE.md` references point to
the canonical shared policy, while `AGENTS.md` supplies only Codex runtime
translations. Run `scripts/check_phase_prompts.py` for the requested ADR or
prompts. Do not weaken the checker or prompts to manufacture a passing result.
