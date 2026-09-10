---
type: "query"
date: "2026-09-10T07:04:43.807543+00:00"
question: "Was agent skill installation historically owned by this repository or ../ai-harness-setup?"
contributor: "graphify"
outcome: "dead_end"
correction: "Use sibling repository README, symlink resolution, and both repositories' git history for ownership; current local sibling name is ai-harness-settings, not ai-harness-setup."
---

# Q: Was agent skill installation historically owned by this repository or ../ai-harness-setup?

## Answer

The graph did not establish historical ownership. Git history and the live symlink show user-level skills are managed by sibling ai-harness-settings: ~/.agents/skills resolves to ai-harness-settings/ai-dev/agents/skills, whose README defines it as the user-level harness and shared-skills backup. pfBlockerNG's setup-agent-skills.sh first appeared in commits 121e3135e and 94ab8f8fc on 2026-09-09/10.

## Outcome

- Signal: dead_end
- Correction: Use sibling repository README, symlink resolution, and both repositories' git history for ownership; current local sibling name is ai-harness-settings, not ai-harness-setup.
