---
type: "query"
date: "2026-09-10T07:18:34.807117+00:00"
question: "Remove setup-agent-skills.sh, its ShellSpec, repository-intelligence guidance, and stale query memories introduced by issue 3255"
contributor: "graphify"
outcome: "useful"
---

# Q: Remove setup-agent-skills.sh, its ShellSpec, repository-intelligence guidance, and stale query memories introduced by issue 3255

## Answer

The setup command and its focused ShellSpec are isolated to the issue 3255 change. Remove both and the six-line repository-intelligence guidance. Preserve the earlier dead-end query memory because its correction correctly says user-level skills do not belong in pfBlockerNG; preserve the coverage-pairing query because it documents a general CI contract.

## Outcome

- Signal: useful