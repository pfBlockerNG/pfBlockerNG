---
type: "query"
date: "2026-09-12T18:03:27.596189+00:00"
question: "Graphify fork installation commit pin and upgrade integration"
contributor: "graphify"
outcome: "dead_end"
correction: "Use pyproject.toml, uv.lock, scripts/agent/ensure-graphify.sh and GitHub commit ancestry for installation and pin provenance."
---

# Q: Graphify fork installation commit pin and upgrade integration

## Answer

The semantic query did not locate the installer pin. pyproject.toml and uv.lock own the pfBlockerNG fork commit; scripts/agent/ensure-graphify.sh installs that specification. GitHub compare confirms upstream PR 3075 head 1ad08a9 is two commits ahead of v0.9.59.

## Outcome

- Signal: dead_end
- Correction: Use pyproject.toml, uv.lock, scripts/agent/ensure-graphify.sh and GitHub commit ancestry for installation and pin provenance.