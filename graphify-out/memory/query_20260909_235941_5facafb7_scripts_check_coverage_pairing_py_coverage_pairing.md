---
type: "query"
date: "2026-09-09T23:59:41.945334+00:00"
question: "scripts/check_coverage_pairing.py Coverage pairing workflow base SHA changed files scripts tests mapping"
contributor: "graphify"
outcome: "useful"
source_nodes: ["scripts/check_coverage_pairing.py", ".github/workflows/test.yml"]
---

# Q: scripts/check_coverage_pairing.py Coverage pairing workflow base SHA changed files scripts tests mapping

## Answer

Coverage pairing treats scripts/ as release-plane behavior and validates PR-body Frozen RED evidence in CI; local uncommitted pairing only proved a tests/ path was present.

## Outcome

- Signal: useful

## Source Nodes

- scripts/check_coverage_pairing.py
- .github/workflows/test.yml