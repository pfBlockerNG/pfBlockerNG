---
type: "query"
date: "2026-09-10T07:43:16.732179+00:00"
question: "check_coverage_pairing no-test-needed PR lookup labels body"
contributor: "graphify"
outcome: "useful"
---

# Q: check_coverage_pairing no-test-needed PR lookup labels body

## Answer

The checker only honors the exemption when invoked with both --warn-only and --pr-body-file. scripts/agent/run-gates.sh invokes the checker with only --name-status-z, so local canonical gates cannot consume the PR label/body and correctly remain red for a test-deletion-only retirement. CI owns the live label/body exemption path.

## Outcome

- Signal: useful