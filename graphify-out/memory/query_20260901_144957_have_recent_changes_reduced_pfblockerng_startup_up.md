---
type: "query"
date: "2026-09-01T14:49:57.463913+00:00"
question: "Have recent changes reduced pfBlockerNG startup update load on weak hardware?"
contributor: "graphify"
outcome: "dead_end"
correction: "The broad graph traversal was noisy; current source, architecture/spec documentation, git history, and GitHub issues #468, #1944, #2100, #2138, and #2306 supplied the answer."
---

# Q: Have recent changes reduced pfBlockerNG startup update load on weak hardware?

## Answer

Yes: boot sync exits before feed processing; reboot state is restored; the fixed 15-minute scheduler performs once-only catch-up, serializes passes, and skips unchanged work; DNSBL swaps use a RAM gate. No Netgate 2100 benchmark was completed.

## Outcome

- Signal: dead_end
- Correction: The broad graph traversal was noisy; current source, architecture/spec documentation, git history, and GitHub issues #468, #1944, #2100, #2138, and #2306 supplied the answer.