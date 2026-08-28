---
type: "query"
date: "2026-08-28T07:45:08.505226+00:00"
question: "packaging, release archive, deploy overlay, file lists referencing .inc paths"
contributor: "graphify"
outcome: "dead_end"
correction: "The question was about reference COUNTS across file types, which is a text-frequency question the graph does not model. git grep -Io on the owned basenames answered it: 37 files inside src/, 2279 hits outside."
---

# Q: packaging, release archive, deploy overlay, file lists referencing .inc paths

## Answer

Returned smoke-test and archive-test nodes (ArchiveProbeTest, test_reproducible_source_archive, SmokeVM helpers); truncated at 63 of 518 nodes by the token budget.

## Outcome

- Signal: dead_end
- Correction: The question was about reference COUNTS across file types, which is a text-frequency question the graph does not model. git grep -Io on the owned basenames answered it: 37 files inside src/, 2279 hits outside.