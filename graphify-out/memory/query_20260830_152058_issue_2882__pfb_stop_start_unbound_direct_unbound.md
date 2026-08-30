---
type: "query"
date: "2026-08-30T15:20:58.071316+00:00"
question: "Issue 2882: pfb_stop_start_unbound direct Unbound daemon startup spawn, existing bounded-wait process-tree patterns, preserving retry rollback apply-ledger behavior, and focused tests"
contributor: "graphify"
outcome: "useful"
---

# Q: Issue 2882: pfb_stop_start_unbound direct Unbound daemon startup spawn, existing bounded-wait process-tree patterns, preserving retry rollback apply-ledger behavior, and focused tests

## Answer

Located pfb_stop_start_unbound at pfblockerng.inc:11409 and connected pfb_run_hooks as the existing daemon-survivor wait pattern; test impact remained broad/truncated and will be resolved with CodeGraph.

## Outcome

- Signal: useful
