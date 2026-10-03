---
type: "query"
date: "2026-10-03T04:20:05.720093+00:00"
question: "Which smoke tests and helpers configure DNSBL, restart pfb_dnsbl twice, inspect lighttpd_pfb processes/listeners, and fetch HTTP/HTTPS block pages?"
contributor: "graphify"
outcome: "useful"
---

# Q: Which smoke tests and helpers configure DNSBL, restart pfb_dnsbl twice, inspect lighttpd_pfb processes/listeners, and fetch HTTP/HTTPS block pages?

## Answer

The graph identified SmokeVM.php_eval, SmokeVM.ssh, DNSBL CaseContext/reload helpers, and test_smoke_matrix as the relevant smoke surfaces, but did not isolate an existing restart probe.

## Outcome

- Signal: useful