---
type: "query"
date: "2026-10-03T04:15:10.625264+00:00"
question: "Where is the shared pfb_dnsbl service restart primitive generated, how does its stop/start choreography reach lighttpd_pfb, which callers invoke restart_service('pfb_dnsbl'), and which behavioral test patterns can execute generated rc services with process/time command doubles?"
contributor: "graphify"
outcome: "useful"
---

# Q: Where is the shared pfb_dnsbl service restart primitive generated, how does its stop/start choreography reach lighttpd_pfb, which callers invoke restart_service('pfb_dnsbl'), and which behavioral test patterns can execute generated rc services with process/time command doubles?

## Answer

The graph narrowed the implementation to pfblockerng.inc, the pfSense restart_service seam, and PHP service-generation doubles/tests; exact caller and generated-script bodies require CodeGraph.

## Outcome

- Signal: useful