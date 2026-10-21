---
type: "query"
date: "2026-10-21T22:32:13.985198+00:00"
question: "pfb_dns_proxy_ready pfb_dns_proxy_startup_check Unbound upstream readiness lifecycle tests"
contributor: "graphify"
outcome: "useful"
---

# Q: pfb_dns_proxy_ready pfb_dns_proxy_startup_check Unbound upstream readiness lifecycle tests

## Answer

Narrowed readiness and smoke coverage to pfblockerng.inc:4839-4884, DnsProxyReadinessTest.php, DnsProxyActivationRollbackTest.php and test_smoke_pfb_dns_resolver_state.py; raw source confirmed gateway marker ignores Unbound liveness and generator hardcodes v4.

## Outcome

- Signal: useful