---
type: "query"
date: "2026-10-18T21:32:26.016723+00:00"
question: "pfB-DNS reply logging UI toggle flow smoke tests local-smoke"
contributor: "graphify"
outcome: "useful"
---

# Q: pfB-DNS reply logging UI toggle flow smoke tests local-smoke

## Answer

Located tests/smoke/ui/test_functional.py logging-Off persistence case and tests/smoke/test_smoke_dns_proxy.py standalone Reply Reports case. GateReplyUI verified 2 live UI save flows and 15 renders at817aca434; a missing-key DNSBL-save mutant failed the persistence assertion.

## Outcome

- Signal: useful