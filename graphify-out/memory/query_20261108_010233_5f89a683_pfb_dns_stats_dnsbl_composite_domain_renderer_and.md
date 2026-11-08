---
type: "query"
date: "2026-11-08T01:02:33.804392+00:00"
question: "pfb_dns_stats DNSBL composite domain renderer and replysrcipd filters"
contributor: "graphify"
outcome: "dead_end"
correction: "Use the exact pfblockerng_alerts.php top-level composite-key consumers and executed review render/filter probes; natural-language keyword matches favored unrelated resolver stats."
---

# Q: pfb_dns_stats DNSBL composite domain renderer and replysrcipd filters

## Answer

The broad query returned resolver statistics rather than Reports top-level consumers. Direct source enumeration located DNSBL domain/type and mode/domain rendering plus the replysrcipd POST filter at pfblockerng_alerts.php:691,4969-4990; all must preserve comma-bearing domains.

## Outcome

- Signal: dead_end
- Correction: Use the exact pfblockerng_alerts.php top-level composite-key consumers and executed review render/filter probes; natural-language keyword matches favored unrelated resolver stats.