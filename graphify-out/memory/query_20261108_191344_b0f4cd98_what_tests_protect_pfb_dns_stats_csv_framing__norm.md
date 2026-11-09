---
type: "query"
date: "2026-11-08T19:13:44.500044+00:00"
question: "What tests protect pfb_dns_stats CSV framing, normalization, suffix counts and full-history aggregation?"
contributor: "graphify"
outcome: "useful"
---

# Q: What tests protect pfb_dns_stats CSV framing, normalization, suffix counts and full-history aggregation?

## Answer

The scoped result located DnsStatsSuffixAggregationTest, DnsStatsAggregationTest and the CSV/framing smoke cases. Those established the existing semantic matrix; exact CodeGraph helper source and the read-only appliance cost-attribution probe, not the graph, established the CPU bottleneck. The new batching and resource characterization tests extend those existing contracts.

## Outcome

- Signal: useful