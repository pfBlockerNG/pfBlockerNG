---
type: "query"
date: "2026-11-07T22:16:09.909034+00:00"
question: "pfB DNS Prometheus exporter query counters transport labels query type blocked"
contributor: "graphify"
outcome: "dead_end"
correction: "Source grep and targeted codegraph exploration identified the exporter and SQLite queries."
---

# Q: pfB DNS Prometheus exporter query counters transport labels query type blocked

## Answer

DNSBL counters are rendered by pfb_metrics_render and read from SQLite by pfb_metrics_collect; their current data has no transport or qtype breakdown.

## Outcome

- Signal: dead_end
- Correction: Source grep and targeted codegraph exploration identified the exporter and SQLite queries.