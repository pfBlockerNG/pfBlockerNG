---
type: "query"
date: "2026-11-07T22:16:10.028788+00:00"
question: "DNSBL SQLite group counters deleted removed disabled feeds updates retained"
contributor: "graphify"
outcome: "useful"
---

# Q: DNSBL SQLite group counters deleted removed disabled feeds updates retained

## Answer

dnsbl_save_stats removes numeric rows for groups outside alias_dnsbl_all, while nonnumeric disabled rows can remain; DNSBL counters are per group, not per feed.

## Outcome

- Signal: useful