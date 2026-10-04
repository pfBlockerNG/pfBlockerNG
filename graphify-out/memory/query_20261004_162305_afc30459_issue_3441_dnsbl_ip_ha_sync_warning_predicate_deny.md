---
type: "query"
date: "2026-10-04T16:23:05.353501+00:00"
question: "issue 3441 DNSBL IP HA sync warning predicate Deny actions stored settings"
contributor: "graphify"
outcome: "useful"
---

# Q: issue 3441 DNSBL IP HA sync warning predicate Deny actions stored settings

## Answer

The scoped graph located the prior stored-versus-runtime issue-3441 query. Final review and executed canonical-normalizer probes establish that restored/HA DNSBL IP settings accept Deny, Permit, and Match actions; all nine generate auto rules and must warn. Disabled, invalid, and all four Alias actions must not warn. The page reads stored gateway enable flags, not runtime mirrors.

## Outcome

- Signal: useful