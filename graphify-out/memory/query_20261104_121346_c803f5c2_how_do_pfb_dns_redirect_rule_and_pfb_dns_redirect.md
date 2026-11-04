---
type: "query"
date: "2026-11-04T12:13:46.545183+00:00"
question: "How do pfb_dns_redirect_rule and pfb_dns_redirect_target6 choose a target per interface, and how are client ACLs derived in native Resolver mode?"
contributor: "graphify"
outcome: "useful"
---

# Q: How do pfb_dns_redirect_rule and pfb_dns_redirect_target6 choose a target per interface, and how are client ACLs derived in native Resolver mode?

## Answer

Located the redirect builder and target helper in pfblockerng.inc. The builder keeps the client source address and creates per-interface rules; native Resolver acceptance depends separately on its client ACL. The live native LAN-listened probe answered through lanip without new grants.

## Outcome

- Signal: useful