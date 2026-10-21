---
type: "query"
date: "2026-10-21T22:32:47.593227+00:00"
question: "pfb_dns_proxy_clause pfb_dns_proxy_resolver pfb_unbound_listens_v6"
contributor: "graphify"
outcome: "useful"
---

# Q: pfb_dns_proxy_clause pfb_dns_proxy_resolver pfb_unbound_listens_v6

## Answer

Source confirmed Resolver move clause at pfblockerng.inc:14799-14801 and generator at 4606: both loopback backend interfaces are emitted but only IPv4 --upstream used. Native get_interface_ip(lo0) can select configured loopback family; readiness must inspect actual generated command.

## Outcome

- Signal: useful