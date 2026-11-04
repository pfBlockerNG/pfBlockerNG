---
type: "query"
date: "2026-11-04T21:23:29.172814+00:00"
question: "managed Resolver VIP DNS gateway fixed standard transport ports live listeners tests"
contributor: "graphify"
outcome: "useful"
---

# Q: managed Resolver VIP DNS gateway fixed standard transport ports live listeners tests

## Answer

Narrowed affected semantic tests to DnsProxyDdrDoh443InterfacesTest, DnsProxyDoh443LiveTest, DnsProxyLiveListenersTest and gateway live listener rigs; exact flag and ownership behavior comes from CodeGraph main.go/tlsbind.go/listeners.go and scoped PHP source.

## Outcome

- Signal: useful