---
type: "query"
date: "2026-11-04T22:13:03.390677+00:00"
question: "DNS proxy encrypted listener test fixture DNS Name requirement DnsProxyServiceTest DnsListenVipInterfaceAddressesTest"
contributor: "graphify"
outcome: "useful"
---

# Q: DNS proxy encrypted listener test fixture DNS Name requirement DnsProxyServiceTest DnsListenVipInterfaceAddressesTest

## Answer

Legacy encrypted fixtures require an explicit valid pfB-DNS Name. DnsProxyServiceTest owns its sandbox settings; DnsListenVipInterfaceAddressesTest served() must combine normal and fixed-port flags. KeepRunningScenario krEnableDot is the shared encrypted-only fixture for package and live-listener tests.

## Outcome

- Signal: useful