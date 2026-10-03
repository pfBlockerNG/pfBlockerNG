---
type: "query"
date: "2026-10-03T05:48:02.352075+00:00"
question: "How do pfb_create_dnsbl, pfb_create_lighttpd, test_dnsbl_ipv6_vip_block_page, and the IPv4/IPv6 DNSBL NAT rows relate for issue 3407?"
contributor: "graphify"
outcome: "useful"
---

# Q: How do pfb_create_dnsbl, pfb_create_lighttpd, test_dnsbl_ipv6_vip_block_page, and the IPv4/IPv6 DNSBL NAT rows relate for issue 3407?

## Answer

The graph located the permanent live test in tests/smoke/test_smoke_matrix.py and linked it to the pfblockerng.inc production surface plus smoke helpers. It confirms the branch scope is the DNSBL NAT-row emission and direct VIP listener behavior; raw source details still require the named files because the broad traversal was truncated.

## Outcome

- Signal: useful