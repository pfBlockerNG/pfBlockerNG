---
type: "query"
date: "2026-11-05T01:36:27.277698+00:00"
question: "pfb_validate_dns_listen_vip_only_post pfb_dns_listen_vips_apply listener-only DNS policy"
contributor: "graphify"
outcome: "useful"
---

# Q: pfb_validate_dns_listen_vip_only_post pfb_dns_listen_vips_apply listener-only DNS policy

## Answer

Activation blocker is separate from listener and Name enforcement. Keep basic prerequisites; remove DHCP/RA validation refusal and F2 NULL/automatic helper extension. Preserve original apply own-list narrowing and selected foreign/frozen ownership skip. DnsVipOnlyModeTest retains endpoint/prerequisite/apply coverage; new listener-only policy regression covers the authorized cutover.

## Outcome

- Signal: useful