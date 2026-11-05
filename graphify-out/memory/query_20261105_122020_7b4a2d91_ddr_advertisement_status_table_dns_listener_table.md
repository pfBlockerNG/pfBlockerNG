---
type: "query"
date: "2026-11-05T12:20:20.283232+00:00"
question: "DDR advertisement status table DNS listener table refresh expected hostname interface addresses"
contributor: "graphify"
outcome: "dead_end"
correction: "Literal advertisement/refresh label grep located pfb_dns_ddr_status, pfb_dns_ddr_status_panel and the page call; direct reads traced the current implementation."
---

# Q: DDR advertisement status table DNS listener table refresh expected hostname interface addresses

## Answer

The broad graph query returned address-test topology but did not locate the DDR page collector or renderer. Exact labels located the implementation in pfblockerng.inc:15931 and pfblockerng_dns.php:424.

## Outcome

- Signal: dead_end
- Correction: Literal advertisement/refresh label grep located pfb_dns_ddr_status, pfb_dns_ddr_status_panel and the page call; direct reads traced the current implementation.