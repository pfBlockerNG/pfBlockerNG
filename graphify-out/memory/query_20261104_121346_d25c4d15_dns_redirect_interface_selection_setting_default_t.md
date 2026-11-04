---
type: "query"
date: "2026-11-04T12:13:46.671999+00:00"
question: "DNS Redirect interface selection setting default toggle pfb_dns_redirect"
contributor: "graphify"
outcome: "dead_end"
correction: "Literal registered-key search found dnsbl/dnsbl_redir and dnsbl/dnsbl_redir_int in pfblockerng_extra.inc:1836-1848, pfblockerng_dnsbl.php:3214-3269, and selected-only reconciliation in pfblockerng_apply.inc:3253-3324."
---

# Q: DNS Redirect interface selection setting default toggle pfb_dns_redirect

## Answer

The broad graph query did not locate the existing control. DNSBL already provides Enable and an explicit interface multi-select with an empty default; no apply-all toggle or automatic ACL expansion is needed.

## Outcome

- Signal: dead_end
- Correction: Literal registered-key search found dnsbl/dnsbl_redir and dnsbl/dnsbl_redir_int in pfblockerng_extra.inc:1836-1848, pfblockerng_dnsbl.php:3214-3269, and selected-only reconciliation in pfblockerng_apply.inc:3253-3324.