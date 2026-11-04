---
type: "query"
date: "2026-11-04T21:33:03.356318+00:00"
question: "Where are DNSBL DNS Caching controls, DNS Bypass Prevention controls, and pfB-DNS DDR status displayed and how are cache preservation and bypass rules gated?"
contributor: "graphify"
outcome: "dead_end"
correction: "pfblockerng_dnsbl.php3209,3409; pfblockerng_apply.inc3206,3254,3352; pfblockerng.inc17572,17577,17807-17808"
---

# Q: Where are DNSBL DNS Caching controls, DNS Bypass Prevention controls, and pfB-DNS DDR status displayed and how are cache preservation and bypass rules gated?

## Answer

The broad graph query returned truncated neighborhoods; scoped source reads established the exact UI sections, DNSBL rule gates and unreachable normal cache dump path.

## Outcome

- Signal: dead_end
- Correction: pfblockerng_dnsbl.php3209,3409; pfblockerng_apply.inc3206,3254,3352; pfblockerng.inc17572,17577,17807-17808