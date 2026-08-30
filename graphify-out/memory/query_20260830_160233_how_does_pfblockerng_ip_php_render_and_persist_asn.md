---
type: "query"
date: "2026-08-30T16:02:33.176126+00:00"
question: "How does pfblockerng_ip.php render and persist asn_token compared with maxmind_key, and where are equivalent live UI tests?"
contributor: "graphify"
outcome: "useful"
---

# Q: How does pfblockerng_ip.php render and persist asn_token compared with maxmind_key, and where are equivalent live UI tests?

## Answer

Graph oriented the investigation to pfblockerng_ip.php, pfb_filter, Form_Input, and the live WebUI harness. Exact source inspection then showed asn_token was loaded from stored iconfig, rendered as text, and unconditionally overwritten on blank POST, while maxmind_key was write-only/password/blank-preserving. Coverage belongs in test_render_smoke.py and test_functional.py.

## Outcome

- Signal: useful