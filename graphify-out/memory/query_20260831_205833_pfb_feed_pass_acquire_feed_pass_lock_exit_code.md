---
type: "query"
date: "2026-08-31T20:58:33.363671+00:00"
question: "pfb_feed_pass_acquire feed pass lock exit code"
contributor: "graphify"
outcome: "useful"
---

# Q: pfb_feed_pass_acquire feed pass lock exit code

## Answer

acquire() is at pfblockerng.inc:19042; its fopen-failure branch returned TRUE (fail-open) while the un-contended flock failure returned FALSE. Callers: begin() plus extra.inc/alerts.php. Fixed to fail closed for #3000.

## Outcome

- Signal: useful