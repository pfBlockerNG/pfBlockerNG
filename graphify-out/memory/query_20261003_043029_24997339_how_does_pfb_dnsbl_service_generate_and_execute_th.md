---
type: "query"
date: "2026-10-03T04:30:29.304316+00:00"
question: "How does pfb_dnsbl_service generate and execute the DNSBL rc start/stop path, and how should its behavioral test exercise it?"
contributor: "graphify"
outcome: "useful"
---

# Q: How does pfb_dnsbl_service generate and execute the DNSBL rc start/stop path, and how should its behavioral test exercise it?

## Answer

pfb_dnsbl_service() (pfblockerng.inc ~3837) builds $rc start/stop bodies and hands them to write_rcfile(); pfSense wraps them as rc_start()/rc_stop() with default rc_restart = rc_stop; rc_start. Graph query returned mostly unrelated nodes. Test: capture bodies via tests/php/pfsense_doubles.php write_rcfile double, rewrite absolute paths to sandbox command doubles, run under dash with a modeled process table + tick clock (tests/php/DnsblServiceRestartTest.php). Fix: rc_stop polls pgrep -x lighttpd_pfb (TERM@0s, KILL@5s, return 1@7s); rc_start does rc_stop || return 1.

## Outcome

- Signal: useful