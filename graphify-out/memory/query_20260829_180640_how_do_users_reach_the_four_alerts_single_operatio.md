---
type: "query"
date: "2026-08-29T18:06:40.528401+00:00"
question: "How do users reach the four Alerts single-operation mutations delete_ip re-add, delete_ipwhitelist delete, ip_remove lock re-add, and ip_white add, and which tests cover their UI and feed-pass lock interactions?"
contributor: "graphify"
outcome: "useful"
---

# Q: How do users reach the four Alerts single-operation mutations delete_ip re-add, delete_ipwhitelist delete, ip_remove lock re-add, and ip_white add, and which tests cover their UI and feed-pass lock interactions?

## Answer

The graph located the existing Alerts mutation coverage in tests/php/AlertsPfctlCheckedSitesTest.php and reachable UI coverage in tests/smoke/ui/test_alerts.py, narrowing production analysis to the Alerts page.

## Outcome

- Signal: useful