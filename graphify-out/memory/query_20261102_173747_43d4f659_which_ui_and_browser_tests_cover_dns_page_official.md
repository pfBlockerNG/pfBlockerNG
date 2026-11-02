---
type: "query"
date: "2026-11-02T17:37:47.292038+00:00"
question: "Which UI and browser tests cover DNS page official versus experimental sections and DNSBL webserver collapse defaults?"
contributor: "graphify"
outcome: "useful"
---

# Q: Which UI and browser tests cover DNS page official versus experimental sections and DNSBL webserver collapse defaults?

## Answer

The subgraph locates tests/smoke/ui/test_browser_dns.py for experimental notices and src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php collapses for expand-all. Ranged source reads show Reply Logging is last and Webserver lacks collapse flags; user clarified moving existing section, without new category headings.

## Outcome

- Signal: useful