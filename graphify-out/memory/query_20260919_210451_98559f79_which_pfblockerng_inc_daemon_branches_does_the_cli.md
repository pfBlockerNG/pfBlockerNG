---
type: "query"
date: "2026-09-19T21:04:51.707756+00:00"
question: "Which pfblockerng.inc daemon branches does the CLI dispatch invoke, and which constants do those branches and pfb_global reference during include time?"
contributor: "graphify"
outcome: "dead_end"
correction: "CodeGraph explore answered the reachability half (pfb_global:3307, pfb_daemon_dnsbl:19069, pfb_daemon_filterlog:18357, pfb_reentry_timeout:5205 referencing PFB_REENTRY_TIMEOUT_MIN/MAX). The remaining half is a line-ordering question the graph does not model - top-level statement order relative to the dispatch line - so grep over the raw source is the correct surface for enumerating the 21 guarded if (!defined()) sites."
---

# Q: Which pfblockerng.inc daemon branches does the CLI dispatch invoke, and which constants do those branches and pfb_global reference during include time?

## Answer

Returned an unfocused subgraph dominated by unrelated test nodes (test_agent_roles_check, test_check_composer_vendor); no dispatch-branch or constant-reference edges surfaced.

## Outcome

- Signal: dead_end
- Correction: CodeGraph explore answered the reachability half (pfb_global:3307, pfb_daemon_dnsbl:19069, pfb_daemon_filterlog:18357, pfb_reentry_timeout:5205 referencing PFB_REENTRY_TIMEOUT_MIN/MAX). The remaining half is a line-ordering question the graph does not model - top-level statement order relative to the dispatch line - so grep over the raw source is the correct surface for enumerating the 21 guarded if (!defined()) sites.