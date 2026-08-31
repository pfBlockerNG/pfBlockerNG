---
type: "query"
date: "2026-08-31T16:56:28.225752+00:00"
question: "issue 3004 release-published explicit workflow_dispatch release-with-changelog exact run"
contributor: "graphify"
outcome: "useful"
---

# Q: issue 3004 release-published explicit workflow_dispatch release-with-changelog exact run

## Answer

release-published.yml now owns one explicit workflow_dispatch path keyed by exact Release ID/tag, resolves the published Release live before existing classification, and release-with-changelog dispatches and watches the exact downstream run.

## Outcome

- Signal: useful