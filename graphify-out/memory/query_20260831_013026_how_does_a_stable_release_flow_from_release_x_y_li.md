---
type: "query"
date: "2026-08-31T01:30:26.544000+00:00"
question: "How does a stable release flow from release/X.Y line tags through release.yml draft healthcheck to release-with-changelog publication?"
contributor: "graphify"
outcome: "useful"
---

# Q: How does a stable release flow from release/X.Y line tags through release.yml draft healthcheck to release-with-changelog publication?

## Answer

Graph located release gates (test_release_tag_after_verify, test_issue2145_release_skills, release_ci_gate_spec) confirming: build+verify before tag, draft healthcheck outputs, changelog skill publishes the draft. Live git state checked next.

## Outcome

- Signal: useful
