---
type: "query"
date: "2026-08-31T13:46:49.105902+00:00"
question: "Issue 2997 release tag-only mutation Graphify merge-driver inventory and tests"
contributor: "graphify"
outcome: "useful"
---

# Q: Issue 2997 release tag-only mutation Graphify merge-driver inventory and tests

## Answer

The exhaustive driver inventory treated refs/tags pushes as content mutations. release/3.3 contains no Graphify files, and tag-release only pushes an annotated tag ref, so the tag job should be excluded while seven branch/content mutation jobs remain guarded.

## Outcome

- Signal: useful