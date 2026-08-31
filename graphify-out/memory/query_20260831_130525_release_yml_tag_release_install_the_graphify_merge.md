---
type: "query"
date: "2026-08-31T13:05:25.462326+00:00"
question: "release.yml tag-release Install the Graphify merge driver ensure-graphify-merge-driver release/3.3 missing helper"
contributor: "graphify"
outcome: "useful"
---

# Q: release.yml tag-release Install the Graphify merge driver ensure-graphify-merge-driver release/3.3 missing helper

## Answer

The tag-release job checks out the historical release source, then invokes a merge-driver helper absent from release/3.3. The current helper also expects patch-graphify.sh under the target checkout. A trusted workflow-SHA scripts checkout plus helper-local patch fallback is required.

## Outcome

- Signal: useful
