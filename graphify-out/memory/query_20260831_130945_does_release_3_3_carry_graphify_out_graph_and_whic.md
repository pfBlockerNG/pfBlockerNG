---
type: "query"
date: "2026-08-31T13:09:45.430450+00:00"
question: "Does release/3.3 carry graphify-out graph and which tag-release merge-driver helper files are required?"
contributor: "graphify"
outcome: "corrected"
correction: "git ls-tree -r origin/release/3.3 showed no Graphify or agent-helper files"
---

# Q: Does release/3.3 carry graphify-out graph and which tag-release merge-driver helper files are required?

## Answer

Exact git tree inspection found no .gitattributes, graphify-out, or scripts/agent paths on release/3.3. Tag-release only pushes an immutable tag ref, so no content merge can invoke a Graphify merge driver; installing it there is unnecessary and breaks historical release lines.

## Outcome

- Signal: corrected
- Correction: git ls-tree -r origin/release/3.3 showed no Graphify or agent-helper files
