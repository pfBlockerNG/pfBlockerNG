---
type: "query"
date: "2026-08-29T07:50:29.875831+00:00"
question: "Where does py-charset-normalizer identity flow through build, tagged/Nightly handoff, catalog, and smoke?"
contributor: "graphify"
outcome: "useful"
---

# Q: Where does py-charset-normalizer identity flow through build, tagged/Nightly handoff, catalog, and smoke?

## Answer

Graph located build-dep fixture and tagged/Nightly handoff contracts plus smoke catalog consumers; production identity is read from FreeBSD-ports while Nightly artifact names are generic wiring fixtures.

## Outcome

- Signal: useful