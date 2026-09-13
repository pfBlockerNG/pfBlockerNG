---
type: "query"
date: "2026-09-13T13:37:35.362888+00:00"
question: "Which tests gate the production ZIP pipefail shell capability for issue #2821?"
contributor: "graphify"
outcome: "useful"
source_nodes: [".requirePipefailShell()"]
---

# Q: Which tests gate the production ZIP pipefail shell capability for issue #2821?

## Answer

Query requirePipefailShell narrowed the affected path to DownloadExtractedPayloadSanityTest.php:L320 and downloadArchive:L336, shared by its four test methods. Source-specific review additionally identifies DownloadRejectValidatorClearTest fixture and its sibling capability guard. CI matrix and tool setup are configuration surfaces, outside this code graph.

## Outcome

- Signal: useful

## Source Nodes

- .requirePipefailShell()