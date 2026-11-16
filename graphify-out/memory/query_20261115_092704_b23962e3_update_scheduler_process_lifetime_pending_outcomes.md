---
type: "query"
date: "2026-11-15T09:27:04.772537+00:00"
question: "Update scheduler process lifetime pending outcomes admission restart"
contributor: "graphify"
outcome: "dead_end"
correction: "CodeGraph and go/pfb_core/update/{command,supervisor,gate}.go plus scheduler/scheduler.go provide actual ownership source."
---

# Q: Update scheduler process lifetime pending outcomes admission restart

## Answer

Root graph returned PHP tests but did not expose Go worker ownership. CodeGraph plus exact Go source identified watchdog group kill and scheduler launch-before-save.

## Outcome

- Signal: dead_end
- Correction: CodeGraph and go/pfb_core/update/{command,supervisor,gate}.go plus scheduler/scheduler.go provide actual ownership source.