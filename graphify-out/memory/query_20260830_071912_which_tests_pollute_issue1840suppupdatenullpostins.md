---
type: "query"
date: "2026-08-30T07:19:12.817203+00:00"
question: "Which tests pollute Issue1840SuppUpdateNullPostinstallTest globals under random PHPUnit order?"
contributor: "graphify"
outcome: "dead_end"
correction: "Use CodeGraph source flow plus executed pinned-order/filter probes to identify the producer."
---

# Q: Which tests pollute Issue1840SuppUpdateNullPostinstallTest globals under random PHPUnit order?

## Answer

The graph located Issue1840SuppUpdateNullPostinstallTest and its production dependency but did not identify the state producer.

## Outcome

- Signal: dead_end
- Correction: Use CodeGraph source flow plus executed pinned-order/filter probes to identify the producer.