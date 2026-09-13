---
type: "query"
date: "2026-09-13T19:21:36.704056+00:00"
question: "pfb_registry_pass pfb_run_migrations pfblockerng_category_edit global_log"
contributor: "graphify"
outcome: "dead_end"
correction: "CodeGraph source and targeted configuration reads establish extra.inc:1333 global disabled_log default; category_edit.php:558/892/1041 legacy Enabled fallback; wizard.inc:290 enabled seed; apply.inc:2146 global precedence. Graph query returned broad topology rather than the default contract."
---

# Q: pfb_registry_pass pfb_run_migrations pfblockerng_category_edit global_log

## Answer

Global registry, group editor, wizard, and apply precedence are the owning surfaces for the default correction.

## Outcome

- Signal: dead_end
- Correction: CodeGraph source and targeted configuration reads establish extra.inc:1333 global disabled_log default; category_edit.php:558/892/1041 legacy Enabled fallback; wizard.inc:290 enabled seed; apply.inc:2146 global precedence. Graph query returned broad topology rather than the default contract.