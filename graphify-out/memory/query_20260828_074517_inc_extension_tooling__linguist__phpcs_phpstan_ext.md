---
type: "query"
date: "2026-08-28T07:45:17.012016+00:00"
question: "inc extension tooling, linguist, phpcs phpstan extensions, file naming convention"
contributor: "graphify"
outcome: "dead_end"
correction: "Tool-configuration questions are answered by the config files themselves (.gitattributes, .editorconfig, phpcs.xml.dist, phpstan.neon), which the code graph does not index as configuration semantics."
---

# Q: inc extension tooling, linguist, phpcs phpstan extensions, file naming convention

## Answer

Returned test-file nodes (test_workflow_files_scan_both_yaml_extensions, WidgetIncludeConventionTest, test_context_budget); no configuration surface.

## Outcome

- Signal: dead_end
- Correction: Tool-configuration questions are answered by the config files themselves (.gitattributes, .editorconfig, phpcs.xml.dist, phpstan.neon), which the code graph does not index as configuration semantics.