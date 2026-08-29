---
type: "query"
date: "2026-08-28T07:45:08.400332+00:00"
question: "PHP include require of .inc files, pfblockerng.inc loading convention"
contributor: "graphify"
outcome: "dead_end"
correction: "The answer was in configuration and require_once lines, not code structure: phpcs.xml.dist extensions=\"php,inc\", phpstan.neon fileExtensions [php, inc], .editorconfig [*.{php,inc}], and the require_once('...inc') statements at the head of each www/ page. Reached by reading those files and by git grep, not by the graph."
---

# Q: PHP include require of .inc files, pfblockerng.inc loading convention

## Answer

Returned PHPCS sniff and test nodes (RequirePfbFilterSniff, WidgetIncludeConventionTest, pfblockerng.sh functions); none carried the include convention.

## Outcome

- Signal: dead_end
- Correction: The answer was in configuration and require_once lines, not code structure: phpcs.xml.dist extensions="php,inc", phpstan.neon fileExtensions [php, inc], .editorconfig [*.{php,inc}], and the require_once('...inc') statements at the head of each www/ page. Reached by reading those files and by git grep, not by the graph.