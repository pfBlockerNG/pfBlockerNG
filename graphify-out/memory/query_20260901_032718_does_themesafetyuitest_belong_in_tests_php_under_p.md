---
type: "query"
date: "2026-09-01T03:27:18.781948+00:00"
question: "Does ThemeSafetyUiTest belong in tests/php under pfBlockerNG's testing strategy, and which contracts should live in PHPUnit source tests versus Tier A ui_render and Tier B ui_browser tests?"
contributor: "graphify"
outcome: "useful"
---

# Q: Does ThemeSafetyUiTest belong in tests/php under pfBlockerNG's testing strategy, and which contracts should live in PHPUnit source tests versus Tier A ui_render and Tier B ui_browser tests?

## Answer

Mostly. ThemeSafetyUiTest belongs as a fast hermetic source-invariant gate in PHPUnit, but it is supplementary and its name overstates its reach. Repository policy requires www changes to carry Tier A ui_render coverage and visual or structural behavior to carry Tier B ui_browser coverage. PR #2857 ultimately added test_theme_legibility_render.py and test_browser_theme_legibility.py after review, so final layering was mostly correct. Remaining gap: ThemeSafety itself cannot detect inherited/computed contrast, and browser coverage validates Support layout rather than systematic dark-theme or CodeMirror contrast. Keep the file where it is, treat it as opaque-background pairing lint, and put future user-visible theme claims in focused Tier A/B tests instead of expanding the parser.

## Outcome

- Signal: useful