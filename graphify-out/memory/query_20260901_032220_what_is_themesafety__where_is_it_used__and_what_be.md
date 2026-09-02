---
type: "query"
date: "2026-09-01T03:22:20.368315+00:00"
question: "What is ThemeSafety, where is it used, and what behavior does it enforce?"
contributor: "graphify"
outcome: "useful"
---

# Q: What is ThemeSafety, where is it used, and what behavior does it enforce?

## Answer

ThemeSafetyUiTest is a PHPUnit source scanner introduced with PR #2857. It scans PHP, INC, JS, and CSS under pfBlockerNG UI/package/widget/webasset roots and fails on opaque background declarations lacking a foreground in the same element or declaration context. Translucent, transparent, null, interpolated, and CSS-variable values are accepted. Existing unresolved sites are pinned in a dated TODO; dnsbl_default.php is allowlisted because no pfSense theme applies. It is Tier 1 only: it does not render pages or calculate WCAG contrast.

## Outcome

- Signal: useful