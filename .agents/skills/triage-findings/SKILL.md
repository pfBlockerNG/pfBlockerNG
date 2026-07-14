---
name: triage-findings
description: Validate a batch of pfBlockerNG pull-request findings against current code and classify each as apply, skip, or defer with evidence. Use when review feedback is numerous or disputed.
---

# Triage review findings

Read `../../../.claude/workflows/triage-findings.js` for the verdict schema. Use read-only
`adversarial-reviewer` subagents for independent findings, or validate inline for
a small set. Check current code, reproduce where possible, use blame to distinguish
PR-introduced from pre-existing defects, and never silently drop a real finding.
The parent makes the final apply/skip/defer decision and replies to review threads.
