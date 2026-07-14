---
name: issue-triage
description: Produce an evidence-backed pfBlockerNG issue verdict, impact assessment, and ordered fix plan. Use from issue triage before code changes.
---

# Triage an issue

Read `../../../.claude/workflows/issue-triage.js` for the durable triage-record fields and
its exact evidence standard. Use a read-only `planner` against an up-to-date
target-base worktree. Verify each claim, consider alternatives, reproduce when
possible, assess impact, record cited paths and base tip, and return a plan of
self-contained delegated steps. Never edit or comment on the issue in this stage.
