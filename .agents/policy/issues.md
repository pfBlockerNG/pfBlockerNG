# GitHub issues — reading, triage gates, lifecycle

Scope: working, triaging, or transitioning GitHub issues. Load when: any issue work.

**Read the whole issue before working it** — title, body, AND every comment
(`gh issue view <N> --comments`); later comments routinely revise/narrow/downgrade/invalidate
the original (issue #25). Never act on the opening text alone. Branch: `issue/{NN}-{slug}`.

## Scanner/audit finding gate

A scanner, audit, or review finding is **actionable** and may become a GitHub issue only when
executed evidence proves at least one of these:

1. A supported producer (GUI, API, import, upgrade, persisted configuration, or external
   data) can generate it without modifying the request outside that producer.
2. It crosses an authentication or authorization boundary.
3. It causes persistent, cross-user, confidentiality/integrity, or service-wide availability
   impact.

Before issue creation, record the producer, supported-path verdict, required privilege,
whether hand-crafting is required, impact scope, and black-box reproduction. A hand-crafted
request requiring an already-authorized actor and causing only that request to fail is
**HARDENING-ONLY**: keep it in the audit record, classify it `SKIP` rather than `DEFER`, and
do not create an issue or modify production code. A scanner sink/crash probe alone proves a
language behaviour, not an actionable product defect.

## TypeError-class tracker (#1143)

Every newly found **actionable** TypeError-class defect (a request/array value reaching a
string-typed sink — the array-`$_POST` family: #1070/#1106/#1128/#1139) gets its own issue and
is linked as a sub-issue of tracker #1143 (GraphQL `addSubIssue`); never fold it into an older
issue. HARDENING-ONLY findings do not become tracker children.

## Issue state (lifecycle — native signals, #1388)

Native GitHub signals replace the retired `WIP`/`Waiting PR` labels (adopted 2026-07-17 from
the probe evidence in issue #1388). Applies to all work going forward; old issues keep their
legacy labels — no bulk migration, but clear a legacy label whenever a transition you perform
would have cleared it. Descriptive labels (`bug`, `enhancement`, …) stay.

- **Pick up (claimed)** → `gh issue edit <N> --add-assignee @me`.
- **PR open (waiting-PR)** → `Fixes #N` in the PR body; the state is **derived** from the
  open PR (GraphQL `closedByPullRequestsReferences` filtered to `state == OPEN` — merged PRs
  still appear even with `includeClosedPrs: false`; the `linked:pr` search qualifier
  over-matches merged-but-open issues, pre-filter only). No issue write.
- **PR merged** → the issue auto-closes (`state_reason: completed`) — no write. PR closed
  unmerged → the reference drops by itself; the assignee persists (back to claimed).
- **Resolved without a PR** → `gh issue close <N> --reason completed`; dropped/can't-fix →
  remove the assignee, close `--reason "not planned"` (or `duplicate`) + a status comment
  explaining why.
- **Blocked** → native issue dependencies (GraphQL `addBlockedBy`/`removeBlockedBy`).
  Blocked means a `blockedBy` node with `state: OPEN` — closing a blocker does NOT remove
  the relation and `issueDependenciesSummary` counts closed blockers, so check node states.
- **Waiting-for-information** → the `needs-info` label (the one state with no native
  primitive).
- **Pickup scan** → `is:open no:assignee`, then drop issues with open blockers; one bulk
  GraphQL `repository.issues` query reads the whole board (assignees, linked PRs,
  dependencies, sub-issues) in a single call.
