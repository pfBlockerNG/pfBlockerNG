# GitHub issues — reading, triage gates, lifecycle

Scope: work, triage, or transition GitHub issues. Load when: any issue work.

**Read the whole issue before working it** — title, body, AND every comment
(`gh issue view <N> --comments`); later comments routinely revise/narrow/downgrade/invalidate
original (issue #25). Never act on opening text alone. Branch: `issue/{NN}-{slug}`.

**Filing is a dev seat's job** (owner, 2026-08-31). A smoke seat that finds something
relays it to a dev seat to open the issue or PR, unless the owner is working with that
smoke seat directly. The finder still supplies the evidence; the dev seat files it and
owns it from there.

## Scanner/audit finding gate

Scanner, audit, or review finding **actionable** and may become GitHub issue only when
executed evidence proves at least one:

1. Supported producer (GUI, API, import, upgrade, persisted configuration, or external
   data) can generate it without modifying request outside that producer.
2. Crosses authentication or authorization boundary.
3. Causes persistent, cross-user, confidentiality/integrity, or service-wide availability
   impact.

Before issue creation, record producer, supported-path verdict, required privilege,
whether hand-crafting required, impact scope, black-box reproduction. Hand-crafted
request needing already-authorized actor and causing only that request to fail is
**HARDENING-ONLY**: keep in audit record, classify `SKIP` not `DEFER`, and
no issue, no production code change. Scanner sink/crash probe alone proves
language behaviour, not actionable product defect.

## TypeError-class tracker (#1143)

Every newly found **actionable** TypeError-class defect (request/array value reaching
string-typed sink — array-`$_POST` family: #1070/#1106/#1128/#1139) gets own issue and
links as sub-issue of tracker #1143 (GraphQL `addSubIssue`); never fold into older
issue. HARDENING-ONLY findings do not become tracker children.

## Classification at creation

Every issue creation path — human, agent, issue form, or automation — sets exactly one
native GitHub issue type from this table:

| Issue type | Use for |
| --- | --- |
| `Bug` | Unexpected or regressed existing behaviour, including defects in CI tooling |
| `Feature` | A new user-facing capability |
| `Task` | Improvements to existing behaviour; implementation slices; maintenance, testing, CI, documentation, research, and process work |

Labels are optional. Add one only when it gives orthogonal routing, subsystem, risk,
or workflow metadata not already carried by native type (`CI`, `dnsbl`, `security`,
`wayfinder:*`, etc.). Never add `bug` or `enhancement` just to duplicate `Bug`, `Feature`,
or `Task`. Defect = `Bug`; new user-facing capability = `Feature`; improvement to
existing behaviour or maintenance = `Task`. Set type at creation
(`gh issue create --type Bug`); set useful additive labels at creation too.

## Issue state (lifecycle — native signals, #1388)

Native GitHub signals replace retired `WIP`/`Waiting PR` labels (adopted 2026-07-17 from
probe evidence in issue #1388). Applies to all work going forward; old issues keep
legacy labels — no bulk migration, but clear legacy label whenever transition you perform
would have cleared it. Additive labels (`CI`, `dnsbl`, `security`, …) stay.

- **Pick up (claimed)** — `gh issue edit <N> --add-assignee @me`.
- **PR open (waiting-PR)** — `Fixes #N` in PR body; state **derived** from
  open PR (GraphQL `closedByPullRequestsReferences` filtered to `state == OPEN` — merged PRs
  still appear even with `includeClosedPrs: false`; `linked:pr` search qualifier
  over-matches merged-but-open issues, pre-filter only). No issue write.
- **PR `MERGED` by GitHub squash or indirect local fast-forward** — verify the landed
  commit and issue auto-closure (`state_reason: completed`).
- **Local fast-forward not inferred as `MERGED`** — post landed evidence, close the open
  PR, close the issue `--reason completed`, and verify both terminal states. A PR closed
  without either landing path drops its reference; assignee persists (back to claimed).
- **Resolved without a PR** — `gh issue close <N> --reason completed`; dropped/can't-fix —
  remove assignee, close `--reason "not planned"` (or `duplicate`) + status comment
  explaining why.
- **Blocked** — native issue dependencies (GraphQL `addBlockedBy`/`removeBlockedBy`).
  Blocked means `blockedBy` node with `state: OPEN` — closing blocker does NOT remove
  relation and `issueDependenciesSummary` counts closed blockers, so check node states.
- **Waiting-for-information** — `needs-info` label (one state with no native
  primitive).
- **Pickup scan** — `is:open no:assignee`, then drop issues with open blockers; one bulk
  GraphQL `repository.issues` query reads whole board (assignees, linked PRs,
  dependencies, sub-issues) in single call.
