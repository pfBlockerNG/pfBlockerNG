# CodeRabbit — the contract

Scope: every GitHub PR that carries a product, CI, test, or script change.
Load when: opening or pushing a PR, seeing a Fair Usage / "Review limit
reached" notice, landing, or asking whether CodeRabbit reviewed a SHA.

- **Owner:** repo owner. **Last-verified:** 2026-08-15.
- **Why:** CodeRabbit's review is beneficial. Fair Usage is per-developer
  adaptive: after a burst of PR reviews the next slot is delayed and the
  bot posts a quota notice instead of a review. A quota notice is not a
  review. The Aug 15 landing loop merged many SHAs that way because
  landing used to **drop** CodeRabbit when the stated wait was over five
  minutes. That drop is retired.

Composes with [`landing.md`](landing.md) (triage, three-leg, merge gate),
[`waits.md`](waits.md) (no orphaned waits), and `.coderabbit.yaml` (what
auto-review spends).

## Fixed floors

- CodeRabbit stays **advisory for CI**: the `CodeRabbit` check never
  blocks `wait-checks.sh`. A quota check is `SUCCESS` with
  "Review rate limited" — that is not a finished review.
- Three-leg adversarial review is still mandatory. It does **not**
  replace CodeRabbit. Both run.
- A SHA whose only CodeRabbit engagement is a quota notice is
  **unreviewed by CodeRabbit**. Do not report it as "CR clean".
- **Never** `@coderabbitai review` (or `resume`) while the latest
  CodeRabbit comment is a quota notice whose "Next review available in"
  has not elapsed. That spends nothing and can refresh the window.
- **`@coderabbitai review` only works when automatic reviews are
  paused.** CodeRabbit is incremental: if auto-review is still on, a
  later `@coderabbitai review` replies "Already reviewed" / "This
  command is applicable only when automatic reviews are paused" and
  does not look at the head. That is what happened on #2430. Agents
  **must** `@coderabbitai pause` (see below) before any manual review
  command.
- **Never** `@coderabbitai review` again after a finished review for
  format-only, comment-only, ruff, or mechanical APPLY-of-CR's-own-diff.
  Those incrementals are what burned the Aug 15 hourly allowance.
- Do not enable usage-based billing or paste billing org IDs into
  comments. Billing is an owner decision.
- **Do not open a ready PR while the ledger says wait.** There is
  no Fair Usage REST API and no mute label. Immediately before
  `gh pr create`, run `scripts/agent/before-pr-create.sh`. Exit 3
  → wait until the printed `next slot` (or until the owner says
  open anyway). Do not invent `cr-hold` / `cr-go` labels.

## Advisory limit (not a mute gate)

`scripts/agent/coderabbit_limit.py status` reconstructs a **lower
bound** on this repo's PR-review spend from
`GET /repos/{o}/{r}/issues/comments?since=` and prints the full
picture (plan hourly columns, 7-day taper band, used/remaining
this hour, last review, next slot, live quota if any). Use
`created_at` — CodeRabbit edits the summarize comment in place.
Incrementals collapse onto that comment; other repos are
invisible. Wrong on the cheap side costs one delayed PR; a mute
gate would need an exact number we do not have (#2435).

No GitHub Action. Only agents consume the number, so the script
on the PR-open path is the feature. There is no hold workflow.

`@coderabbitai pause` and `@coderabbitai review` are **one PR, at
review time only**. Never `@coderabbitai review` while the latest
CodeRabbit comment is a live quota countdown. Never broadcast
pause comments.

`.coderabbit.yaml` pauses incremental auto-review after two
reviewed commits (`auto_pause_after_reviewed_commits: 2`): first
look plus the APPLY round. Turning incrementals off dropped the
APPLY review — that is where the #2432 / #2434 defects lived.
Format-only pushes after pause do not spend a slot.
`review_status: false` hides "Review skipped" status widgets.

## Owner override and substitute reviewer

Only the **repo owner**, in conversation, may spend a slot anyway
or name another reviewer. No labels. Agents never invent a
substitute. Three-leg still runs. CLI-in-CI is #2436 (needs a
burst test + an Agentic API key before anyone builds it).

## Required path (every future PR)

1. Run `scripts/agent/before-pr-create.sh`. Exit 3 → do not
   `gh pr create` until the printed next slot, unless the owner
   overrode in this conversation. Exit 0 → open a non-draft PR.
   Auto-review should ACK within ten minutes
   (`wait-reviewer.sh --until ack`).
2. **ACK is a real review** (walkthrough plus "Actionable comments
   posted" / "No actionable comments", or an inline review on the
   head SHA) → triage every finding per landing.md. Stop here.
3. **ACK is only a quota notice** ("Review limit reached" /
   `rate limited by coderabbit.ai` and no finished review):
   1. Do not comment on siblings and do not open another ready PR.
   2. Re-run `before-pr-create.sh` (or read the quota line).
      Parse **Next review available in** (`N` minutes or hours).
      Unparsable → treat as 15 minutes, once.
   3. Arm a **self-terminating** wait for `N + 30s`
      ([`waits.md`](waits.md): cap inside the wait, never a bare
      unbounded sleep). If `N` exceeds the waits.md two-hour
      ladder, wait the ladder, then **record a miss** — do not
      nudge. A late nudge during a still-open window refreshes
      the countdown (fixed floor above).
   4. When the wait ends, post **exactly one** top-level
      `@coderabbitai review` if the PR is paused; otherwise
      `@coderabbitai pause` first, then `review`.
   5. Arm `--until finished`. **FINISHED** → triage.
      **Another quota notice** → wait that new window **once**,
      nudge **once** more, then stop. Record the miss
      (SHA + title) on the landing audit. Do not loop.
4. **NOACK** in ten minutes → `@coderabbitai pause` if not already,
   then one `@coderabbitai review`, fresh ten-minute ack window.
   Still silent → CodeRabbit unavailable; three-leg carries the
   review step. Never a second no-ack nudge.
5. **PAUSE** (branch too active): leave paused when the latest
   commits are format-only or mechanical review-fixes. `@coderabbitai
   resume` only when product behaviour changed **and** no live
   quota notice is in force.
6. Incremental auto-review is capped by
   `auto_pause_after_reviewed_commits: 2` in `.coderabbit.yaml`.
   After pause, do not spend a slot unless step 5 says resume.

Merge still does not *wait on the CodeRabbit check*. It **does**
follow this path before claiming CodeRabbit reviewed the head.
If the path ends in a recorded miss, three-leg may land the PR;
the SHA stays on the unreviewed-by-CR list until a later
CodeRabbit-style pass.

## Improve the limit (every quota notice)

A quota notice is a spend defect, not just a delay. Before the
next PR opens, inspect **this session's** spend and apply any
tightening that is obvious **now** (same session, not "later"):

| Waste | Tighten |
| --- | --- |
| `@coderabbitai review` after ruff / comment APPLY / CR's own suggested diff | stop; landing spend rule already forbids it |
| Third+ incremental on one PR | confirm `auto_pause_after_reviewed_commits` is 2; lower to 1 if incrementals are the burst |
| Auto-review of `.md`, `.agents/`, `docs/`, `legacy/`, vendored trees | confirm `.coderabbit.yaml` `path_filters`; add the new tree |
| Many product PRs in one hour | serialize: do not `gh pr create` until `before-pr-create.sh` says open |
| Quota notice on every open PR | stop opening ready PRs; wait the printed next slot |
| `@coderabbitai review` on an unpaused PR | no-op ("Already reviewed"); pause first |
| Nudge while a quota notice is still counting down | never; wait the stated window |

Write one line on the PR audit: what spent the slots, what you
changed (config / behaviour / nothing because already tight).
If `.coderabbit.yaml` or this file should change, change it in
this session.

Docs: [Fair Usage](https://docs.coderabbit.ai/management/plans#fair-usage-limits-policy),
[rate limits](https://docs.coderabbit.ai/management/plans#rate-limits).
A CodeRabbit MCP connection does **not** raise review quota
(MCP is CodeRabbit *pulling* issue trackers into a review).

## Missed-review backlog

When a merged SHA had only a quota notice (or no CR engagement)
and no later finished review of that SHA:

- Append one line to [`.agents/policy/coderabbit-misses.md`](coderabbit-misses.md)
  (`SHA  title  PR#`). Newest first.
- Later sessions review that list CodeRabbit-style (correctness,
  hostile inputs, test honesty) newest first.
- Do not start the older 481-commit tail unless a current cluster
  requires it.

## Out of scope

- Making the CodeRabbit check required in branch protection.
- Paying per-file overage without an owner decision.
- Re-reviewing a SHA CodeRabbit already finished, just because
  a later format commit landed.
