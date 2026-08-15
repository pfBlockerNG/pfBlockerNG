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
- **Mute auto-review while Fair Usage is live.** A quota notice on
  one PR will otherwise fire on every other open PR and pollute
  them with the same "Review limit reached" comment. The mute is
  the `cr-hold` label (preferred) or a `WIP` title / `WIP` label /
  `[skip review]` title — `.coderabbit.yaml` skips auto-review on
  all of those. Do **not** retitle a ready PR as WIP just to mute
  CodeRabbit; use `cr-hold`. Drafts are also skipped
  (`drafts: false`).

## Do not spam pause comments

Broadcasting `@coderabbitai pause` on every open PR is the spam
we are avoiding. Mute is a **label**, applied by the
`coderabbit-hold` workflow (no comment) or by `gh pr edit --add-label
cr-hold`. `.coderabbit.yaml` skips auto-review on `cr-hold`.

`@coderabbitai pause` and `@coderabbitai review` are **one PR, at
review time only**:

1. Quota notice → the Action labels every open PR `cr-hold`. Agents
   do **not** comment on the siblings.
2. After the window: remove `cr-hold` from **one** PR, post
   `@coderabbitai pause` **once** on that PR (required: `@review` is
   a no-op unless auto-review is paused — #2430), then
   `@coderabbitai review` **once**. Leave every other PR labeled.
3. Never `@coderabbitai pause` or `review` on a PR that still has
   `cr-hold`, and never on a PR whose latest CR comment is a live
   quota countdown.
4. `@coderabbitai resume` only when product behaviour changed after
   a finished review **and** no quota window is live.

`.coderabbit.yaml` already turns off incremental auto-review and
status-only comments so a later push does not spend a slot or post
"Review skipped".

## Mute while a quota window is live

Any agent (this one or another) that sees a quota notice, or that
opens a PR knowing a window is still counting down:

1. Let the `coderabbit-hold` workflow label open PRs, or
   `gh pr edit N --add-label cr-hold` yourself. **No pause comments
   on the siblings.**
2. New PRs during the window: `gh pr create --label cr-hold` (or
   open as draft). Never open a ready, unlabeled, non-draft PR
   while a countdown is live.
3. Leave `cr-hold` on siblings until **their** turn. Removing it
   from every PR at once just recreates the burst.
4. When the window elapses: remove `cr-hold` from **one** PR,
   `@coderabbitai pause` once on that PR, then `@coderabbitai
   review` once. Do not comment on the rest.
5. `cr-hold` is not "work unfinished". Three-leg, CI, and landing
   continue.

## Required path (every future PR)

1. Open a non-draft PR. Auto-review should ACK within ten minutes
   (`wait-reviewer.sh --until ack`).
2. **ACK is a real review** (walkthrough plus "Actionable comments
   posted" / "No actionable comments", or an inline review on the
   head SHA) → triage every finding per landing.md. Stop here.
3. **ACK is only a quota notice** ("Review limit reached" /
   `rate limited by coderabbit.ai` and no finished review):
   1. Do not comment on siblings. The hold workflow (or
      `gh pr edit --add-label cr-hold`) mutes them.
   2. Apply `cr-hold` to every **other** open PR if the Action
      has not yet (mute section above).
   3. Parse **Next review available in** (`N` minutes or hours).
      Unparsable → treat as 15 minutes, once.
   4. Arm a **self-terminating** wait for `N + 30s`
      ([`waits.md`](waits.md): cap inside the wait, never a bare
      unbounded sleep). If `N` exceeds the waits.md two-hour
      ladder, wait the ladder, then **record a miss** — do not
      nudge. A late nudge during a still-open window refreshes
      the countdown (fixed floor above).
   5. When the wait ends, remove `cr-hold` from **this** PR only
      (it must already be paused), then post **exactly one**
      top-level `@coderabbitai review`. If the PR is not paused,
      `@coderabbitai pause` first, then `review` — never `review`
      on an unpaused PR.
   6. Arm `--until finished`. **FINISHED** → triage.
      **Another quota notice** → re-apply `cr-hold`, wait that
      new window **once**, nudge **once** more, then stop.
      Record the miss (SHA + title) on the landing audit. Do not loop.
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
| Many product PRs in one hour | serialize: next PR opens with `cr-hold` (or as draft) until the in-flight PR's first finished CR review |
| Quota notice on every open PR | `@coderabbitai pause` + `cr-hold` on siblings immediately |
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
