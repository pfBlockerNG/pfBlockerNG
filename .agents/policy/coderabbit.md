# CodeRabbit — the contract

Scope: every GitHub PR that carries a product, CI, test, or script change.
Load when: a PR is ready to be judged, a Fair Usage / "Review limit
reached" notice appears, or you are dispatching the CLI-in-CI workflow.

- **Owner:** repo owner. **Last-verified:** 2026-08-17.
- **Why:** CodeRabbit's review is beneficial, but Fair Usage is
  per-developer and adaptive: after a burst the next slot is delayed and
  the bot posts a quota notice instead of a review. **Automatic review
  is off** (`.coderabbit.yaml`, `auto_review.enabled: false`), so a PR is
  reviewed only when we ask. We spend the one slot deliberately, on a PR
  we already believe is mergeable. Predicting the free window was not
  worth the machinery it cost, and it is retired (owner, 2026-08-17).

Composes with [`landing.md`](landing.md) (triage, leg review, merge gate),
[`waits.md`](waits.md) (no orphaned waits), and `.coderabbit.yaml`.

## Fixed floors

- **CodeRabbit is not part of the standard PR wait.** Opening or pushing
  a PR triggers nothing. There is no acknowledgement window and no
  auto-review poll. Never wait on CodeRabbit before you have asked it.
- **Ask once, at the end.** Post exactly one top-level
  `@coderabbitai review` when **all** of these hold: development is
  finished; the adversarial review of [`landing.md`](landing.md) is
  complete and its findings are resolved; CI is green on the head SHA;
  and you judge the code ready to merge. Anything short of that is not
  worth a slot.
- CodeRabbit stays **advisory**: the `CodeRabbit` check never blocks
  `wait-checks.sh` and never blocks merge.
- The adversarial leg review is still mandatory and still runs first.
  CodeRabbit does not replace it, and it does not replace CodeRabbit.
- A quota notice is not a review. A SHA whose only CodeRabbit engagement
  is a quota notice is **unreviewed by CodeRabbit**; do not report it as
  "CR clean".
- **Never** `@coderabbitai review` while the latest CodeRabbit comment is
  a quota notice whose "Next review available in" has not elapsed. That
  spends nothing and can refresh the window.
- **Never** ask again after a finished review for a format-only,
  comment-only, lint, or mechanical APPLY-of-CodeRabbit's-own-diff round.
  Ask a second time only if product behaviour materially changed after
  the review, and only once.
- **Never write the handle live when you are writing ABOUT it.** GitHub sends the
  mention from inside inline code too — a ledger entry recording that we never
  asked for a review, with the handle in backticks in a table cell, tagged the bot
  and drew an auto-reply that also wrote the exchange into its learnings
  (PR #2520, 2026-08-18). In ledgers, audit comments, issue bodies, commit
  messages and policy text, break it (`@ coderabbitai`) or name it in prose. Write
  it live ONLY when the ask itself is the intent. An accidental tag is not an ask:
  it spends goodwill, muddies the audit trail about whether a review was requested,
  and can read as a second ask inside a live quota window.
- No `@coderabbitai pause` / `resume` dance. Auto-review is off, so
  pausing buys nothing; never broadcast pause comments.
- No mute labels. `cr-hold` / `cr-go` do not exist; do not invent them.
- Do not enable usage-based billing or paste billing org IDs into
  comments. Billing is an owner decision.

## Required path (every PR)

1. Land the work through [`landing.md`](landing.md) as usual: adversarial
   review, findings triaged and pushed, CI green on the head SHA.
2. When you judge the PR mergeable, post **exactly one** top-level
   `@coderabbitai review` comment.
3. Arm a bounded wait for the result — `scripts/agent/wait-reviewer.sh
   --repo OWNER/REPO --pr N --handle coderabbitai --until finished
   --since <now>` (self-exiting; the result file's LAST line is the
   verdict), per [`waits.md`](waits.md).
4. Act on the verdict:
   - **FINISHED** → triage every finding per landing.md. Done.
   - **QUOTA `<mins>`** → wait that window (the waits.md ladder bounds
     it). If it exceeds the two-hour ladder, record a miss and do **not**
     nudge — a nudge inside a live window refreshes the countdown.
     Otherwise post one more `@coderabbitai review` and re-arm. A second
     quota notice ends it: record the miss, do not loop.
   - **NOACK / NOTPRESENT / TIMEOUT** → re-ask **once** with a fresh
     window. Still silent → CodeRabbit is unavailable; the legs
     carry the review step. Never a second silent-nudge.
   - **DECLINE** (the PR base is not the default branch) — post one comment
     asking for a full review (`@ coderabbitai trigger full review and tell me
     when you are finished`), then re-arm finished-only with `--since` now.
     Never re-trigger on a repeat decline.
   - **The bot's wording drifts.** If diagnostics show a finished review the
     matcher missed, read the comment body and adjust the pattern rather than
     waiting out the timeout. Real review content beside a quota notice is
     FINISHED — content beats the quota phrase.
   - **Multiple handles:** run the wait once per handle and continue when all
     **engaged** reviewers finish; tolerate absent ones. The DECLINE/re-ask
     machinery is CodeRabbit-specific — other handles use only FINISHED /
     QUOTA / NOTPRESENT / TIMEOUT. For a human handle, the first new review or
     comment since the wait started is FINISHED.
   - `wait-reviewer.sh` handle matching is case-insensitive and anchored —
     never append `[bot]` yourself.

5. Merge never waits on the CodeRabbit check, but it does follow this
   path before claiming CodeRabbit reviewed the head. If the path ends in
   a recorded miss, the leg review may land the PR and the SHA stays on the
   unreviewed-by-CodeRabbit list.

Every quota notice still gets one line on the PR audit saying what spent
the slot. With automatic review off, the only spend this repo controls is
the explicit ask above, so the fix is almost always "ask later, once".

## Owner override and substitute reviewer

Only the **repo owner**, in conversation, may spend a slot anyway or name
another reviewer. No labels. Agents never invent a substitute, and
the leg review still runs. CLI-in-CI is #2436:
`.github/workflows/coderabbit-cli.yml` is **dispatch-only** (not on push)
so it cannot walk the PR Fair Usage band by itself. It needs the secret
`CODERABBIT_API_KEY` (Agentic key), and its findings are file-level.

## Missed-review backlog

When a merged SHA had only a quota notice (or no CodeRabbit engagement)
and no later finished review of that SHA:

- Prepend one line to [`coderabbit-misses.md`](coderabbit-misses.md), newest
  first, in the one-line shape its own header documents and
  `scripts/check_context_budget.py` enforces. The review story stays on the PR;
  the ledger carries the pointer.
- Later sessions review that list CodeRabbit-style (correctness, hostile
  inputs, test honesty), newest first.
- Do not start the older 481-commit tail unless a current cluster
  requires it.

## Out of scope

- Making the CodeRabbit check required in branch protection.
- Paying per-file overage without an owner decision.
- Re-reviewing a SHA CodeRabbit already finished, just because a later
  format commit landed.
- Predicting the Fair Usage window. There is no REST API for it, and the
  estimator that tried is retired.

Docs: [Fair Usage](https://docs.coderabbit.ai/management/plans#fair-usage-limits-policy),
[rate limits](https://docs.coderabbit.ai/management/plans#rate-limits).
A CodeRabbit MCP connection does **not** raise review quota.
