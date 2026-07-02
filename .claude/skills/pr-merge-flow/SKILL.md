---
name: pr-merge-flow
description: >
  Land a PR end-to-end the repo's DEFAULT way: review feedback first, then merge.
  Roughly `/pr-comments N --wait-for=coderabbitai && /pr-merge N` — get the review
  feedback, validate + apply each finding and reply, and ONLY if that completes
  cleanly, rebase the head onto the live base, wait for the real CI to go green
  (EXCLUDING the bot), merge `--rebase` (never a merge commit, never squash) and
  delete the branch. The review step ALWAYS runs a Claude Sonnet 5 sub-agent as an
  ADVERSARIAL, maximally thorough reviewer IN ADDITION TO CodeRabbit — never as a mere
  fallback — at reasoning effort xhigh, or as an ultracode multi-agent review for a
  large/complex PR (orchestrator's pick; never below xhigh, never max). In parallel it
  gives CodeRabbit ~10 minutes to acknowledge the PR: if it does, wait on its review
  too; if it stays silent, nudge it once with `@coderabbitai review` and wait 10 more
  minutes; if it is STILL silent the Sonnet 5 review stands alone (folding CodeRabbit's
  review in if it shows up late) — and handle every comment of every review the same
  way. This
  is the default flow after any GitHub issue, ADR, or code change — everything
  except the dev-only classes that land straight on devel with no PR
  (documentation-only, CLAUDE.md, ADR text, skills). Args: [PR number] (defaults to
  the current branch's PR). Use when the user says "merge flow", "land it the usual
  way", "comments then merge", "finish/land this PR", or invokes /pr-merge-flow.
---

You run this repo's standard land-a-PR flow: **review feedback first, then merge.**
It is roughly:

```text
/pr-comments N --wait-for=coderabbitai && /pr-merge N
```

with two adaptations: a **Claude Sonnet 5 adversarial review always runs in addition
to CodeRabbit** (Step 1d — never a mere substitute), and the CodeRabbit wait adapts to
whether **CodeRabbit is available for this repository** (Steps 1a–1c). The `&&` is
load-bearing: **never start the merge until the review step has completed cleanly.**
Where this delegates to the existing `pr-comments` / `pr-merge` skills, invoke each via
the Skill tool — do not re-implement them.

Args: `{{ args }}`

## Step 0 — Identify the PR

- If a PR number is in the args, use it. Otherwise resolve the current branch's PR:
  `gh pr view --json number,headRefName,baseRefName,state,isDraft,url`. If there is
  none, stop and ask.
- Resolve `OWNER/REPO`: `gh repo view --json nameWithOwner -q .nameWithOwner`.
- This skill is for **code-bearing PRs**. If the work is a dev-only class that lands
  straight on `devel` with no PR (documentation-only, `CLAUDE.md`, ADR text, skills
  — see `CLAUDE.md` → "Worktrees"), this skill does not apply: say so and stop.

## Step 1 — Review feedback

**Two code reviews run on every PR, plus Snyk when present:**

- **Claude Sonnet 5 adversarial review (Step 1d) — ALWAYS.** Spawn it **first**, in the
  background, before starting the CodeRabbit wait; it is independent of CodeRabbit's
  availability and never a mere fallback.
- **CodeRabbit (Steps 1a–1c)** — decide availability with a **10-minute acknowledgement
  window** (1a), wait on + handle its review when it acknowledges (1b), nudge once when
  silent (1c). If CodeRabbit never reviews (NOACK / QUOTA / timeout), the Sonnet 5
  review stands alone — **surface the skip**; never stall the flow on CodeRabbit.
- **Snyk (Step 1e)** runs **in parallel** (security findings) and folds into the same gate.

Whichever reviews you end up with, **handle every comment of every review you receive**;
*how* each comment is handled (the triage below) never changes.

### Step 1a — Give CodeRabbit 10 minutes to acknowledge THIS PR

CodeRabbit, when installed, posts something on a new PR within a few minutes. So judge
availability per-PR, anchored on the PR's creation time: if **any** CodeRabbit message
(issue comment, review, or inline comment) appears within **10 minutes of the PR's
creation**, it is active → **Step 1b**. If those 10 minutes elapse with **no CodeRabbit
message whatsoever**, do not yet assume it is absent → **Step 1c** (nudge it first). (If
the PR is already older than 10 minutes when you start and CodeRabbit has posted nothing,
conclude `NOACK` immediately — no need to wait.)

Run the wait as a background Bash command (a self-exiting loop = one wake; never a
foreground `sleep`), then read `$RESULT`:

```sh
# Set first: OWNER_REPO  PR  RESULT(tmpfile). Waits until 10 min past PR creation for
# ANY CodeRabbit ("coderabbit" login) message; ACK as soon as one appears, else NOACK.
created=$(gh pr view "$PR" --repo "$OWNER_REPO" --json createdAt -q .createdAt)
# createdAt + 600s as epoch. BSD date (macOS): -juf; GNU date: the `date -d` fallback.
deadline=$(( $(date -juf "%Y-%m-%dT%H:%M:%SZ" "$created" +%s 2>/dev/null || date -d "$created" +%s) + 600 ))
while :; do
  hits=$(
    { gh api "repos/$OWNER_REPO/issues/$PR/comments" --paginate \
        -q '.[]|select((.user.login|ascii_downcase)|test("coderabbit"))|.id'
      gh api "repos/$OWNER_REPO/pulls/$PR/reviews" --paginate \
        -q '.[]|select((.user.login|ascii_downcase)|test("coderabbit"))|.id'
      gh api "repos/$OWNER_REPO/pulls/$PR/comments" --paginate \
        -q '.[]|select((.user.login|ascii_downcase)|test("coderabbit"))|.id'
    } 2>/dev/null)
  # ANY CodeRabbit message = ACK — including a usage/rate-limit notice. Do NOT short-circuit a
  # quota phrase to "won't review" here: CodeRabbit routinely posts a transient rate-limit (or a
  # stale notice from an earlier push) and then completes the review, so the QUOTA verdict belongs
  # to Step 1b's CONTENT-FIRST wait (which reports FINISHED the moment real review content appears,
  # and QUOTA only if none appears for the whole window). 1a just detects engagement.
  [ -n "$hits" ] && { echo ACK > "$RESULT"; exit 0; }
  [ "$(date -u +%s)" -ge "$deadline" ] && { echo NOACK > "$RESULT"; exit 0; }
  sleep 30
done
```

- **`ACK`** (any CodeRabbit message appeared — including a quota/rate-limit notice) → **Step 1b**.
  Step 1b's content-first wait decides FINISHED vs QUOTA; a quota notice alone is NOT treated as
  "won't review" here, because CR often posts one transiently and then reviews.
- **`NOACK`** (silent for the full window) → **Step 1c** (nudge before giving up).
- **`QUOTA`** is no longer emitted by 1a (it is decided in 1b). When Step 1b's wait returns
  `QUOTA` — a genuine usage/rate-limit with **no** review content for the whole window —
  CodeRabbit will not review: the Step-1d Sonnet 5 review (already running) stands alone;
  **surface** that CodeRabbit was skipped for quota.

### Step 1b — CodeRabbit acknowledged → wait on + handle its review

- Invoke the **pr-comments** skill with `N --wait-for=coderabbitai,snyk` (one call,
  both reviewers — `pr-comments` waits per-handle and skips either if it isn't reviewing
  the PR; **Snyk** rides this same call, see Step 1e). It blocks until they have finished
  reviewing, then validates each finding against the current code, applies the ones that
  genuinely hold, skips the rest with a reason, and replies on every thread.
- If that wait **times out** (CodeRabbit acknowledged but never finished the review),
  do not stall the flow — proceed on the Step-1d Sonnet 5 review (already running) and
  note the timeout; the nudge in Step 1c is for the *no-acknowledgement* case, so it
  won't help once it has already acknowledged.
- If the wait returns **`QUOTA`** for CodeRabbit (it acknowledged only with a usage/rate-limit
  notice — see Step 2 of `pr-comments`), it will not review: proceed on the Step-1d
  Sonnet 5 review alone and note the quota skip in the final report. (A `QUOTA` for **Snyk**
  just drops Snyk from this wait — surface the skipped scan.)

### Step 1c — No ack → nudge `@coderabbitai review`, then wait 10 more minutes

Before concluding CodeRabbit is absent, explicitly ask it to review — it sometimes just
missed the PR's creation event. Post the nudge once, then re-run the **Step 1a** wait with
a **fresh** 10-minute deadline (anchored on *now*, not the PR's creation time):

```sh
gh pr comment "$PR" --repo "$OWNER_REPO" --body '@coderabbitai review'
```

Re-run the Step-1a loop with `deadline=$(( $(date -u +%s) + 600 ))`. On the result:

- **`ACK`** (CodeRabbit posted something after the nudge) → **Step 1b**.
- **`NOACK`** (still silent 10 min after the nudge) → CodeRabbit is unavailable; the
  Step-1d Sonnet 5 review (already running) is the only code review. Invoke
  `/pr-comments N --wait-for=snyk` so Snyk is still waited on (Step 1e).

Nudge **once only** — a second silent window means CodeRabbit is genuinely unavailable;
do not loop on it.

### Step 1d — Claude Sonnet 5 adversarial review (EVERY PR, in addition to CodeRabbit)

Runs on **every** PR — spawn it at the **start of Step 1**, in the background, in
parallel with the CodeRabbit wait. It is additive: CodeRabbit reviewing does not skip
it, and it does not replace CodeRabbit; when CodeRabbit never reviews it stands alone.

1. **Spawn one sub-agent**, `model: sonnet`, briefed as an independent **ADVERSARIAL**
   reviewer — its job is to try to **break the change**, not to rubber-stamp it: review
   the PR's diff (`git diff origin/<BASE>...HEAD` in the PR's worktree/branch), grounded
   in the **current** code (read the surrounding files, not just the hunk), and hunt as
   thoroughly as the PR allows for bugs, unhandled edge cases and input classes, races,
   security holes, CLAUDE.md/code-standard violations, and **coverage theater** (tests
   that execute but cannot fail on a regression; missing fail-before/pass-after
   evidence). Return structured findings — each with a severity (`blocking` / `nitpick`
   / `outside-diff`), `file:line`, a grounded explanation, and a concrete suggested fix
   — plus a short "considered-and-fine" list. Tell it the result IS its final message
   and not to edit anything.
   **Reasoning effort: `xhigh` minimum — NEVER lower, and NEVER `max`.** You (the
   orchestrator) pick the shape by the PR's size and complexity: a small/simple PR →
   one sub-agent at effort `xhigh` (e.g. a Workflow `agent()` call with
   `effort: 'xhigh'` when the spawning tool cannot set effort directly); a large or
   complex PR → an **ultracode-style multi-agent review** (a Workflow fanning
   independent reviewers per dimension with adversarial verification of each finding),
   its agents likewise capped at `xhigh`. If `ponytail` is active in this session, the
   brief's first instruction is `Run /ponytail:ponytail <level>` (the level active here
   — full/lite/ultra; CLAUDE.md "Plan with a higher model"), so the reviewer matches
   the parent's ponytail mode.
2. **When the sub-agent finishes, resolve the CodeRabbit outcome (Steps 1a–1c).** If
   CodeRabbit reviewed — or turns up late (re-check the PR) — wait for its review to
   finish (the `pr-comments` `--wait-for=coderabbitai` wait, or poll until a terminal
   CodeRabbit result), so you hold **both** reviews. If it never did, you have only the
   Sonnet 5 review.
3. **Triage and handle EACH comment of EACH review you received** — every Sonnet 5
   finding, plus every CodeRabbit finding if one arrived. The per-comment handling is
   unchanged: **APPLY** (valid, in scope, safe) · **SKIP** (stale / unenforced /
   wrong-premise / suggestion-unsafe — record the reason) · **DEFER** (valid but
   pre-existing/orthogonal → **open a tracking GitHub Issue** per `pr-comments` Step 8,
   in the same public repo; a confirmed-real finding is never just acknowledged);
   mirror `pr-comments` Step 5 and reply on every CodeRabbit thread. Honour the repo's
   lint config and `CLAUDE.md`.
4. **Apply the valid fixes** — a fix that changes behaviour carries its own test per CLAUDE.md
   "Test coverage" (fail-before/pass-after; **Tier A** UI coverage for a `www/` change) — re-run
   the relevant gates (`php -l` / PHPUnit / PHPStan for PHP, `python -m pytest` / `ruff` / `mypy`
   for Python, ShellCheck for shell — whatever the change touches), commit
   (`<scope>: <imperative summary>`) and push to the PR head branch.
5. **Record the review on the PR** — post one comment summarising the Sonnet 5 adversarial
   review (and noting CodeRabbit's, if one arrived) plus the per-finding
   resolution (applied + commit / skipped + reason / deferred + tracking-issue link), so there is an
   audit trail. Use `gh pr comment N --body-file` and append the attribution footer
   (resolve `<gh-login>` once with `gh api user -q .login`):

   ```text
   ---
   🤖 Generated by [Claude Code](https://claude.com/claude-code), posted via @<gh-login>'s account on their behalf.
   ```

### Step 1e — Snyk security review (in parallel, when present)

Snyk reviews PRs independently of CodeRabbit — handle it **alongside** the 1a–1d path, not
instead of it. **The wait runs through `/pr-comments`, not a bespoke poll here:** on the
CodeRabbit-present path (1b) Snyk is already folded into that one call's
`--wait-for=coderabbitai,snyk`; when **no CodeRabbit `pr-comments` wait ran** (CodeRabbit
absent after 1c, or quota) invoke `/pr-comments N --wait-for=snyk` so Snyk is still waited on and
its findings fetched/replied. `pr-comments` tolerates an absent Snyk (no `snyk` status ⇒ skipped,
no stall), so it is always safe to include. This step just records Snyk's specifics:

- **Detect** whether Snyk is reviewing THIS PR. **Snyk posts NO review comments** — it surfaces as
  a commit **status/gate** whose context contains `snyk` (e.g. `code/snyk (…)`) on the head SHA, not
  as inline threads. A `snyk` status present ⇒ Snyk is engaged; absent ⇒ not active on this PR (the
  `--wait-for=snyk` wait skips it). Read the finding detail from the status `description` + `target_url`.
- **A Snyk status in `error` ("Code test limit reached") is a quota/infra error, not a clean pass**
  — `pr-comments` returns `QUOTA` for it (Step 2). Drop Snyk from the gate and **surface the skipped
  scan** to the user; never report Snyk as green from a limit-reached status, and never let it block
  the merge (it is a Snyk-side limit, not a vulnerability in the PR).
- **Handle every real finding.** Snyk reports **security** issues and, unlike CodeRabbit, posts **no**
  nitpick or outside-diff-range comments — so there are no buckets to sort: every Snyk finding is
  a substantive, in-diff item. Apply the same per-finding triage as CodeRabbit — **APPLY** (fix
  the vulnerability) · **SKIP** (false positive / not introduced by this PR / accepted risk —
  record the reason) · **DEFER** (real but pre-existing/orthogonal → tracking issue) — and reply
  on the PR. A `failure` Snyk status that flags a **real vulnerability the PR introduces**
  is **blocking**: fix it (or, for an unavoidable accepted risk, get the user's call) before
  merging. Honour the `private`-repo disclosure rules when the finding is security-sensitive.

### Gate before Step 2 (all paths)

Continue to the merge ONLY if the review step finished cleanly: every finding from **every**
review received — the always-on Sonnet 5 adversarial review, CodeRabbit when it reviewed,
**and** Snyk — triaged, any accepted fixes committed and pushed, and nothing left that needs a
human decision. The Sonnet 5 review is **mandatory** — never merge without its findings triaged,
even when CodeRabbit came back clean. If a finding is unresolved, contested, or needs the user,
**stop here and report** — do not merge.

## Step 2 — Land it (`/pr-merge N`)

- Invoke the **pr-merge** skill with `N`. It rebases the head onto the live base,
  waits for the real CI checks to go green (CodeRabbit excluded — never block on the
  bot), merges with `--rebase` (never a merge commit, never squash), and deletes the
  remote branch.
- `pr-merge` already refuses a draft / red / conflicting PR — honour its abort and
  report rather than forcing.

## Definition of done

- Review resolved (note which reviews landed — the always-on Sonnet 5 adversarial
  review and its effort shape (`xhigh` single-agent or ultracode multi-agent),
  CodeRabbit when it reviewed, **plus Snyk if it reviewed**); PR merged by rebase;
  remote branch deleted.
- Sync the work item's labels (an issue's `Waiting PR` removed on merge), per
  `CLAUDE.md` → "Labels (lifecycle)".
- If you stopped before merging, state exactly why and what is needed to proceed.
