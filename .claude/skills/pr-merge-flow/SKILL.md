---
name: pr-merge-flow
description: >
  Land a PR end-to-end the repo's DEFAULT way: review feedback first, then merge.
  Roughly `/pr-comments N --wait-for=coderabbitai && /pr-merge N` — get the review
  feedback, validate + apply each finding and reply, and ONLY if that completes
  cleanly, rebase the head onto the live base, wait for the real CI to go green
  (EXCLUDING the bot), merge `--rebase` (never a merge commit, never squash) and
  delete the branch. The review step ALWAYS runs ONE Claude sub-agent as an
  ADVERSARIAL, maximally thorough reviewer IN ADDITION TO CodeRabbit — never as a mere
  fallback — at reasoning effort xhigh (never below, never max): the latest Sonnet
  (5 or newer) by default, the latest Fable (5 or newer) for a large/complex PR
  (orchestrator's pick; never Opus, never a multi-agent fan-out). In parallel it
  gives CodeRabbit ~10 minutes to acknowledge the PR: if it does, wait on its review
  too; if it stays silent, nudge it once with `@coderabbitai review` and wait 10 more
  minutes; if it is STILL silent the Claude review stands alone (folding CodeRabbit's
  review in if it shows up late); a CodeRabbit rate-limit notice follows the 5-minute
  rule (resume > 5 min = proceed without it; else wait 5 min, nudge once, and drop it on
  any further problem). GitHub Copilot's review is REQUESTED when available (skipped if
  already reviewing) and waited on, bounded. Snyk is advisory — never waited on; only a
  terminal failure verdict (it ran and flagged something) enters the gate. Handle every
  comment of every review the same way. This
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

with two adaptations: a **single-sub-agent Claude adversarial review always runs in
addition to CodeRabbit** (Step 1d — never a mere substitute), and the CodeRabbit wait adapts to
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
- **Transport check (managed environments):** `command -v gh && gh auth status` once. `gh`
  absent → GitHub reads/writes via the session's `mcp__github__*` tools, and every wait below
  runs as **wakeup-paced MCP checks** instead of a background bash loop (same rungs, caps, and
  give-up budget — CLAUDE.md "No orphaned waits" §4 / workflow-reference "Managed
  environments"). Neither `gh` nor a GitHub MCP server → stop and report.
- This skill is for **code-bearing PRs**. If the work is a dev-only class that lands
  straight on `devel` with no PR (documentation-only, `CLAUDE.md`, ADR text, skills
  — see `CLAUDE.md` → "Worktrees"), this skill does not apply: say so and stop.

## Step 1 — Review feedback

**Review sources on every PR:**

- **Claude adversarial review (Step 1d) — ALWAYS.** Spawn it **first**, in the
  background, before starting the CodeRabbit wait; it is independent of CodeRabbit's
  availability and never a mere fallback.
- **GitHub Copilot (Step 1f) — request + wait when available.** If Copilot is not already
  reviewing the PR, request its review at the start of Step 1; either way, wait for it
  (bounded) and triage its findings. If the request fails (Copilot review unavailable),
  skip and note it — never stall on Copilot.
- **CodeRabbit (Steps 1a–1c)** — decide availability with a **10-minute acknowledgement
  window** (1a), wait on + handle its review when it acknowledges (1b), nudge once when
  silent (1c). A rate-limit notice follows the **5-minute rule** (see 1b): resume time
  > 5 min ⇒ proceed without CodeRabbit; ≤ 5 min ⇒ wait 5 min, nudge once, resume — and if
  the nudged wait hits any further problem, proceed without it. If CodeRabbit never
  reviews (NOACK / QUOTA / timeout), the remaining reviews stand — **surface the skip**;
  never stall the flow on CodeRabbit.
- **Snyk (Step 1e) — advisory, no wait.** Read its status post-hoc before the gate; only a
  terminal `failure` verdict (Snyk actually ran and flagged something) enters the gate.

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
  CodeRabbit will not review: the Step-1d Claude review (already running) stands alone;
  **surface** that CodeRabbit was skipped for quota.

### Step 1b — CodeRabbit acknowledged → wait on + handle its review

- Invoke the **pr-comments** skill with `N --wait-for=coderabbitai`. It blocks until
  CodeRabbit has finished reviewing, then validates each finding against the current
  code, applies the ones that genuinely hold, skips the rest with a reason, and replies
  on every thread. Its `QUOTA <mins>` result implements the **5-minute rule** (the
  rate-limit notice's own "Next review available in" time): > 5 min ⇒ CodeRabbit is
  dropped from this flow; ≤ 5 min ⇒ one 5-minute wait + one `@coderabbitai review` nudge +
  one resumed wait, and **any further problem on the nudged wait drops CodeRabbit** —
  never block on it twice.
- If that wait **times out** (CodeRabbit acknowledged but never finished the review),
  do not stall the flow — proceed on the Step-1d Claude review (already running) and
  note the timeout; the nudge in Step 1c is for the *no-acknowledgement* case, so it
  won't help once it has already acknowledged.
- If the wait resolves to CodeRabbit dropped under the **5-minute rule** (`QUOTA` with a
  long resume time, or a failed post-nudge wait — see Step 2 of `pr-comments`), proceed on
  the Step-1d Claude review + Step-1f Copilot review and note the quota skip in the final
  report.

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
  Step-1d Claude review and the Step-1f Copilot review carry the review step.

Nudge **once only** — a second silent window means CodeRabbit is genuinely unavailable;
do not loop on it.

### Step 1d — Claude adversarial review (EVERY PR, ONE sub-agent, in addition to CodeRabbit)

Runs on **every** PR — spawn it at the **start of Step 1**, in the background, in
parallel with the CodeRabbit wait. It is additive: CodeRabbit reviewing does not skip
it, and it does not replace CodeRabbit; when CodeRabbit never reviews it stands alone.

1. **Spawn ONE sub-agent** (model per the shape rule below), briefed as an independent **ADVERSARIAL**
   reviewer — its job is to try to **break the change**, not to rubber-stamp it. The brief
   MUST include **the work item's intent** — the issue/ADR link, its acceptance criteria /
   coverage matrix, and the PR body — because a diff-only reviewer can never catch "asked for
   ALL X, delivered a subset, claimed completeness"; the diff is internally consistent, only
   diff-vs-spec exposes it. The reviewer: reviews the PR's diff
   (`git diff origin/<BASE>...HEAD` in the PR's worktree/branch), grounded
   in the **current** code (read the surrounding files, not just the hunk), and hunts as
   thoroughly as the PR allows for bugs, unhandled edge cases and input classes, races,
   security holes, CLAUDE.md/code-standard violations, and **coverage theater** (tests
   that execute but cannot fail on a regression; missing fail-before/pass-after
   evidence; negative assertions with no fixture that could fail them; red-runs
   manufactured via faults production cannot produce). Mandatory hunt items:
   **spec coverage** — each acceptance criterion / matrix row mapped to where the diff
   satisfies it, silently narrowed scope flagged; **per-file verdict** — every changed
   file gets findings / considered-and-fine / not-examined-because (a review missing
   files is incomplete — re-run it); **hostile inputs** — any new/changed parser, regex,
   or guard probed with the CLAUDE.md "THE BRIEF" §4 input classes; **hardcoding** —
   env-derived literals (versions, ABIs, paths, column indexes) that the spec or matrix
   says must be enumerated or resolved at runtime; **`www/` touched → Tier-A UI test
   present, else a `blocking` finding** (test mandate #4); **stale comments/docs** about
   touched symbols. The VENDORED plugin trees (`.claude/skills/ponytail/`,
   `.claude/skills/caveman/`) are OUT of review scope — byte-identical upstream copies (see
   their UPSTREAM files); only byte-identity with the pinned ref and the provenance itself
   are reviewable, never their content or style. The reviewer **executes, not just reads**: it MAY run the gates and
   MUST ground each `blocking` correctness claim in an executed probe (command + output —
   the "Empirically verified:" standard) wherever the claim is executable off-appliance.
   Each finding: severity (`blocking` / `nitpick` / `outside-diff`), `file:line`, the
   grounded explanation + how-to-reproduce, and a concrete suggested fix. Tell it the
   result IS its final message and not to edit anything.
   **Reasoning effort: `xhigh` — NEVER lower, and NEVER `max`. Always ONE sub-agent —
   never a multi-agent fan-out** (user directive 2026-07-11; the old `review-fanout`
   default is retired — that committed workflow now runs only on an explicit user
   request). You (the orchestrator) pick the **model** by the PR's size and complexity —
   and record the chosen model + the size metric that drove it in the Step-1d.5 audit
   comment: a small/simple PR → `model: sonnet`; a large or complex PR
   (roughly: >300 changed lines, >6 files, or any behaviour change in `src/`'s
   parsing/guard/scheduling logic) → `model: fable` — **never Opus**. Always the bare
   family alias, which resolves to the LATEST generation (Sonnet 5 / Fable 5 or newer);
   never pin a dated model ID — a pinned ID silently ages. The single
   reviewer covers all three lenses itself (contract-conformance vs the spec,
   correctness + hostile inputs, test honesty). Do **not** propagate ponytail
   to the reviewer (CLAUDE.md: ponytail governs what you build; a reviewer builds
   nothing — thoroughness and finding detail are outside its scope).
2. **When the sub-agent finishes, resolve the CodeRabbit outcome (Steps 1a–1c).** If
   CodeRabbit reviewed — or turns up late (re-check the PR) — wait for its review to
   finish (the `pr-comments` `--wait-for=coderabbitai` wait, or poll until a terminal
   CodeRabbit result), so you hold **both** reviews. If it never did, you have only the
   Claude review.
3. **Triage and handle EACH comment of EACH review you received** — every Claude-review
   finding, plus every CodeRabbit finding if one arrived. The per-comment handling is
   unchanged: **APPLY** (valid, in scope, safe) · **SKIP** (stale / unenforced /
   wrong-premise / suggestion-unsafe — record the reason) · **DEFER** (valid but
   pre-existing/orthogonal → **open a tracking GitHub Issue** per `pr-comments` Step 8,
   in the same public repo; a confirmed-real finding is never just acknowledged);
   mirror `pr-comments` Step 5 and reply on every CodeRabbit thread. Honour the repo's
   lint config and `CLAUDE.md`. **Anti-self-grading asymmetry (you wrote or gated this
   code — you don't get to wave its review away):** a `blocking` correctness/security
   finding is closed only by **APPLY** (with its test) or **explicit user sign-off** —
   the Snyk rule, applied to the Claude review; SKIPping one requires **reproduction
   evidence that its premise is wrong** (a command + output demonstrating it, recorded
   in the reply), never prose alone; and a finding that cites a CLAUDE.md mandate
   cannot be self-skipped by the agent whose code it flags — fix it or escalate to the
   user ("precedent elsewhere is also untested" is not an exemption the mandate
   recognizes). Style/lint nits may still be skipped on config grounds alone.
4. **Apply the valid fixes** — a fix that changes behaviour carries its own test per CLAUDE.md
   "Test coverage" (fail-before/pass-after; **Tier A** UI coverage for a `www/` change) — re-run
   the **canonical gates** (CLAUDE.md table) for whatever the fixes touch, commit
   (`<scope>: <imperative summary>`) and push to the PR head branch. **Review-fix commits are
   new unreviewed code** — two of the audited defect chains entered through them — so for any
   non-trivial APPLY, re-run a focused review of the fix delta (same reviewer contract, scoped
   to the fix commits) before the Gate below.
5. **Record the review on the PR** — post one comment summarising the Claude adversarial
   review (and noting CodeRabbit's, if one arrived) plus the per-finding
   resolution (applied + commit / skipped + reason / deferred + tracking-issue link), so there is an
   audit trail. Use `gh pr comment N --body-file` and append the attribution footer
   (resolve `<gh-login>` once with `gh api user -q .login`):

   ```text
   ---
   🤖 Generated by [Claude Code](https://claude.com/claude-code), posted via @<gh-login>'s account on their behalf.
   ```

### Step 1e — Snyk security review (advisory — read post-hoc, never wait)

Snyk is **not** a required check and is **never waited on**. Immediately before the Gate
below, read its state once from the head SHA:

- No `snyk` status/check present → Snyk isn't active on this PR; nothing to do.
- Status `error` ("Code test limit reached"), `pending`, or any non-terminal state → the scan
  did not run (or hasn't finished): **ignore it** — it neither blocks nor passes; note the
  skipped scan in the audit trail. Do not treat a quota/infra error as a signal at all.
- Status **`failure` with a real finding** (Snyk actually ran and flagged something — read the
  detail from the status `description` + `target_url`) → that is a genuine security finding:
  triage it like any blocking review finding (**APPLY** the fix with its test · **SKIP** only
  with demonstrated false-positive evidence · **DEFER** pre-existing/orthogonal → tracking
  issue), honouring the `private`-repo disclosure rules when sensitive.
- Status `success` → note it; still not a gate requirement.

### Step 1f — GitHub Copilot review (request + wait when available)

Runs on **every** PR, started at the beginning of Step 1 alongside the reviewer spawn and the
CodeRabbit wait:

1. **Already reviewing?** Check for an existing Copilot review or a pending request:
   `gh api repos/OWNER/REPO/pulls/N/reviews --paginate -q '.[]|select(.user.login|test("copilot";"i"))|.id'`
   and `gh pr view N --json reviewRequests`. If Copilot has reviewed or is requested,
   **skip the request** — go straight to the wait.
2. **Request it:** `gh pr edit N --add-reviewer "@copilot"` (fallback:
   `gh api --method POST repos/OWNER/REPO/pulls/N/requested_reviewers -f 'reviewers[]=copilot-pull-request-reviewer[bot]'`).
   If both fail, Copilot code review is not available on this repo/plan — **skip this step
   and note it**; never stall.
3. **Wait (bounded)** for its review: poll `.../pulls/N/reviews` for a copilot login
   submission since the request — Copilot typically reviews within a few minutes; use a
   self-exiting background loop with a ~10-minute window. Timeout → proceed and note it
   (the pre-merge catch-all sweep will still pick up a late review).
4. **Triage its findings** exactly like any other review (APPLY / SKIP / DEFER + reply per
   thread) — a summary-only "generated no comments" review is just noted in the audit trail.
   **A confirmed-real finding the reviewer itself downgrades to "pre-existing / out of scope /
   no action needed" still enters triage**: DEFER + tracking issue, never a silent drop — PR
   #937's focused re-review found two real pre-existing bugs that existed only in the session
   transcript until the post-merge audit surfaced them (#941, #943).

### Gate before Step 2 (all paths)

Continue to the merge ONLY if the review step finished cleanly: every finding from **every**
review received — the always-on Claude adversarial review, Copilot when it reviewed,
CodeRabbit when it reviewed, and any **terminal Snyk `failure` finding** (Step 1e; a Snyk
quota/infra error is ignored, not gated) — triaged, any accepted fixes committed and pushed,
and nothing left that needs a human decision. The Claude review is **mandatory** — never
merge without its findings triaged, even when every bot came back clean. **Produce the findings ledger before invoking `pr-merge`:**
a numbered list of every finding with its outcome — `fixed@<commit>` / `skipped: <evidence>` /
`deferred: <issue link>` — folded into the Step-1d.5 audit comment; refuse to merge while any
item lacks an outcome. **When NO external reviewer reviewed a substantive PR** (CodeRabbit dropped under the
5-minute rule AND Copilot unavailable/timed out), **escalate instead of merging on the single
Claude pass** — a focused second single-agent pass over the final diff (Fable at `xhigh` if
the first pass ran Sonnet), or pace the merge; the audited defect window coincided exactly with a
bots-quota batch-merge cadence. If a finding is unresolved, contested, or needs the user,
**stop here and report** — do not merge.

**Catch-all sweep (last thing before merging):** "every review received" means every review on
the PR, not just the handles you waited on. Reviewers you did not arm a wait for — **GitHub
Copilot** (`copilot-pull-request-reviewer[bot]`), another bot, a human — can post at any moment,
including seconds before the merge. Immediately before invoking `pr-merge`, list ALL reviews and
their inline comments (`gh api repos/OWNER/REPO/pulls/N/reviews --paginate` +
`.../pulls/N/comments --paginate`, no login filter) and triage anything not yet handled with the
usual APPLY / SKIP / DEFER + reply. A summary-only review with no findings (e.g. Copilot's
"generated no comments") just gets noted in the audit trail. This sweep caught nothing being
lost once (PR #778 — Copilot reviewed 2 min pre-merge, clean pass) but exists because next time
it may not be clean.

## Step 2 — Land it (`/pr-merge N`)

- Invoke the **pr-merge** skill with `N`. It rebases the head onto the live base,
  waits for the real CI checks to go green (CodeRabbit excluded — never block on the
  bot), merges with `--rebase` (never a merge commit, never squash), and deletes the
  remote branch.
- `pr-merge` already refuses a draft / red / conflicting PR — honour its abort and
  report rather than forcing.

## Definition of done

- Review resolved (note which reviews landed — the always-on single-agent Claude
  adversarial review and its model (`sonnet` or `fable`, always `xhigh`),
  Copilot when it reviewed, CodeRabbit when it reviewed, plus any terminal Snyk
  `failure` finding); PR merged by rebase; remote branch deleted.
- Sync the work item's labels (an issue's `Waiting PR` removed on merge), per
  `CLAUDE.md` → "Labels (lifecycle)".
- **Trigger sweep (mandatory — CLAUDE.md "No orphaned waits").** The task just reached a
  terminal state, so kill every wait tied to it NOW, by class: `TaskStop` each background
  poll you started for it; `CronDelete` every remaining heartbeat rung; unsubscribe any
  PR/event subscription. Any `ScheduleWakeup` you armed cannot be cancelled — confirm its
  prompt was self-invalidating and let it no-op. Then `TaskList` once: stop anything stale
  you own from earlier items. Report the sweep in one line (what was stopped / "nothing
  pending").
- If you stopped before merging, state exactly why and what is needed to proceed.
