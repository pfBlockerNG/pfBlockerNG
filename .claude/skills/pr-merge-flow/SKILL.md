---
name: pr-merge-flow
description: >
  Land a PR end-to-end the repo's DEFAULT way: review feedback first, then merge.
  Roughly `/pr-comments N --wait-for=coderabbitai && /pr-merge N` — get the review
  feedback, validate + apply each finding and reply, and ONLY if that completes
  cleanly, rebase the head onto the live base, wait for the real CI to go green
  (EXCLUDING the bot), merge `--rebase` (never a merge commit, never squash) and
  delete the branch. The review step ALWAYS runs the committed `review-single`
  workflow — ONE Claude sub-agent as an ADVERSARIAL reviewer IN ADDITION TO CodeRabbit,
  never a mere fallback — at reasoning effort xhigh (never below, never max): the latest
  Sonnet (5 or newer) — Fable (5 or newer), preferred for a large/complex PR, is temporarily
  unavailable, so use Sonnet (never Opus, never a multi-agent fan-out). In parallel it
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
  absent → `mcp__github__*` tools + wakeup-paced waits per workflow-reference "Managed
  environments" (§4); neither `gh` nor a GitHub MCP server → stop and report.
- This skill is for **code-bearing PRs**. If the work is a dev-only class that lands
  straight on `devel` with no PR (documentation-only, `CLAUDE.md`, ADR text, skills
  — see `CLAUDE.md` → "Worktrees"), this skill does not apply: say so and stop.

## Step 1 — Review feedback

**Review sources on every PR:**

- **Claude adversarial review (Step 1d) — ALWAYS.** Spawn it **first**, before
  starting the CodeRabbit wait (the Workflow tool is already asynchronous — it returns
  immediately; `run_in_background` is not a Workflow parameter, never pass it). The review
  Workflow is **harness-tracked** — never arm a wait for it; the CodeRabbit wait beside it is
  for an **untracked** external, which is why that one gets a bounded poll and this one does
  not. It is independent of CodeRabbit's availability and never a mere fallback.
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

Run the wait via **`scripts/agent/wait-reviewer.sh`** as a background Bash command
(self-exiting), stdout to a result file; its LAST line is the verdict:

```sh
sh scripts/agent/wait-reviewer.sh --repo "$OWNER_REPO" --pr "$PR" \
  --handle coderabbitai --until ack > "$RESULT" 2>&1
# ack mode: ANY CodeRabbit message = ACK (including a quota notice — 1b's content-first
# wait decides FINISHED vs QUOTA); silent for the cap (default 20 polls x 30 s = the
# 10-minute window) = NOACK. Exit 3 = gh unavailable: mcp__github__* wakeup-paced
# checks instead (CLAUDE.md "No orphaned waits" #4).
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

Re-run the Step-1a wait with a fresh window: the same `wait-reviewer.sh --until ack`
command plus `--since "$(date -u +%Y-%m-%dT%H:%M:%SZ)"`. On the result:

- **`ACK`** (CodeRabbit posted something after the nudge) → **Step 1b**.
- **`NOACK`** (still silent 10 min after the nudge) → CodeRabbit is unavailable; the
  Step-1d Claude review and the Step-1f Copilot review carry the review step.

Nudge **once only** — a second silent window means CodeRabbit is genuinely unavailable;
do not loop on it.

### Step 1d — Claude adversarial review (EVERY PR, ONE sub-agent, in addition to CodeRabbit)

Runs on **every** PR — spawn it at the **start of Step 1**, in parallel with the
CodeRabbit wait; the Workflow call is already asynchronous (returns immediately), so
pass no extra parameter — `run_in_background` is not a Workflow parameter and fails
validation. Being harness-tracked, it needs no wait of its own: end the turn and answer its
completion notification (only the untracked CodeRabbit/CI legs get a bounded wait). It is
additive: CodeRabbit reviewing does not skip it, and it does not
replace CodeRabbit; when CodeRabbit never reviews it stands alone.

1. **Run the committed `review-single` workflow** — the reviewer contract (adversarial
   brief, the three lenses, hostile-input classes, execution-grounded blocking claims,
   per-file verdicts, vendored-tree exclusion, schema-forced findings) lives in
   `.claude/workflows/review-single.js`, the single source of truth — do NOT restate or
   re-improvise it:
   `Workflow({name: 'review-single', args: {pr: N, base: '<base>', worktree: '<path>',
   spec: '<see below>', model: 'sonnet'}})`.
   Your (orchestrator) duties around that call:
   - **Build the `spec`** from the work item's intent — the issue/ADR link, its
     acceptance criteria / coverage matrix, and the PR body. A diff-only reviewer can
     never catch "asked for ALL X, delivered a subset, claimed completeness"; only
     diff-vs-spec exposes it.
   - **Pick the model** by the PR's size and complexity, and record the chosen model +
     the size metric that drove it in the Step-1d.5 audit comment: `model: sonnet`
     by default; the highest-tier model (currently `fable`) for a large/complex PR —
     >300 changed lines, >6 files, or any behaviour change in `src/`'s
     parsing/guard/scheduling logic — where whole-PR cross-referencing pays
     (fall back to sonnet when the top tier is unavailable). **Never Opus, never a multi-agent fan-out** (user
     directive 2026-07-11 — `review-fanout` runs only on an explicit user request),
     never below `xhigh`, never `max`; the bare family alias resolves to the LATEST
     generation (Sonnet 5 or newer) — never pin a dated model ID.
   - **Validate the result**: treat `findings` as the review; `per_file` must cover
     every changed file (a review missing files is incomplete — re-run it).
   - **Fallback** (Workflow tool unavailable): spawn ONE plain Agent sub-agent with the
     same model and effort, briefed from the workflow script's PROMPT; do **not**
     propagate ponytail to it (CLAUDE.md: ponytail governs what you build; a reviewer
     builds nothing).
2. **When the sub-agent finishes, resolve the CodeRabbit outcome (Steps 1a–1c).** If
   CodeRabbit reviewed — or turns up late (re-check the PR) — wait for its review to
   finish (the `pr-comments` `--wait-for=coderabbitai` wait, or poll until a terminal
   CodeRabbit result), so you hold **both** reviews. If it never did, you have only the
   Claude review.
3. **Dedupe across reviewers, then triage every finding.** First MERGE the findings of
   all reviews received (the Claude review, CodeRabbit, Copilot, a terminal Snyk failure)
   by file:line + substance — reviewers routinely flag the same defect, and triaging each
   copy separately wastes a validation and splinters the audit trail. One verdict per
   underlying finding; every reviewer's thread still gets its reply (pointing at the
   shared resolution). Then handle EACH deduped finding. The per-finding handling is
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
   non-trivial APPLY, re-run `review-single` scoped to the fix delta (same args, `base` set
   to the pre-fix head SHA so the diff is exactly the fix commits) before the Gate below.
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
3. **Wait (bounded)** for its review: `sh scripts/agent/wait-reviewer.sh --repo O/R
   --pr N --handle copilot --until finished --max-iter 20` in the background (~10-minute
   window; anchored handle matching — `copilot` matches `copilot-pull-request-reviewer[bot]`
   via its `handle-` prefix). TIMEOUT →
   proceed and note it (the pre-merge catch-all sweep still picks up a late review).
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
Claude pass** — a focused second single-agent pass over the final diff (the highest-tier model —
currently Fable — preferred, else Sonnet), or pace the merge; the audited defect window coincided exactly with a
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

- The merge is **user-directed**: the user's invocation of this flow (directly or via
  `/gh-issue --fix`) is the standing authorization for the merge step, provided the
  Step-1 review gate completed cleanly.
- Invoke the **pr-merge** skill with `N`. It rebases the head onto the live base,
  waits for the real CI checks to go green (CodeRabbit excluded — never block on the
  bot), merges with `--rebase` (never a merge commit, never squash), and deletes the
  remote branch.
- `pr-merge` already refuses a draft / red / conflicting PR — honour its abort and
  report rather than forcing.

## Definition of done

- Review resolved (note which reviews landed — the always-on single-agent Claude
  adversarial review and its model (`sonnet`, or `fable` on a large/complex PR; always `xhigh`),
  Copilot when it reviewed, CodeRabbit when it reviewed, plus any terminal Snyk
  `failure` finding); PR merged by rebase; remote branch deleted.
- Sync the work item's labels (an issue's `Waiting PR` removed on merge), per
  `CLAUDE.md` → "Labels (lifecycle)".
- **Trigger sweep (mandatory).** The task just reached a terminal state: run the
  cancel-on-resolution sweep — CLAUDE.md "No orphaned waits" / workflow-reference "Bounded
  waits" §3 (kill every trigger class, then `TaskList` once for stale waits you own) — and
  report it in one line (what was stopped / "nothing pending").
- If you stopped before merging, state exactly why and what is needed to proceed.
