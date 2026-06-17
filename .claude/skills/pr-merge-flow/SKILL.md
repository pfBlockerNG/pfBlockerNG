---
name: pr-merge-flow
description: >
  Land a PR end-to-end the repo's DEFAULT way: review feedback first, then merge.
  Roughly `/pr-comments N --wait-for=coderabbitai && /pr-merge N` — get the review
  feedback, validate + apply each finding and reply, and ONLY if that completes
  cleanly, rebase the head onto the live base, wait for the real CI to go green
  (EXCLUDING the bot), merge `--rebase` (never a merge commit, never squash) and
  delete the branch. The review step gives CodeRabbit ~10 minutes to acknowledge the
  PR: if it does, wait on its review; if it stays silent, nudge it once with
  `@coderabbitai review` and wait 10 more minutes, and only if it is STILL silent spawn
  a Claude Sonnet sub-agent to review in its place (still folding CodeRabbit's review in
  if it shows up late) — and handle every comment of every review the same way. This
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

with one adaptation — the review **source** depends on whether **CodeRabbit is
available for this repository** (Step 1). The `&&` is load-bearing: **never start
the merge until the review step has completed cleanly.** Where this delegates to the
existing `pr-comments` / `pr-merge` skills, invoke each via the Skill tool — do not
re-implement them.

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

Decide the review source with a **10-minute acknowledgement window** (1a), run the
matching path — 1b (CodeRabbit) or 1c (Sonnet substitute, which still folds CodeRabbit
back in if it shows up late) — then apply the shared gate. Whichever reviews you end up
with, **handle every comment of every review you receive**; *how* each comment is
handled (the triage below) never changes.

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
  [ -n "$hits" ] && { echo ACK > "$RESULT"; exit 0; }
  [ "$(date -u +%s)" -ge "$deadline" ] && { echo NOACK > "$RESULT"; exit 0; }
  sleep 30
done
```

- **`ACK`** (a CodeRabbit message appeared) → **Step 1b**.
- **`NOACK`** (silent for the full window) → **Step 1c** (nudge before giving up).

### Step 1b — CodeRabbit acknowledged → wait on + handle its review

- Invoke the **pr-comments** skill with `N --wait-for=coderabbitai`. It blocks until
  CodeRabbit has finished reviewing, then validates each finding against the current
  code, applies the ones that genuinely hold, skips the rest with a reason, and
  replies on every thread.
- If that wait **times out** (CodeRabbit acknowledged but never finished the review),
  do not stall the flow — fall back to the Sonnet stand-in (**Step 1d**); the nudge in
  Step 1c is for the *no-acknowledgement* case, so it won't help once it has already
  acknowledged.

### Step 1c — No ack → nudge `@coderabbitai review`, then wait 10 more minutes

Before concluding CodeRabbit is absent, explicitly ask it to review — it sometimes just
missed the PR's creation event. Post the nudge once, then re-run the **Step 1a** wait with
a **fresh** 10-minute deadline (anchored on *now*, not the PR's creation time):

```sh
gh pr comment "$PR" --repo "$OWNER_REPO" --body '@coderabbitai review'
```

Re-run the Step-1a loop with `deadline=$(( $(date -u +%s) + 600 ))`. On the result:

- **`ACK`** (CodeRabbit posted something after the nudge) → **Step 1b**.
- **`NOACK`** (still silent 10 min after the nudge) → **Step 1d**.

Nudge **once only** — a second silent window means CodeRabbit is genuinely unavailable;
do not loop on it.

### Step 1d — Still no ack → Claude Sonnet sub-agent reviewer (fold in a late CodeRabbit)

Stand in a reviewer yourself; if CodeRabbit turns up late, fold its review in too.

1. **Spawn one sub-agent** with the Agent tool, `model: sonnet`, briefed to act as
   CodeRabbit: review the PR's diff (`git diff origin/<BASE>...HEAD` in the PR's
   worktree/branch), grounded in the **current** code (read the surrounding files,
   not just the hunk), and return structured findings — each with a severity
   (`blocking` / `nitpick` / `outside-diff`), `file:line`, a grounded explanation,
   and a concrete suggested fix — plus a short "considered-and-fine" list. Tell it
   the result IS its final message and not to edit anything.
2. **When the sub-agent finishes, re-check the PR for CodeRabbit.** If it has now
   posted anything (it acknowledged late, during the Sonnet review), treat it as
   available after all: wait for its review to finish (the `pr-comments`
   `--wait-for=coderabbitai` wait, or poll until a terminal CodeRabbit result), so you
   hold **both** reviews. If it is still silent, you have only the Sonnet review.
3. **Triage and handle EACH comment of EACH review you received** — every Sonnet
   finding, plus every CodeRabbit finding if one arrived. The per-comment handling is
   unchanged: **APPLY** (valid, in scope, safe) · **SKIP** (stale / unenforced /
   wrong-premise / suggestion-unsafe — record the reason) · **DEFER** (valid but
   pre-existing/orthogonal → **open a tracking GitHub Issue** per `pr-comments` Step 8,
   in the same public repo; a confirmed-real finding is never just acknowledged);
   mirror `pr-comments` Step 5 and reply on every CodeRabbit thread. Honour the repo's
   lint config and `CLAUDE.md`.
4. **Apply the valid fixes**, re-run the relevant gates (`php -l` / PHPUnit / PHPStan
   for PHP, `python -m pytest` / `ruff` / `mypy` for Python, ShellCheck for shell —
   whatever the change touches), commit (`<scope>: <imperative summary>`) and push to
   the PR head branch.
5. **Record the review on the PR** — post one comment summarising the Sonnet substitute
   review (and noting CodeRabbit's, if it was folded in) plus the per-finding
   resolution (applied + commit / skipped + reason / deferred + tracking-issue link), so there is an
   audit trail. Use `gh pr comment N --body-file` and append the attribution footer
   (resolve `<gh-login>` once with `gh api user -q .login`):

   ```text
   ---
   🤖 Generated by [Claude Code](https://claude.com/claude-code), posted via @<gh-login>'s account on their behalf.
   ```

### Gate before Step 2 (both paths)

Continue to the merge ONLY if the review step finished cleanly: every finding
triaged, any accepted fixes committed and pushed, and nothing left that needs a
human decision. If a finding is unresolved, contested, or needs the user, **stop
here and report** — do not merge.

## Step 2 — Land it (`/pr-merge N`)

- Invoke the **pr-merge** skill with `N`. It rebases the head onto the live base,
  waits for the real CI checks to go green (CodeRabbit excluded — never block on the
  bot), merges with `--rebase` (never a merge commit, never squash), and deletes the
  remote branch.
- `pr-merge` already refuses a draft / red / conflicting PR — honour its abort and
  report rather than forcing.

## Definition of done

- Review resolved (note which reviewer was used — CodeRabbit or the Sonnet
  substitute); PR merged by rebase; remote branch deleted.
- Sync the work item's labels (an issue's `Waiting PR` removed on merge), per
  `CLAUDE.md` → "Labels (lifecycle)".
- If you stopped before merging, state exactly why and what is needed to proceed.
