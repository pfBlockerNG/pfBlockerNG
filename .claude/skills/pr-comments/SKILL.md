---
name: pr-comments
description: >
  Retrieve a pull request's review comments — CodeRabbit's inline findings PLUS
  its nitpick and outside-diff-range findings (and human reviewer comments) —
  validate each against the CURRENT code, apply the ones that genuinely hold
  (skip the rest with a reason, defer pre-existing ones to their own PR), then
  reply on every thread. With --wait-for=<handle> it first blocks until that
  reviewer (usually CodeRabbit) has FINISHED reviewing — polling the PR, not a
  one-shot read — and, if CodeRabbit declines because the base isn't the default
  branch, comments to trigger a full review and keeps waiting. Args: [PR number]
  [--wait-for=<handle>] (PR defaults to the current branch's). Use when the user
  says "address the PR comments", "fix the CodeRabbit comments", "handle the
  review feedback on PR N", "wait for CodeRabbit then handle the comments", or
  invokes /pr-comments.
---

You resolve review feedback on a PR. The non-negotiable principle: **validate
each finding against the current code before touching anything** — reviewers
(CodeRabbit especially) comment on a specific commit, so a finding may be stale,
unenforced, out of scope, or its suggested fix may itself be wrong. Never paste a
suggested diff blindly. Apply what holds, skip what doesn't (with a reason), and
reply to every thread.

## Step 1 — Identify the PR and branch

- If a PR number was given, use it. Else find the PR for the current branch:
  `gh pr view --json number,headRefName,baseRefName,url,state`. If there is none,
  stop and ask.
- Resolve `OWNER/REPO` with `gh repo view --json nameWithOwner -q .nameWithOwner`.
- Be on the PR's **head** branch (checkout if needed) so fixes land on it.
- Parse flags: `--wait-for=<handle>` (also accept `--wait-for <handle>`) turns on
  the wait in Step 2. Without it, skip Step 2 entirely and go to Step 3.

## Step 2 — (optional) Wait for the reviewer to finish — `--wait-for=<handle>`

**Only when `--wait-for=<handle>` was given** (e.g. `/pr-comments --wait-for=coderabbitai`,
typically run the instant you push the PR). Block here until `<handle>` has
**finished reviewing**, then fall through to the rest of the flow.

- **"Finished" = the reviewer has posted its findings in the PR** — inline review
  comments and/or a final summary message. It does **not** mean any code/commit
  landed; never wait on commits. CodeRabbit reviews incrementally and shows a
  transient "review in progress" state, so a one-shot read is wrong — you must
  **poll** until the findings are actually up.
- **Resolve the login case-insensitively, and pass the BARE handle.** `coderabbit`,
  `Coderabbit`, `coderabbitai` all map to the bot — set `HANDLE=coderabbitai`. The
  poll matches both the bare login AND the `[bot]`-suffixed form (the real login is
  `coderabbitai[bot]`), so do NOT append `[bot]` yourself; an exact-equality match
  against the bare handle silently misses the real `…[bot]` login and the wait times
  out with the review actually done (this bit us).

**Mechanism — one self-exiting background poll per wait, then act on the result.**
Set the env, run the script below as a **Bash command with `run_in_background: true`**
(per the harness, a background `until`-style loop that exits when the condition is
true gives you a single wake — do not use a foreground `sleep`), then read
`$RESULT` when it wakes you:

```sh
# Set first: OWNER_REPO  PR  HANDLE(lowercased)  MODE(full|finished)  SINCE(ISO8601)  RESULT(tmpfile)
# First wait: MODE=full, SINCE=head commit time → `gh pr view "$PR" --json commits -q '.commits[-1].committedDate'`
#             (anchors on the current code, so a stale prior review doesn't satisfy the wait).
i=0
while [ "$i" -lt 60 ]; do                       # ~30 min at 30s/poll
  inline=$(gh api "repos/$OWNER_REPO/pulls/$PR/comments" --paginate \
    -q ".[] | select((.user.login|ascii_downcase)==\"$HANDLE\" or (.user.login|ascii_downcase)==\"${HANDLE}[bot]\") | select(.created_at > \"$SINCE\") | .id" 2>/dev/null)
  review=$(gh api "repos/$OWNER_REPO/pulls/$PR/reviews" --paginate \
    -q ".[] | select((.user.login|ascii_downcase)==\"$HANDLE\" or (.user.login|ascii_downcase)==\"${HANDLE}[bot]\") | select(.submitted_at > \"$SINCE\") | (.body // \"x\")" 2>/dev/null)
  issuec=$(gh api "repos/$OWNER_REPO/issues/$PR/comments" --paginate \
    -q ".[] | select((.user.login|ascii_downcase)==\"$HANDLE\" or (.user.login|ascii_downcase)==\"${HANDLE}[bot]\") | select(.updated_at > \"$SINCE\") | (.body // \"\")" 2>/dev/null)
  # FINISHED = a TERMINAL review result: an inline comment, a submitted review, the
  # "Actionable comments posted: N" header, OR a clean pass ("No actionable comments
  # were generated"). A clean pass IS a success — nothing to apply. An ERROR message
  # (rate limit / service failure) matches none of these, so it falls through and the
  # poll keeps waiting → TIMEOUT (surfaced to the user) — never reported as success.
  if [ -n "$inline" ] || [ -n "$review" ] \
       || printf '%s' "$issuec" | grep -qiE 'actionable comments posted|no actionable comments'; then
    { echo FINISHED; printf '%s\n' "$issuec"; } > "$RESULT"; exit 0
  fi
  # DECLINE (only when MODE=full) = "Review skipped" because the base isn't the default branch
  if [ "$MODE" = full ] && printf '%s' "$issuec" | grep -qi 'review skipped' \
       && printf '%s' "$issuec" | grep -Eqi 'base branch|base branches|default branch'; then
    { echo DECLINE; printf '%s\n' "$issuec"; } > "$RESULT"; exit 0
  fi
  i=$((i + 1)); sleep 30
done
echo TIMEOUT > "$RESULT"
```

CodeRabbit's exact wording drifts — if the markers above don't fire when you can
see (in the diagnostics) that it clearly did finish or decline, read the actual
comment body and adjust the `grep` patterns rather than waiting out the timeout.

**When it wakes you, read `$RESULT` and branch:**

- **`FINISHED`** → the reviewer has posted a terminal result. Fall through to Step 3.
  This includes a **clean pass** ("No actionable comments were generated") — a
  success with nothing to apply; Steps 4–5 will simply find no actionable items and
  Step 9 reports it clean. (An error/rate-limit message is deliberately NOT treated
  as finished — it falls through to `TIMEOUT`, which is surfaced to the user.)
- **`DECLINE`** → CodeRabbit refused because the PR's base isn't the default branch.
  Post **one** top-level comment to trigger a full review, then **re-arm the poll in
  finished-only mode** (`MODE=finished`, `SINCE=now` = `date -u +%Y-%m-%dT%H:%M:%SZ`)
  and wait again. Comment body (use `gh pr comment "$PR" --body-file <file>`, with
  the attribution footer from Step 7):

  ```text
  @coderabbitai trigger full review and tell me when you are finished
  ```

  Address the **real** handle (`@coderabbitai`); CodeRabbit acts on the natural
  language, and `@coderabbitai full review` is its canonical command if the phrase
  doesn't bite. Finished-only mode is deliberate: it won't re-trigger on a repeat
  decline (that would loop forever) — it waits for the fresh review, or times out.
- **`TIMEOUT`** → `<handle>` didn't finish within the window. Report it and ask
  whether to keep waiting or to proceed with whatever is there.

For a **human** (non-bot) handle there is no in-progress/decline state — the first
new review or comment since you started waiting is "finished," which the `FINISHED`
branch already covers; you never reach `DECLINE`.

## Step 3 — Reconcile the branch first

Reviewers/bots may have pushed to the PR branch (e.g. a "CodeRabbit Generated Unit
Tests" commit). `git fetch origin <head>` and **fast-forward** the local head to
`origin/<head>` before editing, so you don't diverge. If tests/files were added,
run the suite once to see the baseline.

## Step 4 — Fetch ALL comment sources (the inline list is NOT the whole set)

CodeRabbit spreads findings across three places — pull all three:

1. **Inline review comments** (the "actionable" ones; each carries a
   "🤖 Prompt for AI Agents" block):
   `gh api repos/OWNER/REPO/pulls/N/comments --paginate -q '.[] | "── \(.id) | \(.path):\(.line // .original_line) | \(.user.login) ──\n\(.body)\n"'`
2. **Review summary bodies** — this is where "🧹 Nitpick comments" and
   "⚠️ Outside diff range comments" live (collapsed `<details>`, each often with
   its own AI-prompt block). These have **no inline thread**, so they are easy to
   miss:
   `gh api repos/OWNER/REPO/pulls/N/reviews --paginate -q '.[] | select(.body != "") | .body'`
3. **Top-level issue/summary comment(s)**:
   `gh api repos/OWNER/REPO/issues/N/comments --paginate -q '.[] | "── \(.id) | \(.user.login) ──\n\(.body)\n"'`

Bodies are large — save them to a file and `grep -nE "Nitpick comments|Outside
diff range|Additional comments|Actionable comments|Prompt for AI Agents"` to
enumerate every finding (inline + nitpick + outside-diff-range) and its location.
Build the full list before fixing anything.

## Step 5 — Validate each finding against the CURRENT code (the crux)

For every finding, decide a verdict — do **not** auto-apply:

- **Read the cited code as it is now.** The finding may already be **stale/fixed**
  by a later commit on the branch. Confirm it still applies.
- **Is the rule even enforced here?** Check repo config before "fixing" a lint nit
  — e.g. in this repo ruff `select = [E,F,W,I]` (so `S110`/`BLE001` don't fire,
  and ruff doesn't implement `F824` at all). A nit for an unenforced rule is noise;
  skip it.
- **Scope, via `git blame`.** Is the code the PR introduced, or **pre-existing /
  outside the diff**? A pre-existing latent bug is real but usually belongs in its
  own PR, not bloating this one.
- **Sanity-check the suggested fix itself.** CodeRabbit's proposed diff can be
  wrong or unsafe (e.g. producing malformed output). Validate the *suggestion*,
  not just the *problem*.
- **Verdict:** **APPLY** (valid, in scope, safe) · **SKIP** (stale / unenforced /
  wrong-premise / suggestion-unsafe — record the reason) · **DEFER** (valid but
  pre-existing/orthogonal → its own branch+PR).

## Step 6 — Apply the valid fixes

- Minimal changes, matching repo conventions (see `CLAUDE.md`).
- Re-run the gates: `python -m pytest`, `ruff check .` / `ruff format .`, `php -l`
  / ShellCheck for any PHP/shell touched. Nothing red.
- Commit (`<scope>: <imperative summary>`) and push to the PR head branch (direct
  push; the PR updates itself).

## Step 7 — Reply to every finding

Use `--body-file` / `-F body=@<file>` for **all** replies — never inline `--body`
(the shell mangles backticks and `${...}` in CodeRabbit-style text).

**Attribution footer (required).** Everything you post here goes through the
user's `gh` account, so it shows up under *their* name. To avoid any confusion
about who is actually writing, append a footer to **every** body you send — inline
replies, top-level comments, and the bodies of any PR you open (Step 8) —
separated by a `---` line:

```text
---
🤖 Generated by [Claude Code](https://claude.com/claude-code), posted via @<gh-login>'s account on their behalf.
```

Resolve `<gh-login>` once with `gh api user -q .login`. Add this footer to the
body file before posting.

- **Inline review comments** → threaded reply:
  `gh api --method POST repos/OWNER/REPO/pulls/N/comments/{COMMENT_ID}/replies -F body=@<file> -q .html_url`
- **Nitpick / outside-diff-range findings** (live in the review body, no thread)
  → one top-level PR comment: `gh pr comment N --body-file <file>`. Address
  `@coderabbitai` directly when you want it to re-check or acknowledge.
- Each reply states the verdict plainly: **applied** (cite the commit),
  **skipped** (the validated reason), or **deferred** (link the new PR).

## Step 8 — Deferred findings → their own PR (optional)

For a valid-but-pre-existing finding, branch off the base, fix it there, and open
a separate PR (`--body-file` for the body; push the branch first, PR only if
direct push is blocked). Link that PR in the reply on the original thread.

## Step 9 — Report back

Summarize: findings by source (inline / nitpick / outside-diff-range), how many
**applied** (+ commit hash), **skipped** (with reasons), **deferred** (+ PR
links); gate results; and any thread you could not resolve.
