---
name: pr-merge-flow
description: >
  Land a PR end-to-end the repo's DEFAULT way: review feedback first, then merge.
  Roughly `/pr-comments N --wait-for=coderabbitai && /pr-merge N` — get the review
  feedback, validate + apply each finding and reply, and ONLY if that completes
  cleanly, rebase the head onto the live base, wait for the real CI to go green
  (EXCLUDING the bot), merge `--rebase` (never a merge commit, never squash) and
  delete the branch. The review step adapts to the repo: if CodeRabbit is active it
  waits on CodeRabbit; if CodeRabbit is NOT available for the repo it spawns a
  Claude Sonnet sub-agent to review in its place, then triages the same way. This
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

First decide the review source (1a), run the matching path (1b or 1c), then apply the
shared gate. The gate is identical for both paths.

### Step 1a — Is CodeRabbit available for this repo?

There is no unauthenticated API for "is the app installed", so probe by recent
activity: if CodeRabbit has reviewed/commented on **any** of the last few PRs it is
active; if the last several PRs show **zero** CodeRabbit activity it is not installed
on this repo (e.g. it was left behind by an org transfer).

```sh
# OWNER_REPO from Step 0. Counts CodeRabbit (login matches "coderabbit") activity
# across the last 6 closed PRs; any non-zero line => available.
for n in $(gh pr list --repo "$OWNER_REPO" --state closed --limit 6 --json number -q '.[].number'); do
  gh api "repos/$OWNER_REPO/issues/$n/comments" --paginate \
    -q '[.[]|select((.user.login|ascii_downcase)|test("coderabbit"))]|length'
  gh api "repos/$OWNER_REPO/pulls/$n/reviews" --paginate \
    -q '[.[]|select((.user.login|ascii_downcase)|test("coderabbit"))]|length'
done
```

- **Available** (any non-zero) → **Step 1b**.
- **Not available** (all zero) → **Step 1c**.

### Step 1b — CodeRabbit available → wait on CodeRabbit

- Invoke the **pr-comments** skill with `N --wait-for=coderabbitai`. It blocks until
  CodeRabbit has finished reviewing, then validates each finding against the current
  code, applies the ones that genuinely hold, skips the rest with a reason, and
  replies on every thread.
- If that wait **times out** (CodeRabbit silently went away despite the probe), do
  not stall the flow — fall back to **Step 1c**.

### Step 1c — CodeRabbit NOT available → Claude Sonnet sub-agent reviewer

Stand in a reviewer yourself, then triage exactly as `pr-comments` would.

1. **Spawn one sub-agent** with the Agent tool, `model: sonnet`, briefed to act as
   CodeRabbit: review the PR's diff (`git diff origin/<BASE>...HEAD` in the PR's
   worktree/branch), grounded in the **current** code (read the surrounding files,
   not just the hunk), and return structured findings — each with a severity
   (`blocking` / `nitpick` / `outside-diff`), `file:line`, a grounded explanation,
   and a concrete suggested fix — plus a short "considered-and-fine" list. Tell it
   the result IS its final message and not to edit anything.
2. **Triage each finding yourself against the CURRENT code** — do not auto-apply.
   Per finding: **APPLY** (valid, in scope, safe) · **SKIP** (stale / unenforced /
   wrong-premise / suggestion-unsafe — record the reason) · **DEFER** (valid but
   pre-existing/orthogonal → its own branch+PR). This mirrors `pr-comments` Step 5;
   honour the repo's lint config and `CLAUDE.md` conventions.
3. **Apply the valid fixes**, re-run the relevant gates (`php -l` / PHPUnit / PHPStan
   for PHP, `python -m pytest` / `ruff` / `mypy` for Python, ShellCheck for shell —
   whatever the change touches), commit (`<scope>: <imperative summary>`) and push to
   the PR head branch.
4. **Record the review on the PR** — post one comment summarising the substitute
   review and the per-finding resolution (applied + commit / skipped + reason /
   deferred + link), so there is an audit trail. Use `gh pr comment N --body-file`
   and append the attribution footer (resolve `<gh-login>` once with
   `gh api user -q .login`):

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
