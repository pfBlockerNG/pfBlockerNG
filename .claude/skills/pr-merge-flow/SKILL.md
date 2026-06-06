---
name: pr-merge-flow
description: >
  Land a PR end-to-end the repo's DEFAULT way: review feedback first, then merge.
  Shorthand for `/pr-comments N --wait-for=coderabbitai && /pr-merge N` — block
  until CodeRabbit finishes, validate + apply each finding and reply on every
  thread, and ONLY if that completes cleanly, rebase the head onto the live base,
  wait for the real CI to go green (EXCLUDING the bot), merge `--rebase` (never a
  merge commit, never squash) and delete the branch. This is the default flow
  after any GitHub issue, ADR, or code change — everything except the dev-only
  classes that land straight on devel with no PR (documentation-only, CLAUDE.md,
  ADR text, skills). Args: [PR number] (defaults to the current branch's PR). Use
  when the user says "merge flow", "land it the usual way", "comments then
  merge", "finish/land this PR", or invokes /pr-merge-flow.
---

You run this repo's standard land-a-PR flow: **review feedback first, then merge.**
It is the exact shorthand for:

```text
/pr-comments N --wait-for=coderabbitai && /pr-merge N
```

The `&&` is load-bearing: **never start the merge until the comments step has
completed cleanly.** This skill orchestrates the two existing skills in order — it
does not re-implement them; invoke each via the Skill tool.

Args: `{{ args }}`

## Step 0 — Identify the PR

- If a PR number is in the args, use it. Otherwise resolve the current branch's PR:
  `gh pr view --json number,headRefName,state,isDraft,url`. If there is none, stop
  and ask.
- This skill is for **code-bearing PRs**. If the work is a dev-only class that lands
  straight on `devel` with no PR (documentation-only, `CLAUDE.md`, ADR text, skills
  — see `CLAUDE.md` → "Worktrees"), this skill does not apply: say so and stop.

## Step 1 — Review feedback (`/pr-comments N --wait-for=coderabbitai`)

- Invoke the **pr-comments** skill with `N --wait-for=coderabbitai`. It blocks until
  CodeRabbit has finished reviewing, then validates each finding against the current
  code, applies the ones that genuinely hold, skips the rest with a reason, and
  replies on every thread.
- **Gate before Step 2.** Continue to the merge ONLY if the comments step finished
  cleanly: every finding triaged + replied, any accepted fixes committed and pushed,
  and nothing left that needs a human decision. If a finding is unresolved,
  contested, or needs the user, **stop here and report** — do not merge.

## Step 2 — Land it (`/pr-merge N`)

- Invoke the **pr-merge** skill with `N`. It rebases the head onto the live base,
  waits for the real CI checks to go green (CodeRabbit excluded — never block on the
  bot), merges with `--rebase` (never a merge commit, never squash), and deletes the
  remote branch.
- `pr-merge` already refuses a draft / red / conflicting PR — honour its abort and
  report rather than forcing.

## Definition of done

- Review threads resolved + replied; PR merged by rebase; remote branch deleted.
- Sync the work item's labels (an issue's `Waiting PR` removed on merge), per
  `CLAUDE.md` → "Labels (lifecycle)".
- If you stopped before merging, state exactly why and what is needed to proceed.
