---
name: pr-merge
description: >
  Land a pull request the repo's way: rebase its head branch onto the target
  branch, push, wait for CI to go green (EXCLUDING CodeRabbit — never block on
  the bot), then merge with `--rebase` (never a merge commit, never squash) and
  delete the remote branch. Refuses to merge a draft, a conflicting/unmergeable
  PR, or one whose CI is red. Args: [PR number] (defaults to the current
  branch's PR). Use when the user says "merge this PR", "land PR N", "rebase and
  merge", "merge it once CI passes", or invokes /pr-merge. Companion to
  /pr-comments — handle review feedback first, then /pr-merge.
---

You land a PR. The non-negotiable rules, all from this repo's `CLAUDE.md`:

- **Rebase only.** Merge with `gh pr merge --rebase` — **never** a merge commit,
  **never** squash. History across `main` ← `devel` is strictly linear, so every
  landing is a rebase/replay.
- **Rebase onto the live base first.** `devel` advances out of band (parallel
  agents). Fetch and rebase the head branch onto the **current** remote base, push
  `--force-with-lease`, and let CI re-run on the rebased commits — *that* is the CI
  you wait on. A PR behind its base must be made a clean fast-forward before it
  lands.
- **Never block on CodeRabbit or Snyk.** Wait for the real CI checks; treat any check
  whose name matches `coderabbit` or `snyk` (case-insensitive) as advisory — CodeRabbit's
  state (pending, pass, "Review skipped") never gates the merge, and Snyk's quota/infra
  `error` ("Code test limit reached") is a skipped scan, not a failure. The one exception:
  a terminal Snyk `fail` carrying a **real finding** is a security finding to resolve
  before merging (Step 4). Review feedback is `/pr-comments`' job, not this skill's.
- **Never merge a red, draft, or unmergeable PR.** Abort and report instead.
- **Work in a dedicated worktree** (repo rule for AI agents) — never rebase/push
  from the primary checkout.

Args: `{{ args }}`

## Step 1 — Identify the PR and branch

- If a PR number was given in the args, use it. Otherwise resolve the current
  branch's PR: `gh pr view --json number,headRefName,baseRefName,state,isDraft,mergeable,url`.
  If there is none, stop and ask.
- Resolve `OWNER/REPO`: `gh repo view --json nameWithOwner -q .nameWithOwner`.
- Record `HEAD` (`headRefName`) and `BASE` (`baseRefName`).

## Step 2 — Preflight: refuse the cases that must not merge

Read the PR state once and bail early (report, do not proceed) if:

- `state != OPEN` (already merged or closed).
- `isDraft == true` — tell the user to mark it ready first.
- `mergeable == CONFLICTING` — it needs conflict resolution; that is not this
  skill's job. (`UNKNOWN` just means GitHub is still computing — re-read after a
  few seconds.)

Only continue when the PR is OPEN, ready, and mergeable.

## Step 3 — Rebase the head branch onto its base, push

Do this in a **dedicated worktree** (never the primary checkout). Reuse a worktree for `HEAD`
**only if you created it earlier in this run** — if one exists at the path but you did not
create it (possibly a live parallel session's: `git -C <path> status` shows foreign uncommitted
changes), do **not** touch or `--force`-remove it; create your own at a fresh path. Otherwise
create one:

```sh
git fetch origin
git worktree add <path> "$HEAD"          # checks out the PR head branch
# inside <path>:
git rebase "origin/$BASE"                # replay onto the LIVE base tip
```

- Resolve any conflicts the rebase surfaces. If they are non-trivial or ambiguous,
  stop and hand back to the user — do not guess a resolution just to land the PR.
- Push the rebased branch: `git push --force-with-lease`. (If the rebase was a
  no-op because the branch was already on the base tip, the push is a no-op too —
  fine.)
- The force-push re-triggers CI on the rebased commits. Step 4 waits on that run,
  not a stale one.

## Step 4 — Wait for CI to pass (excluding CodeRabbit)

Poll `gh pr checks` until every **required** check has completed — excluding
**CodeRabbit** (advisory bot) and **Snyk** (advisory security scan; its quota/infra `error`
state must never gate a merge) — then decide.
Run the loop as a **Bash command with `run_in_background: true`** (a background
`until`-style loop that self-exits gives a single wake — do not foreground-`sleep`),
then read `$RESULT`:

```sh
# Set first: PR  EXCLUDE(regex, default 'coderabbit|snyk')  RESULT(tmpfile)
i=0
while [ "$i" -lt 80 ]; do                                  # ~40 min at 30s/poll
  json=$(gh pr checks "$PR" --json name,bucket 2>/dev/null)
  rel=$(printf '%s' "$json" | jq -c "[.[] | select((.name|ascii_downcase|test(\"$EXCLUDE\"))|not)]")
  total=$(printf '%s' "$rel" | jq 'length')
  fail=$(printf '%s' "$rel" | jq '[.[]|select(.bucket=="fail" or .bucket=="cancel")]|length')
  pend=$(printf '%s' "$rel" | jq '[.[]|select(.bucket=="pending")]|length')
  if [ "$fail" -gt 0 ]; then { echo FAIL;    printf '%s\n' "$rel"; } > "$RESULT"; exit 0; fi
  if [ "$total" -gt 0 ] && [ "$pend" -eq 0 ]; then { echo PASS; printf '%s\n' "$rel"; } > "$RESULT"; exit 0; fi
  i=$((i + 1)); sleep 30
done
echo TIMEOUT > "$RESULT"
```

`bucket` is one of `pass` / `fail` / `pending` / `skipping` / `cancel`; `skipping`
counts as done-not-failed. Requiring `total > 0` avoids declaring PASS before any
check has registered. When it wakes you, read `$RESULT`:

- **`PASS`** → every required check is green. One post-pass read of the excluded Snyk
  status (`gh pr checks "$PR" | grep -i snyk`): a terminal **`fail` whose description is a
  real finding** (NOT "Code test limit reached"/quota/infra `error`) is a genuine security
  finding — stop and route it through the review flow instead of merging. Quota/error/
  pending/absent → proceed (note the skipped scan). Then go to Step 5.
- **`FAIL`** → a real check failed (the body lists which). **Do not merge.** Report
  the failing checks and their run URLs (`gh pr checks "$PR"`) and stop.
- **`TIMEOUT`** → checks did not finish in the window. Report and ask whether to
  keep waiting or stop. Never merge on a timeout.

## Step 5 — Merge with rebase

```sh
gh pr merge "$PR" --rebase
```

- **Do not** pass `--delete-branch` here. Known repo gotcha: `gh pr merge
  --delete-branch` runs a local post-merge step that checks out the base branch,
  which **fails when another worktree already holds that base** — even though the
  remote merge succeeded. So merge first, verify, then delete the branch in Step 6.
- Never substitute `--merge` or `--squash`.

## Step 6 — Verify, then clean up

- **Confirm the merge actually landed** (the local step above can error while the
  remote merge succeeded): `gh pr view "$PR" --json state,mergedAt -q '.state'`
  must be `MERGED`.
- **Delete the remote branch separately** (avoids the Step 5 gotcha):
  `git push origin --delete "$HEAD"`.
- **Remove the worktree from the PRIMARY checkout** (it errors if run from *inside*
  the tree): `git worktree remove <path>`. If you created a throwaway branch only
  to hold the worktree, delete it too.

**Trigger sweep (mandatory — CLAUDE.md "No orphaned waits").** The task just reached a
terminal state, so kill every wait tied to it NOW, by class: `TaskStop` each background
poll you started for it; `CronDelete` every remaining heartbeat rung; unsubscribe any
PR/event subscription. Any `ScheduleWakeup` you armed cannot be cancelled — confirm its
prompt was self-invalidating and let it no-op. Then `TaskList` once: stop anything stale
you own from earlier items. Report the sweep in one line (what was stopped / "nothing
pending").

## Step 7 — Report back

State plainly: the PR number and title, whether a rebase was needed (and onto which
base tip), the CI verdict (which checks passed; that CodeRabbit was intentionally
not waited on), the merge result (`MERGED`, rebased), and that the remote branch and
worktree were cleaned up. If you aborted at any step, say exactly why and what the
user needs to do.
