#!/bin/sh
# SessionStart hook: bring the checkout's current branch up to date with its base.
#
# Why this exists: the repo merges rebase-only, which rewrites commit hashes. A
# leftover session branch (claude/*, issue/*, adr/*) whose PR already landed
# still shows its commits as "unmerged" under every hash-based check
# (git log origin/devel..HEAD, merge-base --is-ancestor) -- so agents rebuild or
# stack on already-merged work. git rebase is the native cure: rebasing onto
# origin/devel drops the already-applied commits by patch-id and replays only
# the genuinely-new ones. This hook runs it every session so no agent has to
# remember, and reports what happened.
#
#   base branch (devel/main) -> fast-forward only (ff-only) to its own remote;
#                               a diverged base is surfaced, never rewritten
#   session branch           -> rebase onto origin/devel: merged commits drop,
#                               new commits replay on the live base
#   dirty tree               -> touch nothing; tell the agent to sync by hand
#   rebase conflict (~1%)    -> abort cleanly; tell the agent to resolve by hand
#
# ponytail: base is origin/devel for every non-base branch -- the documented
# branch point for adr/issue/claude branches. A rare main-targeting branch
# rebases onto devel; the agent corrects that by hand.
#
# This covers only the FIRST sync of a session (SessionStart fires once). The
# companion PreToolUse hook (skill-branch-sync.sh) re-runs the same logic
# before every gh-issue/adr-phase/adr-create/delegate/adr-all invocation, so a
# long session with several work items stays synced between them too.

. "$(dirname "$0")/branch-sync-core.sh"
branch_sync_run SessionStart
