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
#   base branch (devel/main) -> pull --rebase its own remote (fast-forward)
#   session branch           -> rebase onto origin/devel: merged commits drop,
#                               new commits replay on the live base
#   dirty tree               -> touch nothing; tell the agent to sync by hand
#   rebase conflict (~1%)    -> abort cleanly; tell the agent to resolve by hand
#
# ponytail: base is origin/devel for every non-base branch -- the documented
# branch point for adr/issue/claude branches. A rare main-targeting branch
# rebases onto devel; the agent corrects that by hand.

git rev-parse --git-dir >/dev/null 2>&1 || exit 0
branch=$(git symbolic-ref --short HEAD 2>/dev/null) || exit 0   # detached -> skip

git fetch --quiet origin >/dev/null 2>&1 || true

emit() {
	printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"%s"}}\n' "$1"
}

case "$branch" in
	devel | main) base="origin/${branch}" ;;
	*) base="origin/devel" ;;
esac

git rev-parse --verify --quiet "$base" >/dev/null 2>&1 || exit 0

# Nothing to do if already at/behind-only with no divergence for base branches,
# or already sitting on the live base for session branches.
before=$(git rev-list --count "${base}..HEAD" 2>/dev/null || echo 0)
behind=$(git rev-list --count "HEAD..${base}" 2>/dev/null || echo 0)
[ "$before" -eq 0 ] && [ "$behind" -eq 0 ] && exit 0

if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
	emit "SESSION BRANCH '${branch}': ${before} commit(s) ahead of ${base}, ${behind} behind, but the working tree is DIRTY so it was left untouched. Commit or discard your changes, then run: git rebase ${base}  (or, on a base branch, git pull --rebase). Rebasing onto ${base} drops any already-merged commits by patch-id -- do NOT trust git log ${base}..HEAD, which overcounts them after a rebase-merge."
	exit 0
fi

case "$branch" in
	devel | main)
		if git merge --ff-only --quiet "$base" >/dev/null 2>&1; then
			emit "BASE BRANCH '${branch}': fast-forwarded ${behind} commit(s) up to ${base}. Checkout is current."
		else
			emit "BASE BRANCH '${branch}': has ${before} local commit(s) not on ${base} and could not fast-forward. This branch is meant to be PR-only -- reconcile by hand (git pull --rebase) before starting work."
		fi
		;;
	*)
		if git rebase "$base" >/dev/null 2>&1; then
			after=$(git rev-list --count "${base}..HEAD" 2>/dev/null || echo 0)
			dropped=$((before - after))
			if [ "$after" -eq 0 ]; then
				emit "SESSION BRANCH '${branch}': all ${dropped} commit(s) were already merged into devel (rebase dropped them by patch-id despite rebase-rewritten hashes). Branch now equals ${base} -- a clean, current base. Do NOT rebuild the old commits; the prior tip is in the reflog. Cut a fresh worktree for new work if the skill calls for one."
			else
				emit "SESSION BRANCH '${branch}': rebased onto ${base}; dropped ${dropped} already-merged commit(s) and replayed ${after} genuinely-new one(s) on the live base. Push with --force-with-lease. (Hash-based git log ${base}..HEAD had reported ${before}, overcounting the merged ones.)"
			fi
		else
			git rebase --abort >/dev/null 2>&1
			emit "SESSION BRANCH '${branch}': rebase onto ${base} hit a conflict and was ABORTED -- branch is unchanged. Resolve by hand: git rebase ${base}  then --force-with-lease push. The conflict is the ~1% case rebase cannot auto-resolve."
		fi
		;;
esac
