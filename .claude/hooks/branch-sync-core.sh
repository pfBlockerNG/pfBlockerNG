#!/bin/sh
# .claude/hooks/branch-sync-core.sh -- shared fetch+rebase-onto-base logic.
#
# Sourced by two thin wrappers:
#   session-branch-sync.sh  (SessionStart, once per session)
#   skill-branch-sync.sh    (PreToolUse on the Skill tool, once per
#                            gh-issue/adr-phase/adr-create/delegate/adr-all
#                            invocation -- mechanically enforces those
#                            skills' "every invocation, even mid-session"
#                            Step 0 sync instead of relying on prose)
#
# Call branch_sync_run <hookEventName> after any wrapper-specific gating.
# Emits at most one hookSpecificOutput JSON object on stdout; silent
# (return 0, no output) when there is nothing to report. See
# session-branch-sync.sh for the full behavioural writeup (base selection,
# dirty-tree handling, rebase-conflict abort) -- unchanged here, only
# hookEventName varies by caller.

branch_sync_run() {
	hook_event_name=$1

	git rev-parse --git-dir >/dev/null 2>&1 || return 0
	# Detached HEAD (which includes a paused/in-progress rebase) -> skip
	# untouched -- also what keeps this from ever running `git rebase
	# --abort` on someone's in-progress rebase.
	branch=$(git symbolic-ref --short HEAD 2>/dev/null) || return 0

	# Bound the fetch so a SYN-dropping network can't hang the caller.
	git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=15 fetch --quiet origin >/dev/null 2>&1 || true

	emit() {
		msg=$1
		command -v iconv >/dev/null 2>&1 && msg=$(printf '%s' "$msg" | iconv -f UTF-8 -t UTF-8 -c 2>/dev/null)
		esc=$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')
		printf '{"hookSpecificOutput":{"hookEventName":"%s","additionalContext":"%s"}}\n' "$hook_event_name" "$esc"
	}

	case "$branch" in
		devel | main) base="origin/${branch}"; kind="BASE BRANCH" ;;
		*) base="origin/devel"; kind="SESSION BRANCH" ;;
	esac

	git rev-parse --verify --quiet "$base" >/dev/null 2>&1 || return 0

	before=$(git rev-list --count "${base}..HEAD" 2>/dev/null || echo 0)
	behind=$(git rev-list --count "HEAD..${base}" 2>/dev/null || echo 0)
	[ "$before" -eq 0 ] && [ "$behind" -eq 0 ] && return 0

	if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
		emit "${kind} '${branch}': ${before} commit(s) ahead of ${base}, ${behind} behind, but the working tree is DIRTY so it was left untouched. Commit or discard your changes, then run: git rebase ${base}  (or, on a base branch, git merge --ff-only ${base}). Rebasing onto ${base} drops any already-merged commits by patch-id -- do NOT trust git log ${base}..HEAD, which overcounts them after a rebase-merge."
		return 0
	fi

	case "$branch" in
		devel | main)
			if [ "$before" -gt 0 ]; then
				emit "BASE BRANCH '${branch}': has ${before} local commit(s) not on ${base}. This branch is meant to be PR-only -- reconcile by hand before starting work (push them via a PR, or reset to ${base})."
			elif git merge --ff-only --quiet "$base" >/dev/null 2>&1; then
				emit "BASE BRANCH '${branch}': fast-forwarded ${behind} commit(s) up to ${base}. Checkout is current."
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
			elif git rebase --abort >/dev/null 2>&1; then
				emit "SESSION BRANCH '${branch}': rebase onto ${base} FAILED and was ABORTED -- branch is unchanged (stderr was suppressed, so the cause is unshown). Re-run by hand to see why: git rebase ${base}  (most often a merge conflict, the ~1% rebase cannot auto-resolve), then --force-with-lease push."
			else
				emit "SESSION BRANCH '${branch}': rebase onto ${base} FAILED and the --abort ALSO failed -- the repo may be stuck mid-rebase. Inspect by hand: git status; git rebase --abort."
			fi
			;;
	esac
}
