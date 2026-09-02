#!/bin/sh
# SessionStart hook: bring the checkout's current branch up to date with its base.
#
# Why this exists: devel advances outside a live session, so an active session
# branch can fall behind its base. Rebasing onto origin/devel is the native
# synchronization step: Git drops individually patch-equivalent commits and
# replays genuinely new ones. A branch whose PR was squash-merged may instead
# conflict because its original commit boundaries no longer exist upstream;
# the hook aborts cleanly and reports that case rather than guessing.
#
#   base branch (devel/main) -> fast-forward only (ff-only) to its own remote;
#                               a diverged base is surfaced, never rewritten
#   session branch           -> rebase onto origin/devel: merged commits drop,
#                               new commits replay on the live base
#   shallow history gap      -> unshallow once, then require a visible merge
#                               base; otherwise report + touch nothing
#   dirty tree               -> touch nothing; tell the agent to sync by hand. Only
#                               TRACKED changes count: an untracked file (a fresh
#                               graphify-out/memory/ record) blocks nothing unless the
#                               incoming commits track that path -- git refuses that
#                               itself, and both arms below report it
#   rebase conflict (~1%)    -> abort cleanly; tell the agent to resolve by hand
#
# ponytail: base is origin/devel for every non-base branch -- the documented
# branch point for adr/issue/claude branches. A rare main-targeting branch
# rebases onto devel; the agent corrects that by hand.

git rev-parse --git-dir >/dev/null 2>&1 || exit 0
# Detached HEAD (which includes a paused/in-progress rebase) -> skip untouched.
# This guard is ALSO what keeps the hook from ever running `git rebase --abort`
# on someone's in-progress rebase -- keep it (don't swap in `git branch
# --show-current`, which returns "" instead of failing and would slip through).
branch=$(git symbolic-ref --short HEAD 2>/dev/null) || exit 0

# Bound the fetch so a SYN-dropping network can't hang session start: abort if
# throughput stays under 1 KB/s for 15s. git config (portable) rather than a
# timeout(1) wrapper (absent on some agent OSes); non-fatal either way.
git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=15 fetch --quiet origin >/dev/null 2>&1 || true

# Emit one SessionStart JSON object. A branch name is an arbitrary byte string
# (git does not enforce UTF-8), so drop invalid sequences (iconv -c, when present)
# and JSON-escape backslash then double quote -- either would otherwise produce
# JSON a strict parser rejects, silently dropping the injected context.
emit() {
	msg=$1
	command -v iconv >/dev/null 2>&1 && msg=$(printf '%s' "$msg" | iconv -f UTF-8 -t UTF-8 -c 2>/dev/null)
	esc=$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')
	printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"%s"}}\n' "$esc"
}

case "$branch" in
	devel | main) base="origin/${branch}"; kind="BASE BRANCH" ;;
	*) base="origin/devel"; kind="SESSION BRANCH" ;;
esac

git rev-parse --verify --quiet "$base" >/dev/null 2>&1 || exit 0

# A shallow boundary can hide the true ancestry between an older session branch
# and a freshly fetched base. Without this guard, `git rebase origin/devel`
# treats the boundary as history's root and replays old BASE commits as if they
# belonged to the session branch. Recover the missing ancestry once; never
# launch a rebase that still has no visible merge base.
case "$branch" in
	devel | main) ;;
	*)
		if ! git merge-base HEAD "$base" >/dev/null 2>&1; then
			if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
				git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=15 \
					fetch --quiet --unshallow origin >/dev/null 2>&1 || true
			fi
			if ! git merge-base HEAD "$base" >/dev/null 2>&1; then
				emit "SESSION BRANCH '${branch}': NO VISIBLE MERGE BASE with ${base}; branch left untouched. If this clone is shallow, run 'git fetch origin --unshallow' (or deepen it) and confirm 'git merge-base HEAD ${base}' prints a commit before rebasing. Never run a plain rebase across a missing merge base: it replays base history as work."
				exit 0
			fi
		fi
		;;
esac

# Nothing to do if already at/behind-only with no divergence for base branches,
# or already sitting on the live base for session branches.
before=$(git rev-list --count "${base}..HEAD" 2>/dev/null || echo 0)
behind=$(git rev-list --count "HEAD..${base}" 2>/dev/null || echo 0)
[ "$before" -eq 0 ] && [ "$behind" -eq 0 ] && exit 0

if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
	emit "${kind} '${branch}': ${before} commit(s) ahead of ${base}, ${behind} behind, but the working tree is DIRTY so it was left untouched. Commit or discard your changes, then run: git rebase ${base}  (or, on a base branch, git merge --ff-only ${base}). Rebasing can drop individually patch-equivalent commits, but git log ${base}..HEAD cannot tell whether equivalent changes already landed in a squash commit."
	exit 0
fi

case "$branch" in
	devel | main)
		# Branch on $before, not merge's exit code: a purely-ahead base branch
		# (unpushed local commit, behind=0) makes `git merge --ff-only` succeed
		# trivially ("Already up to date", rc 0), which would misreport an
		# unpushed commit as "current". Any local commit not on the remote =>
		# not current; only behind=0/ahead=0 (already filtered above) is clean.
		if [ "$before" -gt 0 ]; then
			emit "BASE BRANCH '${branch}': has ${before} local commit(s) not on ${base}. This branch is meant to be PR-only -- reconcile by hand before starting work (push them via a PR, or reset to ${base})."
		elif git merge --ff-only --quiet "$base" >/dev/null 2>&1; then
			emit "BASE BRANCH '${branch}': fast-forwarded ${behind} commit(s) up to ${base}. Checkout is current."
		else
			emit "BASE BRANCH '${branch}': fast-forward to ${base} FAILED -- branch is unchanged (stderr was suppressed). Usually an untracked file that ${base} now tracks: move it aside, then run: git merge --ff-only ${base}"
		fi
		;;
	*)
		if git rebase "$base" >/dev/null 2>&1; then
			after=$(git rev-list --count "${base}..HEAD" 2>/dev/null || echo 0)
			dropped=$((before - after))
			if [ "$after" -eq 0 ]; then
				emit "SESSION BRANCH '${branch}': all ${dropped} commit(s) were patch-equivalent to devel and dropped by rebase. Branch now equals ${base} -- a clean, current base. Do NOT rebuild the old commits; the prior tip is in the reflog. Cut a fresh worktree for new work if the skill calls for one."
			else
				emit "SESSION BRANCH '${branch}': rebased onto ${base}; dropped ${dropped} patch-equivalent commit(s) and replayed ${after} genuinely-new one(s) on the live base. Push with --force-with-lease. (Hash-based git log ${base}..HEAD had reported ${before}; it counts divergent commit objects, not squash-equivalent changes.)"
			fi
		elif git rebase --abort >/dev/null 2>&1; then
			emit "SESSION BRANCH '${branch}': rebase onto ${base} FAILED and was ABORTED -- branch is unchanged (stderr was suppressed, so the cause is unshown). Re-run by hand to see why: git rebase ${base}  (often a merge conflict; an obsolete squash-merged branch can conflict because upstream no longer has its original commit boundaries), then --force-with-lease push."
		elif [ -d "$(git rev-parse --git-path rebase-merge)" ] || [ -d "$(git rev-parse --git-path rebase-apply)" ]; then
			emit "SESSION BRANCH '${branch}': rebase onto ${base} FAILED and the --abort ALSO failed -- the repo may be stuck mid-rebase. Inspect by hand: git status; git rebase --abort."
		else
			emit "SESSION BRANCH '${branch}': rebase onto ${base} could not start -- branch is unchanged (stderr was suppressed). Usually an untracked file that ${base} now tracks (git status shows it): move it aside, then run: git rebase ${base}"
		fi
		;;
esac
