#!/bin/sh
# work-branch.sh -- derive the canonical work-item branch name (the CLAUDE.md
# "Branch naming" sanitiser) and optionally cut the worktree for it.
#
# Usage: work-branch.sh <issue|adr> <NN> [TITLE ...] [--worktree] [--claim] [--path PATH] [--base REF]
#   Prints the branch name (`issue/NN-slug` / `adr/NN-slug`; empty slug -> bare `type/NN`).
#   --worktree  also `git fetch origin` + `git worktree add -b BRANCH PATH BASE` at an
#               ABSOLUTE path (default <primary checkout>/.claude/worktrees/<type>-<NN>,
#               or <TMPDIR>/pfblockerng-<type>-<NN> under Codex; a relative --path anchors
#               at the primary checkout); an existing branch or path gets a `-<epoch>` suffix
#               (collision rule). Every created worktree initializes CodeGraph,
#               Graphify, and enabled Serena tools.
#               Prints `BRANCH<TAB>PATH` instead.
#   --base REF  worktree base (default origin/devel)
#   --claim     with `issue … --worktree`: assign an UNCLAIMED issue to the caller
#               (`gh issue edit NN --add-assignee @me`) before cutting the worktree.
#
# Claim gate (workflow.md "Claim": the assignee IS the claim, set before any work):
# `issue NN --worktree` refuses (exit 3) when the issue is unassigned or assigned
# to someone other than the caller (`gh api user`); someone else's claim is refused
# even with --claim. gh absent/unreachable = loud "claim NOT verified" warning and
# proceed (MCP-only sessions verify the assignee themselves). ADR worktrees and
# bare name derivation never touch gh.
#
# Sanitiser (pinned by tests/shell/agent_work_branch_spec.sh): lowercase; every
# non-[a-z0-9] run collapses to one '-'; trim leading/trailing '-'; truncate to <=30
# chars at a '-' boundary (never a trailing '-').

usage() {
	echo "usage: work-branch.sh <issue|adr> <NN> [TITLE ...] [--worktree] [--claim] [--path PATH] [--base REF]" >&2
	exit 2
}

slugify() {
	s=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | LC_ALL=C tr -c 'a-z0-9' '-' \
		| LC_ALL=C sed -e 's/--*/-/g' -e 's/^-//' -e 's/-$//')
	if [ "${#s}" -gt 30 ]; then
		head30=$(printf '%.30s' "$s")
		rest=${s#"$head30"}
		case "$rest" in
			-*) s=$head30 ;;   # the cut lands exactly on a token boundary: keep the prefix
			*)
				case "$head30" in
					*-*) s=${head30%-*} ;;   # drop the straddling token: back to the last '-'
					*) s=$head30 ;;
				esac
				;;
		esac
		s=$(printf '%s' "$s" | LC_ALL=C sed 's/-$//')
	fi
	printf '%s' "$s"
}

# claim_gate NN DO_CLAIM -- refuse (exit 3) on POSITIVE evidence that issue NN is
# not the caller's claim: no assignee, or assigned to someone else (the caller
# is `gh api user`). With DO_CLAIM=1 an unassigned issue is claimed first. When
# gh is absent or cannot answer (MCP-only or offline sessions) the claim is not
# verifiable here: warn loudly and proceed -- the session verifies the assignee
# with its own GitHub tools; the gate must not strand environments without gh.
claim_gate() {
	cg_nn=$1 cg_claim=$2
	cg_unverified() {
		echo "work-branch.sh: WARNING claim NOT verified for issue #$cg_nn ($1) — the assignee IS the claim (workflow.md \"Claim\"); confirm it is assigned to you with your GitHub tools before working" >&2
		return 0
	}
	command -v gh >/dev/null 2>&1 || { cg_unverified "gh not installed"; return 0; }
	cg_me=$(gh api user --jq .login 2>/dev/null) && [ -n "$cg_me" ] ||
		{ cg_unverified "gh api user failed"; return 0; }
	cg_assignees=$(gh issue view "$cg_nn" --json assignees --jq '[.assignees[].login] | join(",")' 2>/dev/null) ||
		{ cg_unverified "gh issue view failed"; return 0; }
	case ",$cg_assignees," in
		*",$cg_me,"*) return 0 ;;
	esac
	if [ -n "$cg_assignees" ]; then
		echo "work-branch.sh: issue #$cg_nn is claimed by $cg_assignees, not $cg_me — one claimed ticket maps to one live session (workflow.md \"Claim\"); coordinate or take over per the staleness rule before cutting a worktree" >&2
		exit 3
	fi
	if [ "$cg_claim" -eq 1 ]; then
		gh issue edit "$cg_nn" --add-assignee @me >/dev/null 2>&1 ||
			{ echo "work-branch.sh: could not claim issue #$cg_nn (gh issue edit --add-assignee @me failed)" >&2; exit 3; }
		return 0
	fi
	echo "work-branch.sh: issue #$cg_nn is not claimed (no assignee) — the assignee IS the claim and is set before any work (workflow.md \"Claim\"); re-run with --claim to assign it to $cg_me, or \`gh issue edit $cg_nn --add-assignee @me\`" >&2
	exit 3
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	scrub_git_env "$0"
	kind='' nn='' title='' do_worktree=0 do_claim=0 path='' base='origin/devel'
	case "$1" in issue|adr) kind=$1; shift ;; *) usage ;; esac
	case "$1" in *[!0-9]*|'') usage ;; *) nn=$1; shift ;; esac
	while [ $# -gt 0 ]; do
		case "$1" in
			--worktree) do_worktree=1; shift ;;
			--claim) do_claim=1; shift ;;
			--path) [ $# -ge 2 ] || usage; path=$2; shift 2 ;;
			--base) [ $# -ge 2 ] || usage; base=$2; shift 2 ;;
			*) title="$title $1"; shift ;;
		esac
	done

	slug=$(slugify "$title")
	branch="$kind/$nn${slug:+-$slug}"

	if [ "$do_worktree" -eq 0 ]; then
		printf '%s\n' "$branch"
		exit 0
	fi

	require_tool git
	[ "$kind" = issue ] && claim_gate "$nn" "$do_claim"
	# Anchor at the PRIMARY checkout: rc-mode/managed sessions run inside a linked
	# session worktree, where --show-toplevel would nest the new worktree in a tree
	# whose lifecycle the harness owns (pinned by agent_work_branch_spec.sh).
	common=$(git rev-parse --git-common-dir) || exit 2
	# CDPATH= : a CDPATH hit would echo the dir and hijack a relative cd.
	root=$(CDPATH='' cd "$common/.." && pwd -P) || exit 2
	if [ ! -d "$root/.git" ]; then
		echo "work-branch.sh: cannot locate the primary checkout from '$common' (unsupported layout, e.g. --separate-git-dir)" >&2
		exit 2
	fi
	if git -C "$root" remote get-url origin >/dev/null 2>&1; then
		if ! git -C "$root" fetch origin >/dev/null 2>&1; then
			echo "work-branch.sh: git fetch origin failed" >&2
			exit 1
		fi
	fi
	if git show-ref --verify -q "refs/heads/$branch" ||
	   git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
		branch="$branch-$(date +%s)"
	fi
	if [ -z "$path" ]; then
		case "${CODEX_THREAD_ID:-}" in
			'') path="$root/.claude/worktrees/$kind-$nn" ;;
			*) tmp_root=$(CDPATH='' cd "${TMPDIR:-/tmp}" 2>/dev/null && pwd -P) || tmp_root=/tmp
				path="$tmp_root/pfblockerng-$kind-$nn" ;;
		esac
	fi
	case "$path" in /*) ;; *) path="$root/$path" ;; esac   # worktree add needs ABSOLUTE paths
	[ -e "$path" ] && path="$path-$(date +%s)"
	git worktree add -b "$branch" "$path" "$base" >/dev/null || exit 1
	initializer=${PFB_INIT_WORKTREE_TOOLS:-$(dirname "$0")/init-worktree-tools.sh}
	sh "$initializer" "$path"
	initializer_status=$?
	if [ "$initializer_status" -ne 0 ]; then
		echo "work-branch.sh: removing worktree and branch after tool initialization failure" >&2
		git worktree remove --force "$path" >/dev/null 2>&1 || {
			echo "work-branch.sh: failed to remove incomplete worktree '$path'" >&2
			exit 1
		}
		git branch -D "$branch" >/dev/null 2>&1 || {
			echo "work-branch.sh: failed to delete incomplete branch '$branch'" >&2
			exit 1
		}
		exit "$initializer_status"
	fi
	printf '%s\t%s\n' "$branch" "$path"
}

case "${AGENT_SOURCE_ONLY:-0}" in
	1) ;;
	*) main "$@" ;;
esac
