#!/bin/sh
# work-branch.sh -- derive the canonical work-item branch name (CLAUDE.md "Branch naming"
# sanitiser, implemented once so it is never hand-derived) and optionally cut the
# worktree for it.
#
# Usage: work-branch.sh <issue|adr> <NN> [TITLE ...] [--worktree] [--path PATH] [--base REF]
#   Prints the branch name (`issue/NN-slug` / `adr/NN-slug`; empty slug -> bare `type/NN`).
#   --worktree  also `git fetch origin` + `git worktree add -b BRANCH PATH BASE` at an
#               ABSOLUTE path (default <repo>/.claude/worktrees/<type>-<NN>); an existing
#               branch or path gets a `-<epoch>` suffix (collision rule). Prints
#               `BRANCH<TAB>PATH` instead.
#   --base REF  worktree base (default origin/devel)
#
# Sanitiser (pinned by tests/shell/agent_work_branch_spec.sh): lowercase; every
# non-[a-z0-9] run collapses to one '-'; trim leading/trailing '-'; truncate to <=30
# chars at a '-' boundary (never a trailing '-').

usage() {
	echo "usage: work-branch.sh <issue|adr> <NN> [TITLE ...] [--worktree] [--path PATH] [--base REF]" >&2
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

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	scrub_git_env "$0"
	kind='' nn='' title='' do_worktree=0 path='' base='origin/devel'
	case "$1" in issue|adr) kind=$1; shift ;; *) usage ;; esac
	case "$1" in *[!0-9]*|'') usage ;; *) nn=$1; shift ;; esac
	while [ $# -gt 0 ]; do
		case "$1" in
			--worktree) do_worktree=1; shift ;;
			--path) path=$2; shift 2 ;;
			--base) base=$2; shift 2 ;;
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
	root=$(git rev-parse --show-toplevel) || exit 2
	git fetch origin >/dev/null 2>&1
	if git show-ref --verify -q "refs/heads/$branch" ||
	   git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
		branch="$branch-$(date +%s)"
	fi
	[ -n "$path" ] || path="$root/.claude/worktrees/$kind-$nn"
	case "$path" in /*) ;; *) path="$root/$path" ;; esac   # worktree add needs ABSOLUTE paths
	[ -e "$path" ] && path="$path-$(date +%s)"
	git worktree add -b "$branch" "$path" "$base" >/dev/null || exit 1
	printf '%s\t%s\n' "$branch" "$path"
}

case "${AGENT_SOURCE_ONLY:-0}" in
	1) ;;
	*) main "$@" ;;
esac
