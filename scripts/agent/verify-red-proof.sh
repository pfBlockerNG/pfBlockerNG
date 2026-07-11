#!/bin/sh
# verify-red-proof.sh -- mechanically re-execute a red->green proof (CLAUDE.md "THE GATE"
# item 2): freeze-hash check, revert the src paths to HEAD~1 (tests stay), expect the
# pinning test to FAIL, restore, expect it to PASS. The single implementation the
# gh-issue / adr-phase / delegate gates and the phase-step verifier reference.
#
# Usage: verify-red-proof.sh --worktree PATH --test-cmd 'CMD' --src PATH [--src PATH ...]
#                            [--hash FILE=SHA ...]
#   --test-cmd  run via `sh -c` from the worktree root; nonzero exit = red, zero = green
#   --src       production path(s) reverted to HEAD~1 for the red run (repo-relative)
#   --hash      committed reproduction-test freeze check: `git hash-object FILE` must
#               equal SHA (the handoff's red-time hash) -- an edited test proves nothing
#
# Prints FREEZE-OK / RED-OK / GREEN-OK step lines, then final `VERDICT: PASS`.
# Any step failing prints the failing step + `VERDICT: FAIL` and exits 1. Requires a
# clean tree (exit 2 otherwise); the src paths are restored on every exit path.

worktree='' test_cmd=''
srcs='' hashes=''

usage() {
	echo "usage: verify-red-proof.sh --worktree PATH --test-cmd 'CMD' --src PATH [--src ...] [--hash FILE=SHA ...]" >&2
	exit 2
}

fail() {
	printf '%s\nVERDICT: FAIL\n' "$1"
	exit 1
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	scrub_git_env "$0"
	while [ $# -gt 0 ]; do
		case "$1" in
			--worktree) worktree=$2; shift 2 ;;
			--test-cmd) test_cmd=$2; shift 2 ;;
			--src) srcs="$srcs $2"; shift 2 ;;
			--hash) hashes="$hashes $2"; shift 2 ;;
			*) usage ;;
		esac
	done
	[ -n "$worktree" ] && [ -n "$test_cmd" ] && [ -n "$srcs" ] || usage
	require_tool git

	if [ -n "$(git -C "$worktree" status --porcelain)" ]; then
		echo "DIRTY-TREE: the gate re-derives from committed state; commit or clean first." >&2
		exit 2
	fi

	for pair in $hashes; do
		file=${pair%%=*}
		want=${pair#*=}
		got=$(git -C "$worktree" hash-object "$file") || fail "FREEZE-FAIL: cannot hash $file"
		if [ "$got" != "$want" ]; then
			fail "FREEZE-FAIL: $file is $got, red-time hash was $want (test edited between red and green)"
		fi
		printf 'FREEZE-OK: %s\n' "$file"
	done

	# shellcheck disable=SC2086 # srcs is a space-separated path list by construction
	git -C "$worktree" checkout HEAD~1 -- $srcs || fail "REVERT-FAIL: could not check out HEAD~1 src paths"
	# shellcheck disable=SC2064,SC2086 # expand now: restore exactly these paths on any exit.
	# INT/TERM trapped explicitly: under dash (Linux /bin/sh) an EXIT trap does NOT run
	# on an untrapped signal, which would strand the src paths at HEAD~1.
	trap "git -C '$worktree' checkout HEAD -- $srcs" EXIT
	# shellcheck disable=SC2064,SC2086 # expand now, deliberately (same paths as above)
	trap "git -C '$worktree' checkout HEAD -- $srcs; trap - EXIT; exit 130" INT TERM

	if (cd "$worktree" && sh -c "$test_cmd" >/dev/null 2>&1); then
		fail "RED-FAIL: test passed against HEAD~1 src -- it does not pin the defect"
	fi
	printf 'RED-OK: test fails against HEAD~1 src\n'

	# shellcheck disable=SC2086
	git -C "$worktree" checkout HEAD -- $srcs || fail "RESTORE-FAIL"
	trap - EXIT INT TERM

	if ! (cd "$worktree" && sh -c "$test_cmd" >/dev/null 2>&1); then
		fail "GREEN-FAIL: test fails against HEAD -- the fix does not satisfy its own pin"
	fi
	printf 'GREEN-OK: test passes against HEAD\nVERDICT: PASS\n'
}

case "${AGENT_SOURCE_ONLY:-0}" in
	1) ;;
	*) main "$@" ;;
esac
