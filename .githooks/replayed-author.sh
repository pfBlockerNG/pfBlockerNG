#!/bin/sh
# Sourced by prepare-commit-msg and pre-push (issue #3642). A rebase or
# cherry-pick keeps the original author and only makes the configured user the
# committer, so an agent commit may carry a foreign author exactly when it
# replays a PUBLISHED commit: some commit reachable from a remote-tracking ref has
# the same author name, email and author timestamp.
#
# author_is_replayed <name> <email> <unix-ts>
#   0 = a published commit has that exact author identity; 1 = none (a failing git
#   yields no candidates, so it is 1 too).
# The timestamp narrows candidates in awk (digits only, no names involved); name
# and email are then compared as whole strings by the shell, never as patterns, so
# metacharacters in a name cannot match loosely. This guards against accidents, not
# against an agent that forges a remote-tracking ref: identity, not content, is checked.
author_is_replayed() {
	[ -n "$1" ] && [ -n "$2" ] && [ -n "$3" ] || return 1
	_ra_candidates=$(git log --remotes --format='%H %at' 2>/dev/null |
		awk -v ts="$3" '$2 == ts { print $1 }')
	while IFS= read -r _ra_sha; do
		[ -n "$_ra_sha" ] || continue
		[ "$(git log -1 --format=%an "$_ra_sha" 2>/dev/null)" = "$1" ] || continue
		[ "$(git log -1 --format=%ae "$_ra_sha" 2>/dev/null)" = "$2" ] || continue
		return 0
	done <<PFB_REPLAY_CANDIDATES
$_ra_candidates
PFB_REPLAY_CANDIDATES
	return 1
}
