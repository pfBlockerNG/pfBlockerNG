#!/bin/sh
# Copilot session marker — write on sessionStart, remove on sessionEnd.
#
# Copilot CLI exports no environment variable identifying its session to the
# shells it spawns, so the git hooks cannot detect "an agent is driving this"
# the way they do for Claude (CLAUDECODE) and Codex (CODEX_THREAD_ID). This
# script leaves a file holding the CLI's pid in the COMMON git dir — shared by
# the primary checkout and every linked worktree — and .githooks/pre-push plus
# .githooks/prepare-commit-msg treat a marker whose pid is still alive as an
# agent runtime.
#
# The pid is what makes a stale marker harmless: a session killed without its
# sessionEnd hook leaves the file behind, and the hooks ignore it once the
# process is gone rather than blocking the owner's own commits forever.
#
# The cloud agent needs none of this: it sets COPILOT_AGENT_PROMPT itself.
#
# Usage: copilot-session-marker.sh start|end   (wired in .github/hooks/pfblockerng.json)

set -u

action=${1:-}

common_dir=$(git rev-parse --git-common-dir 2>/dev/null) || exit 0
[ -n "$common_dir" ] || exit 0
marker="${common_dir}/pfb-copilot-session"

case "$action" in
	start)
		# $PPID is the Copilot CLI process that spawned this hook shell.
		printf '%s\n' "$PPID" > "$marker" 2>/dev/null || exit 0
		;;
	end)
		rm -f "$marker" 2>/dev/null || exit 0
		;;
	*)
		echo "usage: copilot-session-marker.sh start|end" >&2
		exit 2
		;;
esac

exit 0
