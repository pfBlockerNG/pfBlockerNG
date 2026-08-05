#!/bin/sh
# Copilot session markers — write on sessionStart, remove on sessionEnd.
#
# Copilot CLI exports no environment variable identifying its session to the
# shells it spawns, so the git hooks cannot detect "an agent is driving this"
# the way they do for Claude (CLAUDECODE) and Codex (CODEX_THREAD_ID). This
# script records the CLI process in `<common-git-dir>/pfb-copilot-sessions/`,
# shared by the primary checkout and every linked worktree, and
# .githooks/pre-push plus .githooks/prepare-commit-msg treat any record naming a
# LIVE process as an agent runtime.
#
# One file per session, named for the CLI pid: concurrent Copilot sessions on
# one clone are normal here, and a single shared marker would let the first
# sessionEnd disarm the guards for every other session still running.
#
# The recorded pid must OUTLIVE this script. The hook chain is
# `copilot -> bash -c -> copilot-session-hook.sh -> this script`, so $PPID here
# is the dispatcher shell, which exits immediately; walking up to the ancestor
# whose command is `copilot` is what makes the liveness check meaningful (probed
# 2026-08-05: the dispatcher's own parent is the `copilot` process itself).
# A pid that is gone is ignored rather than trusted, so a session killed without
# its sessionEnd hook cannot block the owner's own later commits.
#
# The cloud agent needs none of this: it sets COPILOT_AGENT_PROMPT itself.
#
# PFB_COPILOT_PID overrides the ancestor walk with an explicit pid: the seam the
# specs drive (no Copilot CLI runs in the suite) and the escape hatch for a
# wrapper that hides the CLI from the process tree.
#
# Usage: copilot-session-marker.sh start|end|active
#        `active` exits 0 iff at least one live session record remains.

set -u

action=${1:-}

common_dir=$(git rev-parse --git-common-dir 2>/dev/null) || exit 0
[ -n "$common_dir" ] || exit 0
sessions="${common_dir}/pfb-copilot-sessions"

# The pid of the Copilot CLI driving this session, or empty when no `copilot`
# ancestor exists (the hook was invoked outside a Copilot session).
copilot_pid() {
	if [ -n "${PFB_COPILOT_PID:-}" ]; then
		case "$PFB_COPILOT_PID" in '' | 0 | *[!0-9]*) return ;; esac
		printf '%s\n' "$PFB_COPILOT_PID"
		return
	fi
	pid=$$
	depth=0
	while [ "$depth" -lt 12 ]; do
		pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
		case "$pid" in '' | 0 | 1) return ;; esac
		case "$(basename "$(ps -o comm= -p "$pid" 2>/dev/null)")" in
			copilot) printf '%s\n' "$pid"; return ;;
		esac
		depth=$((depth + 1))
	done
}

case "$action" in
	start)
		pid=$(copilot_pid)
		# No CLI ancestor: nothing meaningful to record, and a bogus pid would
		# either never expire or expire instantly.
		[ -n "$pid" ] || exit 0
		# Redirection failures (a read-only .git) are reported by the SHELL, not
		# by the command, so the whole block is silenced rather than each line.
		{
			# `true >` not `: >`: a redirection error on a SPECIAL builtin aborts
			# the whole shell under ash/dash (issues #1172, #1850).
			mkdir -p "$sessions" && true > "${sessions}/${pid}"
		} 2>/dev/null || exit 0
		;;
	end)
		pid=$(copilot_pid)
		[ -n "$pid" ] || exit 0
		rm -f "${sessions}/${pid}" 2>/dev/null || exit 0
		;;
	active)
		[ -d "$sessions" ] || exit 1
		for record in "$sessions"/*; do
			[ -e "$record" ] || continue
			pid=$(basename "$record")
			case "$pid" in '' | 0 | *[!0-9]*) continue ;; esac
			if kill -0 "$pid" 2>/dev/null; then
				exit 0
			fi
			# Opportunistic prune: the session behind this record is gone.
			rm -f "$record" 2>/dev/null
		done
		exit 1
		;;
	*)
		echo "usage: copilot-session-marker.sh start|end|active" >&2
		exit 2
		;;
esac

exit 0
