#!/bin/sh
# mcp-token-savior.sh — shared Claude/Codex stdio launcher for the token-savior MCP
# server (wired via .mcp.json and .codex/config.toml).
# Installs TS_SOURCE into a per-user cached venv, then execs it. The default TS_SOURCE pins
# upstream token-savior-recall 4.21.0 with the MCP and vector-memory extras. A TS_SOURCE change
# is detected via the .pfb-ts-source stamp and triggers a clean venv rebuild;
# a mkdir lock serializes concurrent sessions racing that rebuild (the venv is one shared
# per-user cache). The lock holder records its PID inside the lock so a waiter can reap a
# lock whose holder died without releasing it. Requires python3 >= 3.11.
# Env (all optional):
#   WORKSPACE_ROOTS        comma-separated project roots (default: every usable worktree
#                          of the current Git repository, otherwise current directory)
#   CLAUDE_PROJECT_ROOT    active root hint understood by Token Savior (default: current
#                          Git worktree; applies to every agent client)
#   TOKEN_SAVIOR_CLIENT    telemetry client label (default: claude-code; Codex config
#                          passes codex explicitly)
#   TOKEN_SAVIOR_PROFILE   server tool profile (default: optimized)
#   TS_VENV                venv location (default: ${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv)
#   TS_SOURCE              pip requirement to install (default: upstream 4.21.0)
#   TS_LOCK_WAIT           max seconds to wait on another session's rebuild (default 300)
#   INCLUDE_PATTERNS       colon-separated index globs; the default below REPLACES the
#                          server's built-in list, which lacks .php/.inc/.sh — this repo's
#                          main languages (globs from the git ls-files extension histogram)
#   TOKEN_SAVIOR_MAX_FILE_SIZE  index size cap in bytes (default here 2000000 —
#                          pfblockerng.inc is ~844 KB; the server's 500 KB default skips it)
set -eu

venv="${TS_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv}"
# Trim trailing slashes so the lock and dirname derivations below treat $venv
# as the final path component (a trailing slash once nested the lock inside
# the not-yet-created venv and broke every fresh install).
while true; do case "$venv" in */) venv="${venv%/}" ;; *) break ;; esac; done
# The rebuild path below rm -rf's $venv — string checks never resolve '..'
# (only the kernel does, at rm time), so refuse '..' segments and '//' along
# with anything non-absolute ('.', '', '/', relative paths).
case "$venv" in
	*//*|*/..|*/../*) venv_bad=1 ;;
	/?*) venv_bad=0 ;;
	*) venv_bad=1 ;;
esac
if [ "$venv_bad" = 1 ]; then
	echo "mcp-token-savior: refusing venv path '$venv' — TS_VENV must be an absolute path without '..' or '//' segments" >&2
	exit 1
fi
bin="$venv/bin/token-savior"
stamp="$venv/.pfb-ts-source"
TS_SOURCE="${TS_SOURCE:-token-savior-recall[mcp,memory-vector]==4.21.0}"

holder_alive() {
	kill -0 "$1" 2>/dev/null && return 0
	# kill -0 also fails with EPERM for a LIVE process this user may not signal,
	# so its failure is not proof of death. ps answers regardless of ownership;
	# no ps at all is no evidence, and doubt must never reap a held lock.
	command -v ps >/dev/null 2>&1 || return 0
	ps -p "$1" >/dev/null 2>&1
}

# stdout is the MCP stdio channel — install chatter must stay on stderr
if [ ! -x "$bin" ] || [ "$(cat "$stamp" 2>/dev/null || true)" != "$TS_SOURCE" ]; then
	lock="${venv}.rebuild.lock"
	mkdir -p "$(dirname "$venv")"
	waited=0
	max_wait="${TS_LOCK_WAIT:-300}"
	# The cap below is an integer comparison, and a non-numeric bound makes it
	# error every iteration without ever being true — an unbounded spin, the very
	# hang this lock handling exists to remove. Refuse the bound instead.
	case "$max_wait" in
		''|*[!0-9]*)
			echo "mcp-token-savior: refusing TS_LOCK_WAIT '$max_wait' — it must be a non-negative whole number of seconds" >&2
			exit 1
			;;
	esac
	# A SIGKILLed holder can never run its EXIT trap, so its lock outlived it and
	# blocked every later session until max_wait expired — nine days, undiagnosed,
	# in issue #1969. So the lock is not trusted on existence alone: the holder
	# records its PID inside it, and a waiter that finds that PID dead reaps the
	# lock and retries the acquisition. A lock carrying no readable PID is never
	# reaped — that is a live holder caught between mkdir and the PID write.
	while ! mkdir "$lock" 2>/dev/null; do
		holder="$(cat "$lock/pid" 2>/dev/null || true)"
		if [ -n "$holder" ] && ! holder_alive "$holder"; then
			rm -rf "$lock"
			continue
		fi
		if [ "$waited" -ge "$max_wait" ]; then
			echo "mcp-token-savior: concurrent rebuild did not complete within ${max_wait}s — if no other session is installing, remove '$lock' and retry" >&2
			exit 1
		fi
		sleep 1
		waited=$((waited + 1))
	done
	# set -e: a failed install still fires the trap, so a crashed rebuild
	# never leaves the lock behind for the next session to time out on.
	trap 'rm -rf "$lock" 2>/dev/null' EXIT
	printf '%s\n' "$$" > "$lock/pid"
	# Re-check under the lock — a concurrent session may have finished the
	# same rebuild while this one waited on mkdir.
	if [ ! -x "$bin" ] || [ "$(cat "$stamp" 2>/dev/null || true)" != "$TS_SOURCE" ]; then
		rm -rf "$venv"
		python3 -m venv "$venv" 1>&2
		"$venv/bin/pip" install --quiet "$TS_SOURCE" 1>&2
		printf '%s\n' "$TS_SOURCE" > "$stamp"
	fi
	rm -rf "$lock"
	trap - EXIT
fi

workspace_root=$PWD
if command -v git >/dev/null 2>&1; then
	repo_root=$(git rev-parse --show-toplevel 2>/dev/null || true)
	[ -z "$repo_root" ] || workspace_root=$repo_root
fi
# '+x' (not ':-') so an explicitly empty override survives: WORKSPACE_ROOTS=''
# means "index nothing", a caller decision, not an unset variable.
if [ "${WORKSPACE_ROOTS+x}" != x ]; then
	WORKSPACE_ROOTS=$workspace_root
	if command -v git >/dev/null 2>&1 && [ -x "$venv/bin/python3" ]; then
		worktree_roots=$(git worktree list --porcelain -z 2>/dev/null | "$venv/bin/python3" -c '
import os
import sys

roots = []
for record in sys.stdin.buffer.read().split(b"\0\0"):
    fields = record.split(b"\0")
    if any(field.startswith(b"prunable") for field in fields):
        continue
    path = next((field[9:] for field in fields if field.startswith(b"worktree ")), None)
    if path is None:
        continue
    root = os.path.abspath(os.fsdecode(path))
    if os.path.isdir(root):
        roots.append(root)
sys.stdout.write(",".join(roots))
' || true)
		[ -z "$worktree_roots" ] || WORKSPACE_ROOTS=$worktree_roots
	fi
fi
if [ "${CLAUDE_PROJECT_ROOT+x}" != x ]; then
	CLAUDE_PROJECT_ROOT=$workspace_root
fi
TOKEN_SAVIOR_CLIENT="${TOKEN_SAVIOR_CLIENT:-claude-code}"
TOKEN_SAVIOR_PROFILE="${TOKEN_SAVIOR_PROFILE:-optimized}"
INCLUDE_PATTERNS="${INCLUDE_PATTERNS:-**/*.py:**/*.php:**/*.inc:**/*.sh:**/*.js:**/*.md:**/*.txt:**/*.json:**/*.jsonc:**/*.yml:**/*.yaml:**/*.xml:**/*.conf:**/*.toml:**/*.neon}"
TOKEN_SAVIOR_MAX_FILE_SIZE="${TOKEN_SAVIOR_MAX_FILE_SIZE:-2000000}"
export WORKSPACE_ROOTS CLAUDE_PROJECT_ROOT TOKEN_SAVIOR_CLIENT TOKEN_SAVIOR_PROFILE INCLUDE_PATTERNS TOKEN_SAVIOR_MAX_FILE_SIZE
exec "$bin"
