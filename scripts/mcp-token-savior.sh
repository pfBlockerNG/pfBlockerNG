#!/bin/sh
# mcp-token-savior.sh — stdio launcher for the token-savior MCP server (wired via .mcp.json).
# Installs TS_SOURCE into a per-user cached venv, then execs it. The default TS_SOURCE is the
# andrebrait/token-savior fork's `integration` branch pinned by commit — it carries fixes and
# language support not yet merged upstream (Mibayy/token-savior PRs #47 #53 #54 #57 #58 #59
# #60 #62); repoint to PyPI's token-savior-recall[mcp,memory-vector] once those merge. A TS_SOURCE change (e.g. a
# new pinned commit) is detected via the .pfb-ts-source stamp and triggers a clean venv rebuild;
# a mkdir lock serializes concurrent sessions racing that rebuild (the venv is one shared
# per-user cache). Requires python3 >= 3.11 and git (pip installs from a git URL).
# Env (all optional):
#   WORKSPACE_ROOTS        comma-separated project roots (default: current directory)
#   TOKEN_SAVIOR_PROFILE   server tool profile (default: optimized)
#   TS_VENV                venv location (default: ${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv)
#   TS_SOURCE              pip requirement to install (default: the pinned fork commit)
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
while :; do case "$venv" in */) venv="${venv%/}" ;; *) break ;; esac; done
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
TS_SOURCE="${TS_SOURCE:-token-savior-recall[mcp,memory-vector] @ git+https://github.com/andrebrait/token-savior@162aa29947fc98da8dfc5319e9fd59b11bdfed34}"

# stdout is the MCP stdio channel — install chatter must stay on stderr
if [ ! -x "$bin" ] || [ "$(cat "$stamp" 2>/dev/null || true)" != "$TS_SOURCE" ]; then
	lock="${venv}.rebuild.lock"
	mkdir -p "$(dirname "$venv")"
	if mkdir "$lock" 2>/dev/null; then
		# set -e: a failed install still fires the trap, so a crashed rebuild
		# never leaves the lock behind for the next session to time out on.
		trap 'rmdir "$lock" 2>/dev/null' EXIT
		# Re-check under the lock — a concurrent session may have finished the
		# same rebuild while this one waited on mkdir.
		if [ ! -x "$bin" ] || [ "$(cat "$stamp" 2>/dev/null || true)" != "$TS_SOURCE" ]; then
			rm -rf "$venv"
			python3 -m venv "$venv" 1>&2
			"$venv/bin/pip" install --quiet "$TS_SOURCE" 1>&2
			printf '%s\n' "$TS_SOURCE" > "$stamp"
		fi
		rmdir "$lock" 2>/dev/null
		trap - EXIT
	else
		waited=0
		max_wait="${TS_LOCK_WAIT:-300}"
		while [ -d "$lock" ] && [ "$waited" -lt "$max_wait" ]; do
			sleep 1
			waited=$((waited + 1))
		done
		if [ ! -x "$bin" ] || [ "$(cat "$stamp" 2>/dev/null || true)" != "$TS_SOURCE" ]; then
			echo "mcp-token-savior: concurrent rebuild did not complete within ${max_wait}s — if no other session is installing, remove '$lock' and retry" >&2
			exit 1
		fi
	fi
fi

WORKSPACE_ROOTS="${WORKSPACE_ROOTS:-$PWD}"
TOKEN_SAVIOR_CLIENT="${TOKEN_SAVIOR_CLIENT:-claude-code}"
TOKEN_SAVIOR_PROFILE="${TOKEN_SAVIOR_PROFILE:-optimized}"
INCLUDE_PATTERNS="${INCLUDE_PATTERNS:-**/*.py:**/*.php:**/*.inc:**/*.sh:**/*.js:**/*.md:**/*.txt:**/*.json:**/*.jsonc:**/*.yml:**/*.yaml:**/*.xml:**/*.conf:**/*.toml:**/*.neon}"
TOKEN_SAVIOR_MAX_FILE_SIZE="${TOKEN_SAVIOR_MAX_FILE_SIZE:-2000000}"
export WORKSPACE_ROOTS TOKEN_SAVIOR_CLIENT TOKEN_SAVIOR_PROFILE INCLUDE_PATTERNS TOKEN_SAVIOR_MAX_FILE_SIZE
exec "$bin"
