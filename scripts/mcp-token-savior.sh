#!/bin/sh
# mcp-token-savior.sh — stdio launcher for the token-savior MCP server (wired via .mcp.json).
# First run installs token-savior-recall[mcp] (https://github.com/Mibayy/token-savior) into a
# per-user cached venv, then execs it; later runs exec directly. Requires python3 >= 3.11.
# Env (all optional):
#   WORKSPACE_ROOTS        comma-separated project roots (default: current directory)
#   TOKEN_SAVIOR_PROFILE   server tool profile (default: optimized)
#   TS_VENV                venv location (default: ${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv)
#   INCLUDE_PATTERNS       colon-separated index globs; the default below REPLACES the
#                          server's built-in list, which lacks .php/.inc/.sh — this repo's
#                          main languages (globs from the git ls-files extension histogram)
set -eu

venv="${TS_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv}"
bin="$venv/bin/token-savior"

# stdout is the MCP stdio channel — install chatter must stay on stderr
if [ ! -x "$bin" ]; then
	python3 -m venv "$venv" 1>&2
	"$venv/bin/pip" install --quiet "token-savior-recall[mcp]" 1>&2
fi

WORKSPACE_ROOTS="${WORKSPACE_ROOTS:-$PWD}"
TOKEN_SAVIOR_CLIENT="${TOKEN_SAVIOR_CLIENT:-claude-code}"
TOKEN_SAVIOR_PROFILE="${TOKEN_SAVIOR_PROFILE:-optimized}"
INCLUDE_PATTERNS="${INCLUDE_PATTERNS:-**/*.py:**/*.php:**/*.inc:**/*.sh:**/*.js:**/*.md:**/*.txt:**/*.json:**/*.jsonc:**/*.yml:**/*.yaml:**/*.xml:**/*.conf:**/*.toml:**/*.neon}"
export WORKSPACE_ROOTS TOKEN_SAVIOR_CLIENT TOKEN_SAVIOR_PROFILE INCLUDE_PATTERNS
exec "$bin"
