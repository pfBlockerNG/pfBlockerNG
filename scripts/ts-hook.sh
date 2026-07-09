#!/bin/sh
# ts-hook.sh <module> — run a token-savior Claude Code hook (token_savior.hooks.<module>,
# e.g. bash_rewriter_hook / tool_capture_hook) from the cached venv that
# scripts/mcp-token-savior.sh installs. Pass-through no-op when the venv is absent
# (first session, before the MCP launcher has installed it).
# Env (optional): TS_VENV — venv location (default: ${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv).
# TS_BASH_REWRITE/TS_BASH_COMPACT come from .claude/settings.json env (rewrite on,
# compact off): the compact git compactors parse only human-format output, so combined
# with the rewriter's porcelain/oneline forms they render dirty trees as "clean" and
# diffs/logs as empty (token-savior-recall 4.4.1).
set -eu

py="${TS_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv}/bin/python3"

if [ ! -x "$py" ]; then
	cat >/dev/null
	printf '{"continue": true}\n'
	exit 0
fi
exec "$py" -m "token_savior.hooks.$1"
