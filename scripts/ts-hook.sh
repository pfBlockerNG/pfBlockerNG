#!/bin/sh
# ts-hook.sh <module> — run a token-savior Claude/Codex hook
# (token_savior.hooks.<module>, e.g. bash_rewriter_hook / tool_capture_hook) from the cached venv that
# scripts/mcp-token-savior.sh installs. Pass-through no-op when the venv is not
# fully provisioned (first session before the MCP launcher has installed it, or an
# interrupted rebuild that left a python-only skeleton).
# Env (optional): TS_VENV — venv location (default: ${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv).
# Only tool_capture_hook is wired in .claude/settings.json and .codex/hooks.json — the
# bash rewriter/compactors stay unwired (Bash-output compaction is rtk's job now).
set -eu

venv="${TS_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/token-savior/venv}"
py="$venv/bin/python3"

# No-op unless the venv is FULLY provisioned: the launcher rm -rf's the venv and
# reinstalls on a TS_SOURCE change, writing the .pfb-ts-source stamp ONLY after the
# pip install succeeds. So an interrupted/failed rebuild leaves python present but
# token_savior missing AND no stamp — guarding on the stamp (not just python) skips
# that window instead of crashing the hook with ModuleNotFoundError.
if [ ! -x "$py" ] || [ ! -s "$venv/.pfb-ts-source" ]; then
	cat >/dev/null
	printf '{"continue": true}\n'
	exit 0
fi
exec "$py" -m "token_savior.hooks.$1"
