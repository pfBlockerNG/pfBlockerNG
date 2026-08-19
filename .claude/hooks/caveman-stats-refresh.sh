#!/bin/sh
# caveman-stats-refresh.sh — Stop hook: refresh caveman's savings snapshot (history +
# statusline suffix) by running the cached plugin's caveman-stats.js on this session's
# transcript, throttled to one run per 5 min — keeps the rolling ⛏ badge fresh without a per-turn
# session-log parse and without manual /caveman-stats. Always exits 0: stats never block.
set -eu

stamp="${XDG_CACHE_HOME:-$HOME/.cache}/statusline-rolling/.caveman-stats-last"
now=$(date +%s)
last=$(cat "$stamp" 2>/dev/null) || last=0
case $last in '' | *[!0-9]*) last=0 ;; esac
[ $((now - last)) -ge 300 ] || exit 0
command -v node >/dev/null 2>&1 || exit 0
d="${CLAUDE_PROJECT_DIR:-.}/.claude"
# shellcheck source=.claude/hooks/plugin-install-path.sh
. "$d/hooks/plugin-install-path.sh"
caveman_dir=$(plugin_install_path 'caveman@caveman')
js="${caveman_dir}/src/hooks/caveman-stats.js"
[ -n "$caveman_dir" ] && [ -f "$js" ] || exit 0

tp=$(jq -r '.transcript_path // empty' 2>/dev/null) || tp=''
mkdir -p "${stamp%/*}"
printf '%s\n' "$now" >"$stamp"
if [ -n "$tp" ]; then
	node "$js" --session-file "$tp" >/dev/null 2>&1 || :
else
	node "$js" >/dev/null 2>&1 || :
fi
