#!/bin/sh
# caveman-rolling.sh — statusline suffix ` ⛏ <saved>` as a rolling delta over caveman's
# lifetime savings (sum of the latest est_saved_tokens snapshot per session in
# .caveman-history.jsonl — the same aggregation caveman-stats.js uses). Only as fresh as
# the last /caveman-stats run; silent without jq/history. Window: statusline-rolling.sh.
set -eu

h="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/.caveman-history.jsonl"
{ [ -f "$h" ] && [ ! -L "$h" ]; } || exit 0
total=$(jq -rs '[group_by(.session_id)[] | max_by(.ts) | .est_saved_tokens // 0] | add // 0 | floor' "$h" 2>/dev/null) || exit 0
saved=$(sh "$(dirname "$0")/statusline-rolling.sh" caveman "$total")
[ -n "$saved" ] && printf ' \033[38;5;172m⛏ %s\033[0m' "$saved" || :
