#!/bin/sh
# rtk-statusline.sh — statusline badge ` [RTK <saved>↓]` (per-project token savings via
# `rtk gain -p`) when the rtk binary is available; silent otherwise; plain ` [RTK]` without jq/data.
# Same no-PATH-prepend rule as rtk-hook.sh: the badge means "rewrite active this session".
set -eu

command -v rtk >/dev/null 2>&1 || exit 0
saved=$(rtk gain -p -f json 2>/dev/null \
	| jq -r '(.summary.total_saved // 0) | if . <= 0 then "" elif . >= 10000 then "\(. / 1000 | floor)k" else tostring end' 2>/dev/null) \
	|| saved=''
printf ' \033[38;5;208m[RTK%s]\033[0m' "${saved:+ ${saved}↓}"
