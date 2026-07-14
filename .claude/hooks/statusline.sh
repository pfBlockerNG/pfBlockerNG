#!/bin/sh
# statusline.sh — the repo statusline chain: ponytail + caveman mode badges (vendored
# plugin scripts), then the caveman/TS/RTK savings badges. STATUSLINE_SAVINGS_WINDOW
# (default 24h; off|0|lifetime = lifetime totals) makes every savings number a rolling
# delta via statusline-rolling.sh. In rolling mode the plugin's lifetime ⛏ suffix is
# suppressed and caveman-rolling.sh renders the windowed one instead.
set -eu

d="${CLAUDE_PROJECT_DIR:-.}/.claude"
bash "$d/skills/ponytail/hooks/ponytail-statusline.sh"
printf ' '
case ${STATUSLINE_SAVINGS_WINDOW:-24h} in
	off | 0 | lifetime)
		bash "$d/skills/caveman/src/hooks/caveman-statusline.sh"
		;;
	*)
		CAVEMAN_STATUSLINE_SAVINGS=0 bash "$d/skills/caveman/src/hooks/caveman-statusline.sh"
		sh "$d/hooks/caveman-rolling.sh"
		;;
esac
sh "$d/hooks/ts-statusline.sh"
sh "$d/hooks/rtk-statusline.sh"
