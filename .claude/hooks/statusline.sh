#!/bin/sh
# statusline.sh — the repo statusline chain: ponytail + caveman mode badges from the
# client plugin cache, then the caveman savings badge. STATUSLINE_SAVINGS_WINDOW
# (default 24h; off|0|lifetime = lifetime totals) makes every savings number a rolling
# delta via statusline-rolling.sh. CAVEMAN_STATUSLINE_INLINE (default 1) folds caveman's
# number into the badge — `[CAVEMAN 252k↓]`; 0 keeps the plugin-style ` ⛏ 252k` suffix
# (and, with the window off, the plugin's own untouched lifetime suffix).
set -eu

d="${CLAUDE_PROJECT_DIR:-.}/.claude"
# Resolve the newest cached plugin versions; skip either badge when absent.
plugin_cache="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/plugins/cache"
ponytail_dir=$(ls -td "$plugin_cache"/ponytail/ponytail/*/ 2>/dev/null | head -1)
caveman_dir=$(ls -td "$plugin_cache"/caveman/caveman/*/ 2>/dev/null | head -1)
ponytail_sl="${ponytail_dir}hooks/ponytail-statusline.sh"
caveman_sl="${caveman_dir}src/hooks/caveman-statusline.sh"
if [ -n "$ponytail_dir" ] && [ -f "$ponytail_sl" ]; then
	bash "$ponytail_sl"
	printf ' '
fi

case ${STATUSLINE_SAVINGS_WINDOW:-24h} in
	off | 0 | lifetime) lifetime=1 ;;
	*) lifetime=0 ;;
esac
inline="${CAVEMAN_STATUSLINE_INLINE:-1}"

if [ -z "$caveman_dir" ] || [ ! -f "$caveman_sl" ]; then
	: # no cached caveman plugin — skip its badge
elif [ "$lifetime" = 1 ] && [ "$inline" = 0 ]; then
	bash "$caveman_sl"
else
	badge=$(CAVEMAN_STATUSLINE_SAVINGS=0 bash "$caveman_sl")
	saved=$(sh "$d/hooks/caveman-rolling.sh")
	if [ -n "$saved" ] && [ "$inline" != 0 ]; then
		printf '%s' "$badge" | sed "s/]/ ${saved}↓]/"
	else
		printf '%s' "$badge"
		if [ -n "$saved" ]; then
			printf ' \033[38;5;172m⛏ %s\033[0m' "$saved"
		fi
	fi
fi
