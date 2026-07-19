#!/bin/sh
# rtk-install.sh — SessionStart hook: make RTK available, then trust the checked-in filters
# from the current worktree. When absent, install the checksum-verified upstream binary to
# ~/.local/bin, best-effort symlink it into /usr/local/bin, and update shell profiles for the
# next shell. Never fails session start. RTK_VERSION pins a release.
set -u

rtk_bin=$(command -v rtk 2>/dev/null) || rtk_bin=''
if [ -z "$rtk_bin" ] && [ -x "$HOME/.local/bin/rtk" ]; then
	rtk_bin="$HOME/.local/bin/rtk"
fi

if [ -z "$rtk_bin" ]; then
	{ curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/refs/heads/master/install.sh | sh; } >/dev/null 2>&1 || exit 0

	[ -x "$HOME/.local/bin/rtk" ] || exit 0
	rtk_bin="$HOME/.local/bin/rtk"
	if [ -w /usr/local/bin ] && [ ! -e /usr/local/bin/rtk ]; then
		ln -s "$rtk_bin" /usr/local/bin/rtk 2>/dev/null
	fi
	for f in "$HOME/.profile" "$HOME/.bashrc"; do
		# shellcheck disable=SC2016 # literal $HOME/$PATH wanted: the profile line must expand at ITS read time
		grep -qs '\.local/bin' "$f" || printf 'export PATH="$HOME/.local/bin:$PATH"\n' >> "$f"
	done
fi

project_root=${CLAUDE_PROJECT_DIR:-}
if [ -z "$project_root" ]; then
	git_cdup=$(git rev-parse --show-cdup 2>/dev/null) || exit 0
	project_root=$(CDPATH='' cd "${git_cdup:-.}" && pwd -L) || exit 0
fi
filter_rel='.rtk/filters.toml'
filter_path="$project_root/$filter_rel"
[ -n "$project_root" ] && [ -f "$filter_path" ] && [ ! -L "$filter_path" ] || exit 0
filter_stage=$(git -C "$project_root" ls-files --stage -- "$filter_rel" 2>/dev/null) || exit 0
case "$filter_stage" in
	'100644 '*) ;;
	*) exit 0 ;;
esac
git -C "$project_root" diff --quiet HEAD -- "$filter_rel" 2>/dev/null || exit 0
(CDPATH='' cd "$project_root" && "$rtk_bin" trust >/dev/null 2>&1) || exit 0
exit 0
