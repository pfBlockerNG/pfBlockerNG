#!/bin/sh
# rtk-install.sh — SessionStart hook: install the rtk binary (pre-built, checksum-verified
# by the upstream installer) when absent, e.g. in a cloud session. Installs to ~/.local/bin,
# best-effort symlinks into /usr/local/bin and appends the PATH export to ~/.profile +
# ~/.bashrc so the NEXT shell resolves it — the rtk Bash-rewrite hook stays a no-op until
# the session PATH actually finds rtk. Never fails session start. RTK_VERSION pins a release.
set -u

command -v rtk >/dev/null 2>&1 && exit 0
[ -x "$HOME/.local/bin/rtk" ] && exit 0

{ curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/refs/heads/master/install.sh | sh; } >/dev/null 2>&1 || exit 0

[ -x "$HOME/.local/bin/rtk" ] || exit 0
if [ -w /usr/local/bin ] && [ ! -e /usr/local/bin/rtk ]; then
	ln -s "$HOME/.local/bin/rtk" /usr/local/bin/rtk 2>/dev/null
fi
for f in "$HOME/.profile" "$HOME/.bashrc"; do
	# shellcheck disable=SC2016 # literal $HOME/$PATH wanted: the profile line must expand at ITS read time
	grep -qs '\.local/bin' "$f" || printf 'export PATH="$HOME/.local/bin:$PATH"\n' >> "$f"
done
exit 0
