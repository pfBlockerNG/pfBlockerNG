#!/bin/sh
# vendored-plugin-hook.sh -- run a VENDORED plugin hook script when the real
# marketplace plugin is not installed (managed/cloud sessions never install
# plugins; the vendored copies live in committed .claude/skills/<plugin>/).
#
# Args: $1 = plugin name, $2 = hook script path relative to the vendored root
# (upstream-relative, matching the plugin's own ${CLAUDE_PLUGIN_ROOT} manifest).
#
# Resolution ladder, silent (exit 0) at every rung that does not apply:
#   1. real plugin installed locally -> IT injects; running the vendored copy
#      too would double-inject every event
#   2. no node on PATH -> the static repo hooks (SessionStart mandate,
#      SubagentStart capsule) are the fallback
#   3. vendored script missing (not yet vendored / plugin removed) -> nothing
#   4. otherwise exec node with CLAUDE_PLUGIN_ROOT at the vendored root;
#      stdin (the hook's JSON payload) passes through to the script
set -eu

plugin=$1
js=$2

cfg_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
# installed_plugins.json (keyed plugin@marketplace) is the authoritative "is
# the real plugin present" source -- a marketplace-clone directory check keyed
# by PLUGIN name only works while plugin and marketplace happen to share a
# name (#931 delta review).
installed="${cfg_dir}/plugins/installed_plugins.json"
if [ -f "${installed}" ] && grep -q "\"${plugin}@" "${installed}"; then
	exit 0
fi

command -v node >/dev/null 2>&1 || exit 0

root="${CLAUDE_PROJECT_DIR:-.}/.claude/skills/${plugin}"
[ -f "${root}/${js}" ] || exit 0

CLAUDE_PLUGIN_ROOT="${root}" exec node "${root}/${js}"
