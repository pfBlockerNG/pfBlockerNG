#!/bin/sh
# Resolve one externally installed Claude plugin without guessing from cache mtimes.

plugin_install_path() {
	manifest="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/plugins/installed_plugins.json"
	[ -r "$manifest" ] && command -v jq >/dev/null 2>&1 || return 0
	jq -r --arg key "$1" --arg project "${CLAUDE_PROJECT_DIR:-.}" '
		(.plugins[$key] // []) as $entries
		| (($entries | map(select(.scope == "project" and .projectPath == $project)) | .[-1])
			// ($entries | map(select(.scope == "user")) | .[-1])
			// empty)
		| .installPath // empty
	' "$manifest" 2>/dev/null || :
}
