#!/bin/sh
# Install, update, and activate the supported agent intelligence tools.
# Usage: sh scripts/agent/setup-agent-tools.sh [REPOSITORY]
# Supports macOS and Debian-family Linux; reruns update tools and detected client integrations.

set -eu

usage() {
	echo "usage: setup-agent-tools.sh [REPOSITORY]" >&2
	exit 2
}

fail() {
	echo "setup-agent-tools.sh: $*" >&2
	exit 1
}

install_from_url() {
	installer_url=$1
	installer_file=$(mktemp "${TMPDIR:-/tmp}/setup-agent-tools.XXXXXX") || return 1
	if curl --proto '=https' --proto-redir '=https' -LsSf "$installer_url" > "$installer_file" &&
		sh "$installer_file"; then
		installer_status=0
	else
		installer_status=$?
	fi
	rm -f "$installer_file"
	return "$installer_status"
}

install_linux_prerequisites() {
	require_tool dpkg-query
	set --
	for package in ca-certificates curl git; do
		if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null |
			grep -q 'install ok installed'; then
			set -- "$@" "$package"
		fi
	done
	[ "$#" -gt 0 ] || return 0

	require_tool apt-get
	if [ "$(id -u)" -eq 0 ]; then
		apt-get update
		apt-get install -y "$@"
	else
		require_tool sudo
		sudo apt-get update
		sudo apt-get install -y "$@"
	fi
}

configure_worktrunk() {
	worktrunk_dir=${XDG_CONFIG_HOME:-$HOME/.config}/worktrunk
	worktrunk_config=$worktrunk_dir/config.toml
	worktrunk_path='worktree-path = "{{ repo_path }}/../.{{ repo }}_worktrees/{{ branch | sanitize }}"'
	mkdir -p "$worktrunk_dir"
	[ -f "$worktrunk_config" ] || touch "$worktrunk_config"
	worktrunk_trailing_newline=1
	if [ -s "$worktrunk_config" ]; then
		worktrunk_last_byte_lines=$(tail -c 1 "$worktrunk_config" | wc -l | tr -d '[:space:]')
		[ "$worktrunk_last_byte_lines" -eq 1 ] || worktrunk_trailing_newline=0
	fi
	worktrunk_tmp=$(mktemp "$worktrunk_dir/config.toml.XXXXXX") || return 1
	if ! awk \
		-v managed="$worktrunk_path" \
		-v trailing_newline="$worktrunk_trailing_newline" \
		-v single_key="'worktree-path'" \
		-v basic_multiline='"""' \
		-v literal_multiline="'''" '
		function emit(line) {
			if (emitted) printf "\n"
			printf "%s", line
			emitted = 1
		}
		function is_managed_key(line, equals, key) {
			equals = index(line, "=")
			if (!equals) return 0
			key = substr(line, 1, equals - 1)
			sub(/^[[:space:]]+/, "", key)
			sub(/[[:space:]]+$/, "", key)
			return key == "worktree-path" ||
				key == "\"worktree-path\"" ||
				key == single_key
		}
		BEGIN { root = 1; found = 0; emitted = 0; unsafe = 0 }
		root && $0 !~ /^[[:space:]]*#/ &&
			(index($0, basic_multiline) || index($0, literal_multiline)) {
			unsafe = 1
		}
		root && index($0, "=") {
			array_value = substr($0, index($0, "=") + 1)
			sub(/^[[:space:]]+/, "", array_value)
			if (substr(array_value, 1, 1) == "[") {
				unsafe = 1
			}
		}
		root && /^[[:space:]]*\[/ {
			if (!found) {
				emit(managed)
				found = 1
			}
			root = 0
		}
		root && is_managed_key($0) {
			if (!found) {
				emit(managed)
				found = 1
			}
			next
		}
		{ emit($0) }
		END {
			if (unsafe) exit 1
			if (root && !found) emit(managed)
			if (trailing_newline) printf "\n"
		}
	' "$worktrunk_config" > "$worktrunk_tmp"; then
		rm -f "$worktrunk_tmp"
		return 1
	fi
	mv "$worktrunk_tmp" "$worktrunk_config"
}

disable_serena_dashboard() {
	serena_config=$HOME/.serena/serena_config.yml
	[ -f "$serena_config" ] || fail "Serena did not create '$serena_config'"
	serena_tmp=$(mktemp "$HOME/.serena/serena_config.yml.XXXXXX") || exit 1
	if ! awk -v single_key="'web_dashboard'" '
		function is_dashboard_key(line, colon, key) {
			colon = index(line, ":")
			if (!colon) return 0
			key = substr(line, 1, colon - 1)
			sub(/[[:space:]]+$/, "", key)
			return key == "web_dashboard" ||
				key == "\"web_dashboard\"" ||
				key == single_key
		}
		is_dashboard_key($0) {
			root_keys++
			print "web_dashboard: false"
			next
		}
		{ print }
		END { if (root_keys != 1) exit 1 }
	' "$serena_config" > "$serena_tmp"; then
		rm -f "$serena_tmp"
		return 1
	fi
	mv "$serena_tmp" "$serena_config"
}

setup_serena_client() {
	if serena_output=$(serena setup "$2" 2>&1); then
		return 0
	else
		serena_status=$?
	fi
	case "$serena_output" in
		*'already exists'*) ;;
		*)
			printf '%s\n' "$serena_output" >&2
			return "$serena_status"
			;;
	esac
	case "$1" in
		claude) claude mcp remove serena -s user || return $? ;;
		codex) codex mcp remove serena || return $? ;;
		grok) grok mcp remove serena || return $? ;;
		*) return "$serena_status" ;;
	esac
	serena setup "$2"
}

setup_graphify_client() {
	# Integration and platform-skill installers are separate update surfaces.
	(cd "$HOME" && graphify "$1" install && graphify install --platform "$1")
}

configure_agents() {
	# Run both Graphify update surfaces for every detected harness mapping so neither
	# its integration nor its skill copy stays on the previous package release.
	if command -v claude >/dev/null 2>&1; then
		setup_serena_client claude claude-code
		setup_graphify_client claude
	fi
	if command -v codex >/dev/null 2>&1; then
		setup_serena_client codex codex
		setup_graphify_client codex
	fi
	if command -v grok >/dev/null 2>&1; then
		(cd "$HOME" && graphify agents install)
		setup_serena_client grok grok
		(cd "$HOME" && graphify install --platform agents)
		if ! grok mcp doctor codegraph --json >/dev/null 2>&1; then
			grok mcp remove codegraph >/dev/null 2>&1 || true
			grok mcp add codegraph -- codegraph serve --mcp
		fi
	fi
	if command -v copilot >/dev/null 2>&1; then
		setup_graphify_client copilot
	fi
	if command -v pi >/dev/null 2>&1 ||
		command -v omp >/dev/null 2>&1; then
		setup_graphify_client pi
	fi
}

main() {
	[ "$#" -le 1 ] || usage

	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	scrub_git_env "$0"
	require_tool uname
	platform=$(uname -s)
	case "$platform" in
		Linux) install_linux_prerequisites ;;
		Darwin) require_tool brew ;;
		*) fail "unsupported platform '$platform' (expected Linux or Darwin)" ;;
	esac

	require_tool curl
	require_tool git
	target=${1:-.}
	root=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) ||
		fail "'$target' is not a git worktree"
	root=$(CDPATH='' cd "$root" && pwd -P) || exit 2
	setup_hooks=$root/scripts/setup-hooks.sh
	init_tools=$root/scripts/agent/init-worktree-tools.sh
	[ -f "$setup_hooks" ] || fail "required repository helper '$setup_hooks' is missing"
	[ -f "$init_tools" ] || fail "required repository helper '$init_tools' is missing"

	if [ -n "${XDG_BIN_HOME:-}" ]; then
		xdg_bin_home=$XDG_BIN_HOME
	elif [ -n "${XDG_DATA_HOME:-}" ]; then
		xdg_bin_home=$XDG_DATA_HOME/../bin
	else
		xdg_bin_home=$HOME/.local/bin
	fi
	uv_tool_bin=${UV_TOOL_BIN_DIR:-$xdg_bin_home}
	codegraph_bin=${CODEGRAPH_BIN_DIR:-$HOME/.local/bin}
	cargo_bin=${CARGO_HOME:-$HOME/.cargo}/bin
	PATH="$uv_tool_bin:$codegraph_bin:$xdg_bin_home:$cargo_bin:$PATH"
	export PATH

	case "$platform" in
		Linux)
			if command -v uv >/dev/null 2>&1; then
				# Maintenance, not a prerequisite: every later use is
				# `uv tool install --upgrade`, which any uv performs. A uv
				# that did not come from the standalone installer refuses to
				# self-update and exits non-zero; under `set -eu` that ends
				# the run before a single tool is installed.
				uv self update || true
			else
				install_from_url 'https://astral.sh/uv/install.sh'
			fi
			;;
		Darwin)
			if brew list --versions uv >/dev/null 2>&1; then
				brew upgrade uv
			else
				brew install uv
			fi
			brew_uv_bin=$(brew --prefix uv)/bin
			PATH="$brew_uv_bin:$PATH"
			export PATH
			;;
	esac
	require_tool uv
	uv tool install --upgrade serena-agent
	uv tool install --upgrade graphifyy
	uv tool install --upgrade ast-grep-cli
	uv tool install --upgrade semgrep
	require_tool serena
	require_tool graphify
	require_tool ast-grep
	require_tool semgrep

	if command -v codegraph >/dev/null 2>&1; then
		codegraph upgrade
	else
		install_from_url 'https://raw.githubusercontent.com/colbymchenry/codegraph/main/install.sh'
	fi
	require_tool codegraph
	codegraph install -l global -y -t auto

	install_from_url 'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh'
	require_tool wt
	wt config shell install --yes
	configure_worktrunk

	serena init
	disable_serena_dashboard
	configure_agents

	(cd "$root" && sh "$setup_hooks")
	sh "$init_tools" "$root"
}

main "$@"
