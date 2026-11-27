#!/bin/sh
# Install, update, and activate the supported agent host tools.
# Usage: sh scripts/agent/setup-agent-tools.sh [REPOSITORY]
# Supports macOS and Debian-family Linux; reruns update the tools.

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
	for package in ca-certificates curl git libarchive-tools; do
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
	worktrunk_path='worktree-path = "{{ repo_path }}/.worktrees/{{ branch | sanitize }}"'
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

install_receiving_code_review() {
	source=$root/scripts/agent/skills/receiving-code-review
	destination_parent=$HOME/.agents/skills
	destination=$destination_parent/receiving-code-review
	staged=$destination_parent/.receiving-code-review.new
	previous=$destination_parent/.receiving-code-review.old
	mkdir -p "$destination_parent"
	rm -rf "$staged" "$previous"
	[ -f "$source/SKILL.md" ] || fail "required vendored skill '$source/SKILL.md' is missing"
	[ -f "$source/LICENSE" ] || fail "required vendored skill license '$source/LICENSE' is missing"
	cp -R "$source" "$staged" || {
		rm -rf "$staged"
		return 1
	}
	if [ -e "$destination" ]; then
		mv "$destination" "$previous" || {
			rm -rf "$staged"
			return 1
		}
	fi
	mv "$staged" "$destination" || {
		rm -rf "$staged"
		[ ! -e "$previous" ] || mv "$previous" "$destination"
		return 1
	}
	rm -rf "$previous"
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
	cargo_bin=${CARGO_HOME:-$HOME/.cargo}/bin
	PATH="$uv_tool_bin:$xdg_bin_home:$cargo_bin:$PATH"
	export PATH

	# An installed package manager is used as found, never self-updated (#3106):
	# every later use is `uv tool install --upgrade`, which any uv performs.
	case "$platform" in
		Linux)
			command -v uv >/dev/null 2>&1 || install_from_url 'https://astral.sh/uv/install.sh'
			;;
		Darwin)
			brew list --versions uv >/dev/null 2>&1 || brew install uv
			brew_uv_bin=$(brew --prefix uv)/bin
			PATH="$brew_uv_bin:$PATH"
			export PATH
			;;
	esac
	require_tool uv
	(cd "$root" && sh "$setup_hooks")
	uv tool install --upgrade ast-grep-cli
	uv tool install --upgrade semgrep
	require_tool ast-grep
	require_tool semgrep

	install_from_url 'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh'
	require_tool wt
	wt config shell install --yes
	configure_worktrunk

	install_receiving_code_review

	sh "$init_tools" "$root"
}

main "$@"
