#!/bin/sh
# Shared POSIX resolver for the Graphify launcher and its owning interpreter.
# Safe to source: functions only, with all results written to stdout.

absolutize_graphify_launcher() {
	[ "$#" -eq 1 ] || return 2
	_graphify_launcher=$1
	case "$_graphify_launcher" in
		/*) ;;
		*)
			_graphify_name=${_graphify_launcher##*/}
			_graphify_dir=${_graphify_launcher%/*}
			[ "$_graphify_dir" != "$_graphify_launcher" ] || _graphify_dir=.
			case "$_graphify_dir" in
				-*) _graphify_dir=./$_graphify_dir ;;
			esac
			_graphify_dir=$(CDPATH='' cd -P "$_graphify_dir" 2>/dev/null && pwd -P) || {
				echo "resolve-graphify.sh: cannot resolve selected launcher directory '$_graphify_dir'" >&2
				return 1
			}
			_graphify_launcher=$_graphify_dir/$_graphify_name
			;;
	esac
	printf '%s\n' "$_graphify_launcher"
}

resolve_graphify_launcher() {
	if _graphify_launcher=$(command -v graphify 2>/dev/null) &&
		[ -n "$_graphify_launcher" ]; then
		:
	else
		command -v uv >/dev/null 2>&1 || {
			echo "resolve-graphify.sh: Graphify is not installed; run uv tool install --upgrade 'graphifyy[leiden] @ git+https://github.com/pfBlockerNG/graphify@v0.9.53-pfb.2' first" >&2
			return 1
		}
		_graphify_uv_bin=$(uv tool dir --bin 2>/dev/null) || {
			echo 'resolve-graphify.sh: cannot resolve uv tool executable directory' >&2
			return 1
		}
		_graphify_launcher=$_graphify_uv_bin/graphify
	fi

	_graphify_launcher=$(absolutize_graphify_launcher "$_graphify_launcher") || return 1
	[ -x "$_graphify_launcher" ] || {
		echo "resolve-graphify.sh: Graphify launcher '$_graphify_launcher' is not executable" >&2
		return 1
	}
	printf '%s\n' "$_graphify_launcher"
}

resolve_graphify_interpreter() {
	[ "$#" -eq 1 ] || return 2
	_graphify_launcher=$1
	_graphify_interpreter=$(sed -n '1s/^#![[:space:]]*//p' "$_graphify_launcher" 2>/dev/null)
	_graphify_interpreter=${_graphify_interpreter%% *}
	case "$_graphify_interpreter" in
		/*python*)
			printf '%s\n' "$_graphify_interpreter"
			return 0
			;;
	esac

	# Only uv's own selected launcher may use its shell trampoline. Never parse or
	# follow a shell wrapper selected anywhere else on PATH.
	command -v uv >/dev/null 2>&1 || return 1
	_graphify_uv_bin=$(uv tool dir --bin 2>/dev/null) || return 1
	_graphify_uv_launcher=$(absolutize_graphify_launcher "$_graphify_uv_bin/graphify") || return 1
	[ "$_graphify_launcher" = "$_graphify_uv_launcher" ] || return 1
	_graphify_uv_tools=$(uv tool dir 2>/dev/null) || return 1
	_graphify_interpreter=$_graphify_uv_tools/graphifyy/bin/python
	[ -x "$_graphify_interpreter" ] || return 1

	_graphify_interpreter_token=$("$_graphify_interpreter" -I -c 'import shlex, sys; print(shlex.quote(sys.argv[1]))' "$_graphify_interpreter") || return 1
	_graphify_line1=$(sed -n '1p' "$_graphify_launcher")
	_graphify_line2=$(sed -n '2p' "$_graphify_launcher")
	_graphify_line3=$(sed -n '3p' "$_graphify_launcher")
	[ "$_graphify_line1" = '#!/bin/sh' ] || return 1
	[ "$_graphify_line2" = "'''exec' $_graphify_interpreter_token \"\$0\" \"\$@\"" ] || return 1
	[ "$_graphify_line3" = "' '''" ] || return 1
	"$_graphify_interpreter" -I -c 'import graphify' >/dev/null 2>&1 || return 1
	printf '%s\n' "$_graphify_interpreter"
}
