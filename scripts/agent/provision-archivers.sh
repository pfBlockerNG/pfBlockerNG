#!/bin/sh
# Put the appliance's archivers where the package execs them, mirroring the three CI
# steps in .github/workflows/test.yml ("Put bsdtar at /usr/bin/tar", "Put bsdunzip at
# /usr/bin/unzip", "Put rsync at /usr/local/bin/rsync") so the archive cases that probe
# those absolute paths run locally instead of skipping or failing (issues #2356, #3068,
# #2667, #3135). GNU tar and Info-ZIP are dpkg-diverted, not removed: they move to the
# first of /usr/local/bin, /usr/local/sbin, /usr/sbin that this host's PATH searches
# BEFORE /usr/bin, so callers resolving `tar`/`unzip` by name (dpkg-deb, composer)
# keep the GNU tools. CI's fixed /usr/sbin target only works where PATH searches it
# first; a per-user directory is never a target. Both lookups are asserted, as in CI.
# Usage: provision-archivers.sh [ROOT]
#   ROOT  prefix for /usr/bin and /usr/local/bin (default /); tests provision a fixture tree.
# Debian-family Linux only (macOS ships bsdtar and SIP owns /usr/bin). Idempotent: an
# already-wired host changes nothing and needs no privilege; changes run as root or via
# sudo. Exit 1 when a lookup would be wrong, before anything moves.

set -eu

usage() {
	echo "usage: provision-archivers.sh [ROOT]" >&2
	exit 2
}

fail() {
	echo "provision-archivers.sh: $*" >&2
	exit 1
}

as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	else
		sudo "$@"
	fi
}

# The first system directory PATH searches before $bin; merged /usr makes /bin the same
# directory as /usr/bin, so physical paths are compared.
divert_dir() {
	bin_phys=$(cd "$bin" && pwd -P) || return 1
	rest=$PATH:
	while [ -n "$rest" ]; do
		dir=${rest%%:*}
		rest=${rest#*:}
		[ -n "$dir" ] || continue
		dir_phys=$(cd "$dir" 2>/dev/null && pwd -P) || continue
		[ "$dir_phys" != "$bin_phys" ] || return 1
		case "$dir_phys" in
			"$root/usr/local/bin" | "$root/usr/local/sbin" | "$root/usr/sbin")
				printf '%s\n' "$dir_phys"
				return 0
				;;
		esac
	done
	return 1
}

# $1 tool name, $2 its libarchive replacement, $3 the GNU flavour's version flag, $4 its banner.
put_libarchive() {
	name=$1 bsd=$2 gnu_flag=$3 gnu_banner=$4
	if [ "$(readlink "$bin/$name" 2>/dev/null)" != "$bsd" ]; then
		as_root dpkg-divert --no-rename --divert "$target/$name" --add "$bin/$name"
		if [ ! -e "$target/$name" ]; then
			as_root mv "$bin/$name" "$target/$name"
		elif [ -e "$bin/$name" ] && [ ! -L "$bin/$name" ]; then
			fail "both $bin/$name and $target/$name exist; resolve by hand"
		fi
		as_root ln -sfn "$bsd" "$bin/$name"
	fi
	"$bin/$name" --version | grep -q "^$bsd" || fail "$bin/$name is not $bsd"
	"$name" "$gnu_flag" | grep -q "$gnu_banner" ||
		fail "a bare '$name' no longer resolves to $gnu_banner; put $target ahead of $bin on PATH"
}

put_rsync() {
	[ -x "$local_bin/rsync" ] || as_root ln -sfn "$bin/rsync" "$local_bin/rsync"
	"$local_bin/rsync" --version | grep -qi '^rsync' || fail "$local_bin/rsync is not rsync"
}

main() {
	[ "$#" -le 1 ] || usage
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	require_tool uname
	[ "$(uname -s)" = Linux ] || fail 'Debian-family Linux only: macOS already ships bsdtar at /usr/bin/tar'
	require_tool dpkg-divert
	require_tool apt-get
	root=${1:-}
	root=${root%/}
	bin=$root/usr/bin
	local_bin=$root/usr/local/bin
	target=$(divert_dir) ||
		fail "no system directory precedes $bin on PATH ($PATH): a bare 'tar' would resolve to bsdtar"

	set --
	if [ ! -x "$bin/bsdtar" ] || [ ! -x "$bin/bsdunzip" ]; then
		set -- libarchive-tools
	fi
	[ -x "$bin/rsync" ] || set -- "$@" rsync
	if [ "$#" -gt 0 ]; then
		as_root apt-get update
		as_root apt-get install -y --no-install-recommends "$@"
	fi
	put_libarchive tar bsdtar --version 'GNU tar'
	put_libarchive unzip bsdunzip -v 'Info-ZIP'
	put_rsync
}

main "$@"
