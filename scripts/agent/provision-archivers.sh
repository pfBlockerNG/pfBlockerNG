#!/bin/sh
# Put bsdtar, bsdunzip, and rsync where the appliance execs them, as CI's three "Put …"
# steps in .github/workflows/test.yml do; the why and the PATH-derived divert target are
# in tests/php/README.md "Host archive toolchain" (issue #3135).
# Usage: provision-archivers.sh [ROOT]
#   ROOT  prefix for /usr/bin and /usr/local/bin (default /); tests provision a fixture tree.
# Debian-family Linux with libarchive >= 3.7 (bsdunzip); macOS ships bsdtar and SIP owns
# /usr/bin. Idempotent: a wired host changes nothing and needs no privilege; changes run
# as root or via sudo. Exit 1 before anything moves when a lookup would end up wrong.

set -eu

usage() {
	echo "usage: provision-archivers.sh [ROOT]" >&2
	exit 2
}

fail() {
	echo "provision-archivers.sh: $*" >&2
	exit 1
}

# Where GNU tar and Info-ZIP go: /usr/local/bin when PATH searches it before $bin (every
# Debian PATH shape does), else /usr/sbin (the CI runner shape). Physical paths: merged
# /usr makes /bin the same directory as /usr/bin.
divert_dir() {
	bin_phys=$(CDPATH='' cd -- "$bin" && pwd -P) || return 1
	local_phys=$(CDPATH='' cd -- "$local_bin" 2>/dev/null && pwd -P) || local_phys=
	sbin_phys=$(CDPATH='' cd -- "$root/usr/sbin" 2>/dev/null && pwd -P) || sbin_phys=
	fallback=
	rest=$PATH:
	while [ -n "$rest" ]; do
		dir=${rest%%:*}
		rest=${rest#*:}
		[ -n "$dir" ] || continue
		dir_phys=$(CDPATH='' cd -- "$dir" 2>/dev/null && pwd -P) || continue
		[ "$dir_phys" != "$bin_phys" ] || break
		if [ "$dir_phys" = "$local_phys" ]; then
			printf '%s\n' "$dir_phys"
			return 0
		fi
		[ "$dir_phys" != "$sbin_phys" ] || fallback=$dir_phys
	done
	[ -n "$fallback" ] && printf '%s\n' "$fallback"
}

# $1 tool name, $2 its libarchive replacement, $3 the GNU flavour's version flag, $4 its banner.
put_libarchive() {
	name=$1 bsd=$2 gnu_flag=$3 gnu_banner=$4
	if [ "$(readlink "$bin/$name" 2>/dev/null)" != "$bsd" ]; then
		if [ -e "$target/$name" ]; then
			[ ! -e "$bin/$name" ] || [ -L "$bin/$name" ] ||
				fail "both $bin/$name and $target/$name exist; resolve by hand"
		elif [ -L "$bin/$name" ] || [ ! -f "$bin/$name" ]; then
			fail "$bin/$name is not the GNU $name binary and $target/$name is absent; resolve by hand"
		fi
		as_root dpkg-divert --no-rename --divert "$target/$name" --add "$bin/$name"
		[ -e "$target/$name" ] || as_root mv "$bin/$name" "$target/$name"
		as_root ln -sfn "$bsd" "$bin/$name"
	fi
	"$bin/$name" --version | grep -q "^$bsd" || fail "$bin/$name is not $bsd"
	"$name" "$gnu_flag" | grep -q "$gnu_banner" ||
		fail "a bare '$name' does not resolve to $gnu_banner: GNU $name belongs at $target/$name, ahead of $bin on PATH"
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
	[ -z "$root" ] || root=$(CDPATH='' cd -- "$root" && pwd -P) || fail "ROOT '$1' is not a directory"
	bin=$root/usr/bin
	local_bin=$root/usr/local/bin
	target=$(divert_dir) ||
		fail "neither $local_bin nor $root/usr/sbin precedes $bin on PATH ($PATH): a bare 'tar' would resolve to bsdtar"

	set --
	[ -x "$bin/bsdtar" ] && [ -x "$bin/bsdunzip" ] || set -- libarchive-tools
	[ -e "$bin/unzip" ] || [ -e "$target/unzip" ] || set -- "$@" unzip
	[ -x "$bin/rsync" ] || set -- "$@" rsync
	if [ "$#" -gt 0 ]; then
		as_root apt-get update
		as_root apt-get install -y --no-install-recommends "$@"
	fi
	[ -x "$bin/bsdunzip" ] || fail "$bin/bsdunzip is missing: this libarchive-tools predates libarchive 3.7"
	put_libarchive tar bsdtar --version 'GNU tar'
	put_libarchive unzip bsdunzip -v 'Info-ZIP'
	put_rsync
}

main "$@"
